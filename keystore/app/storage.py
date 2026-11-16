"""密钥服务持久化层（SQLite，挂载在独立持久卷上）。

表：
  master_keys  主密钥本体（随机 32 字节）、状态(active/destroyed)、时间戳
  meta         单例行：当前生效主密钥 id
  idem_log     幂等令牌 -> 首次响应，保证 destroy/rewrap 重放得到同一结果

主密钥只存在本服务进程内存与本卷的 SQLite 中；销毁即把 key 列覆写为
全零并置 destroyed，密码学意义上无法再用于解包。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Optional

from .crypto_envelope import new_data_key, unwrap_dek, wrap_dek

SCHEMA = """
CREATE TABLE IF NOT EXISTS master_keys (
    key_id       TEXT PRIMARY KEY,
    key_material BLOB NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('active','destroyed')),
    created_at   REAL NOT NULL,
    destroyed_at REAL
);
CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    current_key_id TEXT
);
INSERT OR IGNORE INTO meta (id, current_key_id) VALUES (1, NULL);
CREATE TABLE IF NOT EXISTS idem_log (
    token        TEXT PRIMARY KEY,
    status_code  INTEGER NOT NULL,
    response     TEXT NOT NULL,
    created_at   REAL NOT NULL
);
"""


class KeyError_(Exception):
    """业务错误：携带 HTTP 状态码与错误码。"""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class KeyStore:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ---- 内部工具 -------------------------------------------------------
    def _get_key_row(self, cur, key_id: str) -> sqlite3.Row:
        row = cur.execute(
            "SELECT * FROM master_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise KeyError_(404, "key_not_found", f"master key {key_id} not found")
        return row

    def current_key_id(self) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT current_key_id FROM meta WHERE id = 1"
            ).fetchone()
            return row["current_key_id"]

    # ---- 主密钥生命周期 -------------------------------------------------
    def ensure_bootstrap(self) -> dict:
        """无主密钥时自动生成第一把（API 服务首次启动会调用）。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            row = cur.execute(
                "SELECT current_key_id FROM meta WHERE id = 1"
            ).fetchone()
            if row["current_key_id"]:
                key_id = row["current_key_id"]
                created = cur.execute(
                    "SELECT created_at FROM master_keys WHERE key_id=?", (key_id,)
                ).fetchone()
                cur.execute("COMMIT")
                return {"key_id": key_id, "created_at": created["created_at"],
                        "bootstrapped": False}
            key_id = "mk-" + uuid.uuid4().hex
            cur.execute(
                "INSERT INTO master_keys (key_id, key_material, state, created_at) "
                "VALUES (?,?, 'active', ?)",
                (key_id, os.urandom(32), time.time()),
            )
            cur.execute("UPDATE meta SET current_key_id=? WHERE id=1", (key_id,))
            cur.execute("COMMIT")
            return {"key_id": key_id, "created_at": time.time(),
                    "bootstrapped": True}

    def rotate_master(self, token: Optional[str] = None) -> dict:
        """生成新主密钥并切为当前；旧主密钥保留 active 待迁移完成后销毁。
        幂等：同一 token 的重试返回同一次轮换结果，不重复生成 MK。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            if token:
                cached = cur.execute(
                    "SELECT response FROM idem_log WHERE token=?", (token,)
                ).fetchone()
                if cached is not None:
                    cur.execute("COMMIT")
                    import json
                    return {**json.loads(cached["response"]), "idempotent": True}
            old_id = cur.execute(
                "SELECT current_key_id FROM meta WHERE id=1"
            ).fetchone()["current_key_id"]
            new_id = "mk-" + uuid.uuid4().hex
            cur.execute(
                "INSERT INTO master_keys (key_id, key_material, state, created_at) "
                "VALUES (?,?, 'active', ?)",
                (new_id, os.urandom(32), time.time()),
            )
            cur.execute("UPDATE meta SET current_key_id=? WHERE id=1", (new_id,))
            result = {"new_key_id": new_id, "old_key_id": old_id}
            if token:
                import json
                cur.execute(
                    "INSERT OR IGNORE INTO idem_log "
                    "(token, status_code, response, created_at) VALUES (?,?,?,?)",
                    (token, 200, json.dumps(result), time.time()),
                )
            cur.execute("COMMIT")
            return result

    def destroy_master(self, key_id: str) -> dict:
        """销毁主密钥：密钥材料安全覆写。重复销毁是幂等的。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            row = self._get_key_row(cur, key_id)
            if row["state"] == "destroyed":
                cur.execute("COMMIT")
                return {"key_id": key_id, "state": "destroyed",
                        "destroyed_at": row["destroyed_at"], "idempotent": True}
            cur.execute(
                "UPDATE master_keys SET key_material=?, state='destroyed', "
                "destroyed_at=? WHERE key_id=?",
                (b"\x00" * 32, time.time(), key_id),
            )
            # 若销毁的恰为当前密钥（仅测试/异常路径），清空 current 指针
            cur.execute(
                "UPDATE meta SET current_key_id=NULL "
                "WHERE id=1 AND current_key_id=?",
                (key_id,),
            )
            cur.execute("COMMIT")
            return {"key_id": key_id, "state": "destroyed",
                    "destroyed_at": time.time(), "idempotent": False}

    def status(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key_id, state, created_at, destroyed_at FROM master_keys "
                "ORDER BY created_at"
            ).fetchall()
            return {
                "current_key_id": self.current_key_id(),
                "keys": [dict(r) for r in rows],
            }

    # ---- DEK 操作 -------------------------------------------------------
    def generate_dek(self) -> dict:
        """生成新 DEK，用当前主密钥包裹后返回（明文 DEK 同时返回一次，
        供 API 服务立即加密原片；API 不落盘明文 DEK）。"""
        with self._lock:
            cur = self._conn.cursor()
            current = self.current_key_id()
            if not current:
                raise KeyError_(409, "no_active_master",
                                "no active master key; bootstrap first")
            row = self._get_key_row(cur, current)
            dek = new_data_key()
            envelope = wrap_dek(row["key_material"], dek)
            return {"key_id": current, "dek": dek.hex(),
                    "wrapped_dek": envelope.hex()}

    def unwrap(self, key_id: str, wrapped_dek_hex: str) -> dict:
        with self._lock:
            cur = self._conn.cursor()
            row = self._get_key_row(cur, key_id)
            if row["state"] == "destroyed":
                raise KeyError_(410, "key_destroyed",
                                f"master key {key_id} has been destroyed")
            try:
                dek = unwrap_dek(row["key_material"],
                                 bytes.fromhex(wrapped_dek_hex))
            except Exception as exc:  # 认证失败 / 格式错误
                raise KeyError_(400, "unwrap_failed", str(exc)) from exc
            return {"dek": dek.hex()}

    def rewrap(self, old_key_id: str, wrapped_dek_hex: str,
               token: Optional[str]) -> dict:
        """把旧 MK 包裹的 DEK 改用当前 MK 包裹，不暴露明文 DEK 给调用方。
        幂等：同一 token 的重试返回首次结果。"""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            if token:
                cached = cur.execute(
                    "SELECT response FROM idem_log WHERE token=?", (token,)
                ).fetchone()
                if cached is not None:
                    cur.execute("COMMIT")
                    import json
                    return {**json.loads(cached["response"]), "idempotent": True}
            old = self._get_key_row(cur, old_key_id)
            if old["state"] == "destroyed":
                raise KeyError_(410, "key_destroyed",
                                f"master key {old_key_id} has been destroyed")
            new_key_id = cur.execute(
                "SELECT current_key_id FROM meta WHERE id=1"
            ).fetchone()["current_key_id"]
            if not new_key_id:
                raise KeyError_(409, "no_active_master", "no active master key")
            new = self._get_key_row(cur, new_key_id)
            try:
                dek = unwrap_dek(old["key_material"],
                                 bytes.fromhex(wrapped_dek_hex))
            except Exception as exc:
                raise KeyError_(400, "unwrap_failed", str(exc)) from exc
            new_envelope = wrap_dek(new["key_material"], dek)
            result = {"old_key_id": old_key_id, "key_id": new_key_id,
                      "wrapped_dek": new_envelope.hex()}
            if token:
                import json
                cur.execute(
                    "INSERT OR IGNORE INTO idem_log "
                    "(token, status_code, response, created_at) VALUES (?,?,?,?)",
                    (token, 200, json.dumps(result), time.time()),
                )
            cur.execute("COMMIT")
            return result

    def close(self):
        with self._lock:
            self._conn.close()
