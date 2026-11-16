"""API 元数据库（SQLite，WAL）。

只存：原片元数据、密文 blob 路径、信封 DEK（密文）、主密钥 id、状态。
绝不存：明文 DEK、明文原片、主密钥材料。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    image_id        TEXT PRIMARY KEY,
    filename        TEXT,
    content_type    TEXT,
    status          TEXT NOT NULL CHECK (status IN
                        ('receiving','ready','failed')),
    master_key_id   TEXT NOT NULL,
    wrapped_dek     TEXT NOT NULL,           -- 十六进制信封，始终为密文
    blob_path       TEXT NOT NULL,
    plain_size      INTEGER,
    enc_size        INTEGER,
    sha256          TEXT,
    idem_token      TEXT UNIQUE,
    error           TEXT,
    created_at      REAL NOT NULL,
    finalized_at    REAL
);
CREATE INDEX IF NOT EXISTS idx_images_mk ON images(master_key_id);
CREATE INDEX IF NOT EXISTS idx_images_status ON images(status);

CREATE TABLE IF NOT EXISTS rotation_jobs (
    job_id          TEXT PRIMARY KEY,
    state           TEXT NOT NULL CHECK (state IN
                        ('pending','migrating','destroying','completed','failed')),
    old_key_id      TEXT,
    new_key_id      TEXT,
    total           INTEGER NOT NULL DEFAULT 0,
    migrated        INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    started_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    finished_at     REAL
);
"""

TERMINAL_STATES = ("completed", "failed")
# worker 只驱动这两个执行态；pending 是受理占位（轮换调用进行中），
# 由受理端点在拿到密钥服务结果后转 migrating，worker 不得驱动它。
WORKER_STATES = ("migrating", "destroying")


class MetadataDB:
    """每线程独立连接（SQLite 连接不跨线程复用），写操作串行化。"""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._write_lock = threading.RLock()
        self._local = threading.local()
        conn = self._connect()
        conn.executescript(SCHEMA)
        self._migrate(conn)
        conn.commit()
        conn.close()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """旧版本库升级：引入 pending 受理态并放开 old/new_key_id 的 NOT NULL。"""
        cols = {r["name"] for r in conn.execute(
            "PRAGMA table_info(rotation_jobs)").fetchall()}
        if not cols:
            return
        states = [r[0] for r in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='rotation_jobs'").fetchall()]
        ddl = states[0] if states else ""
        if "'pending'" not in ddl:
            conn.execute(
                "UPDATE rotation_jobs SET state='migrating' WHERE state NOT IN "
                "('migrating','destroying','completed','failed')")
            conn.execute(
                "CREATE TABLE rotation_jobs_new ( "
                "job_id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK (state IN "
                "('pending','migrating','destroying','completed','failed')), "
                "old_key_id TEXT, new_key_id TEXT, total INTEGER NOT NULL DEFAULT 0, "
                "migrated INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, "
                "error TEXT, started_at REAL NOT NULL, updated_at REAL NOT NULL, "
                "finished_at REAL)")
            conn.execute(
                "INSERT INTO rotation_jobs_new SELECT job_id, state, old_key_id, "
                "new_key_id, total, migrated, failed, error, started_at, updated_at, "
                "finished_at FROM rotation_jobs")
            conn.execute("DROP TABLE rotation_jobs")
            conn.execute("ALTER TABLE rotation_jobs_new RENAME TO rotation_jobs")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._connect()
            self._local.conn = c
        return c

    # ---- 原片 -----------------------------------------------------------
    def create_image(self, image_id: str, filename: str | None,
                     content_type: str | None, master_key_id: str,
                     wrapped_dek: str, blob_path: str,
                     idem_token: str | None) -> str:
        with self._write_lock:
            if idem_token:
                existing = self.conn.execute(
                    "SELECT image_id FROM images WHERE idem_token=?",
                    (idem_token,)).fetchone()
                if existing:
                    return existing["image_id"]
            now = time.time()
            self.conn.execute(
                "INSERT INTO images (image_id, filename, content_type, status, "
                "master_key_id, wrapped_dek, blob_path, idem_token, created_at) "
                "VALUES (?,?,?, 'receiving', ?,?,?,?,?)",
                (image_id, filename, content_type, master_key_id,
                 wrapped_dek, blob_path, idem_token, now))
            self.conn.commit()
            return image_id

    def get_image(self, image_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE image_id=?", (image_id,)).fetchone()
        return dict(row) if row else None

    def get_by_token(self, idem_token: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE idem_token=?", (idem_token,)).fetchone()
        return dict(row) if row else None

    def finalize_image(self, image_id: str, plain_size: int, enc_size: int,
                       sha256: str) -> None:
        with self._write_lock:
            self.conn.execute(
                "UPDATE images SET status='ready', plain_size=?, enc_size=?, "
                "sha256=?, finalized_at=?, error=NULL WHERE image_id=?",
                (plain_size, enc_size, sha256, time.time(), image_id))
            self.conn.commit()

    def fail_image(self, image_id: str, error: str) -> None:
        with self._write_lock:
            # 失败行释放幂等令牌，允许客户端用同一令牌重新发起上传
            self.conn.execute(
                "UPDATE images SET status='failed', error=?, finalized_at=?, "
                "idem_token=NULL WHERE image_id=?",
                (error[:500], time.time(), image_id))
            self.conn.commit()

    def list_images(self, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self.conn.execute(
            "SELECT image_id, filename, status, master_key_id, plain_size, "
            "sha256, created_at, finalized_at FROM images "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def distinct_key_ids(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT master_key_id FROM images").fetchall()
        return [r["master_key_id"] for r in rows]

    def count_under_key(self, key_id: str,
                        only_migratable: bool = False) -> int:
        sql = "SELECT COUNT(*) AS n FROM images WHERE master_key_id=?"
        if only_migratable:
            # 仅统计会阻塞销毁的行：ready（必须 rewrap）与在途 receiving；
            # failed 行永不会被下载，无需有效信封，不阻塞销毁。
            sql += " AND status IN ('ready','receiving')"
        return self.conn.execute(sql, (key_id,)).fetchone()["n"]

    def iter_under_key(self, key_id: str) -> Iterator[dict]:
        rows = self.conn.execute(
            "SELECT * FROM images WHERE master_key_id=? "
            "AND status IN ('ready','receiving') ORDER BY created_at",
            (key_id,)).fetchall()
        for r in rows:
            yield dict(r)

    def rewrap_row(self, image_id: str, expect_old_key: str,
                   new_key_id: str, new_wrapped: str) -> bool:
        """条件更新：仅当该行仍绑定旧 MK 时改包，返回是否实际更新。

        这样迁移与"迟到的在途上传最终化"互不覆盖：后者若已自行改绑新 MK，
        迁移跳过它即可。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET master_key_id=?, wrapped_dek=? "
                "WHERE image_id=? AND master_key_id=?",
                (new_key_id, new_wrapped, image_id, expect_old_key))
            self.conn.commit()
            return cur.rowcount > 0

    def mark_stale_receiving_failed(self) -> int:
        """进程重启后，所有 receiving 都是上次崩溃的在途上传，
        不允许晚发布（防止它依赖已销毁的旧 MK 才完成）。"""
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='failed', "
                "error='interrupted by service restart', finalized_at=? "
                "WHERE status='receiving'", (time.time(),))
            self.conn.commit()
            return cur.rowcount

    # ---- 轮换作业 -------------------------------------------------------
    def active_rotation(self, include_pending: bool = True) -> dict | None:
        """返回未到终态的作业。include_pending=False 时只看 worker 执行态。"""
        states = ("migrating", "destroying")
        if include_pending:
            states = ("pending",) + states
        marks = ",".join("?" for _ in states)
        row = self.conn.execute(
            f"SELECT * FROM rotation_jobs WHERE state IN ({marks})",
            states).fetchone()
        return dict(row) if row else None

    def create_pending_rotation(self) -> str:
        """先登记 pending 占位作为受理凭证：并发受理与 worker 对账都以它为准。

        密钥代际（old/new_key_id）在轮换调用返回后再回填，因此两者先置 NULL。
        """
        with self._write_lock:
            if self.active_rotation() is not None:
                raise RuntimeError("rotation already in progress")
            job_id = "rot-" + uuid.uuid4().hex
            now = time.time()
            self.conn.execute(
                "INSERT INTO rotation_jobs (job_id, state, total, migrated, "
                "failed, started_at, updated_at) "
                "VALUES (?, 'pending', 0, 0, 0, ?, ?)",
                (job_id, now, now))
            self.conn.commit()
            return job_id

    def fill_rotation(self, job_id: str, old_key_id: str | None,
                      new_key_id: str, total: int) -> None:
        """回填轮换结果并转入 migrating；找不到 pending 行则抛错。"""
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE rotation_jobs SET old_key_id=?, new_key_id=?, total=?, "
                "state='migrating', updated_at=? WHERE job_id=? AND state='pending'",
                (old_key_id, new_key_id, total, time.time(), job_id))
            self.conn.commit()
            if cur.rowcount == 0:
                raise RuntimeError(f"pending rotation {job_id} not found")

    def fail_rotation(self, job_id: str, error: str) -> None:
        """pending 受理失败（且核实不到已生效切换）时终结占位作业。"""
        self.bump_rotation(job_id, state="failed", error=error)

    def create_rotation(self, old_key_id: str, new_key_id: str, total: int,
                        ignore_pending: bool = False) -> str:
        with self._write_lock:
            if self.active_rotation(
                    include_pending=not ignore_pending) is not None:
                raise RuntimeError("rotation already in progress")
            job_id = "rot-" + uuid.uuid4().hex
            now = time.time()
            self.conn.execute(
                "INSERT INTO rotation_jobs (job_id, state, old_key_id, "
                "new_key_id, total, migrated, failed, started_at, updated_at) "
                "VALUES (?, 'migrating', ?,?,?, 0, 0, ?, ?)",
                (job_id, old_key_id, new_key_id, total, now, now))
            self.conn.commit()
            return job_id

    def has_rotation_for(self, old_key_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM rotation_jobs WHERE old_key_id=? LIMIT 1",
            (old_key_id,)).fetchone() is not None

    def get_rotation(self, job_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def latest_rotation(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def all_rotations(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM rotation_jobs ORDER BY started_at").fetchall()
        return [dict(r) for r in rows]

    def bump_rotation(self, job_id: str, migrated: int = 0, failed: int = 0,
                      state: str | None = None, error: str | None = None) -> None:
        with self._write_lock:
            sets = ["updated_at=?"]
            params: list[Any] = [time.time()]
            if migrated:
                sets.append("migrated = migrated + ?")
                params.append(migrated)
            if failed:
                sets.append("failed = failed + ?")
                params.append(failed)
            if state:
                sets.append("state=?")
                params.append(state)
            if error is not None:
                sets.append("error=?")
                params.append(error[:500])
            if state in TERMINAL_STATES:
                sets.append("finished_at=?")
                params.append(time.time())
            params.append(job_id)
            self.conn.execute(
                f"UPDATE rotation_jobs SET {', '.join(sets)} WHERE job_id=?",
                params)
            self.conn.commit()

    def close(self):
        c = getattr(self._local, "conn", None)
        if c:
            c.close()
