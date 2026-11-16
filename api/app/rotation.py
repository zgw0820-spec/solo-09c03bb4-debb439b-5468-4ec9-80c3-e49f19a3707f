"""主密钥轮换后台工作线程。

状态机（状态持久化在 rotation_jobs，进程重启可接续）：
  migrating  ->  逐行 rewrap 信封（不重写图像密文正文）
  destroying ->  确认零残留后销毁旧主密钥（销毁后凭只读状态核实回执）
  completed / failed

并发生态保证：
  * 全程不持锁阻塞下载/上传；慢下载解包走旧 MK（销毁前完成解包即不受影响），
    下载中的帧解密只在本进程内存用明文 DEK，与密钥服务无关；
  * rewrap 用条件 UPDATE（WHERE master_key_id=旧），迟到的在途上传若已自行
    改绑新 MK 则自动跳过；
  * 销毁前再扫一遍残留并补迁，确保不会有原片依赖已销毁密钥；
  * 同一时刻只允许一个轮换作业（DB 约束 + 受理串行化 + 周期对账）；
  * 常驻线程每秒轮询未完成作业，进程重启后自动接续，不依赖唤醒信号。

对账（reconcile）：
  受理新轮换前、worker 空闲时、进程启动时都会核对密钥服务的真实密钥代际。
  若发现"密钥服务已切换、本地却没有对应作业"（崩溃于切换与登记之间、
  轮换回执不明），按代际顺序补建迁移/销毁作业并接续，保证每一把被替代的
  旧 MK 最终都被迁移并销毁，作业的完成状态与实际密钥代际一致。
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import traceback

from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB

POLL_INTERVAL = 1.0
BATCH_PAUSE = 0.02           # 批次间让出，避免挤占在线流量
RETRY_BUDGET = 6             # 单作业内瞬时错误总重试预算
RECONCILE_INTERVAL = 5.0     # 无作业时核对密钥服务代际的周期（秒）
# 超过此时长仍处于 receiving 的上传视为僵死（崩溃残留由启动恢复处理，
# 这里兜底处理连接挂起），判失败以解除对轮换销毁阶段的阻塞。
UPLOAD_STALE_SECONDS = float(os.environ.get("UPLOAD_STALE_SECONDS", "3600"))


async def reconcile_rotations(db: MetadataDB, keys: KeyClient,
                              ignore_pending: bool = False) -> list[str]:
    """核对密钥服务真实代际，为缺失登记的密钥切换补建作业。

    幂等，可在任意时刻反复调用。只登记不驱动（worker/调用方负责接续）。
    任意时刻至多一个未完成作业（含 pending 受理占位），因此每次最多补建一个，
    链条由后续轮次（worker 周期对账）逐代补齐。返回本次新建的作业 id 列表。

    ignore_pending=True 仅用于启动恢复：让对账先于 pending 恢复认领无主切换，
    pending 行本身不参与执行态，不会造成两个作业同时被 worker 驱动。

    触发场景：
      1. 进程崩溃于"密钥服务已 rotate、本地未 create_rotation"窗口；
      2. rotate 调用回执不明（网络错误耗尽重试），调用方据此核实真相；
      3. 密钥服务被外部直接切换（绕过 API）。
    """
    if db.active_rotation(include_pending=not ignore_pending) is not None:
        return []
    status = await keys.master_status()
    current = status.get("current_key_id")
    if not current:
        return []
    # 无主（没有任何作业登记）的被替代 active MK，按密钥代际排序
    missing = [
        k for k in status.get("keys", [])
        if k["key_id"] != current and k["state"] == "active"
        and not db.has_rotation_for(k["key_id"])
    ]
    # 启动恢复且存在遗留 pending 时：若只有一把无主切换，它可唯一归属到
    # 该 pending，让位给 recover_pending 回填（保持一笔作业）；多代际
    # 无法唯一归属，才由对账直接认领最旧一代，pending 随后保守判失败。
    if ignore_pending and missing and any(
            j["state"] == "pending" for j in db.all_rotations()) \
            and len(missing) == 1:
        return []
    created: list[str] = []
    for key in missing:
        total = db.count_under_key(key["key_id"], only_migratable=True)
        # 启动恢复路径可能与遗留 pending 共存：pending 不是执行态作业，
        # 允许先补建 migrating 作业，pending 随后由恢复逻辑另行处置。
        job_id = db.create_rotation(key["key_id"], current, total,
                                    ignore_pending=ignore_pending)
        created.append(job_id)
        break  # 单活跃作业不变式：剩余代际由后续对账补建
    return created


async def recover_pending_rotations(db: MetadataDB,
                                    keys: KeyClient) -> list[str]:
    """恢复崩溃于受理窗口的 pending 占位作业（进程启动时调用一次）。

    须在 reconcile_rotations(ignore_pending=True) 之后运行：无主切换已被
    对账认领为 migrating 作业。对每个遗留 pending 核实密钥服务真相：
      * 恰好存在一把未登记且未被认领的被替代 active MK -> 回填 pending 接续；
      * 无未登记切换（rotate 从未生效，或已被对账认领）-> pending 判 failed，
        释放受理位；多代际且无法唯一归属时同样保守判 failed，
        链条由 worker 周期对账逐代收敛，绝不凭猜测回填。
    返回被恢复（转 migrating）的作业 id。
    """
    recovered: list[str] = []
    status = await keys.master_status()
    current = status.get("current_key_id")
    pending = [j for j in db.all_rotations() if j["state"] == "pending"]
    for job in pending:
        missing = [
            k for k in status.get("keys", [])
            if k["key_id"] != current and k["state"] == "active"
            and not db.has_rotation_for(k["key_id"])
        ]
        if len(missing) == 1 and current and db.active_rotation(
                include_pending=False) is None:
            old = missing[0]
            total = db.count_under_key(old["key_id"], only_migratable=True)
            db.fill_rotation(job["job_id"], old["key_id"], current, total)
            recovered.append(job["job_id"])
        else:
            db.fail_rotation(
                job["job_id"],
                "pending rotation superseded after restart: no uniquely "
                "attributable unregistered key switch")
    return recovered


class RotationWorker:
    def __init__(self, db: MetadataDB, keys: KeyClient,
                 loop: asyncio.AbstractEventLoop):
        self._db = db
        self._keys = keys
        self._loop = loop
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._thread_main, daemon=True,
                                        name="rotation-worker")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _thread_main(self):
        try:
            fut = asyncio.run_coroutine_threadsafe(self._run(), self._loop)
            fut.result()
        except Exception:
            traceback.print_exc()

    async def _run(self):
        """常驻协程：执行态作业驱动到终态；pending 不驱动（归受理/恢复路径）；
        无作业时周期性对账，发现未登记切换即补建并在下一轮驱动。"""
        last_reconcile = 0.0
        while not self._stop.is_set():
            # 只取 worker 执行态，pending 占位由端点/启动恢复负责回填
            job = self._db.active_rotation(include_pending=False)
            if job is not None:
                await self._drive_job(job["job_id"])
                last_reconcile = 0.0  # 作业刚收尾，尽快重新核对代际
                continue
            now = time.time()
            if now - last_reconcile >= RECONCILE_INTERVAL:
                last_reconcile = now
                try:
                    await reconcile_rotations(self._db, self._keys)
                except KeyServiceError as exc:
                    print(f"[rotation] reconcile skipped: {exc.code} {exc.message}")
            await asyncio.sleep(POLL_INTERVAL)

    async def _drive_job(self, job_id: str):
        retries = 0
        while not self._stop.is_set():
            job = self._db.get_rotation(job_id)
            if job is None or job["state"] in ("completed", "failed"):
                return
            try:
                if job["state"] == "migrating":
                    done = await self._migrate(job)
                    retries = 0
                    if done:
                        self._db.bump_rotation(job_id, state="destroying")
                    else:
                        await asyncio.sleep(POLL_INTERVAL)
                elif job["state"] == "destroying":
                    await self._destroy(job)
                    return
            except KeyServiceError as exc:
                retries += 1
                if retries >= RETRY_BUDGET:
                    self._db.bump_rotation(
                        job_id, state="failed",
                        error=f"key service error after retries: "
                              f"{exc.code} {exc.message}")
                    return
                await asyncio.sleep(min(0.5 * (2 ** retries), 8.0))
            except Exception as exc:  # 防御：任何意外都落 failed，不静默
                self._db.bump_rotation(job_id, state="failed",
                                       error=f"unexpected: {exc!r}")
                traceback.print_exc()
                return

    async def _migrate(self, job: dict) -> bool:
        """扫描绑定旧 MK 的行并 rewrap。返回 True 表示零残留可进入销毁。"""
        old_key, new_key, job_id = job["old_key_id"], job["new_key_id"], job["job_id"]
        migrated_now = 0
        for row in self._db.iter_under_key(old_key):
            latest = self._db.get_rotation(job_id)
            if latest is None or latest["state"] == "failed":
                return False
            # 在途上传分两种：
            #  1) 僵死（超时）-> 判失败，禁止晚发布，解除销毁阻塞
            #  2) 活跃 -> 跳过，本轮先迁移别的；下轮再看（最终成功的上传会在
            #     finalize 时改绑当前新 MK；失败的不会成为可读原片）
            if row["status"] == "receiving":
                if time.time() - row["created_at"] > UPLOAD_STALE_SECONDS:
                    self._db.fail_image(
                        row["image_id"],
                        "stale receiving upload during key rotation")
                    self._db.bump_rotation(job_id, migrated=1)
                    migrated_now += 1
                continue
            try:
                token = f"{job_id}:{row['image_id']}"
                res = await self._keys.rewrap(old_key, row["wrapped_dek"], token)
            except KeyServiceError as exc:
                if exc.status_code == 410:
                    # 旧 MK 已被外部销毁：剩余行无法迁移，作业失败而非丢数据
                    self._db.bump_rotation(
                        job_id, failed=1,
                        error=f"old key destroyed with rows remaining: {exc.message}")
                    return False
                raise
            changed = self._db.rewrap_row(row["image_id"], old_key,
                                          res["key_id"], res["wrapped_dek"])
            if changed:
                migrated_now += 1
                self._db.bump_rotation(job_id, migrated=1)
            if migrated_now and migrated_now % 50 == 0:
                await asyncio.sleep(BATCH_PAUSE)

        # 最终核验：在途上传可能在扫描后又落了一行旧 MK，下轮继续补迁到零残留
        return self._db.count_under_key(old_key, only_migratable=True) == 0

    async def _destroy(self, job: dict):
        old_key, job_id = job["old_key_id"], job["job_id"]
        # 销毁前最后一次核实（防扫描窗口内的迟到行）
        if self._db.count_under_key(old_key, only_migratable=True) != 0:
            self._db.bump_rotation(job_id, state="migrating")
            return
        # 销毁；回执丢失时 KeyClient 内部以只读 status 核实，不提前报完成
        await self._keys.destroy_master(old_key)
        # 二次核实：密钥服务视角确实 destroyed
        status = await self._keys.master_status()
        states = {k["key_id"]: k["state"] for k in status.get("keys", [])}
        if states.get(old_key) != "destroyed":
            raise KeyServiceError(503, "destroy_not_verified",
                                  "destroy receipt cannot be verified")
        self._db.bump_rotation(job_id, state="completed")
