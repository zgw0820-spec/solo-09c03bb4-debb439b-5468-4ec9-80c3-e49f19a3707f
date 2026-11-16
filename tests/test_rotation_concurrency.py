"""并发轮换受理与轮换登记对账恢复（本次修复的回归测试）。

覆盖：
  R1 并发两次 POST /rotations：只受理一次（202 + 409），密钥服务只切一次，
     被拒请求不再切密钥，作业登记的新密钥即当前密钥，旧 MK 最终销毁
  R2 密钥服务已切换、本地未登记（模拟崩溃/回执不明）：下次受理先核实并
     补建作业返回 409(reconciled)，且不会再切一次；链条逐代收敛
  R3 API 重启后对账恢复：未登记的多代际切换被逐代补建、迁移并销毁，
     完成状态与密钥服务实际代际一致；期间上传走当前 MK、旧原片可下载
  R4 rotate 回执不明（密钥服务网络失败）：核实到切换已生效则补登记并
     返回 202(reconciled)，不重复切换
  R5 受理窗口崩溃留下 pending 占位：重启后按密钥服务真相恢复——
     切换已生效则回填接续到销毁；未生效则占位判 failed、受理位释放
  R6 旧版本元数据库（无 pending 态）可在线迁移并正常工作
  R7 pending 与多代际未登记切换并存：pending 保守判失败，对账逐代收敛
"""
import sqlite3
import threading
import time
from pathlib import Path

import httpx

from conftest import TOKEN, _download, _upload, _key_headers, _wait_rotation


def _start_rotation(client: httpx.Client) -> httpx.Response:
    return client.post("/rotations", json={"confirm": True})


def _key_status(kc: httpx.Client) -> dict:
    return kc.get("/internal/master/status", headers=_key_headers()).json()


def test_concurrent_rotation_accepted_once_without_double_switch(stack):
    client, kc = stack["client"], stack["key_client"]
    _upload(client, b"race-anchor" * 100, image_id="race-anchor")
    before = _key_status(kc)
    assert len(before["keys"]) == 1
    original = before["current_key_id"]

    # 慢密钥操作放大竞态窗口，两个请求在密钥服务处理期间并发到达
    env = dict(stack["keys"]._env)
    env["KEY_OP_DELAY"] = "0.3"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()

    responses: list[httpx.Response] = []

    def fire():
        responses.append(_start_rotation(client))

    t1, t2 = threading.Thread(target=fire), threading.Thread(target=fire)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    statuses = sorted(r.status_code for r in responses)
    assert statuses == [202, 409], [r.text for r in responses]
    accepted = next(r for r in responses if r.status_code == 202).json()
    rejected = next(r for r in responses if r.status_code == 409).json()
    assert rejected["detail"]["code"] == "rotation_in_progress"
    assert rejected["detail"]["job_id"] == accepted["job_id"]

    # 密钥服务视角：只新增了一把 MK（只切了一次），当前 MK 就是作业登记的新 MK
    after = _key_status(kc)
    assert len(after["keys"]) == 2
    assert after["current_key_id"] == accepted["new_key_id"]
    assert accepted["old_key_id"] == original

    # 作业正常完成、旧 MK 销毁，无任何"中间密钥"残留
    result = _wait_rotation(client, accepted["job_id"])
    assert result["state"] == "completed", result
    final = _key_status(kc)
    assert {k["key_id"]: k["state"] for k in final["keys"]}[original] == "destroyed"
    assert final["current_key_id"] == accepted["new_key_id"]

    # 期间新原片用当前 MK 入仓，旧原片照常下载
    r = _upload(client, b"during-race", image_id="during-race")
    assert r.status_code == 201
    assert r.json()["master_key_id"] == final["current_key_id"]
    assert _download(client, "race-anchor") == b"race-anchor" * 100
    assert _download(client, "during-race") == b"during-race"


def test_unregistered_switch_is_reconciled_before_new_rotation(stack):
    client, kc = stack["client"], stack["key_client"]
    payload = b"orphan-switch" * 50
    _upload(client, payload, image_id="orphan-1")
    mk_before = _key_status(kc)["current_key_id"]

    # 模拟崩溃窗口/回执不明：密钥服务已切换，API 侧没有任何作业登记
    switched = kc.post("/internal/master/rotate",
                       headers=_key_headers()).json()
    assert switched["old_key_id"] == mk_before
    assert client.get("/rotations/latest").json() == {
        "message": "no rotation has ever run"}

    # 再次发起轮换：必须先核实并补建作业（409 reconciled），而不是再切一次
    r = _start_rotation(client)
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["code"] == "rotation_in_progress"
    assert detail.get("reconciled") is True
    job_id = detail["job_id"]

    status_after_attempt = _key_status(kc)
    # 没有因为这次请求再多一把 MK
    assert len(status_after_attempt["keys"]) == 2
    assert status_after_attempt["current_key_id"] == switched["new_key_id"]

    job = client.get(f"/rotations/{job_id}").json()
    assert job["old_key_id"] == mk_before
    assert job["new_key_id"] == switched["new_key_id"]
    result = _wait_rotation(client, job_id)
    assert result["state"] == "completed", result
    states = {k["key_id"]: k["state"]
              for k in _key_status(kc)["keys"]}
    assert states[mk_before] == "destroyed"
    # 旧原片信封已随补建作业迁移，仍可逐字节下载
    assert _download(client, "orphan-1") == payload

    # 链条收敛后允许正常发起下一笔轮换
    next_job = _start_rotation(client)
    assert next_job.status_code == 202, next_job.text
    assert _wait_rotation(
        client, next_job.json()["job_id"])["state"] == "completed"


def test_restart_reconciles_unregistered_multigeneration_chain(stack):
    client, kc = stack["client"], stack["key_client"]
    payload_a = b"gen-a" * 30
    _upload(client, payload_a, image_id="gen-a")
    first_mk = _key_status(kc)["current_key_id"]

    # 模拟 API 宕机期间密钥服务被连续切换两代，本地一笔作业都没有
    kc.post("/internal/master/rotate", headers=_key_headers()).raise_for_status()
    kc.post("/internal/master/rotate", headers=_key_headers()).raise_for_status()
    key_view = _key_status(kc)
    assert len(key_view["keys"]) == 3
    current_mk = key_view["current_key_id"]

    # API 重启：启动对账 + worker 周期对账应逐代补建并收敛
    stack["api"].restart()
    deadline = time.time() + 90
    last_job = None
    while time.time() < deadline:
        ks = _key_status(kc)
        active_states = [k for k in ks["keys"] if k["state"] == "active"]
        last_job = client.get("/rotations/latest").json()
        if len(active_states) == 1 and ks["current_key_id"] == current_mk:
            break
        time.sleep(0.5)
    else:
        raise AssertionError(f"chain did not converge: {_key_status(kc)}")

    # 除当前 MK 外全部销毁；完成状态对应实际代际
    final = _key_status(kc)
    assert {k["key_id"]: k["state"] for k in final["keys"]}[first_mk] == "destroyed"
    assert len([k for k in final["keys"] if k["state"] == "active"]) == 1
    jobs = client.get("/rotations/latest").json()
    assert jobs["state"] == "completed"

    # 旧原片跨两代迁移后仍可读；新原片用当前 MK 入仓
    assert _download(client, "gen-a") == payload_a
    r = _upload(client, b"gen-new", image_id="gen-new")
    assert r.status_code == 201
    assert r.json()["master_key_id"] == current_mk
    assert _download(client, "gen-new") == b"gen-new"


def test_ambiguous_rotate_receipt_is_verified_and_registered(stack):
    """rotate 回执不明（重试全部丢响应）：切换已生效时核实补登记，不重复切换。"""
    client, kc = stack["client"], stack["key_client"]
    payload = b"ambiguous-receipt" * 40
    _upload(client, payload, image_id="amb-1")
    before = _key_status(kc)
    mk_before = before["current_key_id"]

    # 密钥服务对轮换始终不回完整响应（含幂等重放），客户端 5 次尝试全部失败
    env = dict(stack["keys"]._env)
    env["KEY_ROTATE_DROP_RECEIPT"] = "always"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()

    r = _start_rotation(client)
    # 切换实际已生效：端点核实后补登记，按正常受理返回 202(reconciled)
    assert r.status_code == 202, r.text
    receipt = r.json()
    assert receipt.get("reconciled") is True
    assert receipt["old_key_id"] == mk_before

    # 整个受理过程只切了一次（核实期间不会再 rotate）
    ks = _key_status(kc)
    assert len(ks["keys"]) == len(before["keys"]) + 1
    assert ks["current_key_id"] == receipt["new_key_id"]

    # 恢复密钥服务正常响应，补建作业继续迁移并销毁旧 MK
    env["KEY_ROTATE_DROP_RECEIPT"] = "false"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()
    result = _wait_rotation(client, receipt["job_id"], timeout=90)
    assert result["state"] == "completed", result
    states = {k["key_id"]: k["state"] for k in _key_status(kc)["keys"]}
    assert states[mk_before] == "destroyed"
    assert _download(client, "amb-1") == payload

def _insert_pending_job(db_path: Path) -> str:
    """直接在元数据库插入 pending 占位，模拟进程在受理窗口被 kill。"""
    conn = sqlite3.connect(db_path)
    job_id = "rot-pending-crash"
    now = time.time()
    conn.execute(
        "INSERT INTO rotation_jobs (job_id, state, total, migrated, failed, "
        "started_at, updated_at) VALUES (?, 'pending', 0, 0, 0, ?, ?)",
        (job_id, now, now))
    conn.commit()
    conn.close()
    return job_id


def test_pending_rotation_recovered_after_restart_when_switch_happened(stack):
    client, kc = stack["client"], stack["key_client"]
    payload = b"pending-recover" * 40
    _upload(client, payload, image_id="pend-1")
    mk_before = _key_status(kc)["current_key_id"]

    # 密钥服务侧切换已生效，API 侧只留下 pending 占位即崩溃
    switched = kc.post("/internal/master/rotate",
                       headers=_key_headers()).json()
    job_id = _insert_pending_job(stack["data_dir"] / "metadata.db")
    stack["api"].restart()  # 启动恢复应回填并接续

    job = client.get(f"/rotations/{job_id}").json()
    assert job["old_key_id"] == mk_before
    assert job["new_key_id"] == switched["new_key_id"]
    result = _wait_rotation(client, job_id, timeout=60)
    assert result["state"] == "completed", result
    states = {k["key_id"]: k["state"] for k in _key_status(kc)["keys"]}
    assert states[mk_before] == "destroyed"
    assert _download(client, "pend-1") == payload


def test_pending_rotation_failed_after_restart_when_no_switch(stack):
    client = stack["client"]
    # 密钥服务没有任何新切换，pending 占位对应的 rotate 从未生效
    job_id = _insert_pending_job(stack["data_dir"] / "metadata.db")
    stack["api"].restart()
    job = client.get(f"/rotations/{job_id}").json()
    assert job["state"] == "failed"
    assert job["error"]
    # 受理位已释放：可以正常发起并完成一笔新轮换
    r = _start_rotation(client)
    assert r.status_code == 202, r.text
    assert _wait_rotation(client, r.json()["job_id"])["state"] == "completed"


def test_legacy_schema_migrates_and_rotation_works(stack):
    """旧版本库（state 无 pending、密钥列 NOT NULL）在线迁移后功能正常。"""
    stack["api"].stop()
    db_path = stack["data_dir"] / "metadata.db"
    conn = sqlite3.connect(db_path)
    # 重建为修复前的旧表结构
    conn.execute("ALTER TABLE rotation_jobs RENAME TO rotation_jobs_old")
    conn.execute(
        "CREATE TABLE rotation_jobs (job_id TEXT PRIMARY KEY, state TEXT NOT NULL "
        "CHECK (state IN ('migrating','destroying','completed','failed')), "
        "old_key_id TEXT NOT NULL, new_key_id TEXT NOT NULL, total INTEGER NOT NULL "
        "DEFAULT 0, migrated INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL "
        "DEFAULT 0, error TEXT, started_at REAL NOT NULL, updated_at REAL NOT NULL, "
        "finished_at REAL)")
    now = time.time()
    conn.execute(
        "INSERT INTO rotation_jobs (job_id, state, old_key_id, new_key_id, total, "
        "migrated, failed, started_at, updated_at, finished_at) "
        "VALUES ('rot-legacy', 'completed', 'mk-old', 'mk-new', 1, 1, 0, ?, ?, ?)",
        (now, now, now))
    conn.execute("DROP TABLE rotation_jobs_old")
    conn.commit()
    conn.close()

    stack["api"].start()  # 启动即迁移
    client = stack["client"]
    # 旧数据仍可读且状态保留
    job = client.get("/rotations/rot-legacy").json()
    assert job["state"] == "completed" and job["old_key_id"] == "mk-old"
    # 迁移后的表支持 pending 受理：正常发起一笔完整轮换
    r = _start_rotation(client)
    assert r.status_code == 202, r.text
    assert _wait_rotation(client, r.json()["job_id"])["state"] == "completed"


def test_pending_with_multigeneration_switch_converges_after_restart(stack):
    """pending 占位存在时密钥服务已连切两代：pending 保守判失败，
    对账认领最旧一代，worker 周期对账逐代收敛到只剩当前 MK active。"""
    client, kc = stack["client"], stack["key_client"]
    payload = b"multi-gen-pending" * 30
    _upload(client, payload, image_id="mgp-1")
    first_mk = _key_status(kc)["current_key_id"]
    kc.post("/internal/master/rotate", headers=_key_headers()).raise_for_status()
    kc.post("/internal/master/rotate", headers=_key_headers()).raise_for_status()
    view = _key_status(kc)
    assert len(view["keys"]) == 3
    current_mk = view["current_key_id"]

    _insert_pending_job(stack["data_dir"] / "metadata.db")
    stack["api"].restart()

    # 链条最终收敛：除当前 MK 外全部销毁，pending 已被处置（failed），
    # 所有作业终态与实际代际一致
    deadline = time.time() + 90
    while time.time() < deadline:
        ks = _key_status(kc)
        if len([k for k in ks["keys"] if k["state"] == "active"]) == 1:
            break
        time.sleep(0.5)
    else:
        raise AssertionError(f"did not converge: {_key_status(kc)}")
    final = _key_status(kc)
    assert final["current_key_id"] == current_mk
    assert {k["key_id"]: k["state"] for k in final["keys"]}[first_mk] == "destroyed"
    pending_job = client.get("/rotations/rot-pending-crash").json()
    assert pending_job["state"] == "failed"
    assert _download(client, "mgp-1") == payload
