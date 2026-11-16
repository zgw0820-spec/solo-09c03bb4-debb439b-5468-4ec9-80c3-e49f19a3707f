"""T3-T8/T11：轮换正确性、并发不阻塞、丢回执接续、重启恢复。"""
import time

import httpx

from conftest import TOKEN, _download, _upload, _key_headers, _wait_rotation


def _start_rotation(client: httpx.Client) -> dict:
    r = client.post("/rotations", json={"confirm": True})
    assert r.status_code == 202, r.text
    return r.json()


def test_full_rotation_migrates_envelopes_and_keeps_blobs(stack):
    client, kc = stack["client"], stack["key_client"]
    payload1 = b"before-rotation-" + bytes(range(256)) * 20
    assert _upload(client, payload1, image_id="before-1").status_code == 201
    before = client.get("/images/before-1/meta").json()
    old_key = before["master_key_id"]
    blob_file = next(stack["blob_dir"].iterdir())
    blob_bytes_before = blob_file.read_bytes()

    job = _start_rotation(client)
    assert job["old_key_id"] == old_key
    result = _wait_rotation(client, job["job_id"])
    assert result["state"] == "completed", result
    assert result["migrated"] == 1 and result["failed"] == 0

    # 图像密文正文未重写（逐字节相同），仅元数据里的信封换了
    assert blob_file.read_bytes() == blob_bytes_before
    after = client.get("/images/before-1/meta").json()
    assert after["master_key_id"] != old_key
    assert _download(client, "before-1") == payload1

    # 旧 MK 已在密钥服务侧销毁；新入湖走新 MK
    ks = kc.get("/internal/master/status", headers=_key_headers()).json()
    states = {k["key_id"]: k["state"] for k in ks["keys"]}
    assert states[old_key] == "destroyed"
    payload2 = b"after-rotation"
    r = _upload(client, payload2, image_id="after-1")
    assert r.status_code == 201
    assert r.json()["master_key_id"] == ks["current_key_id"]
    assert _download(client, "after-1") == payload2


def test_rotation_progress_and_reject_second_rotation(stack):
    client = stack["client"]
    for i in range(3):
        _upload(client, f"img-{i}".encode() * 100, image_id=f"p-{i}")
    job = _start_rotation(client)
    # 完成前再次发起 -> 409
    r2 = client.post("/rotations", json={"confirm": True})
    assert r2.status_code == 409
    assert r2.json()["detail"]["code"] == "rotation_in_progress"
    result = _wait_rotation(client, job["job_id"])
    assert result["state"] == "completed"
    # 完成后允许新轮换
    job2 = _start_rotation(client)
    assert job2["state"] == "migrating"
    assert _wait_rotation(client, job2["job_id"])["state"] == "completed"
    latest = client.get("/rotations/latest").json()
    assert latest["job_id"] == job2["job_id"]
    assert latest["progress_percent"] == 100.0


def test_second_rotation_does_not_touch_migrated_blobs(stack):
    """二次轮换：已迁移原片的 blob 正文仍逐字节不变，只换信封。"""
    client = stack["client"]
    payload = b"stable-body" * 999
    _upload(client, payload, image_id="stable-1")
    blob_file = next(stack["blob_dir"].iterdir())
    snapshot = blob_file.read_bytes()
    for _ in range(2):
        job = _start_rotation(client)
        assert _wait_rotation(client, job["job_id"])["state"] == "completed"
    assert blob_file.read_bytes() == snapshot
    assert _download(client, "stable-1") == payload


def test_inflight_download_survives_key_destruction(stack):
    """在途下载：先解包 DEK 再销毁旧 MK，慢下载仍完整成功。"""
    client, kc = stack["client"], stack["key_client"]
    payload = bytes((i * 7) % 256 for i in range(2 * 1024 * 1024))
    _upload(client, payload, image_id="inflight-dl")
    old_key = client.get("/images/inflight-dl/meta").json()["master_key_id"]

    # 用短超时客户端发起请求，读到响应头即说明 DEK 已解包；然后立刻销毁旧 MK
    with httpx.Client(base_url=stack["api"].base, timeout=30) as slow:
        with slow.stream("GET", "/images/inflight-dl") as resp:
            assert resp.status_code == 200
            # 此时 API 已完成 unwrap，明文 DEK 在请求内存中
            r = kc.post("/internal/master/destroy",
                        json={"key_id": old_key}, headers=_key_headers())
            assert r.status_code == 200 and r.json()["state"] == "destroyed"
            time.sleep(0.5)  # 模拟客户端慢速读取
            body = b"".join(chunk for chunk in resp.iter_bytes(65536))
    assert body == payload


def test_slow_key_service_does_not_block_other_traffic(stack):
    """慢密钥操作下：慢下载不拖住轮换，其他入湖/取数仍完成。"""
    client = stack["client"]
    for i in range(4):
        _upload(client, f"slow-{i}".encode() * 5000, image_id=f"slow-{i}")
    # 给密钥服务加延迟（重启注入）
    env = dict(stack["keys"]._env)
    env["KEY_OP_DELAY"] = "0.3"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()
    job = _start_rotation(client)
    # 轮换进行中，其他入湖/取数照常完成
    r = _upload(client, b"concurrent-upload", image_id="concurrent-1")
    assert r.status_code == 201
    assert _download(client, "slow-0") == b"slow-0" * 5000
    result = _wait_rotation(client, job["job_id"], timeout=120)
    assert result["state"] == "completed", result
    assert _download(client, "concurrent-1") == b"concurrent-upload"


def test_destroy_lost_receipt_auto_verifies(stack):
    """密钥服务销毁后丢回执：API 自动只读核实并报完成，不提前报完成。"""
    client = stack["client"]
    _upload(client, b"lost-receipt-case", image_id="lr-1")
    env = dict(stack["keys"]._env)
    env["KEY_DESTROY_DROP_RECEIPT"] = "true"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()

    job = _start_rotation(client)
    result = _wait_rotation(client, job["job_id"], timeout=90)
    assert result["state"] == "completed", result
    # 旧 MK 确实被销毁（读密钥服务只读状态核实）
    status = client.get("/keys/status").json()
    assert any(k["key_id"] == job["old_key_id"] and k["state"] == "destroyed"
               for k in status["keys"])
    assert _download(client, "lr-1") == b"lost-receipt-case"


def test_restart_both_services_data_still_byte_readable(stack):
    client = stack["client"]
    payload = b"persist-across-restart" * 1000
    _upload(client, payload, image_id="persist-1")
    # 先轮换并销毁旧 MK，再重启两个服务
    job = _start_rotation(client)
    assert _wait_rotation(client, job["job_id"])["state"] == "completed"
    stack["api"].restart()
    stack["keys"].restart()
    assert _download(client, "persist-1") == payload
    # 重启后还能继续入湖（当前 MK 指针持久化在密钥服务卷上）
    _upload(client, b"new-after-restart", image_id="persist-2")
    assert _download(client, "persist-2") == b"new-after-restart"


def test_rotation_resumes_after_api_restart(stack):
    """轮换进行中 API 重启：作业自动接续直至完成。"""
    client = stack["client"]
    for i in range(5):
        _upload(client, f"resume-{i}".encode() * 100, image_id=f"resume-{i}")
    job = _start_rotation(client)
    # 等到至少开始迁移后重启 API
    deadline = time.time() + 10
    while time.time() < deadline:
        j = client.get(f"/rotations/{job['job_id']}").json()
        if j["migrated"] > 0 or j["state"] != "migrating":
            break
        time.sleep(0.1)
    stack["api"].restart()
    result = _wait_rotation(client, job["job_id"], timeout=60)
    assert result["state"] == "completed", result
    for i in range(5):
        assert _download(client, f"resume-{i}") == f"resume-{i}".encode() * 100


def test_interrupted_upload_fails_after_restart_no_late_publish(stack):
    """旧在途上传在进程重启后判失败，绝不晚发布依赖已销毁密钥的原片。"""
    client = stack["client"]
    # 正常入湖一件，然后制造一个永远不结束的在途上传
    _upload(client, b"ok", image_id="ok-1")
    req = client.build_request("PUT", "/images/zombie-upload",
                               content=b"partial" * 1000,
                               headers={"Content-Type": "application/octet-stream"})
    # 直接在元数据层面模拟 receiving 行（等同上传建立后进程被 kill）
    import sqlite3
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    mk = client.get("/keys/status").json()["current_key_id"]
    conn.execute(
        "INSERT INTO images (image_id, status, master_key_id, wrapped_dek, "
        "blob_path, created_at) VALUES ('zombie-upload','receiving',?,?,?,?)",
        (mk, "00" * 64, str(stack["blob_dir"] / "zombie-upload.msef"), time.time()))
    conn.commit()
    conn.close()
    stack["api"].restart()
    meta = client.get("/images/zombie-upload/meta").json()
    assert meta["status"] == "failed"
    # 轮换仍能走到销毁完成（僵尸行不阻塞）
    job = _start_rotation(client)
    result = _wait_rotation(client, job["job_id"])
    assert result["state"] == "completed", result
    # 正常原片仍可读
    assert _download(client, "ok-1") == b"ok"


def test_upload_spanning_rotation_rebinds_to_new_key(stack):
    """上传建立于旧 MK 期间、完成于轮换之后：finalize 自动 rewrap 改绑新 MK，
    绝不发布依赖已销毁旧 MK 的原片。"""
    client = stack["client"]
    _upload(client, b"anchor", image_id="anchor-1")
    old_key = client.get("/images/anchor-1/meta").json()["master_key_id"]

    # 慢速请求体：首包发出（行已按旧 MK 落库为 receiving）后再发起并完成轮换
    def slow_body():
        yield b"slow-head"
        time.sleep(2.5)  # 覆盖整个轮换窗口
        yield b"slow-tail"

    started = []

    def start_rotation_during_upload():
        time.sleep(0.5)
        started.append(client.post("/rotations", json={"confirm": True}).json())

    import threading
    t = threading.Thread(target=start_rotation_during_upload)
    t.start()
    r = client.put("/images/spanning-real", content=slow_body(),
                   headers={"Content-Type": "application/octet-stream"})
    t.join()
    assert r.status_code == 201, r.text
    job_id = started[0]["job_id"]
    result = _wait_rotation(client, job_id)
    assert result["state"] == "completed", result

    new_key = client.get("/keys/status").json()["current_key_id"]
    # 迟到的成功上传必须绑定新 MK，而不是已销毁的旧 MK
    assert r.json()["master_key_id"] == new_key
    meta = client.get("/images/spanning-real/meta").json()
    assert meta["master_key_id"] != old_key
    assert _download(client, "spanning-real") == b"slow-head" + b"slow-tail"
