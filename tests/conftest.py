"""端到端自测：真实 uvicorn 子进程跑密钥服务与 API 服务。

覆盖：
  T1  上传/按号下载，逐字节一致（含空文件、跨多帧大文件）
  T2  磁盘上只有密文（无明文落盘）、元数据库无明文 DEK
  T3  轮换：新入湖走新 MK；旧原片信封迁移、图像正文不重写；旧 MK 销毁后可读
  T4  轮换进度查询；轮换未完成拒绝新轮换
  T5  慢密钥服务（KEY_OP_DELAY）下慢下载不阻塞轮换、其他入湖取数照常
  T6  在途下载：先解包后销毁旧 MK，下载仍完整成功
  T7  销毁后丢回执（KEY_DESTROY_DROP_RECEIPT）：自动核实接续并正确报完成
  T8  两服务重启（含密钥服务重启）后已接纳原片逐字节可读
  T9  API 进程重启：未完成的在途上传判失败，不晚发布
  T10 幂等上传令牌重放
  T11 轮换中途重启 API：作业自动接续到完成
  T12 篡改密文 -> GCM 验签失败
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "api"
KEY_DIR = ROOT / "keystore"
TOKEN = "test-secret-token"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_healthy(url: str, timeout: float = 30.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"service {url} not healthy: {last}")


class Service:
    def __init__(self, name: str, app_dir: Path, port: int, env: dict):
        self.name = name
        self.proc: subprocess.Popen | None = None
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self._env = env
        self._app_dir = app_dir

    def start(self):
        env = {**os.environ, **self._env, "PYTHONPATH": str(self._app_dir)}
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-m", "uvicorn",
             "app.main:app", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=str(self._app_dir), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        _wait_healthy(f"{self.base}/health")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        out = ""
        if self.proc and self.proc.stdout:
            out = self.proc.stdout.read()
        self.proc = None
        return out

    def restart(self):
        self.stop()
        self.start()


@pytest.fixture
def stack(tmp_path):
    key_db = tmp_path / "keys"
    api_data = tmp_path / "api"
    key_db.mkdir()
    api_data.mkdir()
    kport, aport = _free_port(), _free_port()

    key_svc = Service("keystore", KEY_DIR, kport, {
        "KEYSTORE_DB": str(key_db / "keystore.db"),
        "KEY_SERVICE_TOKEN": TOKEN,
        "KEY_OP_DELAY": "0",
        "KEY_DESTROY_DROP_RECEIPT": "false",
    })
    api_svc = Service("api", API_DIR, aport, {
        "METADATA_DB": str(api_data / "metadata.db"),
        "BLOB_DIR": str(api_data / "blobs"),
        "KEY_SERVICE_URL": f"http://127.0.0.1:{kport}",
        "KEY_SERVICE_TOKEN": TOKEN,
        "UPLOAD_STALE_SECONDS": "2",
    })
    key_svc.start()
    api_svc.start()
    client = httpx.Client(base_url=api_svc.base, timeout=60)
    key_client = httpx.Client(base_url=key_svc.base, timeout=60)
    yield {
        "api": api_svc, "keys": key_svc, "client": client,
        "key_client": key_client, "data_dir": api_data,
        "blob_dir": api_data / "blobs",
    }
    client.close()
    key_client.close()
    api_svc.stop()
    key_svc.stop()


def _key_headers() -> dict:
    return {"X-Key-Service-Token": TOKEN}


def _wait_rotation(client: httpx.Client, job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/rotations/{job_id}").json()
        if job["state"] in ("completed", "failed"):
            return job
        time.sleep(0.25)
    raise AssertionError("rotation did not finish")


def _upload(client: httpx.Client, data: bytes, image_id: str | None = None,
            token: str | None = None) -> httpx.Response:
    headers = {"Content-Type": "application/octet-stream"}
    if token:
        headers["X-Idempotency-Token"] = token
    if image_id:
        return client.put(f"/images/{image_id}", content=data, headers=headers)
    return client.post("/images", content=data, headers=headers)


def _download(client: httpx.Client, image_id: str) -> bytes:
    r = client.get(f"/images/{image_id}")
    assert r.status_code == 200, r.text
    return r.content
