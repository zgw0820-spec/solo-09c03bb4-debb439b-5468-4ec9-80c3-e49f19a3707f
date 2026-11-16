"""T1/T2/T10/T12：存取正确性、明文不落盘、幂等、验签。"""
import os
import sqlite3
from pathlib import Path

import httpx
import pytest

from conftest import _download, _upload


def test_roundtrip_small_empty_and_multiframe(stack):
    client = stack["client"]
    payloads = {
        "empty": b"",
        "small": b"hello-microscopy-\x00\x01\x02" * 10,
        "frame-ish": os.urandom(1024 * 1024 + 123),  # 跨 1MiB 帧边界
        "multi-frame": os.urandom(3 * 1024 * 1024 + 7),
    }
    ids = {}
    for name, data in payloads.items():
        r = _upload(client, data, image_id=f"spec-{name}")
        assert r.status_code == 201, r.text
        ids[name] = r.json()["image_id"]
        got = _download(client, ids[name])
        assert got == data, f"byte mismatch for {name}"

    # 列表与元数据
    listing = client.get("/images").json()["items"]
    assert len(listing) == len(payloads)
    meta = client.get(f"/images/{ids['multi-frame']}/meta").json()
    assert meta["status"] == "ready"
    assert meta["plain_size"] == len(payloads["multi-frame"])
    assert "wrapped_dek" not in meta


def test_no_plaintext_on_disk_and_no_plaintext_dek(stack):
    client = stack["client"]
    secret = b"PLAINTEXT-MARKER-" + os.urandom(2048)
    r = _upload(client, secret, image_id="disk-check")
    assert r.status_code == 201
    # 1) blob 目录中任何文件都不含明文标记
    for path in stack["blob_dir"].rglob("*"):
        if path.is_file():
            assert secret not in path.read_bytes(), "plaintext leaked into blob file"
    # 2) 元数据库（含 WAL）中也不含明文与 32 字节裸 DEK
    for suffix in ("", "-wal", "-shm"):
        p = stack["data_dir"] / ("metadata.db" + suffix)
        if p.exists():
            assert secret not in p.read_bytes()
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    row = conn.execute(
        "SELECT wrapped_dek FROM images WHERE image_id='disk-check'").fetchone()
    # 信封固定 64 字节二进制 -> 128 hex 字符，且不是裸 DEK
    assert len(row[0]) == 128
    conn.close()
    # 3) 下载仍逐字节一致
    assert _download(client, "disk-check") == secret


def test_idempotent_upload_token(stack):
    client = stack["client"]
    h = {"Content-Type": "application/octet-stream",
         "X-Idempotency-Token": "idem-abc-1"}
    r1 = client.post("/images", content=b"same-body", headers=h)
    assert r1.status_code == 201
    r2 = client.post("/images", content=b"different-body", headers=h)
    assert r2.status_code == 200 and r2.json().get("idempotent") is True
    assert r2.json()["image_id"] == r1.json()["image_id"]
    assert _download(client, r1.json()["image_id"]) == b"same-body"


def test_tampered_ciphertext_fails_gcm(stack):
    client = stack["client"]
    r = _upload(client, b"x" * 4096, image_id="tamper-me")
    assert r.status_code == 201
    blob = next(stack["blob_dir"].iterdir())
    raw = bytearray(blob.read_bytes())
    raw[60] ^= 0xFF  # 翻转 salt 后第一帧附近的字节
    blob.write_bytes(bytes(raw))
    # 流式响应头发送后 GCM 验签失败：服务器中断连接，客户端读不到完整正文
    import httpx
    with pytest.raises(httpx.RemoteProtocolError):
        client.get("/images/tamper-me").read()
    # 原片不可被当作有效数据返回；元数据仍可查
    assert client.get("/images/tamper-me/meta").json()["status"] == "ready"


def test_no_plaintext_tempfiles_during_upload(stack):
    """上传期间除密文 blob 外，不得产生任何含明文的临时文件。"""
    import tempfile
    client = stack["client"]
    marker = b"TEMPLEAK-MARKER-" + os.urandom(4096)
    tmp = tempfile.gettempdir()
    before = set(Path(tmp).rglob("*"))
    r = _upload(client, marker * 64, image_id="noleak-1")
    assert r.status_code == 201
    after_files = [p for p in Path(tmp).rglob("*")
                   if p.is_file() and p not in before]
    for p in after_files:
        try:
            assert marker not in p.read_bytes(), f"plaintext leaked to {p}"
        except OSError:
            pass


def test_duplicate_named_upload_rejected(stack):
    client = stack["client"]
    assert _upload(client, b"a", image_id="dup-id").status_code == 201
    r = _upload(client, b"b", image_id="dup-id")
    assert r.status_code == 409
