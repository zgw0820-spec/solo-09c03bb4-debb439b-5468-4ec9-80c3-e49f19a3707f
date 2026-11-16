"""加密模块与信封原语的离线单元测试（不起服务）。"""
import asyncio
import importlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# 两个服务的包都叫 app：清掉可能已缓存的 app.* 后分别加载
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]
sys.path.insert(0, str(ROOT / "api"))
crypto_stream = importlib.import_module("app.crypto_stream")
sys.path.remove(str(ROOT / "api"))
for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
    del sys.modules[name]
sys.path.insert(0, str(ROOT / "keystore"))
crypto_envelope = importlib.import_module("app.crypto_envelope")

CHUNK_SIZE = crypto_stream.CHUNK_SIZE
HEADER_LEN = crypto_stream.HEADER_LEN
IntegrityError = crypto_stream.IntegrityError
decrypt_stream = crypto_stream.decrypt_stream
encrypt_stream = crypto_stream.encrypt_stream
ENVELOPE_LEN = crypto_envelope.ENVELOPE_LEN
new_data_key = crypto_envelope.new_data_key
unwrap_dek = crypto_envelope.unwrap_dek
wrap_dek = crypto_envelope.wrap_dek


async def _roundtrip(data: bytes, dek: bytes):
    out = bytearray()

    async def write(chunk: bytes):
        out.extend(chunk)

    async def plain_chunks():
        for i in range(0, len(data), 777):
            yield data[i:i + 777]

    stats = await encrypt_stream(plain_chunks(), dek, write)
    assert stats["plain_size"] == len(data)
    blob = bytes(out)

    async def cipher_chunks():
        for i in range(0, len(blob), 999):
            yield blob[i:i + 999]

    got = await _collect(decrypt_stream(cipher_chunks(), dek, stats["sha256"]))
    return blob, got, stats


async def _collect(agen):
    out = bytearray()
    async for c in agen:
        out.extend(c)
    return bytes(out)


def test_stream_roundtrip_sizes():
    for size in (0, 1, 1024, CHUNK_SIZE - 1, CHUNK_SIZE,
                 CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 5):
        dek = os.urandom(32)
        data = os.urandom(size)
        blob, got, stats = asyncio.run(_roundtrip(data, dek))
        assert got == data
        n_full, tail = divmod(size, CHUNK_SIZE)
        n_frames = n_full + (1 if tail else 0)
        # 每帧开销 = 4 长度 + 12 nonce + 16 GCM tag；另有文件头与结束帧
        expect = HEADER_LEN + 4 + n_frames * (4 + 12 + 16) + size
        assert stats["enc_size"] == len(blob) == expect


def test_tamper_and_wrong_dek_detected():
    dek = os.urandom(32)
    blob, _, _ = asyncio.run(_roundtrip(b"x" * 5000, dek))
    bad = bytearray(blob)
    bad[HEADER_LEN + 10] ^= 0x01

    async def chunks(buf):
        yield buf

    with pytest.raises(IntegrityError):
        asyncio.run(_collect(decrypt_stream(chunks(bytes(bad)), dek)))
    with pytest.raises(IntegrityError):
        asyncio.run(_collect(decrypt_stream(chunks(blob), os.urandom(32))))


def test_envelope_wrap_unwrap_and_aad():
    mk = os.urandom(32)
    dek = new_data_key()
    env = wrap_dek(mk, dek, b"image-1")
    assert len(env) == ENVELOPE_LEN
    assert unwrap_dek(mk, env, b"image-1") == dek
    with pytest.raises(Exception):
        unwrap_dek(mk, env, b"other-aad")            # AAD 不匹配
    with pytest.raises(Exception):
        unwrap_dek(os.urandom(32), env, b"image-1")  # 错误主密钥
