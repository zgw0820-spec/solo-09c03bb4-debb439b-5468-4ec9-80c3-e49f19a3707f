"""原片流式加密 / 解密（AES-256-GCM 分帧）。

设计目标：
  * 明文原片绝不落盘——加密端一边读 HTTP 流一边分帧，密文直接写 blob 文件；
    解密端读密文分帧验签后直接回写 HTTP 响应。
  * 每件原片独立 DEK（由密钥服务生成、用主密钥信封包裹后存元数据库）。
  * 支持任意大小文件：固定 1 MiB 明文帧，单帧 GCM 认证，失败即中断。

密文文件布局：
  magic(4) = b"MSEF"
  version(1) = 0x01
  salt(16)                    每文件随机；与帧计数器派生 nonce
  重复帧：
    frame_len(4, 大端)        本帧密文长度（含 16 字节 tag）
    nonce(12) = salt[:8] || counter(4, 大端)
    ciphertext + tag(frame_len)
  结束帧 frame_len = 0（无 nonce、无密文），空文件也有结束帧。
"""
from __future__ import annotations

import hashlib
import os
from typing import AsyncIterator, Awaitable, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MSEF"
VERSION = 1
SALT_LEN = 16
NONCE_PREFIX_LEN = 8
CHUNK_SIZE = 1024 * 1024  # 1 MiB 明文帧
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN


class IntegrityError(Exception):
    """解密时 GCM 验签失败或哈希不一致——原片密文已损坏/被篡改。"""


def _frame_nonce(salt: bytes, counter: int) -> bytes:
    return salt[:NONCE_PREFIX_LEN] + counter.to_bytes(4, "big")


async def encrypt_stream(
    plain_chunks: AsyncIterator[bytes],
    dek: bytes,
    write: Callable[[bytes], Awaitable[None]],
) -> dict:
    """消费明文异步流，分帧加密后通过 write 落盘；返回统计与明文哈希。

    明文只存在于内存缓冲（至多 CHUNK_SIZE），不产生任何明文临时文件。
    """
    aes = AESGCM(dek)
    salt = os.urandom(SALT_LEN)
    await write(MAGIC + bytes([VERSION]) + salt)

    digest = hashlib.sha256()
    plain_size = 0
    enc_size = HEADER_LEN
    counter = 0
    buffer = bytearray()

    async def seal(final: bool):
        nonlocal counter, enc_size
        if not final and len(buffer) < CHUNK_SIZE:
            return
        if not buffer:
            return
        frame_bytes = bytes(buffer[:CHUNK_SIZE])
        nonce = _frame_nonce(salt, counter)
        ct = aes.encrypt(nonce, frame_bytes, None)
        frame_len = len(ct).to_bytes(4, "big")
        await write(frame_len + nonce + ct)
        enc_size += 4 + len(nonce) + len(ct)
        counter += 1
        del buffer[:len(frame_bytes)]

    async for chunk in plain_chunks:
        if not chunk:
            continue
        digest.update(chunk)
        plain_size += len(chunk)
        buffer.extend(chunk)
        while len(buffer) >= CHUNK_SIZE:
            await seal(final=False)
    await seal(final=True)

    await write((0).to_bytes(4, "big"))  # 结束帧
    enc_size += 4
    return {
        "plain_size": plain_size,
        "enc_size": enc_size,
        "sha256": digest.hexdigest(),
        "salt": salt.hex(),
    }


class _FrameReader:
    """从密文异步流中按 exact 长度取字节（屏蔽短读）。"""

    def __init__(self, chunks: AsyncIterator[bytes]):
        self._iter = chunks
        self._buf = bytearray()

    async def read_exact(self, n: int) -> bytes | None:
        while len(self._buf) < n:
            try:
                more = await self._iter.__anext__()
            except StopAsyncIteration:
                break
            if more:
                self._buf.extend(more)
        if len(self._buf) < n:
            if not self._buf and n > 0:
                return None  # 干净 EOF
            raise IntegrityError("truncated encrypted frame")
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


async def decrypt_stream(
    cipher_chunks: AsyncIterator[bytes],
    dek: bytes,
    expected_sha256: str | None = None,
) -> AsyncIterator[bytes]:
    """读取密文异步流，逐帧验签解密，yield 明文块。"""
    reader = _FrameReader(cipher_chunks)
    header = await reader.read_exact(HEADER_LEN)
    if header is None or header[:4] != MAGIC or header[4] != VERSION:
        raise IntegrityError("bad encrypted blob header")
    salt = header[5:5 + SALT_LEN]
    aes = AESGCM(dek)
    digest = hashlib.sha256()
    counter = 0

    while True:
        len_bytes = await reader.read_exact(4)
        if len_bytes is None:
            raise IntegrityError("missing terminal frame")
        frame_len = int.from_bytes(len_bytes, "big")
        if frame_len == 0:
            break
        nonce = await reader.read_exact(12)
        if nonce is None:
            raise IntegrityError("truncated frame nonce")
        if nonce != _frame_nonce(salt, counter):
            raise IntegrityError("frame nonce mismatch")
        frame = await reader.read_exact(frame_len)
        if frame is None:
            raise IntegrityError("truncated frame body")
        try:
            plain = aes.decrypt(nonce, frame, None)
        except Exception as exc:
            raise IntegrityError("GCM authentication failed") from exc
        digest.update(plain)
        counter += 1
        yield plain

    if expected_sha256 and digest.hexdigest() != expected_sha256:
        raise IntegrityError("plaintext sha256 mismatch after decryption")
