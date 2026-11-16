"""信封加密原语：主密钥（MK）包裹数据密钥（DEK）。

包裹格式（二进制，小端）：
    magic(4) = b"MKV1"
    nonce(12)  AES-GCM 随机 nonce
    ciphertext(32)  DEK 密文（DEK 固定 32 字节 -> AES-256 密文 32 字节）
    tag(16)  AES-GCM 认证标签
总长度固定 64 字节。

所有对称加密均为 AES-256-GCM（cryptography 库的 AESGCM 把 tag 附在密文后，
因此这里记录为 ct(32)+tag(16) 连续存放）。
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MKV1"
NONCE_LEN = 12
DEK_LEN = 32
ENVELOPE_LEN = len(MAGIC) + NONCE_LEN + DEK_LEN + 16  # 64


def new_data_key() -> bytes:
    """生成一把全新的随机 DEK（AES-256）。"""
    return os.urandom(DEK_LEN)


def wrap_dek(master_key: bytes, dek: bytes, aad: bytes | None = None) -> bytes:
    if len(master_key) != 32:
        raise ValueError("master key must be 32 bytes")
    if len(dek) != DEK_LEN:
        raise ValueError("dek must be 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(master_key).encrypt(nonce, dek, aad)
    return MAGIC + nonce + ct


def unwrap_dek(master_key: bytes, envelope: bytes, aad: bytes | None = None) -> bytes:
    if len(envelope) != ENVELOPE_LEN or envelope[:4] != MAGIC:
        raise ValueError("malformed key envelope")
    nonce = envelope[4:4 + NONCE_LEN]
    ct = envelope[4 + NONCE_LEN:]
    return AESGCM(master_key).decrypt(nonce, ct, aad)
