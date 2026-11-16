"""独立持久化密钥服务。

职责（API 服务不保存任何明文密钥/明文主密钥）：
  * 主密钥生成、轮换、销毁（销毁后密码学意义不可恢复）
  * 数据密钥(DEK)生成与包裹、解包
  * 主密钥轮换时的 DEK 重新包裹（rewrap，不暴露明文 DEK）

可配置故障注入（用于演练"回执丢失"与慢操作）：
  KEY_OP_DELAY               每个写/密码学操作人为延迟秒数（慢密钥服务）
  KEY_DESTROY_DROP_RECEIPT   销毁主密钥成功后不回 HTTP 响应（模拟回执丢失）
  KEY_ROTATE_DROP_RECEIPT    轮换切换成功后不回 HTTP 响应（模拟轮换回执不明）
  KEY_SERVICE_TOKEN          内部服务间鉴权令牌（必填，默认随机仅用于本地）
  KEYSTORE_DB                SQLite 路径（默认 /data/keystore.db，需持久卷）
"""
from __future__ import annotations

import asyncio
import hmac
import os
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .storage import KeyError_, KeyStore

DB_PATH = os.environ.get("KEYSTORE_DB", "/data/keystore.db")
SERVICE_TOKEN = os.environ.get("KEY_SERVICE_TOKEN", "dev-only-key-service-token")
OP_DELAY = float(os.environ.get("KEY_OP_DELAY", "0"))
DESTROY_DROP_RECEIPT = os.environ.get(
    "KEY_DESTROY_DROP_RECEIPT", "false").lower() in ("1", "true", "yes")
# true/yes/1：仅首次调用丢回执（幂等重放可恢复）；always：连幂等重放也丢，
# 用于演练客户端重试耗尽、只能靠只读状态核实的"回执不明"场景。
ROTATE_DROP_RECEIPT = os.environ.get(
    "KEY_ROTATE_DROP_RECEIPT", "false").lower() in ("1", "true", "yes", "always")
ROTATE_DROP_RECEIPT_ALWAYS = os.environ.get(
    "KEY_ROTATE_DROP_RECEIPT", "false").lower() == "always"

app = FastAPI(
    title="Microscopy Key Service",
    version="1.0.0",
    description="主密钥/数据密钥信封管理；独立持久化，API 服务不接触主密钥。",
)
store = KeyStore(DB_PATH)


# --------------------------------------------------------------------------
# 故障注入：只发响应头、不发响应体即结束 ASGI 调用，客户端读到不完整响应，
# 等价于"服务端已完成销毁，但客户端丢了回执"。
# --------------------------------------------------------------------------
class _DropReceiptResponse(JSONResponse):
    async def __call__(self, scope, receive, send):
        await send({"type": "http.response.start", "status": self.status_code,
                    "headers": self.raw_headers})
        # 故意不发送 http.response.body，连接随后被关闭 -> 客户端收不到回执


def _check_token(token: str | None):
    if not token or not hmac.compare_digest(token, SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="invalid service token")


async def _delay():
    if OP_DELAY:
        await asyncio.sleep(OP_DELAY)


def _biz(exc: KeyError_) -> HTTPException:
    return HTTPException(status_code=exc.status_code,
                         detail={"code": exc.code, "message": exc.message})


class WrapBody(BaseModel):
    key_id: str = Field(..., description="包裹该 DEK 所用主密钥 id")
    wrapped_dek: str = Field(..., description="十六进制信封密文")


class RewrapBody(WrapBody):
    pass


class DestroyBody(BaseModel):
    key_id: str


@app.get("/health")
async def health():
    return {"status": "ok", "service": "key-service", "time": time.time()}


@app.post("/internal/master/ensure", summary="无主密钥时引导生成第一把")
async def ensure_master(x_key_service_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    await _delay()
    try:
        return store.ensure_bootstrap()
    except KeyError_ as exc:
        raise _biz(exc)


@app.get("/internal/master/current", summary="查询当前主密钥 id")
async def current_master(x_key_service_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    return {"key_id": store.current_key_id()}


@app.post("/internal/master/rotate", summary="生成并切换到新主密钥（支持幂等令牌）")
async def rotate_master(x_key_service_token: str | None = Header(default=None),
                        x_idempotency_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    await _delay()
    result = store.rotate_master(
        x_idempotency_token or f"auto-{uuid.uuid4()}")
    # 故障注入：轮换已落盘并切换 current，但客户端拿不到完整 HTTP 回执。
    # 默认仅首次调用丢（幂等重放可恢复）；always 模式连重放也丢，
    # 迫使调用方重试耗尽后走只读状态核实/对账接续。
    drop = ROTATE_DROP_RECEIPT and (
        ROTATE_DROP_RECEIPT_ALWAYS or not result.get("idempotent"))
    if drop:
        return _DropReceiptResponse(result, status_code=200)
    return result


@app.post("/internal/master/destroy", summary="销毁指定主密钥（幂等）")
async def destroy_master(body: DestroyBody, request: Request,
                         x_key_service_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    await _delay()
    try:
        result = store.destroy_master(body.key_id)
    except KeyError_ as exc:
        raise _biz(exc)
    # 故障注入：销毁已落盘，但客户端拿不到任何完整 HTTP 回执
    if DESTROY_DROP_RECEIPT and not result.get("idempotent"):
        return _DropReceiptResponse(result, status_code=200)
    return result


@app.get("/internal/master/status", summary="全部主密钥及其状态")
async def master_status(x_key_service_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    return store.status()


@app.post("/internal/dek/generate", summary="生成 DEK 并用当前主密钥包裹")
async def generate_dek(x_key_service_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    await _delay()
    try:
        return store.generate_dek()
    except KeyError_ as exc:
        raise _biz(exc)


@app.post("/internal/dek/unwrap", summary="解包 DEK（仅返回一次明文给 API 进程）")
async def unwrap_dek_endpoint(body: WrapBody,
                              x_key_service_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    await _delay()
    try:
        return store.unwrap(body.key_id, body.wrapped_dek)
    except KeyError_ as exc:
        raise _biz(exc)


@app.post("/internal/dek/rewrap",
          summary="把 DEK 从旧主密钥改包到当前主密钥（支持幂等令牌）")
async def rewrap_dek(body: RewrapBody,
                     x_key_service_token: str | None = Header(default=None),
                     x_idempotency_token: str | None = Header(default=None)):
    _check_token(x_key_service_token)
    await _delay()
    token = x_idempotency_token or f"auto-{uuid.uuid4()}"
    try:
        return store.rewrap(body.key_id, body.wrapped_dek, token)
    except KeyError_ as exc:
        raise _biz(exc)


@app.on_event("shutdown")
def _shutdown():
    store.close()
