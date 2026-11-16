"""密钥服务 HTTP 客户端（API 侧）。

要点：
  * 所有调用携带共享内部令牌；
  * 网络抖动/5xx/不完整响应（密钥服务销毁后丢回执）自动重试，
    并在语义可能已生效时先用只读接口核实真实状态，绝不凭猜测报失败；
  * 410 key_destroyed / 400 验签失败等确定性错误直接抛出。
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import httpx


class KeyServiceError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class KeyClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0,
                 max_attempts: int = 5):
        self._base = base_url.rstrip("/")
        self._headers = {"X-Key-Service-Token": token}
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._client = httpx.AsyncClient(base_url=self._base, timeout=timeout)

    async def aclose(self):
        await self._client.aclose()

    async def _request(self, method: str, path: str, json: dict | None = None,
                       headers: dict | None = None) -> dict[str, Any]:
        url = self._base + path
        hdrs = {**self._headers, **(headers or {})}
        last_exc: Exception | None = None
        for attempt in range(self._max_attempts):
            try:
                resp = await self._client.request(method, url, json=json,
                                                  headers=hdrs)
            except (httpx.NetworkError, httpx.RemoteProtocolError,
                    httpx.TimeoutException) as exc:
                # 连接被重置/读到不完整响应：请求可能已经生效，退避后由调用方
                # 借助幂等令牌/只读核实接续，而不是假定失败。
                last_exc = exc
                await asyncio.sleep(min(0.25 * (2 ** attempt), 4.0))
                continue
            if resp.status_code >= 500:
                last_exc = KeyServiceError(resp.status_code, "key_service_5xx",
                                           resp.text[:200])
                await asyncio.sleep(min(0.25 * (2 ** attempt), 4.0))
                continue
            if resp.status_code >= 400:
                detail = resp.json().get("detail", resp.text) if resp.content else {}
                if isinstance(detail, dict):
                    raise KeyServiceError(resp.status_code,
                                          detail.get("code", "error"),
                                          detail.get("message", str(detail)))
                raise KeyServiceError(resp.status_code, "error", str(detail))
            return resp.json()
        raise KeyServiceError(503, "key_service_unreachable",
                              f"giving up after {self._max_attempts} attempts: "
                              f"{last_exc}")

    # ---- 语义化封装 -----------------------------------------------------
    async def ensure_bootstrap(self) -> dict:
        return await self._request("POST", "/internal/master/ensure")

    async def current_master(self) -> str | None:
        return (await self._request("GET", "/internal/master/current"))["key_id"]

    async def master_status(self) -> dict:
        return await self._request("GET", "/internal/master/status")

    async def rotate_master(self) -> dict:
        # 同一幂等令牌贯穿重试，避免响应丢失后重复生成主密钥
        token = f"rotate-{uuid.uuid4()}"
        return await self._request(
            "POST", "/internal/master/rotate",
            headers={"X-Idempotency-Token": token})

    async def destroy_master(self, key_id: str) -> dict:
        """销毁主密钥。回执可能丢失，故先查状态核实；销毁是幂等的。"""
        try:
            return await self._request(
                "POST", "/internal/master/destroy", json={"key_id": key_id})
        except KeyServiceError as exc:
            status = await self.master_status()
            for k in status.get("keys", []):
                if k["key_id"] == key_id and k["state"] == "destroyed":
                    return {"key_id": key_id, "state": "destroyed",
                            "verified_after_lost_receipt": True}
            raise exc

    async def generate_dek(self) -> dict:
        return await self._request("POST", "/internal/dek/generate")

    async def unwrap(self, key_id: str, wrapped_dek: str) -> bytes:
        data = await self._request(
            "POST", "/internal/dek/unwrap",
            json={"key_id": key_id, "wrapped_dek": wrapped_dek})
        return bytes.fromhex(data["dek"])

    async def rewrap(self, old_key_id: str, wrapped_dek: str,
                     idem_token: str) -> dict:
        # 同一幂等令牌贯穿所有重试，密钥服务端缓存首次结果。
        return await self._request(
            "POST", "/internal/dek/rewrap",
            json={"key_id": old_key_id, "wrapped_dek": wrapped_dek},
            headers={"X-Idempotency-Token": idem_token})
