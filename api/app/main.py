"""显微成像原片单实例 API。

安全边界：
  * 明文原片只在请求/响应的内存流中存在，密文 blob 直接落盘；
  * 明文 DEK 只在单次请求内存中存活，元数据库只存信封密文；
  * 主密钥材料永远只在密钥服务内，本服务通过内部 HTTP 调用包裹/解包。
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

BLOB_DIR = os.environ.get("BLOB_DIR", "/data/blobs")
DB_PATH = os.environ.get("METADATA_DB", "/data/metadata.db")
KEY_SERVICE_URL = os.environ.get("KEY_SERVICE_URL", "http://keystore:8001")
KEY_SERVICE_TOKEN = os.environ.get("KEY_SERVICE_TOKEN", "dev-only-key-service-token")
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 ** 3)))

# 安全约束：Starlette 的 multipart 解析器默认把 >1MiB 的表单文件假脱机到
# 磁盘临时文件，等于让明文原片落盘。将假脱机阈值提高到上传上限，使允许范围
# 内的 multipart 一律留在内存（超限请求在入口处即被 Content-Length 拒绝）。
# 首选仍是原始 application/octet-stream 流式上传，完全不经表单解析器。
from starlette.formparsers import MultiPartParser
MultiPartParser.spool_max_size = MAX_UPLOAD_BYTES

from .crypto_stream import IntegrityError, decrypt_stream, encrypt_stream
from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB
from .rotation import RotationWorker

db = MetadataDB(DB_PATH)
keys = KeyClient(KEY_SERVICE_URL, KEY_SERVICE_TOKEN)
worker: RotationWorker | None = None
main_loop: asyncio.AbstractEventLoop | None = None


# --------------------------------------------------------------------------
# 生命周期：引导主密钥 -> 崩溃恢复（在途上传判失败/轮换接续）-> 启动后台线程
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker, main_loop
    os.makedirs(BLOB_DIR, exist_ok=True)
    main_loop = asyncio.get_running_loop()
    # 等待密钥服务就绪并确保存在当前主密钥（重启幂等）
    for attempt in range(10):
        try:
            await keys.ensure_bootstrap()
            break
        except KeyServiceError:
            await asyncio.sleep(1.0)
    # 崩溃恢复：上次 receiving 的上传一律失败，禁止"晚发布"依赖旧密钥
    stale = db.mark_stale_receiving_failed()
    if stale:
        print(f"[startup] {stale} interrupted upload(s) marked failed")
    # 崩溃对账：上次可能已在密钥服务切换了 MK、却没来得及建本地作业
    try:
        key_status = await keys.master_status()
        current_mk = key_status.get("current_key_id")
        for key in key_status.get("keys", []):
            if (key["key_id"] != current_mk
                    and key["state"] == "active"
                    and not db.has_rotation_for(key["key_id"])):
                job_id = db.create_rotation(
                    key["key_id"], current_mk,
                    db.count_under_key(key["key_id"], only_migratable=True))
                print(f"[startup] reconciled missing rotation job {job_id} "
                      f"for {key['key_id']}")
    except KeyServiceError as exc:
        print(f"[startup] rotation reconciliation skipped: {exc}")
    worker = RotationWorker(db, keys, main_loop)
    worker.start()
    yield
    worker.stop()
    await keys.aclose()
    db.close()


app = FastAPI(
    title="Microscopy Image Warehouse API",
    version="1.0.0",
    description="原片流式加密存取，每件独立 DEK；支持主密钥在线轮换与进度查询。",
    lifespan=lifespan,
)


def _key_error(exc: KeyServiceError) -> HTTPException:
    return HTTPException(status_code=exc.status_code,
                         detail={"code": exc.code, "message": exc.message})


# --------------------------------------------------------------------------
# 上传
# --------------------------------------------------------------------------
async def _stream_to_blob(request: Request, blob_path: str,
                          dek: bytes) -> dict[str, Any]:
    """读 HTTP 请求体 -> 分帧加密 -> 密文直接写盘（无明文临时文件）。"""
    writer = open(blob_path, "wb")  # 二进制密文文件
    loop = asyncio.get_running_loop()

    async def write(data: bytes):
        await loop.run_in_executor(None, writer.write, data)
        await loop.run_in_executor(None, writer.flush)

    try:
        stats = await encrypt_stream(request.stream(), dek, write)
    finally:
        await loop.run_in_executor(None, writer.close)
    return stats


async def _finalize_with_rebind(image_id: str, stats: dict[str, Any]) -> dict[str, Any]:
    """最终化原片；若其 MK 在上传期间已被轮换切换，则先 rewrap 改绑当前 MK。

    是否需要改绑只依据本地轮换记录判断（不额外依赖密钥服务在线）：
    该行绑定的正是最近一次轮换的旧 MK 时，说明它是跨越轮换的在途上传。
    防止在途上传晚发布依赖旧（甚至已销毁）主密钥的原片。
    """
    meta = db.get_image(image_id)
    job = db.latest_rotation()
    if job and meta and meta["master_key_id"] == job["old_key_id"]:
        try:
            res = await keys.rewrap(meta["master_key_id"], meta["wrapped_dek"],
                                    f"finalize:{image_id}")
        except KeyServiceError as exc:
            if exc.status_code == 410:
                # 旧 MK 已销毁且该行信封未能提前迁移：绝不能晚发布不可读原片
                raise HTTPException(
                    status_code=409,
                    detail={"code": "old_key_destroyed",
                            "message": "upload cannot be finalized; its key was "
                                       "rotated and destroyed before completion"})
            raise
        db.rewrap_row(image_id, meta["master_key_id"],
                      res["key_id"], res["wrapped_dek"])
    db.finalize_image(image_id, stats["plain_size"], stats["enc_size"],
                      stats["sha256"])
    return db.get_image(image_id)


def _check_content_length(request: Request):
    cl = request.headers.get("content-length")
    if cl is not None and int(cl) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, detail="upload exceeds MAX_UPLOAD_BYTES")


@app.post("/images", status_code=201,
          summary="上传原片（流式加密；支持 X-Idempotency-Token 幂等）")
async def upload_image(request: Request, response: Response,
                       x_idempotency_token: str | None = Header(default=None),
                       x_filename: str | None = Header(default=None),
                       x_content_type: str | None = Header(default=None)):
    _check_content_length(request)
    # 幂等重放：直接返回既有回执，不重复入湖
    if x_idempotency_token:
        existing = db.get_by_token(x_idempotency_token)
        if existing:
            response.status_code = 200
            return {"image_id": existing["image_id"], "status": existing["status"],
                    "idempotent": True}
    try:
        dek_resp = await keys.generate_dek()
    except KeyServiceError as exc:
        raise _key_error(exc)
    master_key_id = dek_resp["key_id"]
    wrapped_dek = dek_resp["wrapped_dek"]
    dek = bytes.fromhex(dek_resp["dek"])  # 仅存于本请求内存

    image_id = "img-" + uuid.uuid4().hex
    blob_path = os.path.join(BLOB_DIR, image_id + ".msef")
    db.create_image(image_id, x_filename,
                    x_content_type or request.headers.get("content-type"),
                    master_key_id, wrapped_dek, blob_path, x_idempotency_token)
    try:
        stats = await _stream_to_blob(request, blob_path, dek)
        if stats["plain_size"] > MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail="upload exceeds MAX_UPLOAD_BYTES")
        final = await _finalize_with_rebind(image_id, stats)
    except HTTPException:
        db.fail_image(image_id, "upload rejected")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise
    except Exception as exc:  # 写入失败：判失败并清理密文残片
        db.fail_image(image_id, f"upload failed: {exc!r}")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise HTTPException(status_code=502,
                            detail=f"upload failed: {exc!r}") from exc
    finally:
        del dek  # 尽快丢弃明文 DEK 引用
    return {"image_id": image_id, "status": "ready",
            "size": stats["plain_size"], "sha256": stats["sha256"],
            "master_key_id": final["master_key_id"]}


@app.put("/images/{image_id}", status_code=201,
         summary="按调用方指定编号上传原片")
async def upload_image_named(image_id: str, request: Request, response: Response,
                             x_idempotency_token: str | None = Header(default=None),
                             x_filename: str | None = Header(default=None),
                             x_content_type: str | None = Header(default=None)):
    if not image_id or len(image_id) > 128 or "/" in image_id or ".." in image_id:
        raise HTTPException(400, detail="invalid image_id")
    _check_content_length(request)
    if x_idempotency_token:
        existing = db.get_by_token(x_idempotency_token)
        if existing:
            response.status_code = 200
            return {"image_id": existing["image_id"], "status": existing["status"],
                    "idempotent": True}
    current = db.get_image(image_id)
    if current and current["status"] in ("receiving", "ready"):
        raise HTTPException(409, detail=f"image_id already exists ({current['status']})")
    try:
        dek_resp = await keys.generate_dek()
    except KeyServiceError as exc:
        raise _key_error(exc)
    blob_path = os.path.join(BLOB_DIR, image_id + ".msef")
    db.create_image(image_id, x_filename,
                    x_content_type or request.headers.get("content-type"),
                    dek_resp["key_id"], dek_resp["wrapped_dek"],
                    blob_path, x_idempotency_token)
    dek = bytes.fromhex(dek_resp["dek"])
    try:
        stats = await _stream_to_blob(request, blob_path, dek)
        final = await _finalize_with_rebind(image_id, stats)
    except HTTPException:
        db.fail_image(image_id, "upload rejected")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise
    except Exception as exc:
        db.fail_image(image_id, f"upload failed: {exc!r}")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise HTTPException(status_code=502,
                            detail=f"upload failed: {exc!r}") from exc
    finally:
        del dek
    return {"image_id": image_id, "status": "ready",
            "size": stats["plain_size"], "sha256": stats["sha256"],
            "master_key_id": final["master_key_id"]}


# --------------------------------------------------------------------------
# 下载 / 查询
# --------------------------------------------------------------------------
def _cipher_chunks(path: str):
    async def gen():
        loop = asyncio.get_running_loop()
        f = await loop.run_in_executor(None, open, path, "rb")
        try:
            while True:
                chunk = await loop.run_in_executor(None, f.read, 1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            await loop.run_in_executor(None, f.close)
    return gen()


@app.get("/images/{image_id}", summary="按编号下载原片（流式解密，逐帧验签）")
async def download_image(image_id: str):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    if meta["status"] != "ready":
        raise HTTPException(409, detail=f"image is {meta['status']}")
    if not os.path.exists(meta["blob_path"]):
        raise HTTPException(410, detail="encrypted blob missing on storage")
    try:
        # 解包一次：明文 DEK 只在本次请求内存；随后即使密钥服务变慢或
        # 主密钥被销毁，已解包的慢下载也能完整读完（解密不再依赖密钥服务）。
        dek = await keys.unwrap(meta["master_key_id"], meta["wrapped_dek"])
    except KeyServiceError as exc:
        raise _key_error(exc)

    async def plain_iter():
        local_dek = dek  # 局部别名；生成器结束后随帧栈释放，不留长生命周期引用
        try:
            async for chunk in decrypt_stream(
                    _cipher_chunks(meta["blob_path"]), local_dek,
                    expected_sha256=meta["sha256"]):
                yield chunk
        except IntegrityError as exc:
            raise HTTPException(500, detail=f"integrity check failed: {exc}")
        finally:
            del local_dek

    headers = {"X-Image-Id": image_id,
               "X-SHA256": meta["sha256"] or ""}
    if meta["filename"]:
        headers["Content-Disposition"] = (
            f'attachment; filename="{meta["filename"]}"')
    return StreamingResponse(
        plain_iter(),
        media_type=meta["content_type"] or "application/octet-stream",
        headers=headers)


@app.get("/images", summary="列出原片元数据")
async def list_images(limit: int = 100, offset: int = 0):
    return {"items": db.list_images(min(limit, 500), offset)}


@app.get("/images/{image_id}/meta", summary="单件原片元数据/状态")
async def image_meta(image_id: str):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    meta.pop("wrapped_dek", None)
    return meta


# --------------------------------------------------------------------------
# 轮换
# --------------------------------------------------------------------------
class RotationRequest(BaseModel):
    confirm: bool = True


@app.post("/rotations", status_code=202,
          summary="发起主密钥轮换（迁移信封后销毁旧 MK；未完拒绝新轮换）")
async def create_rotation(_: RotationRequest):
    active = db.active_rotation()
    if active is not None:
        raise HTTPException(
            409, detail={"code": "rotation_in_progress",
                         "job_id": active["job_id"], "state": active["state"]})
    try:
        rot = await keys.rotate_master()  # 新入湖立即改用新 MK
        old_key, new_key = rot["old_key_id"], rot["new_key_id"]
        total = (db.count_under_key(old_key, only_migratable=True)
                 if old_key else 0)
        job_id = db.create_rotation(old_key, new_key, total)
    except KeyServiceError as exc:
        raise _key_error(exc)
    return {"job_id": job_id, "state": "migrating", "old_key_id": old_key,
            "new_key_id": new_key, "total_to_migrate": total}


@app.get("/rotations/latest", summary="查询最近一次轮换进度")
async def latest_rotation():
    job = db.latest_rotation()
    if job is None:
        return {"message": "no rotation has ever run"}
    return _rotation_view(job)


@app.get("/rotations/{job_id}", summary="按作业号查询轮换进度")
async def rotation_status(job_id: str):
    job = db.get_rotation(job_id)
    if job is None:
        raise HTTPException(404, detail="rotation job not found")
    return _rotation_view(job)


def _rotation_view(job: dict) -> dict:
    total = max(job["total"], job["migrated"] + job["failed"], 1)
    pct = round(100.0 * (job["migrated"] + job["failed"]) / total, 2)
    return {**{k: v for k, v in job.items()}, "progress_percent": pct}


@app.get("/keys/status", summary="密钥视角状态（代理密钥服务只读接口）")
async def key_status():
    try:
        return await keys.master_status()
    except KeyServiceError as exc:
        raise _key_error(exc)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "image-api", "time": time.time()}
