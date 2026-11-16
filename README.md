# 显微成像原片加密数仓（单实例 API + 独立密钥服务）

显微仪器原片（raw image）的接收、流式加密存储与按号读取。每件原片使用
**独立数据密钥（DEK）**，DEK 由独立持久化的**密钥服务**用主密钥（MK）以
AES-256-GCM 信封包裹；支持主密钥在线轮换：只迁移密钥信封、**不重写图像正文**，
迁移核实完成后再销毁旧主密钥。

## 架构

```
仪器/客户端
   │  HTTP（octet-stream 流式上传 / 按号下载）
   ▼
┌──────────────────────────────┐        内部 HTTP（共享令牌）     ┌──────────────────────────┐
│ image-api (FastAPI, 单实例)   │  ────────────────────────────▶  │ keystore (FastAPI)        │
│  - 原片流式分帧加解密（内存）   │     generate/unwrap/rewrap     │  - 主密钥生命周期          │
│  - SQLite 元数据（只存密文信封）│     rotate/destroy/status      │  - DEK 包裹/解包/改包       │
│  - 轮换作业状态机 + 后台线程    │                                 │  - SQLite 持久卷（MK 本体） │
│  - blob：密文原片 .msef        │                                  └──────────────────────────┘
└──────────────┬───────────────┘                                            │
               │ 卷 api-data                    卷 keystore-data ◀──────────┘
        /data/metadata.db
        /data/blobs/*.msef（密文）
```

**安全边界**

| 资产 | 存在位置 | 不存在位置 |
|---|---|---|
| 主密钥材料 | 仅密钥服务进程内存与其持久卷 SQLite | API 进程/API 卷/日志 |
| 明文 DEK | 仅单次请求的 API 进程内存（请求结束即释放） | 任何磁盘 |
| 明文原片 | 仅请求/响应的内存流（multipart 假脱机已禁用） | 任何磁盘、任何临时文件 |
| 信封 DEK（密文） | API 的 SQLite `images.wrapped_dek` | — |
| 原片密文 | API 卷 `/data/blobs/*.msef`（AES-256-GCM 分帧） | — |

销毁主密钥 = 密钥库中密钥材料被零覆写并置 `destroyed`，密码学意义不可恢复；
对已销毁 MK 的 `unwrap/rewrap` 返回 `410 key_destroyed`。

## 快速启动

```bash
cp .env.example .env          # 修改 KEY_SERVICE_TOKEN 为强随机值
docker compose up --build
```

- API Swagger：<http://localhost:8000/docs>
- 密钥服务 Swagger：<http://localhost:8001/docs>（仅绑定 127.0.0.1）
- 健康检查：`GET /health`（两服务均有）

## 常用接口（API）

| 方法/路径 | 说明 |
|---|---|
| `POST /images` | 流式上传（随机编号）；`X-Idempotency-Token` 幂等；`X-Filename` 可选 |
| `PUT /images/{image_id}` | 按调用方编号上传 |
| `GET /images/{image_id}` | 按号下载，流式解密、逐帧 GCM 验签、SHA-256 校验 |
| `GET /images/{image_id}/meta` | 元数据/状态（不返回信封密文） |
| `GET /images` | 列表 |
| `POST /rotations` | 发起主密钥轮换（body `{"confirm": true}`），返回 202 + job_id |
| `GET /rotations/{job_id}` | 轮换进度（state/migrated/failed/progress_percent） |
| `GET /rotations/latest` | 最近一次轮换 |
| `GET /keys/status` | 代理密钥服务只读状态 |

上传请使用原始 `application/octet-stream`（`curl --data-binary @file`），
避免 multipart 带来的额外内存占用。

```bash
# 上传（按号）
curl -sS -X PUT --data-binary @slide_001.czi \
  -H 'Content-Type: application/octet-stream' \
  -H 'X-Filename: slide_001.czi' \
  http://localhost:8000/images/slide-001

# 下载并逐字节校验
curl -sS http://localhost:8000/images/slide-001 -o /tmp/slide_001.czi
sha256sum slide_001.czi /tmp/slide_001.czi

# 发起轮换 / 查进度
JOB=$(curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"confirm":true}' http://localhost:8000/rotations | python3 -c 'import sys,json;print(json.load(sys.stdin)["job_id"])')
watch -n1 "curl -sS http://localhost:8000/rotations/$JOB"
```

## 轮换语义（需求对照）

1. **并发只受理一次**：`POST /rotations` 的"检查在途作业 → 密钥服务切换 →
   本地登记"全程由受理锁串行化。并发请求中一笔返回 202，其余明确返回
   `409 rotation_in_progress`（携带同一 `job_id`）；被拒请求**不会调用密钥服务
   rotate，因此不可能再切一次密钥**。受理时先落一笔 `pending` 占位作业作为
   持久受理凭证，再调用密钥服务切换并回填转 `migrating`。
2. 切换在密钥服务先生效——**新入湖立即使用新 MK**；后台常驻线程逐行把旧 MK
   包裹的 DEK 调密钥服务 `rewrap` 改包到新 MK，**只更新元数据里的 64 字节
   信封，blob 密文正文逐字节不动**。
3. 销毁前两次零残留核验（扫描后 + 销毁前），确认没有 `ready/receiving` 行
   仍依赖旧 MK，才调用销毁；销毁后再用只读 `status` 核实，**不提前报完成**。
4. **切换已生效但作业未登记/回执不明**：受理前、后台 worker 空闲周期、进程
   启动三处都用同一幂等对账函数核对密钥服务真实代际，发现"已被替代却没有
   作业"的 active MK 就补建迁移/销毁作业并接续（多代际按序逐代收敛）。
   rotate 调用重试仍失败时，先只读核实：切换确实已生效则回填当前 pending
   占位、按 202 `reconciled=true` 返回；核实不到才把错误返回调用方。
5. **在途下载**：下载开始时只向密钥服务解包一次 DEK，之后帧解密完全在 API
   进程内存完成；即使下载很慢、期间旧 MK 被销毁，下载仍完整成功。
6. **在途上传**：上传期间发生轮换（可能跨多代）时，finalize 会先 rewrap
   改绑当前 MK 再发布；若旧 MK 已被销毁（极端窗口）则返回
   `409 old_key_destroyed` 并判失败，**绝不晚发布不可读原片**。进程崩溃留下
   的 `receiving` 在重启时一律判失败；受理窗口崩溃留下的 `pending` 占位在
   重启时按密钥服务真相回填接续或判失败释放受理位。
7. **慢密钥服务不阻塞**：迁移在独立线程、按批让出；在线上传/下载照常完成。
8. **回执丢失**：`destroy`/`rotate` 网络层失败、连接被重置或响应不完整时，
   API 自动重试（rotate 全程复用同一幂等令牌，重试不会再生成新 MK），并以
   只读状态核实操作是否真实生效；rewrap 同样带幂等令牌，重放返回同一结果。
9. **进程重启接续**：轮换作业状态（含 `pending` 受理态）在 SQLite；API 重启
   后自动恢复 pending、对账补登记，并驱动未完成作业到终态；完成状态始终
   对应密钥服务的实际密钥代际。

## 故障注入（演练用，密钥服务环境变量）

| 变量 | 作用 |
|---|---|
| `KEY_OP_DELAY=0.3` | 每个密钥操作人为延迟 0.3s，模拟慢密钥服务 |
| `KEY_DESTROY_DROP_RECEIPT=true` | 销毁成功落盘后故意不回完整 HTTP 响应，模拟销毁后丢回执 |
| `KEY_ROTATE_DROP_RECEIPT=true` | 轮换成功落盘后丢首包回执（幂等重放可恢复） |
| `KEY_ROTATE_DROP_RECEIPT=always` | 连幂等重放也丢，迫使重试耗尽，演练只读核实+对账接续 |

```bash
KEY_DESTROY_DROP_RECEIPT=true docker compose up --build keystore
```

## 自测

```bash
# tests/ 下为真实 uvicorn 子进程的端到端测试（29 项，含离线加密单测）
python -m pytest tests/ -q
```

覆盖：逐字节往返（空文件/跨帧/多帧、密文布局尺寸）、信封 AAD/错钥拒绝、
明文不落盘（blob/元数据库/临时文件三处核查）、幂等上传与密钥操作幂等、
篡改 GCM 失败、完整轮换（信封迁移+正文不动+二次轮换仍不动+销毁后可读）、
进度与轮换拒绝、**并发轮换只受理一次（202+409、只切一次、无中间密钥残留）**、
**未登记切换/多代际链条的对账补建与重启收敛**、**pending 受理占位的崩溃恢复
（切换已生效/未生效两路）**、**轮换回执不明的核实补登记**、**旧库 schema
在线迁移**、慢密钥服务并发、在途下载跨销毁、销毁丢回执自动核实、
双服务重启可读性、轮换中途重启接续、崩溃在途上传不晚发布、
跨越轮换的上传自动改绑。

## 限制与生产化建议（见 docs/ 下说明）

单实例 + SQLite 面向单机/单节点部署；扩成多实例需把轮换协调改为分布式锁、
blob 存储换成对象存储，并在密钥服务前加 mTLS/审计与 HSM/KMS 托管根密钥。
