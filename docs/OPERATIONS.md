# 运维与故障处理手册

## 1. 部署清单

| 组件 | 镜像 | 持久卷 | 暴露 |
|---|---|---|---|
| image-api | microscopy/image-api:1.0.0 | api-data（metadata.db + blobs/） | 8000 |
| keystore | microscopy/keystore:1.0.0 | keystore-data（keystore.db） | 127.0.0.1:8001 |

两个容器必须配置相同的 `KEY_SERVICE_TOKEN`。密钥服务端口只绑回环地址，
不应对仪器网段或公网暴露。

## 2. 数据与密钥位置

- 主密钥材料：仅 `keystore-data` 卷内 SQLite 的 `master_keys.key_material`；
  销毁后该列被 32 字节零覆写、状态置 `destroyed`，不可恢复。
- 数据密钥：永远以 64 字节信封（`MAGIC|nonce|ct|tag`）存在 api-data 的
  `images.wrapped_dek`；明文 DEK 只在 API 单次请求内存中出现。
- 原片：api-data 的 `blobs/*.msef`，全部为 AES-256-GCM 分帧密文；
  明文不落盘（multipart 假脱机已在代码中禁用）。

备份策略：两卷需**一起**备份。单独备份 api-data 在旧 MK 销毁后无法解读；
单独备份 keystore-data 没有原片。建议离线备份 keystore-data 并严格限制访问。

## 3. 标准轮换流程

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"confirm":true}' \
  http://localhost:8000/rotations
# 轮询 GET /rotations/{job_id}，state 终态：completed / failed
```

状态机：`migrating`（逐信封 rewrap，blob 正文不动）→ `destroying`
（零残留核验 + 销毁旧 MK + 只读核实）→ `completed`。
进行中再次发起轮换返回 409。作业失败时先查 `error` 字段，修复后
（通常是密钥服务暂时不可达）重启 API 即可自动接续，无需手工干预。

## 4. 故障演练开关（keystore）

- `KEY_OP_DELAY=<秒>`：模拟慢密钥服务，验证在线流量不被轮换拖死。
- `KEY_DESTROY_DROP_RECEIPT=true`：销毁落盘后丢弃 HTTP 回执，验证 API
  自动重试 + 只读状态核实、作业仍如实报 completed。

## 5. 崩溃/重启语义

| 场景 | 行为 |
|---|---|
| API 在上传中崩溃 | 重启后该件标 `failed`（不晚发布）；blob 残片可按 failed 行清理 |
| API 在轮换中崩溃 | 重启后后台线程自动接续未完成作业到终态 |
| 崩溃于"MK 已切换、作业未建"窗口 | 启动对账自动补建迁移作业 |
| 密钥服务重启 | 主密钥从卷内 SQLite 恢复，已入湖原片逐字节可读 |
| 销毁回执丢失 | KeyClient 重试并以 `/internal/master/status` 只读核实 |

## 6. 已知限制（单实例/SQLite 范围之外）

1. 单实例：API 与密钥服务均为单节点，无水平扩展与高可用；多实例需要
   分布式轮换锁（如 Postgres 行锁/etcd）与共享对象存储。
2. 内部服务间为共享 Bearer 令牌；生产化建议改 mTLS 并加调用审计。
3. 根密钥目前为软件随机生成并存于 SQLite；更高合规要求应替换为 HSM/KMS，
   本服务的信封接口（generate/unwrap/rewrap）保持不变即可适配。
4. GCM 帧验签失败发生在流式响应开始之后，表现为连接中断（HTTP 流无法
   再改状态码）；客户端应将不完整响应当作失败，可重新 GET 重试。
5. 销毁 MK 是不可逆操作；销毁前系统保证无 ready/receiving 行依赖它，
   但 failed 历史行的信封将永久无法解包（这些原片本就不可读）。
