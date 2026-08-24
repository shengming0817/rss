# Event Transport 规则

本文拥有 broker topology、AMQP/MQTT transport、标准 envelope 与订阅路由。Outbox、消费结算、命令和投影分别由
其它规则文件拥有。

## Topology 与选型

- composition root 必须经 typed resolver 按 `Topology` 选型；resolver 只返回 validated decision，adapter 由根构造。
- isolated durable topology 缺 per-domain URL、凭据或 ACL 时 fail-closed；不得回退 shared URL。
- durable 缺 broker 不得降级 in-memory；memory transport 只允许 demo 且 production target 在 Cargo 图不可达。
- 新 transport 必须扩展闭值 decision 与 composition match，不得增加旁路。

载体：`INVARIANT: TOPO-FAILCLOSED-01` / `TOPO-INMEM-SEAL-01`，Hard 由 Cargo/closed types 承载，
Medium 由 resolver 与 composition tests 承载。

## AMQP isolation

- per-domain credential/vhost 与 broker ACL 由外部 broker owner 配置；producer 只 publish 本域，consumer 只
  consume declared queue/topic。
- broker header 中的 tenant 值不是授权凭据；写 application DLQ 前必须验证 relay 签发的 tenant authority。
- ambiguous publish outcome 按可能已发布处理并退休 transport generation；不得换 event ID 或假定未发布。

## Device MQTTS

- production 只有一个稳定 client identity、persistent session、driver 与 exact topic policy；禁止明文 MQTT、
  wildcard、随机 ID、双 driver 或无 feature fallback。
- 构造要求 `mqtts` authority、CA/client credential、匹配证书的 client ID、broker assertion key、非空 device
  scope、合法 session expiry 与递增 credential revision；任一非法即 fail-closed。
- exact topic 与 broker ACL 从同一 tenant/device/generation policy 派生。peer certificate SAN、topic、payload
  digest、QoS 与 retain 必须由 broker-only assertion 绑定；client property 不能伪造 principal。
- 入站 manual ACK 仅在 assertion、scope/generation 和有界 admission 成功后可用；stale epoch、验签失败、
  queue 饱和或 transport outcome unknown 不得提前 success ACK。
- credential reload 只接受同一 identity 的更高 revision；candidate 失败回滚 last-good。
- broker ACK 只证明 transport acceptance，不证明 device/application receipt 或 durable commit。

## Envelope

broker-visible header 只含 canonical tenant、schema identity、occurred time、trace/correlation 与 tenant authority。

- schema identity 由 generated contract 写入，relay 必须以持久列覆盖调用方 header。
- tenant/schema/authority 非法时 fail-closed；trace/correlation 非法时 fail-open 且不得影响授权。
- subject、actor、principal、causation 与业务 metadata 只持久化，不进入 broker header。
- 业务入口不得写 reserved key。

当前 L2 公共 metadata owner 是 `eventing::metadata::EventMetadata`，字段闭合为 canonical `TenantId`、
`Timepoint` 与可选 `CorrelationId`。三个字段均私有，只能经完整 typed constructor 构造；不存在开放 bag、
provider/source、payload、receipt/store/transaction 字段、转换桥、crate-root shortcut 或整体 `Debug`。
raw `EnvelopeMetadata` 只负责 wire `get / iter / insert`，不拥有 typed convenience accessor；消费 preflight
一次产生 validated `EnvelopeHeader` 与同一个 `EventMetadata`。correlation 缺失或非法时降为 `None`，且只可
投影到内部诊断上下文，不得进入 audit record、receipt 或 durable store。audit 解码前先验证 header，随后要求
payload tenant/time 与 `EventMetadata` 严格相等，不匹配必须在写入前失败。#2159 已原子移动 owner 并删除旧路径，
不提供 alias、re-export 或兼容双路径；是否进入 Release API 仍由后续 release selection 独立决定。

## Subscription

- active event 必须有 typed subscriber 与唯一 owner；queue/topic 从 contract 派生，不接受自由字符串旁路。
- subscribe 成功前不得宣告 readiness；supervision failure 必须使对应 capability degraded/not-ready。
- transport 只交付 authenticated envelope，不拥有业务事务、settlement 或 projection checkpoint。
