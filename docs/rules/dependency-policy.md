# RSS 依赖使用与能力实现规则

本文件只拥有依赖与自研准入；能力范围由独立 policy owner 决定。依赖版本和 feature 由 workspace
`Cargo.toml` 与 `Cargo.lock` 声明。

## 实现顺序

```text
直接使用成熟上游
→ 内部薄适配
→ RSS 语义 wrapper / composition
→ 核心不变量需要时自研
```

## 机制归属

| 机制 | 上游机制 | RSS 语义 |
|------|----------|----------|
| 异步与任务 | async runtime / task utility | startup transaction、任务 owner、readiness、drain/shutdown |
| HTTP / RPC | server、router、middleware、client | contract binding、tenant/auth context、统一错误与 lifecycle |
| 序列化与 schema | serializer、schema 标准与库 | contract metadata、compatibility、deterministic codegen |
| 数据库与缓存 | driver、pool、数据库能力 | tenant-safe transaction、RLS、LocalTx、outbox/inbox、fencing |
| 消息与设备协议 | broker/MQTT client | settlement、idempotency、DLQ、command/reconcile 与 recovery |
| 对象存储 | 标准 SDK | archive/WORM receipt、tenant/security policy 与 recovery |
| TLS、身份与密码学 | 安全库与外部身份系统 | verified identity、key-use policy、rotation/revocation、redaction |
| 可观测与弹性 | telemetry、限流与 resilience 库 | RSS label、trace、health、failure posture 与业务幂等边界 |
| 测试与治理 | Cargo/rustc、lint/gate 与测试工具 | conformance、journey、fault/recovery oracle 与结构化诊断 |

具体选择以 workspace 依赖、能力 owner 和真实 consumer 为依据。

## 实施前判定

新增依赖、wrapper、port、adapter 或自研机制前确定：

1. capability owner 与真实 consumer。
2. workspace/upstream 可复用机制。
3. RSS-specific semantic 与 thin adapter 边界。
4. public API、support matrix 与 dependency feature closure 影响。
5. 重复机制的 `yes/no` 结论与明细。
6. upgrade、replacement 与 removal path。

## 机器约束

| 条件 | 权威 carrier |
|------|--------------|
| 使用方直接声明依赖并形成合法无环图 | Cargo manifest/rustc |
| workspace 外部 version pin 与 lock 对齐 | `[workspace.dependencies]`、`Cargo.lock`、`--locked` |
| license、advisory 与 source policy | `deny.toml`、`cargo deny` |

### 临时 advisory 风险接受

图内 RustSec advisory 默认不得 ignore。若修复被上游发布阻塞且产品决定临时接受风险，必须同时满足：

- `deny.toml [advisories].ignore` 使用含 issue 与风险原因的结构化条目，并以完整 `DEFER`
  元数据声明 owner、阻塞条件和撤销条件；
- canonical cargo-audit 步骤同步每个 `--ignore`，保持双扫描器对账；
- 机器守卫必须通过 `WorkspaceFacts` owned resolved-package/edge DTO，对每项 advisory 的完整
  受影响 PackageId 集合与唯一允许集合做精确比较，并锁定唯一依赖根；出现第二脆弱版本、第二
  source、额外父依赖或上游已移除该依赖时 fail-closed，暴露扩大或过期的豁免；
- 风险接受必须有独立 owner 与撤销条件；上游修复可用后升级依赖并在同一变更中删除两侧豁免。

该机制仅表示显式风险接受，不得宣称漏洞已修复，也不得扩大到没有独立跟踪项的其它依赖。

## Wrapper 与 adapter

薄适配至少承载一项 RSS 语义：

- `TenantContext`、Principal 或 Device Identity 传播；
- fail-closed、timeout、readiness、health 或 lifecycle posture；
- LocalTx、outbox、idempotency、settlement、checkpoint 或 fencing；
- redaction、audit 或 trace continuity；
- config、assembly 或 production support 约束；
- 上游错误到稳定 RSS 错误模型的映射。

adapter 与 composition root 持有上游 API；domain 与公开 contract 暴露 RSS 语义。

Tooling 的 Cargo facts 遵循同一边界：复用 `workspacefacts` 时，catalog / feature selection 经 guppy
`PackageGraph` / `CargoSet`，declaration-granularity provenance 经同一 `cargo metadata` JSON 的私有 raw
投影；轻量 CI selector 直接消费标准 `cargo metadata` schema，只输出 package reverse closure。

## Port / trait

RSS port 用于：

- domain 业务或一致性语义；
- raw client 与 domain 之间的安全边界；
- external side effect 的 failure injection、conformance 或 transaction seam；
- 多个实际交付实现的共同 consumer contract；
- 已确认的实现替换需求。

单一 provider 由 composition root 构造，通过窄语义 wrapper 使用。测试复用上游 mock、受控 factory 或测试工具。

## 自研范围

- contract/codegen 与运行 binding；
- L0–L4 typed semantic、receipt、idempotency、fencing/checkpoint 与 recovery；
- tenant-safe transaction/RLS funnel；
- Verified Principal/Tenant/Device/credential 与 authorization obligation；
- AssemblyLock、RuntimePlan、assembly composition 与 runtime inventory；
- startup/readiness/drain/shutdown lifecycle；
- conformance、fault/recovery 与 upgrade evidence。

自研 ADR 记录 invariant、上游组合评估、owner、consumer、正确性/安全/性能/互操作证据，以及替换触发条件。

## 升级与替换

- 升级验证 feature/target、公开行为、schema/wire compatibility 与 production posture。
- workspace 保持统一 dependency declaration 与 feature closure。
- candidate 通过后切换唯一调用路径并移除旧路径。
- production acceptance replacement 必须 first-green 后原子切换并删除旧 carrier。
