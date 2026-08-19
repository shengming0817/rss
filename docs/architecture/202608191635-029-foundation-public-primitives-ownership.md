# ADR-029：Foundation 公共原语唯一 owner 与兼容边界

- **Status**：Accepted
- **Date**：2026-08-19
- **Tracking**：#2148
- **Scope**：ADR-024 的 Foundation Public 细化；后续实现与外部消费由 #2149–#2153 承载

## Context

Platform vNext 已把 contract identity 与 authority-free request context 分别收敛到
`rss-contract` 和 `rss-request-context`。本 ADR 盘点 `TenantId`、contract descriptor、绝对时间、分页游标、
数据分类与可安全传递的错误语义，避免把仓内 `pub`、internal public-api baseline 或用途特化 carrier 误认成
Release API，也避免为这些值再建一个聚合 Foundation facade。

当前事实如下：

- `TenantId` 只有 `rss-request-context::TenantId` 一个定义；`runctx::AppCtx` 直接消费它。
- `ContractDescriptor` 只有 `rss-contract::ContractDescriptor` 一个定义；generated 只生成该类型的常量，
  Platform 只消费 descriptor 做 admission。
- `vocab::UnixEpochSeconds` 与 `vocab::Cursor` 是 publish=false internal carrier；前者只表达非负 Unix 秒，
  后者只校验非空 base64url token。
- `secure::Sensitivity`、`PiiKind` 与 `RedactionMode` 是内部脱敏策略，不是公共数据治理 vocabulary。
- `vocab::CoreError`、`secure::LastError` 与 `diport::RedactedSource` 分别服务 wire/domain、持久化摘要与
  provider source containment，没有一个是 Release API safe-error contract。

后续 #2150、#2151 和 #2153 已接纳真实外部消费方向。因此本 ADR 不以“当前尚无类型”为由否定公共缺口，
而是先冻结唯一 owner 与 carrier replacement，再由后续 PBI 原子物化 API 和 proof。

## Decision

### Owner 与处置矩阵

| 语义 | 当前载体与消费者 | 最终唯一 public owner | keep / move / drop | public、internal 与 authority 边界 | SemVer / 删除条件 |
|---|---|---|---|---|---|
| `TenantId` | `rss-request-context::TenantId`；`runctx`、Platform、域、adapter 与 generated 直接消费 | `rss-request-context::TenantId` | **KEEP** | 可公开解析的 authority-free value；trusted context 只能由 AuthN/AuthZ 后的私有 assembly/Platform mint 铸造 | 保持现有轴 A owner；禁止其它 package 定义、alias 或 re-export |
| Contract descriptor | `rss-contract::{ContractId, ContractVersion, SchemaDigest, ContractDescriptor}`；generated 物化常量，Platform admission 消费 | `rss-contract::ContractDescriptor` 及同包 identity | **KEEP** | descriptor 可构造但不是 admission capability；generated 与 Platform 不取得类型或 mint owner | 保持现有轴 A owner；禁止镜像 descriptor 或提供 convenience path |
| `Timepoint` | internal `vocab::UnixEpochSeconds`；`SystemTime`/Clock 由各内部 owner 使用 | planned `rss-contract::Timepoint` | **MOVE** 公共绝对时间语义；**DROP** 同义 generic carrier | 只拥有 wire、range、ordering 与 fallible conversion；不提供 `now`、Clock 或 deadline authority。`rss-request-context::Deadline` 保持单调请求预算 | #2150 原子迁移重叠消费者并删除 `UnixEpochSeconds`，不保留转换 shim；类型进入 Release API 后按轴 A 演进，wire 变化另走轴 B |
| `PageCursor` | internal `vocab::Cursor`；另有 DLQ、Saga、maintenance 等特化 cursor | planned `rss-contract::PageCursor` | **MOVE** 公共 opaque/bounded token 语义；**DROP** 同义 `vocab::Cursor` | 公共值不泄漏 provider/keyset 形状；malformed/stale 是闭合拒绝语义。具有独立状态机或持久化坐标的 cursor 继续由各 internal owner 持有 | #2150 原子迁移 generic consumer 并删除 `vocab::Cursor`；分页排序、失效或 token wire 变化仍服从轴 B |
| `DataClass` | internal `secure::Sensitivity/PiiKind/RedactionMode` 与 derive policy | planned `rss-contract::DataClass` | **MOVE** 稳定公共分类；**DROP** internal 对公共分类的镜像 | `DataClass` 只表达闭值分类；`secure` 消费它并继续拥有 PII 子类、redaction mode、key 与执行，不公开 redaction engine | #2151 原子切换分类 owner；禁止 alias 或并存的同义 enum，新增/改变公共闭值按轴 A 审查 |
| redact-safe error | `CoreError`、`LastError`、`RedactedSource` 各有不同 internal 职责 | planned `rss-contract::SafeError` | **MOVE** 稳定安全投影；**KEEP** 职责不同的 internal carrier | 只暴露稳定 code/category 与安全 message posture；source、payload、PII、provider 类型和 redaction/mint authority 不可达。internal error 经显式投影进入公共值 | #2151 物化 owner-local type；不 re-export internal error、不公开任意 message/source，不以通用 trait 建第二错误体系 |

`MOVE` 表示公共语义 owner 的原子切换，不表示把旧类型换路径继续发布。语义重叠的 generic carrier 必须在对应实现
PBI 中迁移消费者后删除；语义不同的 `Deadline`、Clock、领域 cursor 与内部错误 carrier 不是兼容层，也不获得
Release API 身份。

### Public path 与禁止边界

- consumer 必须直接从 `rss-contract` 或 `rss-request-context` 的唯一 owner 路径导入；禁止 Platform、generated、
  vocab、secure 或新 facade 再导出同一类型。
- 不建立 `rss-foundation` 聚合包，不建立 shared prelude，不用 alias、deprecated re-export、`From`/`TryFrom`、
  feature flag、双读写或双 dispatch 维持旧路径。
- `rss-contract` 继续 std-only、无 internal workspace 生产依赖；`rss-request-context` 继续只承载 authority-free
  request values/read-only views，不吸收通用 contract vocabulary。
- public value 可由 consumer 构造不等于 consumer 获得可信性。Tenant/request identity、descriptor 与 safe value
  的 authority 仍由各自 admission、AuthN/AuthZ、redaction 或 provider funnel 持有。

### Axis A / Axis B

把 internal carrier 提升为 Foundation 不是路径移动，而是新增 owner-local Release API，再原子删除同义 internal
carrier。internal public-api baseline 不构成外部兼容 authority；不得用 shim 让旧路径进入 Release Surface。

Rust 类型、构造器、闭值集合与 trait surface 属轴 A。时间格式、分页排序/失效、错误 code/message/retryable/status
以及 contract schema 中的对应 wire 语义仍属轴 B；轴 A additive 不授权原地改变 active wire。

## AI-HARD carrier handoff

本 ADR 是决策与 handoff artifact，不声明尚未落地的新 `INVARIANT`，也不把 Markdown、名称搜索或手工计数当作
enforcement。carrier 按现有 PBI DAG 交付：

| 风险 | Canonical carrier | 状态 / owner |
|---|---|---|
| canonical 类型夹带 internal / foreign public type | 当前 owner 的 private representation、直接 Cargo/type identity、Release API forbidden-type/source-identity projection | **active**；#2107 既有 Hard/Medium carrier；不宣称其能识别另一 package 新定义的同义类型 |
| 非 canonical package 新定义同义 `TenantId` / `ContractDescriptor` 或跨 owner re-export | 在既有 typed rustdoc owner projection 中固定 canonical primitive→package 映射，同时拒绝 owner-local mirror 与 foreign source re-export，并配 synthetic red / anti-vacuity | **planned**；#2152 的 Medium ReleaseCheck，不建名称/source-shape scanner |
| Timepoint/PageCursor/DataClass/SafeError 可被任意伪造或夹带内部值 | owner-local private newtype/closed enum、fallible constructor、safe `Debug`/`Display`、Cargo dependency direction | **planned**；#2150/#2151 的 Hard T1 |
| 同义 old/new type、alias 或双路径并存 | 消费者在一次变更中直接迁移；旧 symbol 删除后由 rustc/Cargo 断开所有调用点；不保留 compile-fail 墓碑 | **planned**；#2150/#2151 的 Hard cutover |
| Release API、依赖闭包或 artifact 漂移 | 正向 Release Surface、default/all-features SemVer、release-api exact set、forbidden leakage 与 package proof | **planned extension**；#2152 |
| 无真实外部 consumer 的未来 API | registry-only、locked/offline external consumer，直接从唯一 package path 导入并覆盖拒绝路径 | **planned**；#2153 T2 |

## Four-principle check

- **彻底**：六项均有当前 carrier、最终 owner、authority、兼容风险与删除条件；同义 generic carrier 不留成第二 owner。
- **不向后兼容**：迁移直接切换并删除旧类型/路径，不保留 alias、shim、deprecated re-export、转换桥或双路径。
- **优雅简洁**：复用两个既有 Foundation package 和现有 release proof；不新增 facade、registry、scanner、runner 或发布系统。
- **AI-HARD**：只对既有 carrier 声称 active；未来约束明确交给后续 Hard/Medium owner，本文不冒充机器事实源。

## Consequences

#2148 只改变架构决策与现行规则说明，不改变代码、Cargo graph、Release API baseline、wire、版本或发布状态。
#2149 将本决策纳入产品面 amendment；#2150/#2151 完成类型与原子 cutover；#2152 完成 candidate/package proof；
#2153 完成真实外部消费。任一 planned carrier 未落地前，对应 public API 仍不存在，也不得由本文宣称完成。
