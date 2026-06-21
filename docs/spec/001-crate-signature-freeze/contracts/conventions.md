# Contract: 签名编写 Conventions（PR-0）

> **薄引用** · 持久单源 = ADR-004 [`docs/architecture/202606220106-004-signature-conventions.md`](../../../architecture/202606220106-004-signature-conventions.md)
>
> 全部签名 PR 引用 ADR-004 作为机判 review 基准；本文件不复述正文（避免双源 drift，遵 AI-robust「约束单源」）。
> 涉及 async/dyn 二分（dynosaur）· mock · ctx 传播 · 关闭逆序 · 必填依赖/Clock · serde 边界 · sealed/newtype ·
> 覆盖率豁免 · 对标 ref · 错误 · unsafe 收敛 · dynosaur 版本 pin 时读 ADR-004。

## 范式速查（取值与论证全在 ADR-004 / ADR-001/002/003）

| 项 | 约定（一句话） | 单源 |
|---|---|---|
| C1 async/dyn | DI port（provider-可换、I/O、L1–L4）→ **dynosaur**（native AFIT + `#[dynosaur::dynosaur(DynX = dyn(box) X)]`，定义于 `diport`，注入 `Box/Arc<DynX>`）；L0 纯计算/单实现 → native AFIT + 泛型静态分发 | ADR-004 C1 · ADR-003 §2/§4 |
| C2 mock | 同 crate `#[cfg(test)]`，禁跨 crate 共享；**dynosaur/native-AFIT 下 mockall 形态待 diport spike 验证** | ADR-004 C2 · data-model 待决项#6 |
| C3 ctx | `runctx::RequestCtx<T,P>`（sealed struct + `task_local!`），需 ctx 处显式传 `&RequestCtx`；可观测 ID 走 tracing span 不入签名 | ADR-002 D2 |
| C4 关闭逆序 | `ManagedResource` LIFO、显式 `async fn shutdown`、无 async Drop | ADR-001 |
| C5 必填依赖/Clock | `Box<DynX>` 构造器必填位置参（非 Option）；Clock 同范式、禁默认系统时钟 | ADR-003 §4.3 |
| C6 serde | domain 不 derive Serialize/Deserialize；仅 contract/DTO（generated） | rust-standards |
| C7 sealed/newtype | DI port trait **不跨 crate sealed**（deny.toml wrappers 限定实现方，ADR-003 §4.2 方案②）；adapter raw client `pub(crate)` newtype | ADR-003 §4.2 |
| C8 覆盖率豁免 | 签名 PR body=`todo!()` 不可达 → PR body 声明覆盖率延迟到行为 PR | — |
| C9 对标 ref | PR body 标 `ref: {framework} {path}@{ref}` 或「无需对标：<理由>」 | research.md |
| C10 错误 | `vocab` + `thiserror` 枚举；message `&'static str` const literal | error-handling |
| C11 unsafe 收敛 | 仅 `diport` 有 forbid→deny 例外；`dynosaur` 依赖经 deny.toml 限定到 diport | ADR-003 §3 |
| C12 dynosaur pin | `=0.3.x` | ADR-003 §7/§8 |
