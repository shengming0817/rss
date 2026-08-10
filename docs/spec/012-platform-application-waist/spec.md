# Feature Specification: Platform Public application kernel 与外部消费证明

**Created**: 2026-08-08
**Amended**: 2026-08-10
**Status**: Implemented experimental v0.2 contract
**Owner issues**: #2049, #2051, #2052, #2088, #2089

## v0.2 amendment

`rss-platform` v0.2 将已授权原地演进的 `runtime.inventory@v1` provider posture
`unobserved` 闭值投影为公开 `RuntimeProviderState::Unobserved`，并由 schema 经 deterministic codegen
派生 façade enum。该 breaking Release API 变更不保留 alias、shim 或旧 digest。

## 决策修正

本 amendment 取代本规格旧版的 “thin façade / exact API frozen / 不改变 runtime” 方案。旧方案只能冻结形状，
却没有拥有 authority、dispatch 或 lifecycle，因而不能构成 Platform Public 产品面。v0.1 直接定义
`rss-platform` 为 provider-free、进程内 typed application kernel；旧 #2045 fixture 与 profile API 不保留
alias、shim 或兼容入口。

`core`、`eventing` 仍是 ADR-024 的候选 official profile，但尚未激活，不进入 v0.1 Release API。
本 kernel 不绑定 listener、不构造 provider、不声明 provider/runtime readiness，也不提供 Host/Provider SPI。

## Canonical public contract

`cargo xtask codegen` 从 `owner="_framework" + lifecycle="active" + kind="http"` 的 canonical manifests
投影 sealed contract marker 与 façade-owned DTO。v0.1 exact set 只有 `runtime.inventory`；ID、版本、
schema digest、permission 与 reviewed DTO template 任一漂移必须 fail-closed。
集合 DTO 在构造边界拒绝重复值；listener/provider/placement 还必须满足 canonical stable key 顺序，
失败只返回可匹配的闭值原因码。

公开调用链固定为：

```text
ApplicationBuilder -> Application -> RuntimeHandle
RuntimeHandle::dispatcher -> Dispatcher::verify
Dispatcher::dispatch<C> -> RuntimeHandle::shutdown
```

- `Contract` 是 sealed trait；外部只能实现 `Handler<C>`。
- `ApplicationModule` 登记 typed handler；build 原子拒绝重复 module/contract handler。
- `TrustedIssuer` 只接受静态 ES256 JWKS snapshot，并固定 issuer/audience。
- `AccessToken`、`VerifiedAccess`、`RequestContext` 与 verified views 无 public mint；token/context
  不实现 Clone/Debug/serde。subject 仅允许 `matches_subject`。
- `dispatch<C>` 同时要求 generated marker、已登记 handler、verified authority 和 marker-owned permission。
- `RuntimeHandle` 不可 Clone；`Dispatcher` 可 Clone。shutdown 消费 handle，先进入 draining、拒绝新请求，
  等待在途 handler，并受显式 `Duration` 上界约束；超时保持真实 draining，最后一个在途 handler 退出才
  原子进入 stopped；所有遗留 dispatcher 在 stopped 后 fail-closed。
- conditions 只描述 handlers admitted、accepting dispatch、draining、stopped 的真实 kernel 状态。
- Build/Verify/Dispatch/Shutdown 错误与 diagnostics 只携闭值 code/typed detail，Display/Debug 固定脱敏且无 source；
  runtime 保留最多 64 条最近闭值诊断，不保存 token/identity/provider text。

## Verification profile

v0.1 只支持静态 federated ES256 access token：

- protected header 必须 exact `alg=ES256`、`typ=at+jwt`、非空 exact `kid`，且不得含 `crit`；
- 签名、issuer、audience、`iat/exp/nbf`、最大 900 秒 lifetime、`token_use=access` 全部校验；
- federated principal 只接受 user/device/admin + canonical tenant，或无 tenant 的 superAdmin；
- permissions 必须非空、去重、canonical，dispatch 再检查 contract-owned permission；
- token、subject、tenant、JWKS/config 与 raw source 不得进入 error/diagnostics。

动态 JWKS lifecycle、RSS/service-token profile 与 provider glue 留在 internal Official Integration；federated ES256
签名与标准 access claims 判定复用 Platform owner，Integration 仅叠加 operator kind allowlist、可配置 claim 名与
permission universe，并必须证明投影 identity 与 Platform authority 完全一致。

## Release 与独立证明

`rss-platform` 0.2.0 是 experimental PlatformPublic package，normal/build dependency 只能是外部 crates。
Release Surface 同时守 default/all-features API、SemVer、publish closure 与 forbidden-type leakage。

`cargo xtask package-proof` 必须从当前 revision 生成真实 `.crate`，建立本地 registry，在 workspace 外临时
Git repository 生成独立 `Cargo.lock`，然后以 `--locked --offline` build/run。T2 consumer 必须注册
`runtime.inventory` handler、用 ES256 token 走真实 verify/dispatch、读取 conditions/diagnostics 并 bounded shutdown；
helper 必须精确验证每阶段结构化 receipt。该 proof 由 canonical ReleaseCheck 的 public-api execution owner 执行。

## Non-goals

- HTTP listener、wire transport、真实 provider、T3、official profile activation；
- 通用 DI container、service locator、Provider SPI、第二 composition root；
- internal type re-export/conversion、公开 raw subject/token/key、可伪造 authority；
- no-op start、Unknown readiness、panic/unimplemented lifecycle。
