# Contracts: PDP 验签接线（#1109 剩余 W）

## 无新增 wire contract

本 feature **不新增、不修改任何 wire contract / generated 类型**。理由：

- 验签接缝消费的是**冻结的 `diport::Pdp` port-own 类型**（`RawCredential` / `VerifiedClaims` / `PdpError`，PR 211 已落），非跨域 wire DTO。
- httpserve 放行证据 `Authenticated` 是 **httpserve own 进程内类型**（基础级标量），不跨进程、不上 wire。
- verify-bridge、OidcProvider 均为进程内组件，无 HTTP/event/command contract 变更。

故**无契约扇出闭环**触发（无 schema → generated → 域 crate metadata → tests → docs 链）。各 PR 一致性等级为 **L1 / 无等级**。

## 受约束的已冻接缝（消费方契约，不改签名）

| 接缝 | 位置 | 本 feature 关系 |
|------|------|----------------|
| `diport::Pdp::verify` | `crates/diport/src/pdp.rs` | PR-A1 impl（adapter 实现侧），签名不改 |
| `authn::verify_rss_access` / `verify_federated_access` / `verify_service_token` | `crates/authn` profile-specific 验证 funnel | runtime 按 typed binding 调用 |
| `httpserve::finalize_auth(router, plan)` | `crates/httpserve/src/lib.rs:122` | 签名**保持冻结**（验签桥走组合根外层 layer，不穿入） |

`finalize_auth` / `diport::Pdp` 属库 crate 公开 API 面（轴 A SemVer），由 `cargo public-api` golden 守；本 feature 不改其签名 → 无 public-api diff。

## 治理 / lint（无新增 port → 无新增定义面守卫）

- `rss_diport_impl_allowlist`（dylint）：oidc(adapter) impl `Pdp` 已在 allowlist，无需改。
- `deny.toml` dynosaur/trait-variant 宏白名单（DIPORT-MACRO-CONFINE-01′）：本 feature **不新增 port**（消费已有 `Pdp`），天然满足 ADR-006 §8 验收门槛 ④。
- `deny.toml` `oidc` package wrapper（server/rss/xtask/journeys）已登记；PR-A1/A2 新增 crypto deps 后 `cargo deny check` 复绿。
