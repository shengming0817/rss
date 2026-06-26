# Quickstart: PDP 验签接线验证指南

两层验证：① adapter 验签 round-trip（单测，FixedClock）；② 生产认证闭环（e2e，含拒绝路径）。

## ① adapter 验签 round-trip（PR-A1，无需运行时）

```bash
# 表驱动单测 + RFC7515 known-answer 向量（真验签模块全在 backend feature 下，缺则空跑假绿）
cargo nextest run -p oidc --features backend
```

预期覆盖：
- 合法 ES256 JWT（exp 未来、iss/aud 匹配，FixedClock 设在 exp 之前）→ `Ok(VerifiedClaims)`，subject/tenant/kind 与 payload 一致。
- 合法 HS256 service_token → `Ok`。
- 篡改 payload → `Err(InvalidSignature)`；`alg=none` → `InvalidSignature`。
- exp 过期（FixedClock 设在 exp+leeway 之后）→ `Expired`；exp 边界内（exp<now<exp+leeway）→ `Ok`。
- `alg=RS256`/未知 → `InvalidSignature`（不在白名单，`jws::parse` 拒）；kid 无匹配（US4 JWKS）→ `Untrusted`；iss/aud 不符 → `Untrusted`；alg=HS256 但走 ES256 scheme 路径（alg-scheme 混淆）→ `Untrusted`。
- 错误不含 token/key 字节（Debug 脱敏断言）。
- anti-vacuity：先断言「正确签名通过」，再断言坏签名拒（防恒 false 空 impl 也过坏签名用例）。

## ② httpserve 放行接缝（PR-B，oneshot）

```bash
cargo nextest run --manifest-path crates/httpserve/Cargo.toml -p httpserve
```

预期：注入 `scheme` 匹配的 `Authenticated` → `Require` 路由 200；不注入 / scheme 不匹配（Jwt 证据 vs `Require(Mtls)`）/ `Anonymous` 证据 → 401；`opt_out=Public` → 200（不回归）；无 AuthPlan → 403（AUTH-FAILCLOSED-01）。

## ③ 生产认证闭环 e2e（PR-C，含拒绝路径）

```bash
# 起 router + 真 OidcProvider（静态 key）+ verify-bridge
cargo nextest run -p server -p rss   # in-process oneshot e2e（无需 feature gate；socket bind/serve = #1017）
```

预期（ADR-006 §8 ③）：
- 带有效 JWT（真 OidcProvider 验签通过）请求 `Require(Jwt)` 路由 → 200，request extension 携 `httpserve::Authenticated`（`scheme=Jwt` + principal_kind facet）、enforce `scheme()` exact-match 放行；**本批不承诺 handler 读完整 `Principal`**（完整 Principal 传播属 W 后续，见 spec US3 / data-model F3）。
- **凭据存在但被拒**（坏签名 / 过期 / 错 aud-iss / 验签通过后缺 tenant 等）→ 401（含 requestId）；请求进 verify-bridge `verify_bridge` span，tracing 记 `authz.decision=deny` + 闭值 `authz.deny_reason` 告警分级（`signature_invalid`/`untrusted`/`expired`/`principal_invalid`——对应 PDP `InvalidSignature`/`Untrusted`/`Expired` 与**验签后** authn principal 派生失败；`From<PdpError>` 一一保真为 `AuthnError::TokenInvalid`/`TokenUntrusted`/`TokenExpired`、派生失败归 `PrincipalInvalid`，#1275 + review F1 已落地）+ `error=?err` 变体，日志无 token/subject。
- **无 Authorization 头**（无凭据）→ **不进** verify-bridge（`Some(token)` 才进 span），由内层 enforce fail-closed 401（含 requestId），**无** bridge `authz.deny_reason` 日志（凭据缺失 ≠ 凭据被拒，二者拆分，review F3）。
- 有效请求 → tracing 记 `authz.decision=allow` + `principal.kind`（无 PII）。

## ④ JWKS 轮转（PR-A2 / #1197 — 本地文件源 + 外部 agent 刷新）

```bash
cargo nextest run -p oidc --features backend   # fake JWKS 文件源（jwks::tests）
```

预期：kid=k1 token 通过；轮转（重写文件 + `reload`）后 kid=k2 通过、k1 移除后旧 token → fail-closed；源不可读/空/畸形 → 构造期 fail-fast 拒；刷新失败保留 last-good + `oidc_jwks_ready=false`（degraded，绝不 swap 空集）。

**部署约束**：`JwksKeySource` 从**本地路径**读 JWKS 文档——in-app **零 HTTP/TLS provider**（无 license-clean 成熟 rustls provider，见 research.md R3 决断）。传输完整性属基础设施层：外部 agent / init-container / controller 经**各自的** TLS 拉取 + 轮转后，把 JWKS 文档写入受 **OS 文件权限 / k8s Secret RBAC / 挂载 namespace 隔离**保护的路径（应用只读）。**绝不**让应用经裸 plain-HTTP-over-network 拉 JWKS（research.md F2）。in-app HTTPS 直连外部标准 IdP = follow-up（待成熟 license-clean provider）。

## ⑤ 全量治理门

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                 # 无 ring/rsa/aws-lc/openssl/jsonwebtoken；licenses/bans/advisories 绿
cargo xtask layer-deps           # oidc 不被域依赖；httpserve 无新 path dep
cargo dylint --all               # rss_diport_impl_allowlist：oidc impl Pdp 合法
```

## 安全门人工核对（不可机器全覆盖处）

- `cargo build --release`（bins/server、bins/rss）依赖图**不含** stub Pdp（stub 仅 `[dev-dependencies]`）与禁用 crypto crate。
- 仅 PR-C 启用生产认证（注入 Box<DynPdp> + 挂 verify-bridge）；PR-A1/A2/B 单独 merge 后 `Require` 端点仍 401。
