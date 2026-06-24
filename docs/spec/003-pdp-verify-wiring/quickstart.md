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
- `alg=RS256`/未知 → `Untrusted`；kid 无匹配 → `Untrusted`；iss/aud 不符 → `Untrusted`；alg=HS256 但 key 是 ES256 → `Untrusted`。
- 错误不含 token/key 字节（Debug 脱敏断言）。
- anti-vacuity：先断言「正确签名通过」，再断言坏签名拒（防恒 false 空 impl 也过坏签名用例）。

## ② httpserve 放行接缝（PR-B，oneshot）

```bash
cargo nextest run --manifest-path crates/httpserve/Cargo.toml -p httpserve
```

预期：注入 `Authenticated` → `Require` 路由 200；不注入 → 401；`opt_out=Public` → 200（不回归）；无 AuthPlan → 403（AUTH-FAILCLOSED-01）。

## ③ 生产认证闭环 e2e（PR-C，含拒绝路径）

```bash
# 起 router + 真 OidcProvider（静态 key）+ verify-bridge
cargo nextest run --manifest-path bins/server/Cargo.toml --features integration   # 或 dev-dep 门控
```

预期（ADR-006 §8 ③）：
- 带有效 JWT（真 OidcProvider 验签通过）请求 `Require` 路由 → 200，request extension 携 `httpserve::Authenticated`（principal_kind facet）放行；**本批不承诺 handler 读完整 `Principal`**（完整 Principal 传播属 W 后续，见 spec US3 / data-model F3）。
- 无 Authorization 头 / 坏签名 / 过期 / 错 aud → 401/403（含 requestId），tracing 记 `authz.decision=deny` + 对应 `PdpError` 变体，日志无 token/subject。
- 有效请求 → tracing 记 `authz.decision=allow` + `principal.kind`（无 PII）。

## ④ JWKS 轮转（PR-A2）

```bash
cargo nextest run --manifest-path adapters/oidc/Cargo.toml -p oidc --features jwks   # fake JWKS 源
```

预期：kid=k1 token 通过；轮转后 kid=k2 通过、k1 移除后旧 token → `Untrusted`；JWKS 端点不可达 → `Untrusted`（fail-closed，绝不跳过验签）。

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
