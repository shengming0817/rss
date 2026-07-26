# Implementation Plan: PDP 验签接线（#1109 剩余 W）

**Branch**: `003-pdp-verify-wiring` | **Date**: 2026-06-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/003-pdp-verify-wiring/spec.md`

**Tracking**: Azure Boards #1109 · Epic #991（W 宽扇出）· ADR-006（PDP 内置 + diport::Pdp 接缝）

## Summary

把 `diport::Pdp` 验签接缝（PR 211 已落 trait + verify→mint bridge）从骨架接到生产可达认证路径：真实 crypto verifier adapter（`adapters/oidc` impl `Pdp`，ES256+HS256+JWKS）+ httpserve 认证放行接缝 + 组合根验签桥与埋点 + e2e。技术方向已由 ADR-006（内置 typed authplan + diport::Pdp）、ADR-003（dynosaur dyn port）、供应链约束（RustCrypto，禁 ring/rsa）锁定。本计划裁定 auth-bridge 分层、坐实安全同批门，并把工作切成 **4 个 ≤2000 行 PR（2 wave）**。

## Technical Context

**Language/Version**: Rust（`rust-toolchain.toml` 固定 stable 1.96；lints 自成 nightly workspace，不参与根构建）

**Primary Dependencies**:
- 验签接缝（修订后冻结）：`diport::Pdp`（dynosaur dyn + Send 变体）+ profile-shaped
  `RawCredential` / `VerifiedClaimsView` / `PdpError`；`authn::verify_rss_access` /
  `verify_federated_access` / `verify_service_token` bridge。
- crypto（新增，RustCrypto 纯 Rust）：`p256`（ecdsa，ES256）、`hmac` + `sha2`（HS256，已在 Cargo.lock）；`base64` / `serde` / `serde_json`（已在 workspace deps）。常数时间比较复用 `primitives::crypto`（subtle）。
- JWKS HTTP/TLS（US4/PR-A2，license-clean 待甄别）：候选 rustls + license-clean crypto provider / 本地受信 sidecar + key pinning / 签名 JWKS；**裸 plain-HTTP 否决**（评审 F2，key-source 完整性）；license-clean TLS 不可得则退静态 key、不上线远程 JWKS。详见 research.md R3。
- HTTP runtime：`axum` + `tower`（httpserve 既有；verify-bridge 为 axum 中间件层）。
- 可观测：`tracing`（authz.decision span）。
- 测试：`cargo-nextest`、`rstest`（表驱动）、注入 `FixedClock`、`axum::http` + `tower::ServiceExt::oneshot`（handler/中间件）。

**Storage**: 无（验签为纯计算 + 可选 JWKS 远程 key 缓存，内存）。

**Testing**: adapter 表驱动单测（FixedClock + RFC7515 known-answer 向量）；httpserve 中间件 oneshot 测试；组合根 e2e 集成测试（feature/dev-dep 门控，含拒绝路径）。等级：L1 / 无等级（无 wire 扇出）。

**Target Platform**: Linux server（对外业务 listener 认证路径）。

**Project Type**: Rust 扁平 workspace（库 crate + adapters + bins）。

**Performance Goals**: 验签在请求热路径——key 解析在构造期完成、热路径只做签名校验 + 时钟比较；JWKS 缓存避免每请求远程 fetch。无硬指标。

**Constraints**: 每 PR ≤ 2000 行净增删（例外书面理由）；只在冻结接缝内接线，不改 `diport::Pdp` / `authn` bridge / `finalize_auth` 签名；验签空窗安全门（ADR-006 §5）；禁用 crypto crate（ring/rsa/aws-lc/openssl/jsonwebtoken）；新增治理 ≥ Medium。

**Scale/Scope**: 4 PR / 2 wave；触及 `adapters/oidc`、`crates/httpserve`、`bins/{server,rss}`、根 `Cargo.toml`（workspace crypto deps）；不触域 crate、不触 wire contract / generated。

## Constitution Check

*GATE: 本仓无独立宪法文件——CLAUDE.md 为最高协作规范，docs/rules/* + ADR 为细则。逐条核查：*

- **分层依赖（crate 图 + deny.toml + xtask layer-deps）**：✅ oidc(adapter) impl diport port、不被域依赖；httpserve(服务) **不新增 path dep**（不引兄弟服务 authn，守 `layers.rs:122`）；验签桥落 bins(组合根)，可依赖 httpserve+authn+oidc。无新增跨域/反向依赖。
- **跨域只经 contract**：✅ 本 feature 不新增 wire contract；消费冻结的 diport port-own 类型 + httpserve own 标量，无手写共享 wire crate。
- **AI-robust 三档**（每条新约束标级）：
  - 安全同批门：`Box<DynPdp>` 注入构造器必填参（**Hard**，缺失即编译错）+ 测试 stub adapter crate 不入生产依赖图（`deny.toml` adapter wrapper，**Medium**）+ fail-closed 缺省（**Hard**）+ **bins 生产 `impl Pdp` governance 守卫（Medium，PR-C/T004.6 交付，评审 F1 升级，不 defer）**——见 §决策 3.3。
  - 放行接缝：httpserve own `Authenticated` typed extension——私有字段与 profile-specific shape =
    **Hard/类型层**；enforce 默认拒 = **Medium**；profile-specific constructors 及 `CurrentAuthGrant`
    mint 仅精确组合根 wrapper 可调（`rss_authenticated_callsite` DefId dylint，**Medium**）。
  - alg 白名单 + alg-key 一致：adapter 内 `#[non_exhaustive]` enum-match（类型穷尽）+ 表驱动负用例（**Medium**）。
  - JWKS key-source 完整性：远程 JWKS 经 TLS/pinning/签名 JWKS，禁裸 plain-HTTP（评审 F2）；不可得则退静态 key（**Medium**：构造期拒明文 + deny 甄别）。
  - 类型层不变式不回归（VerifiedClaims 闭合 profile shape、verified newtype 仅由验签 funnel seal、from_verified_* 收 newtype）：既有 **Hard**（private tagged storage + `pub(crate) seal` + 入参类型），本 feature 加回归断言守。
  - **无 Soft 新增**（信任根锁经评审 F1 由 Soft 升 Medium）。
- **错误/PII**：✅ `PdpError` 纯 taxonomy（不携 source）；tracing 只记 `principal.kind` + decision + PdpError 变体名，无 subject/token；`VerifiedClaims`/`RawCredential` Debug 已脱敏（DIPORT-DTO-PII-DEBUG-REDACT-01）。
- **Rust 规范**：✅ Clock 构造器位置参（非 Option/Config，禁系统时钟）；`Box<DynPdp>` 必填非 Option；常数时间 MAC 比较（禁 `==`）；认知复杂度 ≤15（verify 按 alg-dispatch 拆子函数）；覆盖率 ≥80%。
- **供应链（deny licenses/bans/advisories）**：✅ 仅 RustCrypto（hmac/sha2/p256，license-clean）；禁 ring/rsa/aws-lc/openssl/jsonwebtoken；JWKS HTTP/TLS 栈在 PR-A2 经 deny 甄别后引入。
- **对标 ref**：✅ research.md 标 RustCrypto JWT / rust-spiffe JWT-SVID + ES256（p256 ecdsa）对标；`framework-comparison.md` 新增 authn/jwt 行（PR-A1 落地时实拉源码校准 `ref:`）。
- **API 版本**：✅ 不改 wire；库 API 面 `finalize_auth` 保持冻结、`diport::Pdp` 不改（cargo public-api 守）。

**结论**：无违反，无需 Complexity Tracking 豁免。

## 架构裁定（plan 决策）

### 决策 1：auth-bridge 分层 = Option B + C（A 否决）

**A 否决（硬约束）**：`xtask/src/layers.rs:122` `Service => matches!(to, Basis|Engine|DiPort)` —— httpserve 依赖兄弟服务 authn 被 `cargo xtask layer-deps` + deny.toml 编译期拒。无商量余地。

- **B（httpserve own 放行接缝）**：httpserve 在基础级定义 `Authenticated` 证据 extension（脱敏标量 `scheme: RequiredScheme` + `principal_kind`，**零 authn 依赖**）；enforce 层 `reject_if_needed` 改为读 `Authenticated` → 携证据、非 `Anonymous`、`scheme()` exact-match `Require(required)` 则放行，否则 fail-closed 401（替代当前恒 401；杜绝 scheme 混淆）。承载「放行机制」。
- **C（验签桥落唯一组合根）**：「extract 凭据 → profile-specific authn verify → RSS durable
  grant validation → profile-specific `Authenticated` 注入 + 埋点」落 `assemblies/runtime`。

### 决策 2：finalize_auth 签名不破（验签桥走组合根外层 layer）

`finalize_auth(router, plan)` 冻结签名**保留**——非为兼容，而是 B+C 分层下 httpserve 根本不该依赖 authn（穿 verifier 进去违反分层）。组合根在 `finalize_auth` 产出 router 的**外层** `.layer(verify_bridge_middleware(pdp))`。层序（外→内）：request_id → trace → panic_recovery → **verify-bridge（注入 Authenticated）** → Extension(plan) → 路由 → EnforceService（MethodRouter 层读 Authenticated、`scheme()` exact-match `Require(required)` 放行）。外层先执行，extension 注入早于 enforce 读取，顺序天然满足。httpserve Cargo.toml **不新增任何 path dep**。

### 决策 3：安全同批门坐实（ADR-006 §5，三道结构闸）

1. **「启用生产认证」单点 = PR-C**：仅 PR-C 注入 `Box<DynPdp>` + 挂 verify-bridge；PR-A1/A2/B 单独 merge 都不放行任何端点（A1 无人调、B 无人注入 Authenticated → enforce 仍 fail-closed）。
2. **PR-C blocked-by 真 verifier（PR-A1）写入 DAG**：PR-C 须依赖 `oidc` crate 构造 `OidcProvider`；A1 未 merge 时 bins 无 license-clean 真验签 impl 可注入。⚠ **更正（不可误信编译保证）**：`Box<DynPdp>` 是 trait object，类型系统**不**强制只接受 `OidcProvider`（任意 `impl Pdp` 均可包装）。真实机器防线是：(a) `deny.toml` `oidc` wrapper 限定仅 server/rss/xtask/journeys 可依赖 oidc crate（**Medium**）；(b) 测试 stub Pdp 仅在 authn `#[cfg(test)]` / diport `tests/ui` / PR-C `[dev-dependencies]`，不入生产依赖图。
3. **信任根 Medium 守卫（PR-C 内交付，评审 F1 升级）**：`rss_diport_impl_allowlist` 允许 `bins/` 路径 impl diport port（组合根白名单），故 bins **生产代码内联** 一个 always-allow `impl Pdp` 不被 deny.toml / dylint 拦。原计划把它 defer 成 follow-up（Soft）——评审 F1 否决（AI-robust：新增治理 ≥ Medium、信任根锁不可 Soft）。**修订**：PR-C（T004.6）MUST 交付 governance 守卫（`cargo xtask`/dylint）扫 bins 生产 `src/` 的 `impl diport::Pdp`，仅放行 `#[cfg(test)]`/dev-dep，生产内联 always-allow impl → fail（synthetic red case + anti-vacuity）。原 follow-up issue #1199 已折入 #1198、关闭。
4. **fail-closed 缺省**：未挂 verify-bridge 的 listener 仍 401（PR-B 保持默认拒），即使 PR-C 漏接某 listener 也不会「有 plan + always-allow」。

### 决策 4：crypto 选型 → RustCrypto（ES256+HS256），JWKS 远程延后于认证链打通

ES256（`p256` ecdsa，非对称，生产 JWT 默认）+ HS256（`hmac`+`sha2`，内部 service_token，已在 Cargo.lock）。排除 `jsonwebtoken`（拉 ring）、RS256（拉 rsa，RUSTSEC Marvin + deny 守卫）。静态 key set 首批（PR-A1）打通认证链；JWKS 远程 fetch + 缓存 + 轮转（PR-A2）经 `KeySource` 抽象追加，**不改构造器签名**（保 A2∥C 解耦）。详见 research.md。

## Project Structure

### Documentation (this feature)

```text
specs/003-pdp-verify-wiring/
├── plan.md              # 本文件
├── research.md          # Phase 0：crypto 选型 + JWKS HTTP/TLS license 决断 + 对标 ref
├── data-model.md        # Phase 1：SupportedAlg / KeyEntry/KeySource / claims DTO / PdpError 映射 / Authenticated
├── quickstart.md        # Phase 1：FixedClock 验签 round-trip + e2e 认证闭环验证指南
├── contracts/           # Phase 1：无新增 wire contract 说明（消费冻结 diport::Pdp port）
├── checklists/          # spec 质量 checklist
└── tasks.md             # Phase 2：4 PR / 2 wave
```

### Source Code (repository root)

```text
adapters/oidc/
├── Cargo.toml                  # PR-A1：+ p256/hmac/sha2/base64/serde/serde_json；PR-A2：+ HTTP/TLS 栈
├── src/lib.rs                  # PR-A1：OidcProvider 结构 + impl Pdp + impl ManagedResource（去 todo!()）
├── src/verify.rs               # PR-A1：三段解析 + alg-dispatch 验签 + 时钟/iss/aud + VerifiedClaims 映射
├── src/claims.rs               # PR-A1：claims DTO（exp/nbf/iss/aud/sub/tenant/kind）+ PdpError 映射
└── src/jwks.rs                 # PR-A2：JwksKeySource（远程 fetch + 缓存 + 轮转）+ ManagedResource 真实关闭
crates/httpserve/
├── src/auth.rs                 # PR-B：Authenticated(scheme+principal_kind) 证据类型 + reject_if_needed 改读 Authenticated、scheme exact-match 放行
├── src/lib.rs                  # PR-B：导出 Authenticated；finalize_auth 文档（层序，签名不变）
└── tests/runtime.rs            # PR-B：注入 Authenticated→200 / 缺失→401 / opt-out 不回归
assemblies/runtime/
├── src/auth_bridge.rs          # profile verify→RSS durable fence→profile evidence inject + closed telemetry
├── src/phase/finalize.rs       # 构造 typed providers 与必填 grant validation service
└── tests/auth_e2e.rs           # 有效→200；凭据/grant 无效→401；provider outage→503；handler 反空
Cargo.toml（根）                # PR-A1：p256/hmac/sha2 入 [workspace.dependencies]；PR-A2：HTTP/TLS 栈
docs/references/framework-comparison.md  # PR-A1：新增 authn/jwt 验签对标行
```

**Structure Decision（修订）**：verifier 位于 `adapters/oidc`、放行接缝位于 `httpserve`、
验签桥只位于唯一组合根 `assemblies/runtime`；durable grant port 位于 identity，PostgreSQL adapter 以
一次 tenant-scoped query 实现。

**auth_bridge 共享决策（修订）**：验签桥已收口于唯一 `assemblies/runtime/src/auth_bridge.rs`。
降维 `Principal → Authenticated` 仍是验签桥内的内联 mapping，但 constructor 已按 profile 闭合；RSS mapping
额外消费 durable validator 返回的 move-only proof。

## 4-PR 分层（2 wave）

| PR | crate/路径 | 等级 | blocked-by | ~行 | 并行 |
|----|-----------|------|-----------|-----|------|
| **A1** oidc impl Pdp（ES256+HS256+静态 KeySource） | adapters/oidc/{lib,verify,claims}.rs · Cargo.toml · 根 Cargo.toml · framework-comparison.md | 无（adapter 内部） | — | 1100–1500 | **[P]** ∥ B |
| **B** httpserve Authenticated 接缝 + enforce 放行 | crates/httpserve/{auth,lib}.rs（无新 dep）· tests/runtime.rs | L1 | — | 300–500 | **[P]** ∥ A1 |
| **A2** oidc JWKS 远程 fetch + 缓存 + 轮转 + ManagedResource 真实关闭 | adapters/oidc/jwks.rs + lib.rs · Cargo.toml（HTTP/TLS）· 根 Cargo.toml | 无 | A1 | 600–1000 | **[P]** ∥ C |
| **C** 组合根注入 + verify-bridge + 埋点 + e2e（启用生产认证·安全同批） | bins/{server,rss}/{main,auth_bridge}.rs · Cargo.toml · tests/auth_e2e.rs | L1 | A1 + B | 700–1100 | **[P]** ∥ A2 |

**Wave 边界**：W1 = {A1, B}（文件零交叉 + 单独 merge 均不放行端点 → 真并行、零验签空窗）；W2 = {A2, C}（均 blocked-by W1；`adapters/oidc` vs `bins` 零交叉）。

**Wave-2 并行解耦关键**：PR-A1 构造器以 `KeySource`（enum/trait obj）入参；PR-A2 加 `JwksKeySource` impl **不改构造器签名**；PR-C 传 `StaticKeySource` → A2/C 构造器签名稳定、无 rebase 冲突。

**安全同批门在 DAG 中坐实**：C（唯一启用生产认证）blocked-by A1（真 verifier，W1 已 merged）→ C 落地即「真 verifier + 认证挂载」同批，零验签空窗；A2 仅追加 JWKS 能力，不影响已打通的认证链。

## Complexity Tracking

无 Constitution 违反，免填。
