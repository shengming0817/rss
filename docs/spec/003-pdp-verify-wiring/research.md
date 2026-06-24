# Research: PDP 验签接线（#1109 剩余 W）

**Phase 0** · 技术决策 + 供应链甄别 + 对标。所有论断对 `/Users/shengming/Documents/code/rss` 真实源码核实。

## R1. crypto 选型（首批 ES256 + HS256）

### 约束（供应链，硬）

| 约束 | 出处 | 结论 |
|------|------|------|
| 规避 `ring` / `aws-lc-sys` / `aws-lc-rs` / `openssl` | `Cargo.toml:122-134`（lapin/s3/sqlx/redis 全 `default-features=false` 关 TLS，理由 = license 不在 deny allow-list） | jsonwebtoken（拉 ring）**禁** |
| 禁 `rsa` crate 入依赖图 | `deny.toml` `[bans] deny=[{crate="rsa"}]`（RUSTSEC-2023-0071 Marvin 时序攻击，无修复版本）+ `openssl`/`openssl-sys` | RS256（RSA）**禁**，不暴露 alg=RS256 路径 |
| license allow-list | `deny.toml [licenses] allow`（MIT/Apache-2.0/BSD/ISC/Unicode-3.0/Zlib/CDLA/BSL） | RustCrypto（MIT OR Apache-2.0）✅ |

### 选型

| alg | crate | 角色 | 首批 |
|-----|-------|------|------|
| **ES256**（ECDSA P-256 / SHA-256） | `p256`（feature `ecdsa`），复用已在树的 `signature` 2.2.0 | zero-trust 生产默认（非对称，pub key 验签、私钥不出签发方） | ✅ |
| **HS256**（HMAC-SHA256） | `hmac` + `sha2`（**已在 Cargo.lock**，经 sqlx），或复用 `primitives::crypto::MacVerifier` | 内部 service_token / dev（对称共享密钥） | ✅ |
| EdDSA（Ed25519） | `ed25519-dalek` | 非对称备选 | ❌ 延后（接缝 `#[non_exhaustive]` 预留） |
| RS256（RSA） | `rsa` | — | ❌ **禁**（deny 守卫） |

**实测证据**：`Cargo.lock` 已含 `hmac` / `sha2` / `signature` 2.2.0 / `digest` / `crypto-common`（经 sqlx 传递）且 `cargo deny` 当前绿 —— RustCrypto 系 license-clean 是运行期证据非推断。`p256` 同属 RustCrypto，`MIT OR Apache-2.0`，引入后 deny 仍绿。`base64` 0.22 / `serde_json` / `serde` / `subtle` 已在 `[workspace.dependencies]`。

**理由**：
- 生产默认必须**非对称** ES256 —— pub key 可分发给 verifier、私钥不出签发方，对齐「验签 = 信任原点」（`diport/src/pdp.rs:1-6`）。
- HS256 仅内部 service_token / dev（对称密钥须双方共享，不适外部 IdP），对应 `RawCredential::service_token` 路径。
- EdDSA 延后：首批 ES256 已覆盖非对称生产需求；`ed25519-dalek` 是额外供应链面，pre-GA 控面；OIDC IdP 主流 RS256（禁）/ES256，ES256 是可用非对称首选。

## R2. 验签流程关键安全闸

- **alg 白名单**：header alg 必须 ∈ {ES256, HS256}；不在白名单（`alg=none` / RS256 / 未知）→ `InvalidSignature`（`jws::parse` 拒，含 alg=none 经典攻击）；白名单内但与 scheme 路径锁定算法不符（ES256↔HS256 混淆）→ `Untrusted`。
- **alg-key 一致（防 confusion）**：key set 条目自带 `(kid, alg, material)`，token header alg 必须**等于** key 条目 alg —— 防 ES256 公钥被当 HS256 secret（EC 变体 confusion）。
- **service_token 路径隔离**：service_token 走 HS256-only key set，禁用 ES256 key set，与外部 IdP JWT 验签器隔离。
- **时钟注入**：exp/nbf 用注入的 `diport::Clock`（禁系统时钟，clippy `disallowed_methods`），FixedClock 测边界；leeway 可配置。
- **常数时间 MAC 比较**：复用 `primitives::crypto`（subtle），禁 `==`。
- **fail-closed 映射**（→ `PdpError` 三变体）：段数≠3/base64坏/payload JSON坏/sig decode坏/MAC·ECDSA 不通过/alg=none/未知alg/空subject → `InvalidSignature`；exp 过期/nbf 未到 → `Expired`；iss不受信/aud不符/alg-key不符（alg-scheme 路径混淆）/kid无匹配（US4 JWKS） → `Untrusted`。
- **PdpError 纯 taxonomy**：`pdp.rs` 已冻 `PdpError` 不携 source —— adapter 内部 crypto 错误只归类不透传（杜绝凭据泄漏），**无需 RedactedSource**。

## R3. JWKS HTTP/TLS 栈 license 决断（US4 / PR-A2 open risk）

**问题**：JWKS 远程 fetch 需 http client；`reqwest` 默认 feature 拉 `ring`/`aws-lc-rs`（`Cargo.toml:128` 已注此雷区，均 license-banned）；rustls 也需 crypto provider（`ring` 或 `aws-lc-rs`，均禁）。

**安全前置（不可退让）**：JWKS 是验签公钥来源——**裸 plain-HTTP JWKS 把 key-source 完整性从机器可验证降为部署约定**，内网 MITM 可替换 JWKS 公钥伪造 token。故 **plain-HTTP JWKS 不是可上线选项**（评审 finding F2）。远程 JWKS 必须有可机器验证的传输完整性：TLS 证书校验 / mTLS / 签名 JWKS（JWS-protected）/ key pinning / 本地受信 sidecar。

**候选**（PR-A2 落地前裁定，登记备查）：

| 候选 | 利 | 弊 / 风险 | 倾向 |
|------|----|----|------|
| **rustls + license-clean provider**（如 `rustls-rustcrypto`） | 纯 RustCrypto TLS，license-clean，传输完整性机器可验 | provider 成熟度/审计风险，pre-GA 采用需 deny 实测 + 安全评估 | 首选（满足安全前置） |
| **本地受信 sidecar + key pinning / 签名 JWKS** | 不引 TLS crypto 依赖面，传输完整性经 pinning/签名机器可验 | 需部署 sidecar 或签名 JWKS 发布流程 | 次选（满足安全前置） |
| ~~受控网络 plain-HTTP JWKS~~ | ~~零 TLS 依赖面~~ | **否决**：传输完整性退化为部署约定，MITM 可伪造公钥 | ✗ 不可上线 |
| **退静态配置 key（不上线远程 JWKS）** | 完整性经构造期配置注入，零传输面 | 无运行期 key 轮转（需重部署） | **license-clean TLS 不可得时的兜底** |

**判据**：PR-A2 实施前 `cargo deny check` 实测候选依赖树 + 安全评估。**若无 license-clean 成熟 TLS provider 且无 sidecar/pinning 方案，则首批仅保留静态配置 key（PR-A1），不上线远程 JWKS**——绝不以裸 plain-HTTP 兜底。**首批静态 key（PR-A1）不依赖此决断**，认证链打通不被阻塞。最终选型 + 部署约束回写本节 + quickstart（tasks T003.2b）。

## R4. key 管理范式

- **静态 key set（PR-A1）**：`KeySource` 抽象 + `StaticKeySource`（构造期解析 ES256 SEC1/PEM/JWK(x,y) + HS256 secret → `MacKey`，解析失败构造期 `Result`，热路径只 verify）。按 kid 索引。
- **JWKS（PR-A2）**：`JwksKeySource` impl 同 `KeySource` 抽象，远程 fetch + 缓存 + 轮转 + `ManagedResource` 真实关闭（刷新句柄）；**不改 `OidcProvider` 构造器签名**（保 A2∥C 解耦）。
- `OidcProvider` 字段：`key_set` / `service_key_set`（HS256-only）/ `clock: Box<dyn Clock>`（必填位置参）/ `trusted_issuers` / `expected_audience` / `leeway`。sealed-marker；保留 `impl ManagedResource`（首批静态 key 无资源 → `name()="oidc"` / `shutdown()=Ok`，去 todo!()）。

## R5. 对标（ref）

`docs/references/framework-comparison.md` 当前**无 authn/jwt 专行**（已核实）；最近相关 = 证书/PKI L4 `ref: maxlambrecht/rust-spiffe`、授权 PDP `ref: eclipse-biscuit/biscuit-rust`、内置 typed authz `ref: cedar-policy/cedar`（ADR-006 已引）。

**PR-A1 落地时须在 framework-comparison.md 新增 authn/jwt 验签行**（该文件是对标单一事实源，新增模块只改本文件），推荐：

- primary：`ref: RustCrypto/JWT jwt/src/lib.rs@master` —— 纯 RustCrypto JWT 库（HS/ES 验签范式，无 ring），对应 OidcProvider verify 流程。
- secondary：`ref: maxlambrecht/rust-spiffe spiffe/src/svid/jwt/mod.rs@main` —— JWT-SVID exp/aud/iss 校验流程对标。
- ES256 底层：`ref: RustCrypto/elliptic-curves p256/src/ecdsa.rs@master`（`VerifyingKey::verify`）。
- 排除 ring/rsa 证据：`Cargo.toml:122-134` + `deny.toml`（rsa/openssl ban）。

> 注：以上 `ref:` 行号需 PR-A1 developer 用 WebFetch（`raw.githubusercontent.com`）实拉源码校准（上游布局会变）。

## R6. 已有接缝（消费，不改）

- `crates/diport/src/pdp.rs`：`Pdp` trait（`async fn verify(&self, raw: &RawCredential) -> Result<VerifiedClaims, PdpError>`）+ `RawCredential::{jwt, service_token}` + `VerifiedClaims::new(subject, tenant, kind)` + `PdpError` + `DynPdp`（dynosaur）。
- `crates/authn/src/lib.rs:285-322`：`verify_jwt(raw, &DynPdp)` / `verify_service_token` —— 内部调 `pdp.verify` → `Jwt::parse` 结构闸 → `VerifiedJwt::seal` → `Principal::from_verified_jwt`。本 feature 调它，不改它。
- `lints/rss_diport_impl_allowlist`：adapter（`adapters/oidc`）impl diport port **已在 allowlist**，无需改 lint。
- `deny.toml`：`oidc` package wrapper 已登记（server/rss/xtask/journeys）；新增 crypto deps 后须 `cargo deny check` 复绿。
