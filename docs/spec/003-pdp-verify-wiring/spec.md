# Feature Specification: PDP 验签接线（#1109 剩余 W —— verifier adapter + httpserve 认证 + 组合根）

**Feature Branch**: `003-pdp-verify-wiring`

**Created**: 2026-06-24

**Status**: Draft

**Input**: User description: "/ship 1109 —— 把 `diport::Pdp` 验签接缝从骨架接到生产可达认证路径：真实 crypto verifier adapter（oidc impl Pdp）+ httpserve 认证中间件接线 + 可观测埋点 + 组合根注入 + e2e。拆成 ≤2000 行可执行 PR，挂 Azure Boards #1109，按 ship 流程提交 spec。"

**Tracking**: Azure Boards #1109（`[authn] VerifiedJwt newtype 类型层强制验签先于派生 Principal`，cx-3 / pri-p1 / area-auth）· Epic #991（GoCell→Rust 迁移 · W 宽扇出阶段）· ADR-006（`docs/architecture/202606232318-006-pdp-internal-authplan-vs-external-opa.md`）

> **Supersession（#1828）**：本 feature 落地时的 CPU-only verifier / Send-only dyn-port 前提已失效。
> 生产 bridge 现在直接 await `Pdp: Send + Sync`；终止预算由必填、非零的全请求
> `ServerRequestBudget` 在唯一 bindable HTTP funnel 统一拥有，不由 bridge 局部 timeout；以 #1828 与
> ADR-003 / ADR-006 async-serving addendum 为准。

> **Supersession（#1835 / ADR-021）**：RSS Access 现固定为 grant-bound User，必须携完整
> `sid/jti/auth_time/authn_epoch`；`VerifiedClaims` 是 RSS User / Federated Access / Service Token 三种
> 闭合 shape，不再存在通用 claims constructor。下文早期可选字段描述仅作历史规划背景。

---

## 背景与读者

#1109 的**类型层部分已落地并合并到 develop**，不在本 feature 范围：

- **PR 208**（`f93ed35`）：`VerifiedJwt` / `VerifiedServiceToken` newtype（私有字段 + `pub(crate) seal`）+ `Principal::from_verified_jwt(&VerifiedJwt)` 入参收紧（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）—— ADR-006 §8 验收门槛 ①② 已满足。
- **PR 211**（`3f7ab6b`，#1158）：历史上交付了通用 `verify_jwt` 接缝；ADR-017 / ADR-021
  已将其替换为 `verify_rss_access` / `verify_federated_access` / `verify_service_token`。

#1109 **仍 open** 的是 ADR-006 §8 列出的 **W 接线**：真实 crypto verifier adapter（`adapters/oidc` 当前是 `todo!()` stub，只 impl `ManagedResource`，**未 impl `Pdp`**）、httpserve 认证中间件接线（`crates/httpserve/src/auth.rs` `require_response` 当前恒 fail-closed 401，无凭据验证能力）、可观测埋点、组合根注入、e2e 集成测试（验收门槛 ③）。

本 feature 是规划产物：把这条「凭据 → 验签 → 派生 Principal → 放行」的生产认证链从接缝接通，并**安全地打开验签风险窗口**。

「用户」= 两类框架消费者：

- **平台运维 / 部署者**：需要对外业务端点真正校验 JWT/service-token（签名 / exp / iss / aud），无效凭据 fail-closed 拒，有效凭据放行并派生 Principal；需要 JWKS 轮转、认证决策可观测（allow/deny + 失败分类，无 PII）。
- **域 crate 作者**：消费 `AuthRequirement`，不感知验签是内置还是外置；信任边界（验签先于派生 Principal）由类型层 + 组合根注入保证，无法旁路。

**核心安全立场（ADR-006 §5 威胁矩阵 = 最高约束）**：验签空窗期**不得**把 httpserve 认证路径接到生产可达端点（等价零验签放行）；httpserve 认证挂载与真实 verifier **必须同批上线**。

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 真实 crypto verifier（oidc impl Pdp，ES256+HS256）(Priority: P1)

部署者注入 `OidcProvider` 作为 `diport::Pdp`；它对入站凭据做真实验签——三段解析 → alg 白名单选验签器 → 签名校验 → exp/nbf 时钟校验（注入 Clock）→ iss/aud 校验 → 映射 `VerifiedClaims`。任何失败 fail-closed 到 `PdpError`（InvalidSignature / Expired / Untrusted）三变体，不泄凭据。

**Why this priority**: 这是「验签 = 信任原点」的承载物。没有它，`verify_jwt` 注入的是 stub（零验签），整条认证链不可信。是 ADR-006 §8 ③ e2e 的前置、安全同批门的「真 verifier」一侧。

**Independent Test**: 表驱动单测（rstest）+ 注入 FixedClock，覆盖合法 ES256/HS256 token → Ok(VerifiedClaims)；坏签名/坏 MAC/段数≠3/alg=none/RS256/未知 → InvalidSignature；exp 过期/nbf 未到 → Expired；kid 无匹配/iss-aud 不符/alg-key 类型混淆 → Untrusted；known-answer 测试向量（RFC 7515）证明验签正确而非自洽（anti-vacuity）。adapter 不被域依赖（layer-deps）；`cargo deny` 绿（无 ring/rsa）。

**Acceptance Scenarios**:

1. **Given** 一个签名正确、未过期、profile policy 与 iss/aud 匹配的 ES256 access token，**When** typed authn funnel 将其交给对应 `OidcProvider<P>`，**Then** 返回与 profile shape 一致的可信 principal；RSS 必须是 User 且带完整 grant quartet，Federated 保持自身闭值主体语义。
2. **Given** payload 被篡改（签名不匹配），**When** verify，**Then** `Err(PdpError::InvalidSignature)`，错误不携带 token / key 字节。
3. **Given** `exp` 早于注入 Clock 的 now（超 leeway），**When** verify，**Then** `Err(PdpError::Expired)`。
4. **Given** header `alg` 为 `RS256` / `none` / 未知值，**When** verify，**Then** `Err(PdpError::InvalidSignature)`（不在白名单 {ES256, HS256}，`jws::parse` 拒），绝不接受不在白名单的 alg。
5. **Given** token header alg=HS256 但走 JWT scheme 路径（路径锁定 ES256），**When** verify，**Then** `Err(PdpError::Untrusted)`（token alg 与 scheme 路径锁定算法不符，alg-scheme 混淆；US1 静态路径按 alg 判定，kid 选 key 留 US4）。

---

### User Story 2 - httpserve 认证放行接缝（Authenticated 证据 + fail-closed 默认）(Priority: P1)

httpserve 在自身可依赖的层（基础级，零 authn 依赖）定义 `Authenticated` 证据 extension（脱敏标量：已验证的 `scheme: RequiredScheme` + `principal_kind`）；enforce 层对 `Require(required)` 路由改为：request extension 携 `Authenticated`、非 `Anonymous`、**且 `scheme()` exact-match `required`** → 放行，无证据 / 方案不匹配 → fail-closed 401（替代当前恒 401；杜绝 scheme 混淆，如 Jwt 证据撞 `Require(Mtls)`）。httpserve **不新增任何 path 依赖**，`finalize_auth` 签名不变。

**Why this priority**: httpserve 是兄弟服务 authn 的不可依赖方（分层 `layers.rs:122`）；放行机制必须由 httpserve own 的类型承载，否则没有任何 PR 能让需认证端点放行。这是安全同批门的「放行接缝」一侧——但它单独 merge **不**放行任何端点（无人注入 `Authenticated`）。

**Independent Test**: `axum::http` + `tower::ServiceExt::oneshot` 覆盖：注入 `scheme` 匹配的 `Authenticated` → Require 路由 200；不注入 / scheme 不匹配（Jwt 证据 vs `Require(Mtls)`）/ `Anonymous` 证据 → 401；既有 opt-out（Public / PasswordResetExempt）路径不变；无 AuthPlan → 403（AUTH-FAILCLOSED-01 不回归）。

**Acceptance Scenarios**:

1. **Given** 一条 `Require(Jwt)` 路由且 request 携 `scheme=Jwt` 的 `Authenticated` extension，**When** enforce 层处理，**Then** 放行到 handler（200）。
2. **Given** 同路由但 request 无 `Authenticated`，**When** enforce 层处理，**Then** fail-closed 401。
3. **Given** generated route evidence 的 auth 为 `Public`，**When** 经 `GeneratedPrimaryEndpoint` 挂载且无 `Authenticated` 请求，**Then** 仍 200。
4. **Given** 一条 `Require(Jwt)` 路由但 request 携 `scheme=Mtls` 的 `Authenticated`（方案不匹配），**When** enforce 层处理，**Then** fail-closed 401（杜绝 scheme 混淆）。

---

### User Story 3 - 生产认证接线 + 验签桥 + e2e（启用生产认证·安全同批）(Priority: P1)

组合根从配置构造 profile-specific `OidcProvider` 与精确 `ProfileBinding`，在
`httpserve::finalize_auth` 产出的 router **外层**挂 verify bridge：提取 Authorization 凭据 → 按绑定 profile
调用 `authn::verify_rss_access` / `verify_federated_access` / `verify_service_token` → 成功后使用对应
`Authenticated::{new_rss_user,new_federated,new_service}` 注入 request → enforce exact-match
`Require(required)` 放行。RSS 分支在铸证据前还必须完成 durable grant/account 校验并消费
`CurrentAuthGrant`；失败或 profile 不匹配 fail-closed。中间件只记录闭值 deny reason，无 PII。

**Why this priority**: 这是**唯一启用生产认证**的环节，也是 ADR-006 §8 ③「httpserve↔authn 验签接线有集成测试覆盖（含拒绝路径）」的验收点。必须 blocked-by 真 verifier（US1）+ 放行接缝（US2），三者同批生效 → 零验签空窗。

**Independent Test**: e2e 集成测试起 router + 真 `OidcProvider`：有效 JWT → 200 + `Authenticated`（`scheme`=Jwt + principal_kind facet）、`scheme()` exact-match 注入放行；无 token / 坏签名 / 过期 / 错 aud → 401/403（拒绝路径全覆盖）；tracing span 断言 `authz.decision` + `principal.kind`、无 subject/token 泄漏；stub Pdp 仅在 `[dev-dependencies]`，不入 `cargo build --release` 依赖图。

**Acceptance Scenarios**:

1. **Given** 部署注入真 `OidcProvider` + verify-bridge 已挂，**When** 客户端带有效 JWT 请求 `Require(Jwt)` 路由，**Then** 200，request extension 携 `httpserve::Authenticated`（含 `scheme`=Jwt + `principal_kind` facet）、`scheme()` exact-match 放行。**注**：本批仅承诺 `Authenticated` 放行 + `principal_kind` facet；handler / 域授权读**完整 `Principal`**（runctx principal facet 绑定）属 W 阶段后续，不在本批验收（否则验收不可兑现，见 FR-009/data-model）。
2. **Given** 同部署，**When** 客户端无 Authorization 头 / 坏签名 / 过期 token，**Then** fail-closed 401（含 requestId），tracing 记 `authz.decision=deny` + 对应 `PdpError` 变体，日志无 token / subject。
3. **Given** 生产 bin 构建，**When** `cargo build --release`，**Then** 依赖图不含任何 dev/test stub Pdp 与禁用 crypto crate（ring/rsa/aws-lc/openssl/jsonwebtoken）。

---

### User Story 4 - JWKS key 与轮转（本地文件源 + 外部 agent 刷新）(Priority: P2)

typed `OidcProvider<P>` 支持从 profile-specific JWKS 文档拉取公钥（按 kid 索引）+ 缓存 + 轮转；JWKS **必须经可机器验证的传输完整性**（TLS/mTLS/签名 JWKS/key pinning / **本地受信文件源**），**禁裸 plain-HTTP-over-network**，license-clean TLS 不可得则不上线 in-app HTTPS（FR-005）。JWKS 源不可读 / kid 缺失时 fail-closed（`Untrusted`），不放行，并经对应的 `rss_access_token_jwks_ready` / `federated_access_token_jwks_ready` 反映 health。带刷新句柄时另 impl `ManagedResource` 真实关闭。

> **实现决断（#1197，见 research.md R3）**：2026-06 无 license-clean 且生产成熟的 rustls TLS provider，且「应用进程内 HTTPS 拉 JWKS」是被零信任生产系统（Envoy/Istio/SPIFFE/cert-manager）系统性规避的少数派。采纳 R3 **次选「本地文件源」**：`JwksKeySource` 从受 OS 文件权限 / k8s Secret RBAC / 挂载隔离保护的**本地路径**读 JWKS 文档（外部 agent / init-container / controller 经各自 TLS 拉取 + 轮转后写入），**in-app 零 HTTP/TLS provider**；传输完整性属 infra 层（机器强制）。in-app HTTPS 直连外部标准 IdP = follow-up（待成熟 provider，复用 seam）。

**Why this priority**: 静态 key（US1）足以打通生产认证；JWKS 是生产 IdP 对接的真实 key 来源，但引入 key 源刷新 / 轮转 / 关闭编排，是独立工作面，排在认证链打通之后。

**Independent Test**: fake profile-specific JWKS 文件源（dev-only）验证：按 kid 取 key → 验签成功；key 轮转（重写文件 + reload）后新 kid token 通过、旧 kid 被移除后旧 token → fail-closed；JWKS 源不可读 / 空 / 畸形 → 构造期 fail-fast 拒，运行期刷新失败保留 last-good + 对应 profile readiness=false；`cargo deny` 绿（**零新增 HTTP/TLS 栈**——in-app 不引任何 crypto/TLS provider）。

**Acceptance Scenarios**:

1. **Given** JWKS 端点暴露 kid=k1 的 ES256 公钥，**When** verify 带 kid=k1 的 token，**Then** Ok。
2. **Given** key 轮转（k1 移除、k2 加入），**When** verify 旧 kid=k1 token，**Then** `Untrusted`；带 kid=k2 token → Ok。
3. **Given** JWKS 端点不可达，**When** verify，**Then** `Untrusted`（fail-closed），绝不放行。

---

### Edge Cases

- **验签空窗（最高风险）**：#1109 W 未落地期，httpserve 认证路径**不得**接到生产可达端点；本 feature 用「仅 PR-C 启用生产认证 + PR-C blocked-by 真 verifier + stub 无法进生产 bin + fail-closed 缺省」四闸坐实（见 plan.md §安全同批门）。
- **alg=none / alg confusion**：alg=none 直接 InvalidSignature；alg 必须 ∈ {ES256, HS256} 白名单且与 key 类型一致（防 EC 公钥被当 HMAC secret）。
- **service-token 路径隔离**：service_token 走 HS256-only key set（禁 ES256），与外部 IdP JWT 验签器隔离，避免 token 混淆。
- **空 subject**：adapter 的 profile-specific checked factory 早拒 InvalidSignature；authn 对
  `VerifiedClaimsView` 穷尽派生 `Principal` 时再 fail-closed（双闸）。
- **PdpError 泄漏**：`PdpError` 为纯 taxonomy（不携 source），adapter 内部 crypto 错误只归类不透传；tracing 只记变体名 + `principal.kind`，绝不 `{:?}` 整体 Principal/VerifiedClaims/token。
- **verify-bridge 层序错位**：bridge 必须挂在 `finalize_auth` 产出 router 的**外层**（外层先注入 extension，enforce 在 MethodRouter 内层才读到）；e2e「有效 JWT→200」覆盖此回归。
- **JWKS 不可达 / 缓存过期**：fail-closed Untrusted，不回落「跳过验签」；刷新失败经对应 profile readiness probe 反映 health（probe 名 + 注册点 + 失败测试见 FR-005 / tasks T003）。
- **JWKS 传输完整性**：远程 JWKS 经裸 plain-HTTP 拉取 = 内网 MITM 可替换公钥伪造 token → **禁明文 JWKS**；要求 TLS/mTLS/签名 JWKS/key pinning，做不到则退静态 key（FR-005）。

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `OidcProvider` MUST `impl diport::Pdp`，`verify` 对入站 `RawCredential` 做真实验签（签名 + exp/nbf + iss/aud），成功返回 `VerifiedClaims`，任何失败 MUST fail-closed 映射到 `PdpError::{InvalidSignature, Expired, Untrusted}`，MUST NOT `todo!()` panic，MUST NOT 在错误中携带 token / key 字节。
- **FR-002**: 验签 alg MUST 限定白名单 {ES256, HS256}；`alg=none` / RS256 / 未知 alg MUST fail-closed 拒绝；token header alg MUST 与所选 key 类型一致（防 alg-key 混淆）。access JWKS 文档中每把 key MUST 显式声明 `alg=ES256`（缺省 / 非 ES256 MUST fail-closed 拒整份文档；不得按 `kty`/`crv` 推断）。依赖 MUST 仅用 RustCrypto 纯 Rust（`p256`/`hmac`/`sha2`），MUST NOT 引入 `ring` / `rsa` / `aws-lc-*` / `openssl` / `jsonwebtoken`。
- **FR-003**: 时钟 MUST 经构造器位置参注入（`diport::Clock`），MUST NOT 取系统时钟；exp/nbf 校验带可配置 leeway；常数时间比较 MAC（复用 `primitives::crypto`，禁 `==`）。
- **FR-004**: key 源 MUST 经 `KeySource` 抽象（构造期解析 + 校验，解析失败在构造期 `Result`，不入验签热路径）；首批静态配置 key set（按 kid 索引）；service_token MUST 走独立 HS256-only key set（路径隔离）。
- **FR-005**: `OidcProvider<P>` MUST 支持 profile-specific JWKS fetch + 缓存 + 轮转。**key-source 完整性（安全）**：JWKS MUST 经可机器验证的传输完整性（TLS 证书校验 / mTLS / 签名 JWKS / key pinning / **本地受信文件源**）——**裸 plain-HTTP-over-network JWKS MUST NOT 作为可上线选项**（内网 MITM 可替换公钥伪造 token）；若 license-clean TLS 栈暂不可用，则 MUST NOT 上线 in-app HTTPS。in-app HTTP/TLS 栈（若引入）MUST 经 license 甄别（规避 ring/aws-lc/openssl）。JWKS 源不可读 / kid 缺失 MUST fail-closed（`Untrusted`），MUST NOT 跳过验签。**readiness（运维）**：JWKS 刷新失败 MUST 经 `rss_access_token_jwks_ready` / `federated_access_token_jwks_ready` 反映 health，verbose readyz MUST 裁剪敏感字段（无 endpoint 凭据 / key 材料）；带刷新句柄 MUST 另 impl `ManagedResource` 真实关闭。
  - **实现（#1197，#1831 收紧，见 research.md R3 决断）**：采纳「本地文件源」分支——每个 access profile 的 `JwksKeySource` 从独占、受文件权限 / Secret RBAC 保护的本地路径读 JWKS 文档（外部 agent 经各自 TLS 拉取 + 轮转后写入），**in-app 零 HTTP/TLS provider**；后台 poll 重载 + `RwLock<Arc<KeySet>>` 快照原子换出 + kid 索引 + fail-closed（源不可读/畸形/空 → 构造期拒 / 刷新期保留 last-good + 对应 readiness=false，绝不 swap 空集）。readiness probe 注册经组合根 = T004。
- **FR-006**: httpserve MUST 定义 own `Authenticated` 证据 extension（**零 authn 依赖**，私有字段 +
  profile-specific constructor funnel）；RSS constructor MUST 额外消费 opaque `CurrentAuthGrant`。enforce 层
  `Require(required)` 路由 MUST 仅在请求携精确 scheme 的非 Anonymous `Authenticated` 时放行，
  RSS 证据还 MUST 携 current marker；缺证据 / 方案不匹配 MUST fail-closed 401。
- **FR-007**: httpserve crate MUST NOT 新增任何 path 依赖（不引 authn/oidc/crypto）；`finalize_auth(router, plan)` 签名 MUST 保持冻结（验签桥由组合根外层 `.layer()` 装配，非穿入 finalize_auth）。
- **FR-008**: 唯一组合根 `assemblies/runtime` MUST 从配置构造 profile-specific
  `OidcProvider` 与 typed binding；RSS binding MUST 同时携必填 `AuthGrantValidationService`。MUST 在
  `finalize_auth` 产出 router 的**外层**挂 verify bridge；**仅组合根**启用生产认证。
- **FR-009**: verify-bridge MUST 提取凭据 → 调用 profile-specific authn verify funnel → 使用对应
  `Authenticated` constructor 注入；RSS MUST 在 crypto 成功后、handler 前完成 durable current-grant
  validation，无效返回 401，provider 故障返回 503 且不回退。tracing span MUST 只使用闭值、无 PII 标签。
- **FR-010**: 安全同批门 MUST 由结构闸坐实：(a) 仅启用生产认证的 PR blocked-by 真 verifier PR（DAG）；(b) **测试 stub adapter crate** MUST NOT 进生产 bin 依赖图（`deny.toml` adapter wrapper + dev-dependency 隔离，Medium）；(c) `Arc<P>` 注入为构造器必填参，且 `P: Pdp + Send + Sync + 'static`（缺失或不可共享 provider 即编译错，Hard）；(d) fail-closed 为缺省态（Hard）；(e) **生产 Pdp 信任根守卫（Medium，本 feature 内 PR-C 交付，不 defer）**：生产 `impl Pdp` 仅允许 provider adapter，测试替身仅允许测试构建；`rss_pdp_impl_adapter_only` dylint 与 `pdpallow` 守卫 MUST 拒绝其他生产内联 always-allow impl（synthetic red case + anti-vacuity）——**不接受 Soft、不 defer**（AI-robust：新增治理 ≥ Medium）。
- **FR-011**: 系统 MUST 有 e2e 集成测试覆盖 httpserve↔authn 验签接线（ADR-006 §8 ③）：有效凭据 → 200 + `Authenticated`（`scheme` + principal_kind facet）、scheme exact-match 注入放行；无/坏/过期/错 aud 凭据 / 方案不匹配 → 401/403（拒绝路径全覆盖）。本批不承诺 handler 读完整 `Principal`（属 W）。
- **FR-012**: 既有类型层不变式 MUST 不回归：`VerifiedClaims` 仅 `diport::pdp` 定义并保持闭合 profile shape、无通用 constructor；authn 仅在 Pdp 成功后 seal verified newtype（ADR-006 ①）；`Principal::from_verified_*` 仅收 newtype（②）；dynosaur 宏白名单无新增越界（④，本 feature 不新增 port，天然满足）。
- **FR-013**: 每个 PR MUST ≤ 2000 行净增删（特殊情况例外须在 PR 说明理由）；MUST 只在 G0 冻结接缝（`diport::Pdp` / `authn` bridge / `finalize_auth`）内兑现 body，不改公共签名（finalize_auth 保留、Pdp trait 保留）；feature MUST 拆为 4 PR / 2 wave，形成 blocked-by DAG + `[P]` 并行标记，全部挂 Azure Boards #1109。
- **FR-014**: 新增治理机制 MUST ≥ Medium（严禁 Soft）：安全同批门 = 构造器必填参（Hard）+ deny.toml wrapper（Medium）+ fail-closed 缺省；放行接缝 = typed extension + 默认拒（编译期/机器守）。

### Key Entities *(include if feature involves data)*

- **RawCredential**（冻结，`diport::pdp`）：入站凭据——scheme tag（jwt / service_token）+ token bytes；本 feature 不改，仅消费。
- **VerifiedClaims**（`diport::pdp`）：私有 tagged profile shape——`RssUser { UserId, TenantId, VerifiedAccessGrantFacts }` / `FederatedAccess { subject, tenant, PrincipalKind }` / `ServiceToken { ServiceCallerDomain }`；只有 profile-specific checked factory，无通用可选字段 bag，Debug 脱敏。
- **PdpError**（冻结，`#[non_exhaustive]`）：fail-closed 三变体 InvalidSignature / Expired / Untrusted，纯 taxonomy（不携 source）。
- **SupportedAlg**（新，adapter 内部 `#[non_exhaustive]`）：ES256 / HS256；EdDSA 接缝预留（follow-up）。
- **KeyEntry / KeySet / KeySource**（adapter 内部，#1197）：`KeyEntry{ kid: Option<String>, key }`；`KeySet` = ES256/HS256 两集 kid 索引快照；**闭合 `enum KeySource { Static(Arc<KeySet>), Jwks(JwksKeySource) }`**（非新 trait——规避 trait_variant 白名单例外，闭集类型层 Hard）= 静态 set（首批）/ JWKS 本地文件源（US4/#1197）；`OidcProvider::new` 构造器签名稳定，JWKS 作为新 enum 变体不改签名。
- **Authenticated**（httpserve own）：私有字段的放行证据 extension；constructor 按 RSS /
  Federated / Service / mTLS 闭合，RSS 额外携 `CurrentAuthGrant`。
- **VerifyBridge 中间件**（组合根）：extract→profile-specific verify→可选 durable grant validation→
  profile-specific evidence inject + tracing 的 axum 中间件；唯一启用生产认证处。

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `OidcProvider::verify` 对 ES256 + HS256 通过 RFC 7515 known-answer 测试向量（验签正确而非自洽）；坏签名/过期/坏 alg/iss-aud 不符各映射到正确 `PdpError` 变体，100% 表驱动用例通过。
- **SC-002**: 生产依赖图（`cargo build --release` + `cargo deny check`）不含 `ring` / `rsa` / `aws-lc-*` / `openssl` / `jsonwebtoken` 任一；deny licenses/bans/advisories 全绿。
- **SC-003**: 接通后的生产可达 `Require` 端点：有效凭据 200 + `Authenticated`（`scheme` + principal_kind facet）、scheme exact-match 放行；无/坏/过期/错 aud 凭据 / 方案不匹配 401/403；e2e 拒绝路径 100% 覆盖（ADR-006 §8 ③）。
- **SC-004**: 安全同批门机器可验：启用生产认证的 PR（PR-C）blocked-by 真 verifier（PR-A1）；任一中间态不出现「有 plan + always-allow stub」可达端点；stub Pdp 不在任何生产 bin 依赖图（deny + dev-dep 隔离）；**且 PR-C 的 governance 守卫拒绝 bins 生产 `src/` 内联 `impl diport::Pdp`（Medium，synthetic red case 证守卫非恒真）**。
- **SC-005**: profile-specific JWKS 轮转——新 kid token 验签通过、旧 kid 移除后旧 token 拒（Untrusted）；JWKS 不可达 100% fail-closed（经对应 profile readiness probe 反映 health），绝不静默跳过验签；**裸 plain-HTTP JWKS 不在可上线路径**。
- **SC-006**: 认证决策 tracing span 在 allow/deny 两路均产生且字段无 PII（无 subject/token/email）；deny 路区分 `PdpError` 三变体（便于告警分级）。
- **SC-007**: adapter / httpserve 改动覆盖率 ≥ 80%；`cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` 干净；`cargo xtask layer-deps` 绿（oidc 不被域依赖）；`cargo dylint --all` 绿（adapter impl Pdp 在 allowlist）。
- **SC-008**: feature 拆为 4 PR，每个净增删 ≤ 2000 行（例外有书面理由），形成 blocked-by DAG（PR-C←A1∧B；PR-A2←A1）+ 2-wave 排序（W1: A1∥B；W2: A2∥C），全部挂 Azure Boards #1109。

### ADR-006 §8 验收门槛 traceability

| 门槛 | 内容 | 覆盖 |
|------|------|------|
| ① | `VerifiedClaims` 仅 `diport::pdp` 定义并保持闭合 profile shape；verified newtype 仅由 authn 验签 funnel seal | FR-012 + T004.5 不回归断言守；#1835 claim matrix 覆盖 RSS quartet |
| ② | `from_verified_*` 入参必须 newtype | 已由 PR 208 满足；FR-012 + T004.5 守 |
| ③ | httpserve↔authn 验签接线有集成测试（含拒绝路径） | FR-011 + SC-003 + T004.1（e2e 拒绝路径全覆盖） |
| ④ | dynosaur 宏白名单无新增越界 | FR-012 末条 + SC-007（dylint 绿）；本 feature 不新增 port，天然满足 |

## Assumptions

- #1109 类型层（VerifiedJwt newtype + from_verified_* 签名 + diport::Pdp 接缝 + verify→mint bridge）已由 PR 208/211 合并，本 feature **不重做**，仅在其冻结接缝内接线；ADR-006 §8 验收门槛 ① ② 视为已满足、本 feature 加回归断言守不退化。
- ADR-006 已裁决「内置 typed authplan + 预留 diport::Pdp 接缝（impl=#1109），不引外置 OPA」；本 feature 落地内置验签器（OidcProvider），不引 OPA/Rego。
- crypto 选型受供应链约束：`ring`/`aws-lc-*`/`openssl` 因 license（`Cargo.toml:122-134`）、`rsa` 因 RUSTSEC Marvin（`deny.toml` 机器守卫）禁用；RustCrypto 系（hmac/sha2 已在 Cargo.lock，p256 新增）license-clean。详见 research.md。
- ~~JWKS HTTP/TLS 栈的 license-clean 选型是 US4/PR-A2 的 open risk~~ **已裁定（#1197，research.md R3 决断）**：2026-06 无 license-clean 且生产成熟的 rustls TLS provider，且 in-app HTTPS 拉 JWKS 是零信任生产系统规避的少数派 → 采纳 R3 次选「本地文件源 + 外部 agent 刷新」，**in-app 零 HTTP/TLS provider**；**裸 plain-HTTP-over-network JWKS 仍否决**（评审 F2）。in-app HTTPS 直连外部标准 IdP = follow-up（待成熟 provider，复用 seam）。
- httpserve 不可依赖兄弟服务 authn（`xtask/src/layers.rs:122` `Service => Basis|Engine|DiPort`）；故放行机制经 httpserve own 类型 + 组合根桥接（plan.md §auth-bridge 分层）。
- service-token 验签复用 JWT 结构 + HS256（对称内部密钥），与外部 IdP JWT 路径隔离；service-token 的 kind/tenant 由 authn 忽略（固定 kind=Service）。
- e2e 集成测试经 feature/dev-dependency 门控；stub Pdp 仅 dev-dep，不入生产构建。
- 本 feature 不新增 wire contract / generated（消费冻结的 `diport::Pdp` port-own 类型 + httpserve own 标量），无契约扇出；故 PR 一致性等级为 L1 / 无等级。
