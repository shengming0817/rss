# ADR-007：服务/工作负载身份 — service-token tenant binding 与 SPIFFE/mTLS

- **状态**：Accepted（2026-06-23 历史裁决）；Superseded / Closeout recorded（#1500 / #1577 / #1586 / #1597）；
  **#1997 amendment**（标准 compact JWS + signed `tenant_id`，删除私有 MAC）
- **日期**：2026-06-23
- **关联**：issue #1139 [ADR 服务/工作负载身份 SPIFFE/SPIRE+mTLS vs service-token] · epic #991 / Feature #1131 ·
  **#1997** service-token standard JWS cutover
- **依赖 ADR**：**ADR-002**（context 控制流值传播 / tenant source）· **ADR-003**（DI port 范式）· **ADR-006**（credential verifier 与 PDP 边界）· **ADR-017**（互斥 token profile / 标准 signing input）
- **归属**：framework（服务间认证 / 工作负载身份接缝，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6

> **Superseded by #1500（2026-06-30）**：HTTP/Internal 当前执行策略已切为 SPIFFE/SPIRE + listener 级
> mTLS 默认；service-token 仅作为显式 local-test / operator / migration listener 能力保留，不是生产默认路径。
>
> **Closeout addendum（#1500 / #1577 / #1586 / #1597 / #1997）**：service-token tenant binding 现落地为
> 标准 compact JWS HS256：signing input 仅 `base64url(header).base64url(payload)`；signed payload 必含
> canonical `tenant_id`。`diport::ServiceTokenTenantBinding` 是 exact-one canonical `X-Tenant-ID` 的 typed
> **challenger**；OIDC verifier 在标准签名成功、typed claim 生成后、replay consume 前做一次 equality。
> ambient tenant **唯一**来自 sealed typed claim（`VerifiedServiceToken::tenant` / bridge 不从 header 设
> ambient）。历史私有 MAC 扩展已由 #1997 原子删除；最终 tree 不保留旧 token 样本或负向墓碑。
> SPIFFE/mTLS 已落地为 `VerifiedMtlsPeer` + exact SPIFFE allow-set + `MtlsRouteAuthorizer` route gate。
>
> **TENANCY-SERVICE-IDENTITY-SCOPE-01（#1597 / #1997）**：service-token claim-bound tenant scope（signed
> canonical `tenant_id` + header challenger equality）is the only service identity tenant assertion。
> mTLS/SPIFFE service identity is not a tenant source；SPIFFE-ID / `VerifiedMtlsPeer` 只证明 tenantless
> service principal，必须经 exact SPIFFE allow-set 和 route authorizer，不能隐式建立 ambient tenant scope。

---

## 1. 背景

2026-06-23 的原始问题是：RSS 内部 service-to-service 认证要先采用 service-token，还是立即引入
SPIFFE/SPIRE + mTLS。#1577 / #1586 曾以私有 tenant-header MAC 收口 service-token tenant binding；
#1500 已把 mTLS/SPIFFE 生产接线落地；#1597 关闭 service identity 到 tenancy 的边界。**#1997** 将
service-token 从私有 MAC 原子切到标准 JWS signed claim，不改变 mTLS/SPIFFE 边界，也不新增 crypto
依赖或 Soft gate。

迁移溯源（gocell）多处提及 SPIFFE + 跨 Cell mTLS（`spiffeid` sealed 身份）。RSS 当前执行模型采用
listener 级 mTLS + SPIFFE-ID allow-set 做 workload authentication / route admission；tenant scope 仍只来自
ADR-002 声明的 tenant source。

## 2. 当前决策

> 当前态：Internal svc-to-svc 生产默认使用 SPIFFE/SPIRE + mTLS；service-token 仅保留显式
> local-test / operator / migration listener 能力。tenant scope 只来自 JWT tenant claim，或
> service-token **signed** canonical `tenant_id` claim（header 仅 challenger equality）；mTLS/SPIFFE
> 永远不隐式建立 tenant scope。

裁决要点：

1. **mTLS/SPIFFE 是 service identity/authn evidence**：transport verifier 产出 `VerifiedMtlsPeer`，route 层经
   exact SPIFFE allow-set 与 `MtlsRouteAuthorizer` 判定 allow/deny。`VerifiedMtlsPeer` 不携带 tenant assertion，
   也不写入 `PendingScopeCtx` tenant。
2. **service-token 以标准 JWS + signed claim 建立 tenant scope**：contract header mode
   `service-token-tenant-bound`（名称保留）要求 exact-one canonical `X-Tenant-ID` 作为 challenger。mint
   把同一 canonical tenant 签入 payload `tenant_id`；verify 在标准 HS256 成功、typed claim 生成后做
   claim/header equality，再 replay consume。缺 header、重复 header、非 canonical UUID、equality 失败、
   缺 signed `tenant_id`、坏签名均 401；不新增 alias、fallback、unsigned header 宽容或 dual-read；
   不保留旧 token 样本作负向证据。
3. **service principal 本身 tenantless**：service-token principal 和 mTLS service principal 都不把 tenant 放在
   principal variant 内。service-token 的 ambient tenant 只来自已验签 sealed typed claim；mTLS/SPIFFE 的
   route allow 结果不等于 tenant assertion。
4. **不改变 public API / wire / env 面的配置键集合**：继续使用现有 `RSS_INTERNAL_AUTH_SCHEME`、
   `RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET`、`SPIFFE_ENDPOINT_SOCKET` 与既有 Service Token issuer/audience/HS256
   键；#1997 不新增 schema、env var、DI port 或 T3 gate。

## 3. 范式（当前落地形状）

```rust
// service-token: standard compact JWS HS256; signed tenant_id is ambient authority;
// exact-one X-Tenant-ID is challenger-only equality after typed claims, before replay.
diport::ServiceTokenTenantBinding; // typed challenger from exact-one header
// mint sign helper: no binding/header arg → signing input is structurally header.payload
// HS256 verify: no challenger arg → crypto verifies standard JWS only
httpserve::service_token_tenant_binding(...); // parse exact-one header → ServiceTokenTenantBinding

// mTLS/SPIFFE: authenticated service principal evidence, not tenant assertion.
authn::verify_mtls_peer(...)?;        // seals authn::VerifiedMtlsPeer
MtlsRouteAuthorizer { allow_set };    // assembly-private exact SPIFFE RouteAuthorizer

// PendingScopeCtx receives tenant from JWT claim or sealed service-token typed claim.
// VerifiedMtlsPeer alone leaves scope_probe at the existing missing-scope sentinel.
```

listener auth chain 必须显式声明（runtime-api.md）：单 listener 单 scheme；无认证用 `AuthScheme::NoAuth`
（显式 `AuthNone`，非 `Option::None`）；Internal/Admin 上 `NoAuth` 被构造器 fail-closed 拒。

## 4. 后果

- **正**：service identity 与 tenant source 分离。mTLS/SPIFFE 解决 workload authentication；tenant scope 仍由
  typed JWT claim 或 service-token sealed signed claim 进入 `PendingScopeCtx`。
- **正**：跨 tenant replay 面由 signed claim + exact-one header equality 收口；不保留非标准 signing
  input 兼容面，也不保留旧 token 样本/墓碑。
- **正**：生产默认从对称 service-token 身份切到 SPIFFE/SPIRE + mTLS 后，route allow-set 可按 exact SPIFFE-ID
  审计；service-token 能力继续服务 local-test / operator 显式场景。
- **代价**：SPIFFE/SPIRE 需要 agent socket、SVID 轮转与 listener 证书装配；这属于 #1500 已接受的生产运维成本。
  #1997 cutover 另要求有界停流 + drain + mint/verify/runtime 原子部署（见 production closeout）。
- **下游**：设备请求 Internal API 的目标仍是独立 deviceidentity 契约（X.509/OIDC 路径），不是 service-token。

## 5. 威胁矩阵 / amendment 声明

**amendment 声明（#1997）**：本 closeout 不改变 `AuthScheme` 闭值集、不改 listener auth chain 强制、不新增
public env/schema，不换 crypto crate，不新增 Soft/T3 gate。历史私有 MAC 扩展已删除，改为标准 JWS +
signed claim。威胁如下：

| 威胁 | 暴露条件 | 缓解 | enforcement 档位 |
|------|---------|------|-----------------|
| mTLS 被误当 tenant source | handler 或 bridge 从 SPIFFE-ID 推 tenant | `TENANCY-SERVICE-IDENTITY-SCOPE-01` + runtime e2e：`VerifiedMtlsPeer` 通过 mTLS auth 后仍返回 missing-scope sentinel | **Medium**（e2e + `tenancy-closeout`） |
| service-token tenant header replay / spoof | header 与 signed claim 未 equality，或把 header 当 ambient | signed canonical `tenant_id` 为唯一 ambient authority；`ServiceTokenTenantBinding` challenger equality 在 replay 前 fail-closed；缺/重复/非 canonical/不等 → 401 | **Hard/Medium**（typed claim + verifier equality + e2e） |
| 非标准 signing input 回流 | mint/verify 再次接收 binding/challenger 进 crypto，或拼 header 进 MAC | mint sign helper 无 binding 参数、HS256 verify 无 challenger 参数（Hard 结构）；known-answer / recording signer 锁标准 signing-input 字节（Medium） | **Hard/Medium** |
| route allow-set 过宽 | SPIFFE allow-set 使用 prefix/wildcard | exact allow-set + `MtlsRouteAuthorizer`，未知 SPIFFE-ID fail-closed | **Hard/Medium**（typed authorizer + e2e） |
| 控制面 listener 误降级为无认证 | Internal/Admin 上误配 `NoAuth` 或 route opt-out | `AuthPlan::new` fail-closed；控制面拒 route-level Public/Exempt | **Hard**（类型 / 构造器，既有） |

## 6. AI-robust 分级（本 ADR 引入 / 修改的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| mTLS/SPIFFE service identity 不建立 tenant scope | **Medium** | runtime e2e `internal_mtls_verified_peer_remains_tenantless_scope` + `cargo xtask tenancy-closeout` anchors |
| service-token ambient tenant 唯一来自 sealed signed `tenant_id`；header 仅 challenger equality | **Hard/Medium** | typed claim / `ServiceTokenTenantBinding` / OIDC verifier equality + runtime e2e `service_token_establishes_scope_from_claim_bound_tenant` |
| Service Token signing input 仅为标准 JWS | **Hard/Medium** | **Hard**：mint sign helper 无 binding、HS256 verify 无 challenger（typed API 收口）。**Medium**：fixed standard known-answer / recording signer 锁 signing-input 字节。不以已删除旧 API 名或 compile-fail tombstone 为永久 carrier |
| exact SPIFFE allow-set / route authorizer 必须保留 | **Hard/Medium** | `VerifiedMtlsPeer` + `MtlsRouteAuthorizer` + focused auth e2e |
| listener auth chain 显式声明、`NoAuth` ≠ 缺省、控制面拒 `NoAuth` | **Hard** | `AuthPlan::new` fail-closed + 闭值集 `AuthScheme`（既有） |

无 Soft 新增 enforcement。无 T3 新增 gate。

## 7. 备选（为何不取）

- **把 mTLS/SPIFFE 当作 tenant source**：否决。SPIFFE-ID 是 workload identity，不是 tenant assertion；从路径或
  trust domain 推 tenant 会把部署命名耦合到数据隔离边界，且无法表达跨租服务任务。
- **为旧私有 MAC service-token / unsigned header 保留兼容 fallback、dual-read，或在最终 tree 保留旧
  token 样本 / 负向墓碑**：否决。兼容面会重新打开跨 tenant replay；旧样本不是 enforcement carrier。
- **把 exact-one `X-Tenant-ID` 直接写入 ambient scope**：否决。header 只是 challenger；唯一 authority 是
  sealed typed claim。
- **新增 service identity tenancy DI port、schema、env 或 T3 Soft gate**：否决。现有 `auth_bridge`、
  `PendingScopeCtx`、`MtlsRouteAuthorizer`、typed claim 与 `tenancy-closeout` 足以承载边界。

## 8. Follow-up

- 设备 fleet / deviceidentity 契约仍需独立 PBI 明确设备身份命名与 Internal API 边界。
- 多 trust domain 场景如需 SPIFFE federation，应另立 ADR 处理 trust bundle 分发、allow-set 归属和 rollout。

## 对标证据（ref）

- `ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs@master` — route 层异步 authorizer 模式参考。
- `ref: maxlambrecht/rust-spiffe spiffe-rustls/src/lib.rs@main` — rustls mTLS / SPIFFE certificate verification integration 参考。
- `ref: maxlambrecht/rust-spiffe spiffe/src/lib.rs@main` — Workload API / SPIFFE identity primitive 参考。
- `ref: RFC 7515 §5.1 / §7.1` — JWS signing input = ASCII(BASE64URL(UTF8(JWS Protected Header)) ‖ '.' ‖ BASE64URL(JWS Payload))；compact serialization。
