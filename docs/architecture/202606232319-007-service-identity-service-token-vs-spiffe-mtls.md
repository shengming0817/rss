# ADR-007：服务/工作负载身份 — service-token tenant binding 与 SPIFFE/mTLS

- **状态**：Accepted（2026-06-23 历史裁决）；Superseded / Closeout recorded（#1500 / #1577 / #1586 / #1597）
- **日期**：2026-06-23
- **关联**：issue #1139 [ADR 服务/工作负载身份 SPIFFE/SPIRE+mTLS vs service-token] · epic #991 / Feature #1131
- **依赖 ADR**：**ADR-002**（context 控制流值传播 / tenant source）· **ADR-003**（DI port 范式）· **ADR-006**（credential verifier 与 PDP 边界）
- **归属**：framework（服务间认证 / 工作负载身份接缝，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6

> **Superseded by #1500（2026-06-30）**：HTTP/Internal 当前执行策略已切为 SPIFFE/SPIRE + listener 级
> mTLS 默认；service-token 仅作为显式 local-test / operator / migration listener 能力保留，不是生产默认路径。
>
> **Closeout addendum（#1500 / #1577 / #1586 / #1597）**：service-token tenant header MAC 绑定已落地为
> `diport::ServiceTokenTenantBinding` / `diport::service_token_mac_input` +
> `httpserve::service_token_tenant_binding`；HS256 service-token 签名输入绑定 canonical
> `x-tenant-id:<tenant>`，旧 unsigned header/token 直接 401。SPIFFE/mTLS 已落地为 `VerifiedMtlsPeer`
> + exact SPIFFE allow-set + `MtlsRouteAuthorizer` route gate。
>
> **TENANCY-SERVICE-IDENTITY-SCOPE-01（#1597）**：service-token MAC-bound tenant scope is the only service
> identity tenant assertion。mTLS/SPIFFE service identity is not a tenant source；SPIFFE-ID / `VerifiedMtlsPeer`
> 只证明 tenantless service principal，必须经 exact SPIFFE allow-set 和 route authorizer，不能隐式建立
> ambient tenant scope。

---

## 1. 背景

2026-06-23 的原始问题是：RSS 内部 service-to-service 认证要先采用 service-token+MAC，还是立即引入
SPIFFE/SPIRE + mTLS。原文中的 `MAC verifier 随 #1109`、`MAC binding 尚未实装`、`service-token 验签空窗`
均是当时的历史状态描述；#1577 / #1586 已把 service-token tenant header MAC binding 收口，#1500 已把
mTLS/SPIFFE 生产接线落地，#1597 只关闭 service identity 到 tenancy 的最终边界。

迁移溯源（gocell）多处提及 SPIFFE + 跨 Cell mTLS（`spiffeid` sealed 身份）。RSS 当前执行模型采用
listener 级 mTLS + SPIFFE-ID allow-set 做 workload authentication / route admission；tenant scope 仍只来自
ADR-002 声明的 tenant source。

## 2. 当前决策

> 当前态：Internal svc-to-svc 生产默认使用 SPIFFE/SPIRE + mTLS；service-token 仅保留显式
> local-test / operator / migration listener 能力。tenant scope 只来自 JWT tenant claim 或 service-token
> MAC-bound canonical `X-Tenant-ID`；mTLS/SPIFFE 永远不隐式建立 tenant scope。

裁决要点：

1. **mTLS/SPIFFE 是 service identity/authn evidence**：transport verifier 产出 `VerifiedMtlsPeer`，route 层经
   exact SPIFFE allow-set 与 `MtlsRouteAuthorizer` 判定 allow/deny。`VerifiedMtlsPeer` 不携带 tenant assertion，
   也不写入 `PendingScopeCtx` tenant。
2. **service-token 只有 tenant-bound MAC 路径可建立 service identity tenant scope**：
   `service-token-tenant-bound` 把 canonical `X-Tenant-ID` 纳入 HS256 MAC 输入。缺 header、重复 header、非
   canonical UUID、MAC 不匹配、旧 unsigned token/header 均 401；不新增 alias、fallback 或 unsigned header
   宽容路径。
3. **service principal 本身 tenantless**：service-token principal 和 mTLS service principal 都不把 tenant 放在
   principal variant 内。service-token 的 tenant 来自已验签 header binding；mTLS/SPIFFE 的 route allow 结果不等于
   tenant assertion。
4. **不改变 public API / wire / env**：继续使用现有 `RSS_INTERNAL_AUTH_SCHEME`、
   `RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET`、`SPIFFE_ENDPOINT_SOCKET`；不新增 schema、env var 或 DI port。

## 3. 范式（当前落地形状）

```rust
// service-token tenant binding: canonical X-Tenant-ID participates in HS256 MAC input.
diport::ServiceTokenTenantBinding;
diport::service_token_mac_input(...);
httpserve::service_token_tenant_binding(...);

// mTLS/SPIFFE: authenticated service principal evidence, not tenant assertion.
authn::verify_mtls_peer(...)?;        // seals authn::VerifiedMtlsPeer
MtlsRouteAuthorizer { allow_set };    // assembly-private exact SPIFFE RouteAuthorizer

// PendingScopeCtx may receive tenant from JWT claim or verified service-token tenant binding.
// VerifiedMtlsPeer alone leaves scope_probe at the existing missing-scope sentinel.
```

listener auth chain 必须显式声明（runtime-api.md）：单 listener 单 scheme；无认证用 `AuthScheme::NoAuth`
（显式 `AuthNone`，非 `Option::None`）；Internal/Admin 上 `NoAuth` 被构造器 fail-closed 拒。

## 4. 后果

- **正**：service identity 与 tenant source 分离。mTLS/SPIFFE 解决 workload authentication；tenant scope 仍由
  typed JWT claim 或 service-token MAC-bound header 进入 `PendingScopeCtx`。
- **正**：service-token tenant replay 面被 canonical header MAC binding 收口，不保留旧 unsigned header/token
  兼容面。
- **正**：生产默认从对称 service-token 身份切到 SPIFFE/SPIRE + mTLS 后，route allow-set 可按 exact SPIFFE-ID
  审计；service-token 能力继续服务 local-test / operator 显式场景。
- **代价**：SPIFFE/SPIRE 需要 agent socket、SVID 轮转与 listener 证书装配；这属于 #1500 已接受的生产运维成本。
- **下游**：设备请求 Internal API 的目标仍是独立 deviceidentity 契约（X.509/OIDC 路径），不是 service-token。

## 5. 威胁矩阵 / amendment 声明

**amendment 声明**：本 closeout 不改变 `AuthScheme` 闭值集、不改 listener auth chain 强制、不新增 public API。
新增 / 显式化威胁如下：

| 威胁 | 暴露条件 | 缓解 | enforcement 档位 |
|------|---------|------|-----------------|
| mTLS 被误当 tenant source | handler 或 bridge 从 SPIFFE-ID 推 tenant | `TENANCY-SERVICE-IDENTITY-SCOPE-01` 文档锚点 + runtime e2e：`VerifiedMtlsPeer` 通过 mTLS auth 后仍返回 missing-scope sentinel | **Medium**（e2e + `tenancy-closeout`） |
| service-token tenant header replay | token 与 `X-Tenant-ID` 未绑定 | `ServiceTokenTenantBinding` / `service_token_mac_input` 把 canonical tenant header 纳入 HS256 MAC；缺失或不匹配 401 | **Hard/Medium**（auth bridge + e2e） |
| route allow-set 过宽 | SPIFFE allow-set 使用 prefix/wildcard | exact allow-set + `MtlsRouteAuthorizer`，未知 SPIFFE-ID fail-closed | **Hard/Medium**（typed authorizer + e2e） |
| 控制面 listener 误降级为无认证 | Internal/Admin 上误配 `NoAuth` 或 route opt-out | `AuthPlan::new` fail-closed；控制面拒 route-level Public/Exempt | **Hard**（类型 / 构造器，既有） |

## 6. AI-robust 分级（本 ADR 引入 / 修改的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| mTLS/SPIFFE service identity 不建立 tenant scope | **Medium** | runtime e2e `internal_mtls_verified_peer_remains_tenantless_scope` + `cargo xtask tenancy-closeout` anchors |
| service-token tenant scope 必须 MAC-bound canonical `X-Tenant-ID` | **Hard/Medium** | `ServiceTokenTenantBinding` / `service_token_mac_input` / auth bridge fail-closed + runtime e2e |
| exact SPIFFE allow-set / route authorizer 必须保留 | **Hard/Medium** | `VerifiedMtlsPeer` + `MtlsRouteAuthorizer` + focused auth e2e |
| listener auth chain 显式声明、`NoAuth` ≠ 缺省、控制面拒 `NoAuth` | **Hard** | `AuthPlan::new` fail-closed + 闭值集 `AuthScheme`（既有） |

无 Soft 新增 enforcement。

## 7. 备选（为何不取）

- **把 mTLS/SPIFFE 当作 tenant source**：否决。SPIFFE-ID 是 workload identity，不是 tenant assertion；从路径或
  trust domain 推 tenant 会把部署命名耦合到数据隔离边界，且无法表达跨租服务任务。
- **为旧 service-token header/token 保留兼容 fallback**：否决。unsigned header 会重新打开跨 tenant replay 面。
- **新增 service identity tenancy DI port 或 schema**：否决。现有 `auth_bridge`、`PendingScopeCtx`、
  `MtlsRouteAuthorizer` 与 `tenancy-closeout` 足以承载边界。

## 8. Follow-up

- 设备 fleet / deviceidentity 契约仍需独立 PBI 明确设备身份命名与 Internal API 边界。
- 多 trust domain 场景如需 SPIFFE federation，应另立 ADR 处理 trust bundle 分发、allow-set 归属和 rollout。

## 对标证据（ref）

- `ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs@master` — route 层异步 authorizer 模式参考。
- `ref: maxlambrecht/rust-spiffe spiffe-rustls/src/lib.rs@main` — rustls mTLS / SPIFFE certificate verification integration 参考。
- `ref: maxlambrecht/rust-spiffe spiffe/src/lib.rs@main` — Workload API / SPIFFE identity primitive 参考。
