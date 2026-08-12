# Tenancy / ABAC consumer migration guide

本指南面向下游 HTTP/gRPC route、domain service、read-model 和 operator consumer。规则单源仍是
`docs/rules/tenancy.md`；本文件只把当前可消费模式和反例收敛到一个迁移入口。可编译示例见
`examples/tenancy-consumer`。

## AuthZ mode

active HTTP contract 必须声明一个 AuthZ mode。缺 mode、同时声明 mode、或 permission/reason 组合不合法时，
`cargo xtask contract validate` 和 codegen 都 fail-closed。

```toml
[endpoints.http.auth]
mode = "permission"
permission = "identity:profile:read"
```

`permission` mode 进入 `generated::http::*::SPEC.route.auth()`；route 装配只把 `SPEC.route` 与 handler
传给 `httpserve::GeneratedPrimaryEndpoint::new`，permission/resource scope 由 endpoint 内部推导。运行时由
`RouteAuthorizer` 做 coarse route/resource allow/deny，handler 只消费 gate 插入的
`AuthorizedSubject`，不得回读 `Authenticated` 或手写 role literal。

public/pre-auth endpoint 只能用显式 opt-out，并且必须写 reason：

```toml
[endpoints.http.auth]
mode = "public"
reason = "login is pre-auth; tenant scope is populated from X-Tenant-ID"

[endpoints.http.headers]
"X-Tenant-ID" = "populate-only"
```

这是 `identity.login` 的模式。`populate-only` 只把 tenant 填入 pre-auth login 上下文，不代表 header
本身有 cryptographic authenticity。

service-owned endpoint 使用 service token 时必须声明 tenant-bound header：

```toml
[endpoints.http.auth]
mode = "serviceOwned"
reason = "internal service endpoint"

[endpoints.http.headers]
"X-Tenant-ID" = "service-token-tenant-bound"
```

`service-token-tenant-bound`（名称保留，**不再**表示 MAC extension）要求 exact-one canonical
`X-Tenant-ID` 作为 challenger。Service Token 是标准 compact JWS HS256：signing input 仅
`base64url(header).base64url(payload)`；signed payload 必含 canonical `tenant_id`。OIDC verifier 在
标准签名成功、typed claim 生成后、replay consume 前做一次 claim/header equality。ambient tenant
唯一来自 sealed typed claim。缺 header、重复 header、非 canonical tenant、equality 失败、缺
`tenant_id` claim 或坏签名都必须 401。不依赖、也不保留旧私有 MAC token 样本。

## Tenant source

tenant scope 只能来自已声明且已认证入口：

- JWT tenant claim，经 auth bridge 写入 request context。
- `X-Tenant-ID = "service-token-tenant-bound"`，仅 serviceOwned service-token 路径使用：header 是
  challenger；ambient tenant 来自 signed canonical `tenant_id` claim。service-token claim-bound
  tenant scope is the only service identity tenant assertion。

`X-Tenant-ID = "populate-only"` 仅 public/pre-auth 填充路径使用，不是 authenticated ambient tenant source。
mTLS/SPIFFE service identity is not a tenant source；SPIFFE-ID / `VerifiedMtlsPeer` 只证明 service
principal，必须再通过 exact SPIFFE allow-set / `RouteAuthorizer`，不会建立 request tenant scope。

request body/query schema 中的 `tenantId` 不是 tenant source。HTTP request schema 不得声明 `tenantId`，
无例外。指定租户的 audit read 使用 `/api/v1/audit/tenants/{tenantId}/entries` path 参数。

## HTTP examples

`identity.login`:

- `mode = "public"`，带 `reason`。
- header 声明 `"X-Tenant-ID" = "populate-only"`。
- request body 只有 `username` / `password`，不含 tenant。

`identity.profile`:

- `mode = "permission"`，permission 为 `identity:profile:read`。
- `[endpoints.http] selfScoped = true`。
- protected response fields `data.subject` 和 `data.tenantId` enroll 到 `[endpoints.http.projection]`。

`audit.list-entries`:

- `mode = "permission"`，permission 为 `audit:read`。
- query 仅 `limit`/`cursor`，只读 ambient tenant；旧 `tenantId` query 返回 400。
- response 中 `data[].tenantId`、`data[].actor`、`data[].resourceId` 通过 `ResourceProjection` 默认 mask。

`audit.list-tenant-entries`:

- path 为 `/api/v1/audit/tenants/{tenantId}/entries`，仅 verified SuperAdmin。
- authn 先签发不含 All-scope 的 target-bound grant；typed durable audit append 提交成功后，audit 域的
  sealed receipt 才铸造 `CrossTenantReadScope`，再执行 admin read。
- append 是 LocalTx 唯一写 UoW；read 不与 append 处于同一事务。

role assign/revoke:

- `identity.roles-assign` permission 为 `identity:role:assign`。
- `identity.roles-revoke` permission 为 `identity:role:revoke`。
- handler 不能比较 role name 或 `PrincipalKind::Admin` 来绕过 route permission。

## Row and field obligations

`RowVisibility` 是 sealed row obligation。普通 user/device/admin 分别映射到 self/device/tenant scope。
`RowScope::All` 不从普通 `Principal::row_visibility` 签发；跨租户读必须经
`Principal::cross_tenant_audit_grant(...)` 取得不含 visibility 的 target-bound grant，先完成 typed durable
audit append，再由 audit-owned sealed receipt 铸造 read scope。

`ResourceProjection` 是 field obligation carrier。coarse allow 不等于字段明文 allow：

- 缺 projection 时 protected fields 默认渲染为 `"<redacted>"`。
- explicit unmask 只能来自 `RouteAuthorizationDecision::Allow(RouteAuthorizationGrant)` 中的闭值 projection。
- handler/rendering layer 消费 `AuthorizedSubject::projection()` 或 admin read 中同等 projection，不读取 role、
  permission string 或 durable policy 细节。

## gRPC target pattern

gRPC 当前以 `docs/rules/tenancy.md` 为目标规则：非 public RPC 要通过契约 overlay 声明 permission；
owner-scoped RPC 要声明 resource extraction；deny response 使用 sealed ErrorInfo，metadata 不带 subject、
token 或 resource value。#1596 不新增 `contracts/grpc` 或 runtime gRPC implementation。

## Anti-patterns

- Do not put tenant in body: request body `tenantId` is rejected by contract validate/codegen.
- Do not compare role literals: use `GrantPermission::Route(...)` and `RoutePermissionId`.
- Do not make handler-local authz decisions from `Principal.roles`, `PrincipalKind`, `authn::any_role`,
  `authn::self_or`, or `authn::require_any_role`.
- Do not treat ABAC as the tenant boundary. Tenant isolation remains typed `TenantId`, service-token tenant binding,
  `SET LOCAL rss.tenant_id`, FORCE RLS, and non-bypass serving role.
- Do not treat RLS as `RouteAuthorizer`. RLS protects rows; route permission/resource decisions stay in
  `RouteAuthorizer`.

## Verification

For consumer-facing changes run:

```bash
cargo check -p tenancyconsumer
cargo run -p tenancyconsumer
cargo test -p xtask tenancy_closeout
cargo xtask tenancy-closeout
cargo xtask contract validate
```

`cargo check -p tenancyconsumer` is the Hard compile check for shipped example code. `cargo test -p xtask
tenancy_closeout` compiles the generated-spec smoke test from the allowed `xtask -> generated` wrapper instead of adding
an `examples/** -> generated` dependency. `cargo xtask tenancy-closeout` is the Medium reverse self-check that keeps this
guide, the example, and the closeout docs linked.
