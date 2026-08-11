# Contracts — identity 域 crate

> 契约真源在 `contracts/{http,event}/identity/v1/`（声明）→ `generated/src/{http,event}/identity_v1.rs`（派生）。HTTP identity 契约采用 nested v1 形态（`contracts/http/identity/v1/<slug>/`），不再使用旧 `identity/v2` refresh workaround。本文件只是 spec 阶段的契约范围说明，不复制 schema；实际 schema 走 contract-fanout.md 闭环。

> #1842 amendment：`identity.password-change` 与 `identity.account-status-set` 均为 active L2
> OutboxFact producer，精确产生 `identity.security-event`；password-change 不再属于 LocalTx inventory。

## 现存（draft，本 feature 升 active）

- **`identity.login`**（http，**L2 OutboxFact**，`contracts/http/identity/v1/login/`）：`POST /api/v1/identity/login`，Public（opt_out）。tenant 来源 `X-Tenant-ID` header（body 禁 `tenantId`）。req `{username,password}` → resp `{data:{sessionId,expiresAt,accessToken,refreshToken,accessExpiresAt}}`——登录成功首发 access JWT（vault `Signer` 经 `authn::JwtIssuer` 签）+ refresh token bundle（#1252 Join 接线）。
- **`identity.refresh`**（http，**L2 conditional OutboxFact**，`contracts/http/identity/v1/refresh/`）：`POST /api/v1/identity/refresh`，Public（opt_out；refresh token 自身即凭据）。tenant 来源 `X-Tenant-ID` header。req `{refreshToken}` → resp `{data:{accessToken,refreshToken,accessExpiresAt}}`。正常轮换在同一 producer transaction 中 consume old + insert child，使用 no-mutation fact outcome；检测 reuse 时才原子撤销 family、把 grant 提升为 Compromised 并精确产生一条 `identity.security-event`。只有 commit 确认后的不可伪造 receipt 能释放已 mint bearer；未知、重放、过期和 stale 对外保持统一拒绝。
- **`identity.session-created`**（event，L2 OutboxFact）：payload `{sessionId: UUID, subject: UUID / canonical UserId, tenantId: UUID, occurredAt}`；schema/codegen 将三个身份坐标生成为 typed UUID，订阅方 audit 再投影为私有 `SessionId` / `UserId` / `TenantId`。

## 新增（PR5）

| 契约 | kind | 一致性 | owner | 触发 / 订阅 | permission / auth |
|------|------|--------|-------|------------|-------------------|
| `identity.role-assigned` | event | L2 OutboxFact | identity | 触发：角色分配；订阅：audit（已接线，contract lifecycle active） | — |
| `identity.role-revoked` | event | L2 OutboxFact | identity | 触发：角色撤销；订阅：audit（同上） | — |
| `identity.password-change` | http | L2 OutboxFact | identity | `POST /api/v1/identity/password/change`；credential/account/grant/family/outbox 同事务 | `identity:profile:write` |
| `identity.account-status-get` | http | L0 LocalOnly | identity | `GET /api/v1/identity/accounts/{userId}/status` | `identity:account-security:read` |
| `identity.account-status-set` | http | L2 OutboxFact | identity | `PUT /api/v1/identity/accounts/{userId}/status`；四值 desired state，同态零副作用 | `identity:account-security:write` |
| `identity.logout` | http | L2 OutboxFact | identity | `POST /api/v1/identity/logout`，严格 `{}`，按当前 grant evidence 撤销 | `identity:session:logout-current` |
| `identity.logout-all` | http | L2 OutboxFact | identity | `POST /api/v1/identity/logout-all`，严格 `{}`，按 account epoch CAS 撤销全部既存授权 | `identity:session:logout-all` |
| `identity.roles-assign` | http | L2 | identity | `POST /api/v1/identity/roles/{roleId}/bindings`，鉴权 | `identity:role:assign` |
| `identity.roles-revoke` | http | L2 | identity | `DELETE /api/v1/identity/roles/{roleId}/bindings/{subject}`，鉴权（binding 级资源：tenant 从鉴权上下文派生，只撤目标 binding，跨租隐藏存在性） | `identity:role:revoke` |
| `identity.roles-list` | http | L0 | identity | `GET /api/v1/identity/roles`，鉴权 + 分页(limit≤500)，响应 `{data,nextCursor,hasMore}` | `identity:role:read` |
| `identity.profile` | http | L0 | identity | `GET /api/v1/identity/profile`，鉴权（selfScoped） | `identity:profile:read` |

PR5b 同步补齐最小生产 `role_bindings` 表与 `PgRoleBindingLifecycle`：assign/revoke 的 binding 行和 role event outbox 行同事务落库；role event audit consumer 已接线；session invalidation 为未交付业务缺口。

## 扇出闭环（每个新契约，contract-fanout.md）

schema（`*.schema.json`）→ contract.toml（id/kind/consistencyLevel/owner/endpoints/auth）→ `generated`（codegen，diff 一等审查）→ 域 crate metadata（`Cargo.toml [dependencies]` + contractUsages）→ tests（contract-level）→ docs。`cargo xtask contract validate` 守闭环 + id 唯一 + schema title PascalCase。

## contract-fanout Implementation matrix

| 契约 | contract schema | generated | 域 crate metadata | tests | docs |
|------|----------------|-----------|-------------------|-------|------|
| `identity.role-assigned` | 新增 schema.json + contract.toml（lifecycle active） | 新增 identity_v1.rs event type | 新增 Cargo.toml dep + contract.toml contractUsages | 发布侧 producer 测试（audit consumer 已接线） | contracts.md 更新 |
| `identity.role-revoked` | 新增 | 新增 | 新增 | 新增 | 更新 |
| `identity.roles-assign` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.roles-revoke` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.roles-list` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.profile` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.password-change` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.account-status-get/set` | 新增 | 新增 | 新增 | producer assurance + contract test | 更新 |
| `identity.logout` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.session-created` UUID 收口 | 三个身份坐标均为 `format:uuid` | 三字段均为 `uuid::Uuid` | metadata 不变；producer/consumer 走 typed ID funnel | raw wire decode + authn/vocab/audit 回归 | 本页更新 |

## 字段约定

- wire 字段 camelCase（serde rename）；DB snake_case。
- payload 类型经 generated，**不**手写共享 crate（domain-patterns.md §DTO 作用域）。
- 错误响应 shared error schema（`{error:{code,message,retryable,details,requestId}}`）；handler 用 typed response envelope。
