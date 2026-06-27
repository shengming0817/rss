# Contracts — identity 域 crate

> 契约真源在 `contracts/{http,event}/identity/v1/`（声明）→ `generated/src/{http,event}/identity_v1.rs`（派生）。本文件只是 spec 阶段的契约范围说明，不复制 schema；实际 schema 在 PR5 落地，走 contract-fanout.md 闭环。

## 现存（draft，本 feature 升 active）

- **`identity.login`**（http，**L2 OutboxFact**——与权威 `contracts/http/identity/v1/contract.toml` `consistencyLevel = "OutboxFact"` 同源：登录在同事务写本地会话 + 发布 `identity.session-created` outbox fact，故 login 契约整体是 L2；`SessionRepo::create` 仅是其中的 L1 子步骤，不单独成契约一致性边界）：`POST /api/v1/identity/login`，Public（opt_out）。tenant 来源 `X-Tenant-ID` header（body 禁 `tenantId`）。req `{username,password}` → resp `{data:{sessionId,expiresAt,accessToken,refreshToken,accessExpiresAt}}`——登录成功首发 access JWT（vault `Signer` 经 `authn::JwtIssuer` 签）+ refresh token bundle（#1252 Join 接线）。
- **`identity.refresh`**（http，**L1 LocalTx**，`contracts/http/identity/v2/`）：`POST /api/v1/identity/refresh`，Public（opt_out；refresh token 自身即凭据）。tenant 来源 `X-Tenant-ID` header。req `{refreshToken}` → resp `{data:{accessToken,refreshToken,accessExpiresAt}}`——轮换 refresh token 血缘（reuse-detection 级联撤销）+ 铸新 access JWT。未知/重放/过期 → 401（#1252）。
- **`identity.session-created`**（event，L2 OutboxFact）：payload `{sessionId,subject,tenantId,occurredAt}`；订阅方 audit。

## 新增（PR5）

| 契约 | kind | 一致性 | owner | 触发 / 订阅 | permission / auth |
|------|------|--------|-------|------------|-------------------|
| `identity.role-assigned` | event | L2 OutboxFact | identity | 触发：角色分配；订阅：audit（延 #1017，contract lifecycle 暂留 draft 以免触发 active-subscriber 校验） | — |
| `identity.role-revoked` | event | L2 OutboxFact | identity | 触发：角色撤销；订阅：audit（同上） | — |
| `identity.password-change` | http | L1 | identity | `POST /api/v1/identity/password/change`，鉴权（selfScoped） | `identity:profile:write` |
| `identity.logout` | http | L1 | identity | `POST /api/v1/identity/logout`，鉴权（selfScoped）；仅域侧软撤销，硬吊销延 #1003 | `identity:session:write` |
| `identity.roles-assign` | http | L2 | identity | `POST /api/v1/identity/roles`，鉴权 | `identity:role:assign` |
| `identity.roles-revoke` | http | L2 | identity | `DELETE /api/v1/identity/roles/{roleId}/bindings/{subject}`，鉴权（binding 级资源：tenant 从鉴权上下文派生，只撤目标 binding，跨租隐藏存在性） | `identity:role:revoke` |
| `identity.roles-list` | http | L0 | identity | `GET /api/v1/identity/roles`，鉴权 + 分页(limit≤500)，响应 `{data,nextCursor,hasMore}` | `identity:role:read` |
| `identity.profile` | http | L0 | identity | `GET /api/v1/identity/profile`，鉴权（selfScoped） | `identity:profile:read` |

## 扇出闭环（每个新契约，contract-fanout.md）

schema（`*.schema.json`）→ contract.toml（id/kind/consistencyLevel/owner/endpoints/auth）→ `generated`（codegen，diff 一等审查）→ 域 crate metadata（`Cargo.toml [dependencies]` + contractUsages）→ tests（contract-level）→ docs。`cargo xtask contract validate` 守闭环 + id 唯一 + schema title PascalCase。

## contract-fanout Implementation matrix

| 契约 | contract schema | generated | 域 crate metadata | tests | docs |
|------|----------------|-----------|-------------------|-------|------|
| `identity.role-assigned` | 新增 schema.json + contract.toml（lifecycle draft） | 新增 identity_v1.rs event type | 新增 Cargo.toml dep + contract.toml contractUsages | 发布侧 producer 测试（audit consumer 幂等测试延 #1017） | contracts.md 更新 |
| `identity.role-revoked` | 新增 | 新增 | 新增 | 新增 | 更新 |
| `identity.roles-assign` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.roles-revoke` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.roles-list` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.profile` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.password-change` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.logout` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |

## 字段约定

- wire 字段 camelCase（serde rename）；DB snake_case。
- payload 类型经 generated，**不**手写共享 crate（domain-patterns.md §DTO 作用域）。
- 错误响应 shared error schema（`{error:{code,message,details,requestId}}`）；handler 用 typed response envelope。
