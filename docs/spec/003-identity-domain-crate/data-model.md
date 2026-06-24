# Data Model: identity 域 crate

> 实体均为 `identity::domain` 域类型——字段 `pub(crate)`、经 funnel 构造器创建、**不 derive `Serialize`**（wire 经 contract/generated）。下表「当前」列标注 #997 冻结状态（来自 `crates/identity/src/domain/mod.rs`）。

## RBAC 子域（`domain/rbac.rs` + 共享 newtype 在 `domain/mod.rs`）

| 实体 | 字段 | 不变式 / 校验 | 当前 |
|------|------|--------------|------|
| `RoleId` | `(String)` | parse 非空 + 合法标识符；fail-closed | 签名冻结，body `todo!()` |
| `PermissionId` | `(String)` | 同上 | 签名冻结 |
| `ResourcePattern` | `(String)` | parse 合法资源模式（支持通配）；fail-closed | 签名冻结 |
| `Permission` | `id: PermissionId, action: Action, resource_pattern: ResourcePattern` | funnel 构造 | 签名冻结 |
| `Role` | `id: RoleId, name: String, permissions: Vec<PermissionId>` | funnel 构造 | 签名冻结 |
| `RoleBinding` | `subject: String, role: RoleId, tenant: TenantId` | 跨租 fail-closed（IDENTITY-AUTHZ-TENANT-01）；手写 Debug 脱敏 | 签名冻结 |

**纯逻辑**：`authorize_rbac(&Principal, &[RoleBinding], &[Role], &Permission) -> Decision`——遍历同租户绑定 → 解析角色权限 → 匹配目标 Permission（action + resource_pattern）→ 命中 Allow，否则默认 Deny（fail-closed）。

## ABAC 子域（`domain/abac.rs`）

| 实体 | 字段 | 不变式 / 校验 | 当前 |
|------|------|--------------|------|
| `AttributeKey` | `(String)` | parse 非空；fail-closed | 签名冻结 |
| `AttributeValue` | `(String)` | new；手写 Debug 脱敏 | 签名冻结 |
| `AbacAttribute` | `key: AttributeKey, value: AttributeValue` | funnel 构造 | 签名冻结 |
| `PolicyId` | `(String)` | parse；fail-closed | 签名冻结 |
| `PolicyRule` | `attribute_key + operator + expected(value|attr) + effect(Allow|Deny)` | **新增 operator 枚举**（eq/ne/`like`[glob风格,≤256字节,fail-closed]/gt/lt/eq_attr）+ effect(Allow\|Deny)；`like` 模式超长或含非法字符在 parse 阶段 fail-closed 拒绝，防 ReDoS | 当前仅 `attribute_key + expected_value` 等值；本 feature 扩 operator/effect |
| `Policy` | `id: PolicyId, rules: Vec<PolicyRule>` | funnel 构造 | 签名冻结 |

**纯逻辑**：`evaluate_abac(&Principal, &[AbacAttribute], &Policy) -> Decision`——**deny-overrides**：任一命中的 Deny 规则 → 整体 Deny；否则有命中 Allow → Allow；无规则命中 → 默认 Deny；跨租 / 类型不匹配 fail-closed 不命中。

> `PolicyRule` 扩 operator/effect 是在冻结签名内补字段语义；若 `vocab::Decision` 需 Obligations/FieldMask 才能表达 effect 之外的义务，则 PR2 内最小扩展 `vocab`（base crate，PR body 标注），否则用现有 `Decision::{Allow,Deny}`。

## 身份 / 凭据子域（`domain/account.rs` + `ports.rs` CredentialRepo）

| 实体 | 字段 | 不变式 / 校验 | 当前 |
|------|------|--------------|------|
| `AccountStatus` | enum `Active|Suspended|Locked|Deactivated` | 4 值闭值集；合法状态迁移 | 签名冻结（仅 enum 值） |
| `Credential` | `subject + tenant + password_hash + version` | argon2/bcrypt 哈希；version pin；Debug 脱敏；明文永不存 | 新增域类型 |
| `AccountLockout` | `failure_count + window_start + locked_until` | 阈值 5 / 窗口 15min / 锁定 TTL 15min；`record_failure` / `try_lazy_unlock`；窗口/TTL 判定经注入 `Clock` 计算（禁 `SystemTime::now()`）；状态经 `CredentialRepo` port 持久化（多实例安全） | 新增（P1-12） |
| `IdentityError` | enum（pub，non_exhaustive） | 3 值错误 | 签名冻结 |

**port `CredentialRepo`**（`identity::ports`，域形 DI port，dynosaur Send 变体）：`find(subject, tenant) -> Option<Credential>` / `verify_password(...) -> bool`（constant-time）/ `bump_version(...)`（CAS）/ `save(...)`。

## 会话子域（`domain/session.rs` + `ports.rs` SessionRepo）

| 实体 | 字段 | 不变式 | 当前 |
|------|------|--------|------|
| `Session` | `id + principal + expires_at`（authz_epoch 由 authn 提供，不在本 crate 增字段） | TTL 计算用注入 `Clock` | authn::Session 三字段已存（本 crate 编排） |

**port `SessionRepo`**（`identity::ports`）：`create(principal, ttl) -> Session`（L1）/ `revoke(session_id)`（logout）/ `find(session_id)`。

## 凭据 / 应用编排（`application/`）

- `LoginService`（已部分实现 G1）：注入 `CredentialRepo` + `SessionRepo` + `DynPublisher` + `Clock`（构造器位置参）。真实 `login`：从 `X-Tenant-ID` header 取 tenant（body 禁 tenantId）→ 校验密码 → `SessionRepo::create`（L1）→ 同事务 `Publisher::publish(identity.session-created)`（L2）；响应 `data:{sessionId,expiresAt}`（本阶段不含 JWT，JWT 由 authn 在 #1017 接线）。`change_password`：CAS（version pin → bump）。`logout`：`SessionRepo::revoke`（域侧软撤销，已颁发 JWT 在 TTL 内仍有效，硬吊销延 #1003）。
- `RbacAdminService`（PR5）：注入 `RoleRepo` + `DynPublisher`。`assign_role` / `revoke_role`：落绑定 + 发 `identity.role-{assigned,revoked}`（L2）。
- `IdentityDomain`（bootstrap `Domain`）：`init` 声明路由组（Primary listener，`/api/v1/identity`，login opt-out Public）+ 注册 handler；fail-fast，无 panic。

## 事件契约（`contracts/event/identity/v1/`）

| Topic | 一致性级 | payload | 当前 |
|-------|---------|---------|------|
| `identity.session-created` | L2 OutboxFact | `{session_id, subject, tenant_id, occurred_at}` | ✓ 已定义（draft→active） |
| `identity.role-assigned` | L2 OutboxFact | `{subject, role_id, tenant_id, assigned_by, occurred_at}` | 新增（PR5，lifecycle draft） |
| `identity.role-revoked` | L2 OutboxFact | `{subject, role_id, tenant_id, revoked_by, occurred_at}` | 新增（PR5，lifecycle draft） |

> 字段 camelCase（serde rename）；payload 类型经 `generated`，非手写共享 crate。`role-*` 事件订阅方 = audit（角色变更审计），但**运行时订阅消费延 #1017 Join**——本 feature 内 `role-*` lifecycle 暂为 **draft**（active 事件才要求至少一个 subscriber，§active event subscriber；draft 契约设计 + 发布侧不触发该守卫，避免无 subscriber 时 validate 红）。`session-created` 仍 active（G1 已有 audit subscriber）。

## HTTP 契约（`contracts/http/identity/v1/`）

| 端点 | method/path | 一致性 | 鉴权 | Permission | 当前 |
|------|-------------|--------|------|------------|------|
| login | POST `/api/v1/identity/login` | **L2 OutboxFact**（与权威 contract.toml 同源：同事务写会话 + 发 session-created；`SessionRepo::create` 仅 L1 子步骤，不单独成契约边界） | Public（opt_out） | — | ✓ draft→active；tenant 来源 X-Tenant-ID header，body 禁 tenantId；响应不含 JWT |
| password-change | POST `/api/v1/identity/password/change` | L1 | 鉴权（selfScoped） | `identity:profile:write` | 新增 |
| logout | POST `/api/v1/identity/logout` | L1 | 鉴权（selfScoped） | `identity:session:write` | 新增；仅域侧软撤销，硬吊销延 #1003 |
| roles assign | POST `/api/v1/identity/roles` | L2 | 鉴权 | `identity:role:assign` | 新增 |
| roles revoke | DELETE `/api/v1/identity/roles/{roleId}/bindings/{subject}` | L2 | 鉴权（binding 级：tenant 从鉴权上下文，只撤目标 binding，跨租隐藏存在性） | `identity:role:revoke` | 新增 |
| roles list | GET `/api/v1/identity/roles` | L0 | 鉴权 + 分页(limit≤500) | `identity:role:read` | 新增；响应格式 `{data,nextCursor,hasMore}` |
| profile | GET `/api/v1/identity/profile` | L0 | 鉴权（selfScoped） | `identity:profile:read` | 新增 |

> 端点最终集合以 PR5 实施时 contract 设计 + gocell accesscore 映射为准；本表是 spec 阶段范围锚点。每端点 permission overlay 必须在 contract.toml 中声明，缺声明被 codegen fail-closed 拒绝。
