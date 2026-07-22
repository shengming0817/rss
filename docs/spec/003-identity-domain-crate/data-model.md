# Data Model: identity 域 crate

> 实体均为 `identity::domain` 域类型——字段 `pub(crate)`、经 funnel 构造器创建、**不 derive `Serialize`**（wire 经 contract/generated）。下表「当前」列标注 #997 冻结状态（来自 `crates/identity/src/domain/mod.rs`）。

> **[#1835 / ADR-021 所有权修订]** `AuthGrant`、`AuthGrantId`、`AuthnEpoch` 和完整
> `CredentialSecurityEventKind` 当前由 `authn` 拥有；identity 仍拥有账户/凭据聚合、lifecycle ports 与安全事务编排。

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

## 身份 / 凭据与账户安全子域（`domain/account.rs` + `domain/account_security.rs`）

| 实体 | 字段 | 不变式 / 校验 | 当前 |
|------|------|--------------|------|
| `Credential` | `subject + tenant + password_hash + version` | argon2/bcrypt 哈希；version pin；Debug 脱敏；明文永不存 | 新增域类型 |
| `AccountSecurityState` | `tenant_id + user_id + status + authn_epoch + version + status_changed_at + updated_at` | status 为四值闭集；epoch/version checked increment；hydrate 拒绝非法持久值 | #1833 持久真源 |
| `AccountStatus` | enum `Active|Suspended|Locked|Deactivated` | `Active→Suspended|Locked|Deactivated`；`Suspended|Locked→Active|Deactivated`；Deactivated 终态；同态拒绝 | `account_security` 聚合闭值 |
| `AuthnEpoch`（authn-owned） | PostgreSQL-safe unsigned newtype | identity 账户状态消费；进入任一非 Active 状态递增；恢复 Active 保留；溢出拒绝 | #1833；#1835 下沉 authn |
| `AccountSecurityVersion` | PostgreSQL-safe unsigned newtype | 每个成功 transition 递增；CAS expected version 不匹配拒绝 | #1833 |
| `AccountSecurityMutation` | `expected_version + next_state` | 字段私有；只能从当前 state 的合法 transition 构造 | #1833 sealed command |
| `ActiveAccountSecurity` | `tenant + user + authn_epoch` | 只能由 Active state 铸造；crate-private；Debug 不泄漏 subject/epoch | #1833 sealed receipt |
| `AccountLockout` | `failure_count + window_start + locked_until` | 阈值 5 / 窗口 15min / 临时阻断 TTL 15min；`record_failure` 返回 `AllowRetry|TemporarilyBlocked`；TTL 到期只清零自身，不迁移 `AccountStatus` 或 epoch | 新增（P1-12） |
| `IdentityError` | enum（pub，non_exhaustive） | 3 值错误 | 签名冻结 |

**ports**（`identity::ports`，域形 DI port，dynosaur Send 变体）：

- `CredentialRepo`：`find_by_user_id` / `authenticate` / `apply_password_change` / `save`。`authenticate` 是唯一登录漏斗，在一个 tenant writer transaction 中按 credential→account-security 固定锁序执行 KDF、状态门控和临时 lockout 更新；不存在独立 `lockout_status`。
- `AccountSecurityReadRepo`：只读 scoped state；RefreshService 只获得该能力。
- `AccountSecurityLifecycle`：只消费 sealed `AccountSecurityMutation`，以 version CAS 返回新状态或冲突。
- `RefreshTokenStore`：record 持久化 family `authn_epoch_at_issue`；sealed rotation 继承该值。PostgreSQL
  writer 在同一事务锁定 account-security、校验 Active + epoch，再 CAS consume old + insert child，返回
  `Applied|Replay|AccountStale`。

## AuthGrant 聚合与 identity lifecycle port（`authn::grant` + `identity::ports`）

| 实体 | 字段 | 不变式 | 当前 |
|------|------|--------|------|
| `authn::AuthGrant` | `grant_id + tenant + user_id + auth_time + authn_epoch_at_issue + expires_at + status + terminal metadata` | 强类型 user/epoch；Active/Revoked/Compromised 闭值；关闭原因/时间与状态一致；唯一借出 RSS issue input | #1834；#1835 下沉 authn |

**port `AuthGrantLifecycle`**（`identity::ports`）：`persist_login_grant` 原子写 AuthGrant、初始 refresh 与
`identity.session-created` outbox；`find_active` 按当前观察时间过滤；`close` 先撤销 refresh family 再关闭根。

## 凭据 / 应用编排（`application/`）

- `LoginService`：注入 `CredentialRepo` + `AuthGrantLifecycle` + `RefreshService`。真实 `login`：从
  `X-Tenant-ID` header 取 tenant → 原子校验密码、durable Active 状态和临时 lockout → 获得 active receipt
  → refresh pre-mint 重读并核对 Active/epoch → 构造 AuthGrant → 原子持久化根、初始 refresh 与
  `identity.session-created`。任一门控失败均零 mint、零 AuthGrant、零 outbox。
- `RefreshService`：构造时必填 `AccountSecurityReadRepo`；initial issuance 只接受 crate-private active receipt，
  rotate 只接受 canonical User record，并在 mint 前重读 Active 状态与 family issuance epoch。PostgreSQL
  rotation writer 再做最终 Active + epoch + AuthGrant fence；JWT grant claims 已由 #1835 / ADR-021 完成，
  #1839 的 request-time fence 亦已以密封 receipt input + 单次 tenant-scoped grant/account 读取接入，
  只有当前状态匹配才产生 `CurrentAuthGrant`。
- `RbacAdminService`（PR5）：注入 `RoleRepo` + `DynPublisher`。`assign_role` / `revoke_role`：落绑定 + 发 `identity.role-{assigned,revoked}`（L2）。
- `IdentityDomain`（bootstrap `Domain`）：`init` 声明路由组（Primary listener，`/api/v1/identity`，login opt-out Public）+ 注册 handler；fail-fast，无 panic。

## 事件契约（`contracts/event/identity/v1/`）

| Topic | 一致性级 | payload | 当前 |
|-------|---------|---------|------|
| `identity.session-created` | L2 OutboxFact | `{session_id, subject, tenant_id, occurred_at}` | ✓ 已定义（draft→active） |
| `identity.role-assigned` | L2 OutboxFact | `{subject, role_id, tenant_id, assigned_by, occurred_at}` | 新增（PR5，lifecycle draft） |
| `identity.role-revoked` | L2 OutboxFact | `{subject, role_id, tenant_id, revoked_by, occurred_at}` | 新增（PR5，lifecycle draft） |

> 字段 camelCase（serde rename）；payload 类型经 `generated`，非手写共享 crate。`role-*` 事件订阅方 = audit（角色变更审计），但**运行时订阅消费延 #1017 Join**——本 feature 内 `role-*` lifecycle 暂为 **draft**（active 事件才要求至少一个 subscriber，§active event subscriber；draft 契约设计 + 发布侧不触发该守卫，避免无 subscriber 时 validate 红）。PR5b 补齐最小生产 `role_bindings` 表与 `PgRoleBindingLifecycle`，确保 assign/revoke HTTP 端点不是测试专用接线；`session-created` 仍 active（G1 已有 audit subscriber）。

## HTTP 契约（`contracts/http/identity/v1/`）

| 端点 | method/path | 一致性 | 鉴权 | Permission | 当前 |
|------|-------------|--------|------|------------|------|
| login | POST `/api/v1/identity/login` | **L2 OutboxFact**（与权威 contract.toml 同源：同事务写 AuthGrant、初始 refresh 与 `identity.session-created`） | Public（opt_out） | — | ✓ draft→active；tenant 来源 X-Tenant-ID header，body 禁 tenantId；响应含 `{sessionId,expiresAt,accessToken,refreshToken,accessExpiresAt}`（#1252 首发 JWT bundle 已接线） |
| password-change | POST `/api/v1/identity/password/change` | L1 | 鉴权（selfScoped） | `identity:profile:write` | 新增 |
| logout | POST `/api/v1/identity/logout` | L1 | 鉴权（selfScoped） | `identity:session:write` | 新增；仅域侧软撤销，硬吊销延 #1003 |
| roles assign | POST `/api/v1/identity/roles/{roleId}/bindings` | L2 | 鉴权 | `identity:role:assign` | 新增 |
| roles revoke | DELETE `/api/v1/identity/roles/{roleId}/bindings/{subject}` | L2 | 鉴权（binding 级：tenant 从鉴权上下文，只撤目标 binding，跨租隐藏存在性） | `identity:role:revoke` | 新增 |
| roles list | GET `/api/v1/identity/roles` | L0 | 鉴权 + 分页(limit≤500) | `identity:role:read` | 新增；响应格式 `{data,nextCursor,hasMore}` |
| profile | GET `/api/v1/identity/profile` | L0 | 鉴权（selfScoped） | `identity:profile:read` | 新增 |

> 端点最终集合以 PR5 实施时 contract 设计 + gocell accesscore 映射为准；本表是 spec 阶段范围锚点。每端点 permission overlay 必须在 contract.toml 中声明，缺声明被 codegen fail-closed 拒绝。
