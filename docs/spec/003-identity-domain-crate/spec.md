# Feature Specification: identity 域 crate（身份 / 会话 / RBAC / ABAC / 密码 CAS）

**Feature Branch**: `003-identity-domain-crate`

**Created**: 2026-06-24

**Status**: Draft

> **[已超越 #1278]** 本 spec 文内 `SessionRepo`（`create`/`find`/`revoke`）+ `SessionUnitOfWork` 双端口为 PR4 设计快照；#1278 已合并为单一域形 port `SessionLifecycle`（create/find/revoke 同源），权威记录见 ADR-005 §10。本 spec 作历史规划留存，不随后续重构逐处更新。

> **[#1833 安全语义修订]** `AccountStatus` 是持久账户生命周期状态；`AccountLockout` 只表示有 TTL 的暴力破解临时阻断，二者不互相驱动。登录与 refresh 的当前门控以 [ADR-018](../../architecture/202607181623-018-account-security-authentication-gate.md) 为准。

> **[#1834 AuthGrant 破坏性修订]** 内部 `Session` / `SessionId` / `SessionLifecycle` 已被
> `AuthGrant` / `AuthGrantId` / `AuthGrantLifecycle` 完整取代，不提供 alias 或兼容存储。登录原子持久化
> AuthGrant、初始 refresh 和 `identity.session-created` outbox，并在成功 receipt 后才释放 bearer；
> refresh 通过 tenant/grant/user/epoch/status 绑定根。权威记录见
> [ADR-019](../../architecture/202607191202-019-auth-grant-root.md)。本 spec 下文 Session 接口仅为历史快照。

> **[#1835 / ADR-021 所有权修订]** `AuthGrant` 聚合、`AuthGrantId`、`AuthnEpoch` 与完整
> `CredentialSecurityEventKind` 已下沉 `authn`，供 typed issuer 直接消费；identity 仍拥有凭据/账户状态、
> lifecycle port、安全 command/transaction 与 wire 编排。RSS access claims 已在 #1835 交付。

> **[#1277 canonical subject]** 登录查找键 `LoginIdentifier` ∥ canonical `ids::UserId`；
> `CredentialRepo::authenticate` → `AuthOutcome`；session-created `subject` = UUID。详见 data-model.md。

> **[#1842 credential-security 生产修订]** password-change 已从 L1 LocalTx 升级为 L2 OutboxFact，新增
> `identity.account-status-set` L2 路由；两者与 logout 共用 `IdentitySecurityLifecycle` 和唯一
> `PgIdentitySecurityLifecycle`。恢复 Active 不发事件且不复活旧授权。

**Input**: User description: "identity 域 crate（身份/会话/RBAC/ABAC/密码变更 CAS）：在 #997 冻结签名内兑现 domain L0（RBAC/ABAC deny-overrides）+ application（真实登录/会话/密码 CAS/账户锁定/角色管理）+ ports（CredentialRepo/SessionRepo）+ 新事件契约 + handler + contract test。拆成 5 个 ≤2000 行可执行 PR，挂 Azure Boards #1012。"

**Tracking**: Azure Boards Feature #1012（容器，跨 5 PR；子 PBI #1186–#1190）（`[RW-W-identity]`）· Epic #991（GoCell→Rust 迁移 · W 宽扇出阶段）· Blocked-by #999（G1 追踪弹，已闭环）

---

## AuthGrant 当前权威模型（#1834）

- 领域根使用强类型 `UserId`，持有 `auth_time`、账户签发 epoch、过期时间以及
  `Active | Revoked | Compromised` 闭值状态；关闭原因/时间由根转换与数据库 CHECK 双重验证。
- `RefreshTokenRecord` 不再保存 `PrincipalKind/kind/subject`，必须完整绑定 AuthGrant；轮换继承绑定。
- 登录只允许 `prepare_initial` 生成内存 bearer/hash，唯一初始持久化 API 是 combined
  `persist_login_grant`；根、refresh、outbox all-or-none，提交未知不返回 bearer。
- `AuthGrantLifecycle::close` 在同一事务先撤销 refresh family，再关闭根；同一 memory store 同时实现
  lifecycle 与 refresh port。
- HTTP/event 继续保持现有的 `sessionId` 与 `identity.session-created` event wire；access JWT 的
  `sid/jti/auth_time/authn_epoch` grant claims 已由 #1835 / ADR-021 交付。外部 wire 不构成内部旧 Session 抽象的
  兼容 shim。

---

## 背景与读者

本 feature 是 GoCell→Rust 迁移 Epic #991 W 阶段对 `identity` 域 crate 的 body 兑现。G0 阶段（#993 骨架 + #997 签名冻结）已把 `crates/identity/` 全部 trait/type/函数签名冻结（1208 行骨架，`domain/mod.rs` 556 行方法体全 `todo!()`）；G1（#999 追踪弹）已用 seed-login 跑通「登录 → outbox → audit」接缝。本 feature 只在冻结签名内填实现，**不改公共接缝、不弱化既有静态强制**。

「用户」= 两类框架消费者：

- **域 crate 作者 / 组合根**（bins/server、其它域 crate）：需要可用的 RBAC/ABAC 授权决策（纯计算、fail-closed）、真实登录与会话生命周期、密码变更并发安全、账户安全状态、暴力破解临时阻断、角色管理与角色变更事件——且非法用法在编译期 / 构造期不可表达。
- **平台运维 / 零信任治理**：需要跨租户 fail-closed、密码不落明文 / 不进日志、登录失败可触发临时阻断、角色变更可审计、会话事件可被 audit 消费。

「demo 拓扑」= 进程内 in-mem（`seed-login` feature / 测试 / 样例）；「durable 拓扑」= 真实持久化（postgres adapter，**非本 feature 范围**，见 §范围边界）。

---

## 范围边界（明确 In / Out，防止越界到兄弟 W 单元）

**In（#1012 = identity 域 crate 本体，`crates/identity/`）**：

- domain L0：RBAC（`authorize_rbac`）+ ABAC（`evaluate_abac` deny-overrides）+ 全部 newtype funnel 实现。
- application：真实登录路径、会话生命周期域侧编排、密码变更 CAS、账户安全状态门控、暴力破解临时阻断策略、RBAC 角色管理。
- ports：`RoleRepo`（已存）+ 新增 `CredentialRepo` / `SessionRepo`（ADR-005 Option 2 域形 port）。
- internal/mem：测试 / `seed-login` 用 in-mem 替身。
- 新契约：`identity.role-assigned` / `identity.role-revoked`（event L2）+ 新 HTTP 端点契约；`identity.login` / `identity.session-created` draft→active（pre-GA 窗口原地改）。
- handler + contract test + bootstrap 路由组接线 + audit 订阅声明对齐（`session-created` 已有；`role-*` 事件本 feature 仅出 draft 契约设计 + 发布侧，audit 订阅消费延 #1017）。

**Out（属其它 W 单元，作为依赖 / 前置，不在本 feature 实现）**：

- jwt 签发验证 / refresh token / PDP 实现 / CredentialFence → **#1003 authn**（本 feature 仅**消费**其已冻结签名 `Principal` / `PrincipalKind` / `diport::{Pdp,Publisher,Clock}`）；后续 #1833 只在 identity refresh 签发前增加账户安全门控，不改变 JWT wire。
- 真实持久化（postgres `RoleRepo` / `CredentialRepo` / `SessionRepo` impl）→ **adapter 单元（#1009–1011 / #1083 / #1116）**；本 feature 只定义 port + in-mem 替身。
- EST 设备注册 / 证书签发 / CredentialFence sealed 令牌 → 独立 `deviceidentity` crate + authn（后期，非 #1012）。
- `vocab::Decision` 增 Obligations/FieldMask 通道（P0-6 完整态）→ 若 ABAC deny-overrides 最小可用不需要，则不在本 feature 引入；需要则 PR2 内最小改动并在 PR body 标注（base crate 改动）。
- role event audit consumer / session invalidation + journey 全量 + bins/examples 集成 → Join 阶段 **#1017**；PR5b 已补最小 `role_bindings` + `PgRoleBindingLifecycle` 生产闭环。

> **blocked-by 精度**：identity 各子 PR 消费 authn 的是**已冻结签名**，故编译不被 #1003 实现硬阻塞——子 PR 用 in-mem 替身即可独立完成 + 测。5 个子 PBI 的 `Blocked-by` 只声明**彼此之间**与 #999，不错挂 #1003 / adapter（避免假依赖拖慢 wave）。

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - RBAC 授权决策可用（domain L0 RBAC + newtype funnel）(Priority: P1)

组合根 / handler 用 `identity::domain` 的 `RoleId`/`PermissionId`/`Permission`/`Role`/`RoleBinding`/`ResourcePattern` 构造主体的角色绑定与权限集，调 `authorize_rbac(&Principal, &[RoleBinding], &[Role], &Permission) -> Decision` 得到允许/拒绝决策（当前全是 `todo!()`）。非法输入（空 id、非法资源模式）在构造期 fail-closed 拒绝；跨租户绑定一律 Deny。

**Why this priority**: RBAC 是所有授权路径的地基，纯计算、无 I/O、无外部依赖，是临界路径地基。它确立的 newtype funnel + 模块拆分被 US2–US5 全部消费；不落地则其余 4 个 PR 无类型可用。

**Independent Test**: 表驱动 `rstest` 覆盖每个 newtype 的 parse 正常/边界/拒绝、`Permission`/`Role`/`RoleBinding` funnel 构造与访问、`authorize_rbac` 的允许/拒绝/跨租 Deny/空集 fail-closed；`identity` crate 新增代码覆盖率 ≥ 80%（纯逻辑部分趋近 90%），无需任何 adapter 或运行时。

**Acceptance Scenarios**:

1. **Given** 一个非空合法标识符，**When** 调 `RoleId::parse` / `PermissionId::parse`，**Then** 返回 `Ok` 且 `as_str` 回显；空 / 非法字符返回对应 `IdentityError`（fail-closed），不 panic。
2. **Given** principal 持有覆盖目标 `Permission` 的 `RoleBinding`（同租户），**When** 调 `authorize_rbac`，**Then** 返回 `Decision::Allow`。
3. **Given** principal 的 `RoleBinding.tenant != principal.tenant()`，**When** 调 `authorize_rbac`，**Then** 返回 `Decision::Deny`（INVARIANT IDENTITY-AUTHZ-TENANT-01，跨租 fail-closed）。
4. **Given** 空 `RoleBinding` 集或无匹配权限，**When** 调 `authorize_rbac`，**Then** 返回 `Decision::Deny`（默认拒绝，非 panic / 非默认放行）。

---

### User Story 2 - ABAC 策略决策 deny-overrides（domain L0 ABAC）(Priority: P1)

组合根用 `Policy`/`PolicyRule`/`AbacAttribute`/`AttributeKey`/`AttributeValue` 表达属性策略，调 `evaluate_abac(&Principal, &[AbacAttribute], &Policy) -> Decision`。`PolicyRule` 支持比较 operator（eq/ne/like/gt/lt + 跨属性 eq_attr），求值遵循 **deny-overrides** 语义（任一显式 Deny 规则命中即整体 Deny，无匹配则默认 Deny），跨租 fail-closed。

**Why this priority**: ABAC 与 RBAC 并列为零信任授权双路，决定细粒度策略可达性（P0-6 能力缺口）。它独立于 RBAC 子模块（`domain/abac.rs`），可与 US3 并行。

**Independent Test**: 表驱动 `rstest` 覆盖每个 operator 的真/假/类型不匹配、deny-overrides（Deny 优先于 Allow）、无规则匹配默认 Deny、跨租 Deny、`AttributeValue` Debug 脱敏；不需运行时。

**Acceptance Scenarios**:

1. **Given** 一条 `eq` 规则与匹配的属性值，**When** `evaluate_abac`，**Then** 该规则判定 Allow；属性缺失或值不等则该规则不命中。
2. **Given** 同一策略含一条命中的 Deny 规则与一条命中的 Allow 规则，**When** `evaluate_abac`，**Then** 整体 `Decision::Deny`（deny-overrides）。
3. **Given** 策略规则集为空或全不命中，**When** `evaluate_abac`，**Then** `Decision::Deny`（默认拒绝）。
4. **Given** `like`/`gt`/`lt`/`eq_attr` operator 与对应属性，**When** `evaluate_abac`，**Then** 比较语义正确且类型不匹配 fail-closed 判不命中（不 panic）。

**`like` operator 语义边界**：`like` 为 glob 风格通配（`*` 匹配任意长度序列，`?` 匹配单个字符），不支持嵌套通配或正则。模式最大长度 256 字节，parse 阶段 fail-closed 拒绝超长或含非法字符的模式（不推迟到求值），防止 ReDoS 风险。

---

### User Story 3 - 身份 / 凭据管理 + 账户安全门控（identity mgmt，L0/L1）(Priority: P2)

组合根经 `CredentialRepo`（新增域形 port）校验主体凭据：密码用 argon2/bcrypt 哈希 + constant-time 比对（不落明文、不进日志），支持凭据版本 pin。持久 `AccountSecurityState` 以 `AccountStatus`（Active/Suspended/Locked/Deactivated）、`authn_epoch` 与 `version` 驱动账户生命周期；只有 Active 可以登录或签发 refresh。`AccountLockout` 独立记录连续失败窗口（5 次 / 15min）和临时阻断 TTL（15min），到期只清零临时状态，不改变 `AccountStatus` 或 epoch。

**Why this priority**: 是真实登录（US4）的前置——US4 的密码校验消费 `CredentialRepo`。持久生命周期门控和多实例共享的临时暴破阻断都是生产认证的硬要求，但安全含义不能混用。

**Independent Test**: 表驱动覆盖密码哈希校验正确/错误/版本不匹配、`AccountStatus` 状态机及 epoch/version、`AccountLockout` 计数/阈值/窗口过期/阻断 TTL、非 Active 正确密码拒绝；in-mem `CredentialRepo` 替身在 `#[cfg(test)]`；密码与 active receipt 的 Debug 脱敏断言。

**Acceptance Scenarios**:

1. **Given** 正确密码 + 当前版本 + Active 状态，**When** `CredentialRepo` 原子认证，**Then** 返回携带当前 epoch 的 Active 证明；错误密码或过期版本 pin → 拒绝（constant-time）。
2. **Given** 连续 5 次失败在 15min 窗口内，**When** 记录第 5 次失败，**Then** 返回 `TemporarilyBlocked` 并在 TTL 内拒绝登录，但 durable `AccountStatus` 与 epoch 不变。
3. **Given** 临时阻断 TTL 已到期，**When** 触发 lazy-unlock 检查，**Then** 仅清零暴破计数和 `locked_until`；Suspended/Locked/Deactivated 不会因此变为 Active。
4. **Given** 正确密码 + 任一非 Active 状态，**When** 登录或 refresh 签发前门控，**Then** 统一拒绝且不 mint token、不创建会话、不发事件。
5. **Given** 任一携带密码或 Active 证明的类型，**When** 打印 Debug，**Then** password、login（查找键）与 epoch 脱敏；canonical `user_id` 可按类型策略保留或脱敏，但**不得**把登录标识当 wire subject 打印。

**附加验收要求（Acceptance addendum）**：

- **Clock 注入**：`AccountLockout` 的窗口到期 / 临时阻断 TTL 判定 MUST 经构造器注入的 `Clock` 计算，禁止调用 `SystemTime::now()` 或 `sleep`；测试使用 fake `Clock` 推进时间，不依赖真实时间流逝。
- **CredentialRepo 持久化**：`AccountLockout` 状态（失败计数、临时阻断时刻）MUST 经 `CredentialRepo` port 持久化，不能仅存内存——多实例部署下内存态无法共享，暴力破解防御将失效。
- **单一认证漏斗**：`CredentialRepo::authenticate` MUST 在一个事务中按 credential→account-security 固定锁序完成 KDF、durable status 门控与临时 lockout 更新；不存在独立 `lockout_status` 检查入口。
- **持久状态 fail-closed**：credential 存在但 account-security row 缺失、损坏或跨租时，完成 KDF floor 后返回 storage failure，不能补建或按 Active 继续。
- **临界值边界测试**：必须覆盖「窗口恰好到期」与「临时阻断 TTL 恰好到期」两个临界点，确认计数与解锁判定行为确定性。
- **跨租红用例**：`principal.tenant ≠ credential.tenant` 时 MUST Deny，不创建任何会话，不推进锁定计数。
- **Refresh family epoch fence**：根 refresh MUST 持久化签发时 `authn_epoch`，sealed rotation MUST 继承该值；
  application pre-mint 与 PostgreSQL 最终 writer 事务都必须校验当前账号 Active 且 epoch 匹配。Suspend→Active
  后旧 family 必须 fail-closed，final writer 拒绝不得消费 old 或写 child。

---

### User Story 4 - 会话登录生命周期 + 密码变更 CAS + logout（application，L1/L2）(Priority: P2)

`LoginService` 兑现真实登录路径（超越 seed-login）：经 `CredentialRepo` 原子完成密码与 Active 状态门控（消费 US3）→ refresh pre-mint 重读 Active 状态并核对 epoch → 创建授权根 → 在同事务发布 `identity.session-created` outbox fact（L2，已存契约）。密码变更不再由 repo 暴露独立 CAS：`PasswordChangeCommand` 把 credential/account expected snapshot、typed 新密码与 PasswordChanged event 封闭在一起，由唯一 producer transaction 原子更新、撤销既有 grant/family 并写 outbox。logout 同样进入该统一安全 lifecycle。

**Tenant 来源**：login 请求的 tenant 来源为 `X-Tenant-ID` header（pre-auth 路径，tenancy.md Hard），**request body 不得含 `tenantId` 字段**——body 含 tenantId 是 tenancy Hard 违规。

**凭据安全边界**：current 由认证 grant evidence 精确撤销当前 grant/family；all 与 password change 通过 account
epoch CAS 撤销主体全部既存 grant/family。account-status-set 接受四值 desired state，并同样
递增 epoch 后撤销全部旧授权。投影与 `identity.security-event` 在同一事务提交，不存在 opaque target mapping。
Suspended/Locked 恢复 Active 只做状态 CAS：保留 epoch、不发事件、不恢复旧 grant/family；Deactivated 为终态。

**Login 响应**：响应 `data: {sessionId, expiresAt, accessToken, refreshToken, accessExpiresAt}`，登录成功首发 access JWT + refresh token bundle（#1252 已接线；vault Signer 经 authn::JwtIssuer 签）。

**Why this priority**: 把 domain L0（US1–US3）编排成可用的登录会话闭环——这是 identity 对外的核心业务价值。依赖 US3（CredentialRepo）。独占 `application/login.rs` + `domain/session.rs` + `ports.rs`(SessionRepo)。

**Independent Test**: 异步单测（tokio）+ fake Clock/typed lifecycle 替身：登录成功发一条 session-created；密码错误不发事件返 InvalidCredentials；password/account sealed command 在版本冲突时拒绝；logout 撤销授权。PostgreSQL 测试覆盖 credential/account/grant/family/outbox both-or-neither、commit-unknown 不返回 receipt；audit consumer 对九组 kind/target 幂等消费且 mismatch fail-closed。追加跨租红用例（携 tenantA 凭据以 tenantB 登录 → Deny，不创建授权、不发事件）。

**Acceptance Scenarios**:

1. **Given** 合法凭据 + Active 状态 + 合法 `X-Tenant-ID` header，**When** `login`，**Then** 在 token mint 前再次确认 Active/epoch，创建会话 + 发布一条 `identity.session-created`，响应 token bundle。
2. **Given** 错误凭据，**When** `login`，**Then** 返回 `LoginError::InvalidCredentials`，**不**创建会话、**不**发事件（无孤立事件）。
3. **Given** 同一 expected credential/account snapshot 的两次密码变更，**When** 并发执行，**Then** 仅一次原子提交 credential、epoch、授权撤销与 PasswordChanged fact，另一次冲突且零部分副作用。
4. **Given** 两个活动授权，**When** `logout`，**Then** 只撤销当前授权；**When** `logout-all`，**Then** 撤销主体全部既存授权，旧 access/refresh 均返回 401。
5. **Given** tenantA 凭据携 `X-Tenant-ID: tenantB` header，**When** `login`，**Then** Deny，不创建会话，不发事件。

---

### User Story 5 - RBAC 角色管理 + 角色事件 + HTTP handler + contract 接线（L2 + wire）(Priority: P2)

`RoleRepo`（已存 port）兑现角色 CRUD；角色分配 / 撤销定义新事件契约 `identity.role-assigned` / `identity.role-revoked`（event L2 OutboxFact，扇出闭环 schema→generated→metadata→test→docs）+ 发布侧实现——但**本 feature 内 `role-*` 事件 lifecycle 暂为 draft**（audit 订阅消费 + active 升级延 #1017 Join，避免在无 subscriber 时触发 active-subscriber 守卫）。新增 HTTP 端点（roles / profile / password-change / account-status-get/set / logout）的契约 + 真实 axum handler + contract-level 测试；`identity.login` / `identity.session-created` 生命周期 draft→active。

**Why this priority**: 把 identity 能力暴露为 wire 契约 + handler，是域 crate 对外可服务的收口。依赖 US4（登录 handler）、US2（authz handler 用 ABAC）、US1（类型）。最重（含契约 codegen + handler + contract test），估行接近上限。

**Independent Test**: contract-level 测试（`axum::http` + `tower::ServiceExt::oneshot`）覆盖每个端点的正常响应 schema / 参数错误码 / 鉴权边界 / path 参数校验；`role-*` 事件契约 schema 校验 + 发布侧 producer 测试（draft；audit 可消费验证延 #1017）；roles-revoke 只撤目标 binding + 跨租隐藏存在性 contract test；generated diff 作一等审查材料；契约 `cargo xtask contract validate` 绿。

**HTTP 端点清单（US5）**：

| 端点 | Method | Path | AuthZ | Permission |
|------|--------|------|-------|------------|
| roles assign | POST | `/api/v1/identity/roles/{roleId}/bindings` | 鉴权 | `identity:role:assign` |
| roles revoke | DELETE | `/api/v1/identity/roles/{roleId}/bindings/{subject}` | 鉴权（binding 级：tenant 从鉴权上下文，只撤目标 binding，跨租隐藏存在性） | `identity:role:revoke` |
| roles list | GET | `/api/v1/identity/roles` | 鉴权 + 分页(limit≤500)，响应 `{data,nextCursor,hasMore}` | `identity:role:read` |
| profile | GET | `/api/v1/identity/profile` | 鉴权（selfScoped） | `identity:profile:read` |
| password-change | POST | `/api/v1/identity/password/change` | 鉴权（selfScoped） | `identity:profile:write` |
| account status get | GET | `/api/v1/identity/accounts/{userId}/status` | 鉴权；租户内状态查询 | `identity:account-security:read` |
| account status set | PUT | `/api/v1/identity/accounts/{userId}/status` | 鉴权；四值 desired state；同态无副作用 | `identity:account-security:write` |
| logout current | POST | `/api/v1/identity/logout` | 鉴权 grant evidence | `identity:session:logout-current` |
| logout all | POST | `/api/v1/identity/logout-all` | 鉴权 grant evidence | `identity:session:logout-all` |

每个受保护端点 MUST 在 contract.toml 声明具体 permission overlay，不能只写"鉴权"——缺 permission 声明的端点被 codegen fail-closed 拒绝。

**Acceptance Scenarios**:

1. **Given** 角色分配请求，**When** handler 处理，**Then** 经 `RoleRepo` 落角色绑定 + 发布一条 `identity.role-assigned`（L2，contract draft；audit 订阅消费延 #1017）。
2. **Given** 角色撤销请求（`{roleId}/bindings/{subject}`），**When** handler 处理，**Then** 仅撤销目标 binding（跨租输入隐藏存在性）+ 发布 `identity.role-revoked`（含 subject，draft），并触发域侧会话失效编排意图（运行期吊销由 authn 提供）。
3. **Given** 缺参 / 非法 path 参数 / 越权调用，**When** 命中各端点，**Then** 返回 contract 声明的错误码（typed response envelope），非裸 5xx。
4. **Given** 全部端点 handler 落地，**When** 跑 `cargo xtask contract validate`，**Then** `identity.login` / `identity.session-created` 可升 active、扇出闭环完整、generated 与 schema 一致。

---

### Edge Cases

- **跨租户**：任一授权 / 凭据 / 会话操作的 principal.tenant 与资源 tenant 不一致 → fail-closed Deny（不泄漏存在性）。
- **空 / 非 canonical 输入**：所有 newtype parse 在空 / 非法字符时返回 `*Error`，绝不 panic、绝不静默接受。
- **密码 / 凭据**：永不落明文、永不进日志 / Debug / wire；哈希比对 constant-time 防时序侧信道。
- **并发**：password/status sealed command 同时 pin 完整 credential/account snapshot；status PUT 冲突后只在持久状态已收敛到同一目标时返回 `changed=false`，异目标仍 409，且不重试发布事件。
- **事件原子性**：登录失败 / 业务回滚时 outbox 无孤立事件；发布失败按 relay 重试 / DLX（eventexec 已提供）。
- **临时阻断边界**：失败窗口刚过期 / 临时阻断 TTL 刚过期的临界点，计数与解锁判定确定；不得迁移 durable `AccountStatus`。
- **`like` operator**：glob 模式最大 256 字节，超长或含非法字符在 parse 阶段 fail-closed 拒绝，不推迟到求值——防 ReDoS。

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: 系统 MUST 在 `identity::domain` 所有 newtype 上提供 fail-closed 构造（parse 拒绝空 / 非法输入），字段保持 `pub(crate)` + funnel 构造器（不放成 `pub`）。
- **FR-002**: 系统 MUST 实现 `authorize_rbac`，对同租户匹配权限的绑定返回 Allow，跨租 / 无匹配 / 空集返回 Deny（默认拒绝）。
- **FR-003**: 系统 MUST 实现 `evaluate_abac`，支持 operator（eq/ne/like/gt/lt/eq_attr）+ deny-overrides + 默认 Deny + 跨租 fail-closed。
- **FR-004**: 系统 MUST 经 `CredentialRepo` 用 argon2/bcrypt + constant-time 校验密码、支持凭据版本 pin，且密码永不进明文 / 日志 / wire。
- **FR-005**: 系统 MUST 分离持久 `AccountSecurityState`（四值状态 + epoch/version）与临时 `AccountLockout`（阈值 5 / 窗口 15min / 阻断 TTL 15min）；暴破阈值与 TTL 到期都不得迁移 durable 状态。
- **FR-006**: 系统 MUST 在 `LoginService` 真实登录路径上：原子校验凭据和 Active 状态 → token mint 前重读 Active/epoch → 创建会话（L1）→ 同事务发布 `identity.session-created`（L2）；失败不 mint、不创建会话、不发事件。
- **FR-007**: 系统 MUST 用一个 `IdentitySecurityLifecycle` producer transaction 原子完成密码 credential CAS、account epoch/version bump、全部 grant/family 撤销与 PasswordChanged OutboxFact；任一冲突/失败不得部分提交。
- **FR-008**: 系统 MUST 提供 `RoleRepo` 角色 CRUD，并在分配 / 撤销时发布 `identity.role-assigned` / `identity.role-revoked`（L2 OutboxFact，扇出闭环完整）。
- **FR-009**: 系统 MUST 为新 HTTP 端点（roles / profile / password-change / account-status-get/set / logout）提供契约 + 真实 axum handler + typed response envelope（业务 4xx/5xx 不返裸 framework 5xx）。
- **FR-010**: 系统 MUST 经 contract-level 测试覆盖每个 served contract 的正常 schema / 参数错误码 / 鉴权边界 / path 参数校验。
- **FR-011**: 系统 MUST 保留 #997 冻结签名与 INVARIANT（IDENTITY-AUTHZ-TENANT-01 等），不弱化既有 sealed / newtype / `pub(crate)` 静态强制。
- **FR-012**: 系统 MUST NOT 给 domain 类型 derive `Serialize`（`rss_domain_no_serialize` dylint）；wire 类型只经 contract / generated。
- **FR-013**: 系统 MUST 经构造器必填位置参注入 `CredentialRepo` / `AccountSecurityReadRepo` / `SessionRepo` / `Publisher` / `Clock`（缺失即编译错误），不用 `Option` 静默 noop。
- **FR-014**: public 端点降级只经 generated `HttpRouteEvidence::auth() == HttpRouteAuth::Public` +
  `GeneratedPrimaryEndpoint`（login 端点），新增受保护端点默认鉴权（AUTH-OPTOUT-PRIMARYONLY-01）。
- **FR-015**: 列表端点（如 roles 列表）MUST 分页，`limit` 上限 500（rust-standards.md §安全检查点）。
- **FR-016**: login tenant 来源 MUST 为 `X-Tenant-ID` header（pre-auth 路径，tenancy.md Hard）；request body 禁止含 `tenantId` 字段。
- **FR-017**: 每个 active + codegen HTTP 契约 MUST 声明恰一个 AuthZ mode（permission overlay 值 或 显式 opt-out + reason）；缺声明的端点被 codegen fail-closed 拒绝。
- **FR-018**: 列表响应格式 MUST 为 `{data, nextCursor, hasMore}`（rust-standards.md §API）。
- **FR-019**: password change、account status set 与 current/all logout MUST 经唯一 credential-security producer transaction 原子提交业务投影、撤销目标 grant/family 与 security-event；event payload 携 typed initiator kind + 独立版本密钥生成的 tenant/domain-separated HMAC-SHA256 ref 与 key ID，不写 raw subject/target mapping，旧 access/refresh 必须立即失效。
- **FR-020**: `CredentialRepo::authenticate` MUST 是 credential + account-security 的唯一事务认证漏斗；不得提供可拆分的 `lockout_status` 或状态预检 port。
- **FR-021**: 系统 MUST 只允许 Active 账户登录和签发 User refresh；缺失/损坏状态、非 User refresh record 和存储异常均 fail-closed。
- **FR-023**: refresh family MUST 持久化不可改写的 issuance epoch；rotation 最终 writer MUST 在同一事务锁定
  account-security、校验 Active + epoch 后才允许 refresh CAS + child insert，并以 typed outcome 区分 replay
  与 account-stale。
- **FR-022**: HTTP desired-state PUT MUST 经 sealed `AccountStatusSetCommand`；进入非 Active 状态递增 epoch 并撤销旧授权，Suspended/Locked→Active 保留 epoch并发布 `AccountReactivated`，不恢复旧 grant/family；同状态零写入/零事件；Deactivated 为终态。内部无事件恢复仅经独立 `AccountReactivationLifecycle` capability，不得混入 producer port。

### Key Entities *(详见 data-model.md)*

- **Role / Permission / RoleBinding**：RBAC 三元——角色、权限（action + resource_pattern）、主体↔角色↔租户绑定。
- **Policy / PolicyRule / AbacAttribute**：ABAC 策略集、单条规则（operator + key + expected）、属性键值对。
- **Credential / LoginIdentifier / AuthOutcome / AccountSecurityState / AccountLockout**：登录查找键与 canonical `ids::UserId` 分层（#1277）；`authenticate`→`AuthOutcome` 唯一漏斗；凭据（login + user_id + 哈希 + 版本）、持久账户状态（status + authn_epoch + version）、独立的临时暴破计数器。
- **Session**：会话聚合（id / principal / expires_at；epoch 字段由 authn 提供）。
- **事件**：`identity.session-created`、`identity.security-event`（active L2）、`identity.role-assigned` / `identity.role-revoked`（新增，L2）。

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `identity` crate `cargo nextest run` 全绿，新增 / 修改代码覆盖率 ≥ 80%（domain 纯逻辑趋近 90%）。
- **SC-002**: `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --check` + `DYLINT_RUSTFLAGS=-D warnings cargo dylint --all`（fail-closed）全绿（含 `rss_domain_no_serialize`）；等价入口 `cargo xtask verify`。
- **SC-003**: `cargo xtask contract validate` 绿；`identity.login` / `identity.session-created` 升 active；新角色事件契约扇出闭环完整、generated 与 schema 字节一致。
- **SC-004**: 5 个子 PR 每个净增删 ≤ 2000 行（PR5 特殊情况可例外，超则拆 5a/5b）；每个独立可测、可按 wave 并行 / 串行落地。
- **SC-005**: 零跨租泄漏——授权 / 凭据 / 会话路径在跨租输入下 100% fail-closed Deny（表驱动红用例覆盖）。
- **SC-006**: 密码 / 凭据零明文泄漏——日志 / Debug / wire 中无明文密码（脱敏断言 + review 核查）。

## Assumptions

- authn（#1003）的 `Principal` / `PrincipalKind` / `diport::{Pdp,Publisher,Clock}` 等冻结签名已可消费（#997 已冻结），identity 编译不被 authn body 阻塞。
- role assign/revoke 的最小生产持久化由 PR5b 的 `role_bindings` + `PgRoleBindingLifecycle` 提供；role event audit consumer、session invalidation 和全量 journey 仍在 Join（#1017）。
- pre-GA wire 破坏窗口（至 2026-12-31）内允许原地改 active 契约版本（api-versioning.md §兼容窗口），仍走扇出闭环。
- `vocab::Decision` 现形态足以表达 Allow/Deny；若 ABAC 需 Obligations/FieldMask，则 PR2 内最小扩展（base crate 改动，PR body 标注），否则不引入。
- argon2/bcrypt 哈希算法选型沿用 `secure` crate 既有能力（若已提供）；否则在 identity 内最小封装并在 research.md 记对标。
- identity 依赖 authn（服务层）以消费 `authn::Principal`；域可依赖服务层（分层规则允许），`authn` 已在 `deny.toml` 放行，无 deny 违规。
