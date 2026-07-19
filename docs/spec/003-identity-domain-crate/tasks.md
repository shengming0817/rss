---
description: "Task list — identity 域 crate body 兑现"
---

# Tasks: identity 域 crate（身份 / 会话 / RBAC / ABAC / 密码 CAS）

**Input**: Design documents from `specs/003-identity-domain-crate/`（plan.md / spec.md / data-model.md / research.md）

**Tests**: 本 feature **要求测试**（RSS 覆盖率门 ≥ 80%，domain 纯逻辑趋近 90%）——每个用户故事「先写测试 → FAIL → 实现」。

**Organization**: 任务按用户故事分组；每个用户故事 = 一个 **PR**（≤2000 行）= 一个 **子 PBI 工作项**。

## Format: `[ID] [P?] [Story] Description`

- **[P]**: 可并行（不同文件、无依赖）
- **[Story]**: US1–US5
- 路径相对 repo root（`crates/identity/`）

---

## Phase 1: Setup（共享，归入 PR1）

- [ ] T001 [PR1] 把单文件 `domain/mod.rs`（556 行）按子域拆为 `domain/{mod,rbac,abac,account,session}.rs`，`mod.rs` 仅留共享 newtype（RoleId/PermissionId/PolicyId/ResourcePattern/AttributeKey/AttributeValue）+ IdentityError + re-export 枢纽；`lib.rs` 加子模块声明。保持冻结签名与 `pub(crate)` 字段、不动方法签名。
- [ ] T002 [PR1] `Cargo.toml` 补 dev-dep `rstest`（表驱动）；如需 argon2/bcrypt 先确认 `secure` crate 是否已提供，未提供则记入 PR3 task（不在 PR1 引依赖）。

---

## Phase 2: Foundational（阻塞所有用户故事 → 即 PR1 的核心）

**⚠️ PR1 完成前，PR2–PR5 不能开工**（共享 newtype + 模块结构是地基）。

- [ ] T003 [PR1][US1] 先写测试：`domain/rbac.rs` + `domain/mod.rs` 的表驱动 `rstest`——每个 newtype parse 正常/空/非法、`Permission`/`Role`/`RoleBinding` funnel 构造与访问、`authorize_rbac` 允许/拒绝/跨租 Deny/空集 fail-closed。运行确认 FAIL。

---

## Phase 3: User Story 1 - RBAC 授权决策（PR1 · P1 · 基座 MVP，子 PBI：#1186）

**Goal**: newtype funnel 全部可用 + `authorize_rbac` fail-closed 可用。

**Independent Test**: `cargo nextest run -p identity` RBAC 部分全绿，覆盖率达标，无需 adapter。

- [ ] T004 [PR1][US1] 实现共享 newtype funnel（`domain/mod.rs`）：`RoleId`/`PermissionId`/`PolicyId`/`ResourcePattern`/`AttributeKey`/`AttributeValue` 的 `parse`/`new`/`as_str`，空/非法 fail-closed 返回 `IdentityError`。
- [ ] T005 [PR1][US1] 实现 `Permission`/`Role`/`RoleBinding` 构造器 + 访问器（`domain/rbac.rs`），保留 `RoleBinding` Debug 脱敏。
- [ ] T006 [PR1][US1] 实现 `authorize_rbac`：同租户绑定 → 角色权限解析 → action+resource_pattern 匹配 → Allow，否则默认 Deny；跨租 Deny（IDENTITY-AUTHZ-TENANT-01）。
- [ ] T007 [PR1][US1] 跑 `cargo clippy -p identity --all-targets -- -D warnings` + `DYLINT_RUSTFLAGS=-D warnings cargo dylint --all`（含 `rss_domain_no_serialize`，fail-closed）+ fmt；`cargo llvm-cov --lib -p identity` 覆盖率 ≥ 80%。（各 PR 的 dylint 门统一 fail-closed，或经 `cargo xtask verify`。）

**Checkpoint**: PR1 可独立 ship；解锁 PR2–PR5。

---

## Phase 4: User Story 2 - ABAC deny-overrides（PR2 · P1 · Wave 2，∥ PR3，子 PBI：#1187）

**Goal**: `PolicyRule` operator/effect + `evaluate_abac` deny-overrides + 默认 Deny。

**Independent Test**: `domain/abac.rs` 表驱动全绿；deny-overrides / 默认 Deny / 跨租 Deny 红用例覆盖。

- [ ] T008 [PR2][US2] 先写测试（`domain/abac.rs`）：每个 operator(eq/ne/like/gt/lt/eq_attr) 真/假/类型不匹配、deny-overrides（Deny 压 Allow）、无命中默认 Deny、跨租 Deny、`AttributeValue` Debug 脱敏。运行确认 FAIL。
- [ ] T009 [PR2][US2] 在冻结签名内扩 `PolicyRule`：加 typed `operator` 枚举 + `effect(Allow|Deny)`；`AbacAttribute`/`Policy` funnel 实现。
- [ ] T010 [PR2][US2] 实现 `evaluate_abac` deny-overrides（对标 `casbin/casbin-rs src/effector.rs@fc425d4`：Deny 短路、Allow 续扫、缺省 Deny），跨租/类型不匹配 fail-closed 不命中。
- [ ] T011 [PR2][US2] 若 effect 表达需 `vocab::Decision` 扩 Obligations/FieldMask → 最小改 `vocab`（base crate，PR body 标注）；否则用现有 `Decision::{Allow,Deny}`。clippy/dylint/fmt/`cargo llvm-cov --lib -p identity`。

---

## Phase 5: User Story 3 - 身份/凭据管理 + 账户安全门控（PR3 · P2 · Wave 2，∥ PR2，子 PBI：#1188）

**Goal**: `CredentialRepo` 单一认证漏斗 + 密码哈希校验 + version pin + durable `AccountSecurityState` + 独立 temporary `AccountLockout`。

**Independent Test**: in-mem `CredentialRepo` 替身 + 表驱动覆盖凭据校验、四值状态/epoch/version、临时阻断、非 Active 登录拒绝和脱敏。覆盖率命令：`cargo llvm-cov --lib -p identity`。

- [ ] T012 [PR3][US3] 先写测试（`domain/account.rs` + `domain/account_security.rs` + `internal/mem.rs`）：密码校验正确/错误/版本不匹配（constant-time）、完整状态迁移矩阵、epoch/version/CAS/溢出、`AccountLockout` 阈值/窗口/临时阻断 TTL、非 Active 正确密码拒绝、password/receipt Debug 脱敏；确认暴破阈值和 TTL 到期都不迁移 durable status。运行确认 FAIL。
- [ ] T013 [PR3][US3] 定义 `CredentialRepo` 的 combined `authenticate`，删除 `lockout_status`；新增只读 `AccountSecurityReadRepo` 与只消费 sealed mutation 的 `AccountSecurityLifecycle`，所有依赖为必填非 `Option`。
- [ ] T014 [PR3][US3] 在 `domain/account_security.rs` 实现 `AccountSecurityState`、四值 `AccountStatus`、`AuthnEpoch`、`AccountSecurityVersion`、sealed mutation/active receipt；在 `domain/account.rs` 保留 `Credential` 与独立 `AccountLockout`，其 `record_failure` 返回 `AllowRetry|TemporarilyBlocked`。
- [ ] T015 [PR3][US3] `internal/mem.rs` 以一个 inner lock 原子承载 credential/security/lockout；unknown path 保留 dummy KDF，缺失/损坏 security state 完成 KDF floor 后 fail-closed；清理旧明文比对与拆分状态预检。
- [ ] T015b [PR3][US3] 核查 `deny.toml` `wrappers` 集合与 xtask `EXTERNAL_CONFINEMENT_WRAPPERS` 相等（DIPORT-MACRO-CONFINE-01′，identity 已在白名单，作显式核查）。clippy/dylint/fmt/`cargo llvm-cov --lib -p identity`。

---

## Phase 6: User Story 4 - 会话登录 + 密码 CAS + logout（PR4 · P2 · Wave 3，子 PBI：#1189）

**Goal**: 真实 `LoginService`（消费 `CredentialRepo`）+ `SessionRepo` + session-created L2 + 密码变更 CAS + logout。

**Independent Test**: tokio 异步单测 + fake 替身：登录成功发一条事件 / 错误不发 / CAS 冲突拒绝 / logout 撤销。覆盖率命令：`cargo llvm-cov --lib -p identity`。

- [ ] T016 [PR4][US4] 先写测试（`application/login.rs` + `domain/session.rs`）：Active login 成功创建会话+发 session-created；Suspended/Locked/Deactivated 即使密码正确也返回 InvalidCredentials 且零 token/session/outbox；密码错误、跨租、storage failure 和缺失 security state 均 fail-closed；change_password CAS、logout 和 tenant header 边界继续覆盖。运行确认 FAIL。
- [ ] T017 [PR4][US4] 定义 `SessionRepo`（`ports.rs`，域形 port）：`create`(L1)/`revoke`/`find`；`Session` 域类型（`domain/session.rs`）。
- [ ] T018 [PR4][US4] `LoginService` 真实 `login`：从 `X-Tenant-ID` header 获取 tenant → combined authenticate 产出 active receipt → refresh pre-mint 重读并核对 Active/epoch → `SessionRepo::create`(L1) → 同事务 `Publisher::publish(identity.session-created)`(L2)；任一失败发生在 mint/session/outbox 之前。
- [ ] T019 [PR4][US4] `change_password`（version pin CAS）+ `logout`（`SessionRepo::revoke`，域侧软撤销）。clippy/dylint/fmt/`cargo llvm-cov --lib -p identity` + L1/L2 原子性测试。

---

## Phase 7: User Story 5 - 角色管理 + 角色事件 + handler + contract 接线（PR5a+PR5b · P2 · Wave 4，子 PBI：#1190）

**Goal**: `RoleRepo` CRUD + `role-{assigned,revoked}` 事件契约（扇出闭环）+ 真实 axum handler + contract test + 生命周期升级。

**拆分说明**：PR5 预定义拆为 PR5a（角色事件契约 + RbacAdminService，~1000 行）和 PR5b（HTTP 端点契约 + handler + contract test + 生命周期升级，~1100 行），各 ≤2000 行，不等待超限才拆。

**Independent Test**: contract-level 测试（`axum::http`/`oneshot`）覆盖每端点 schema/错误码/鉴权/path；`cargo xtask contract validate` 绿。覆盖率命令：`cargo llvm-cov --lib -p identity`。

**PR5 开工前必须列 contract-fanout Implementation matrix**（见下节）。

### PR5a：角色事件契约 + RbacAdminService

- [ ] T021 [PR5a][US5] 新事件契约 `identity.role-assigned`/`identity.role-revoked`：`contracts/event/identity/v1/` schema + contract.toml（L2 OutboxFact，`lifecycle: draft` 以免触发 active-subscriber 校验——audit 订阅延 #1017 Join）→ `generated/src/event/identity_v1.rs`（codegen）→ 域 crate metadata。
- [ ] T023 [PR5a][US5] `RbacAdminService`（`application/rbac_admin.rs`）：`RoleRepo` CRUD + assign/revoke 发 role-* 事件（L2）。clippy/dylint/fmt/`cargo llvm-cov --lib -p identity`。

### PR5b：HTTP 端点契约 + handler + contract test + 生命周期升级

- [ ] T020 [PR5b][US5] 先写 contract test（stub-first：先 codegen 空 handler stub → contract test 可编译但 FAIL → 再填实现）：login/roles/roles-revoke/profile/password/logout 各端点正常 schema + 参数错误码 + 鉴权边界 + path 校验。运行确认 FAIL。
- [ ] T022 [PR5b][US5] 新 HTTP 端点契约（roles-assign/roles-revoke/roles-list/profile/password-change/logout）+ 每端点声明具体 permission overlay（见 spec.md US5 端点表）：`contracts/http/identity/v1/` + generated；`identity.login`/`identity.session-created` draft→active（pre-GA 原地）；roles-list 分页响应格式 `{data,nextCursor,hasMore}` + limit≤500。
- [ ] T024 [PR5b][US5] 真实 axum handler（`handler.rs`）+ typed response envelope；`IdentityDomain::init` 路由组接线（Primary listener，login opt-out Public，其余端点鉴权 + 各自 permission）+ audit 订阅声明对齐。
- [ ] T025 [PR5b][US5] `cargo xtask contract validate` 绿 + generated diff 审查；clippy/dylint/fmt/`cargo llvm-cov --lib -p identity`。

### contract-fanout Implementation matrix（PR5 开工前确认）

| 契约 | contract schema | generated | 域 crate metadata | tests | docs |
|------|----------------|-----------|-------------------|-------|------|
| `identity.role-assigned` | 新增（lifecycle draft） | 新增 | 新增 Cargo.toml dep + contract.toml | 发布侧 producer 测试（audit consumer 幂等测试延 #1017） | contracts.md 更新 |
| `identity.role-revoked` | 新增（lifecycle draft） | 新增 | 新增 | 发布侧 producer 测试（audit consumer 测试延 #1017） | 更新 |
| `identity.roles-assign` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.roles-revoke` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.roles-list` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.profile` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.password-change` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |
| `identity.logout` | 新增 | 新增 | 新增 | 新增 contract test | 更新 |

---

## Dependencies & Execution Order（= Wave）

```
Wave 1: PR1(US1)                 ← 基座，阻塞全部
Wave 2: PR2(US2) ∥ PR3(US3)      ← 均 blocked-by PR1；不同 domain 子文件，可并行
Wave 3: PR4(US4)                 ← blocked-by PR1, PR3（消费 CredentialRepo）
Wave 4: PR5(US5)                 ← blocked-by PR1, PR2(ABAC handler), PR4(登录 handler)
```

- **临界路径**：PR1 → PR3 → PR4 → PR5（深度 4）。PR2 随 Wave 2 并行，不占临界路径。
- **冲突分析**：PR2 ∥ PR3 唯一共享面 = `lib.rs`/`domain/mod.rs` 的 `mod` 声明 + re-export（≤5 行 additive）→ 低冲突，后开工者 rebase 即可；非同文件业务交叉。
- **同文件归一**：`ports.rs` 被 PR3(CredentialRepo)/PR4(SessionRepo) additive 追加；`application/mod.rs` 被 PR1/PR4/PR5 追加 re-export——均 additive，按 wave 串行落地天然不冲突。PR3→PR4 因 blocked-by 串行，`ports.rs` 无并行冲突。

## Implementation Strategy

1. **MVP first**：PR1（US1 基座）独立 ship + 验证 → 解锁全部。
2. **增量**：Wave 2 起每个 PR 独立可测、独立 ship、独立 review（按 diff 行数 1/2/3/6 reviewer）。
3. **并行**：Wave 2 的 PR2/PR3 可派两个 developer 并行（不同 domain 子文件）。

## Notes

- 每个 PR = 一个子 PBI 工作项（area-auth/type-enhancement/pri/cx，见 plan.md PR 表）。
- AI-HARD 验收项（每 PR review 硬核查）见 plan.md §AI-HARD 约束。
- 真依赖接线 + journey 全量 + bins/examples 在 Join 阶段 #1017，非本 feature。
