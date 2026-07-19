# Implementation Plan: identity 域 crate（身份 / 会话 / RBAC / ABAC / 密码 CAS）

**Branch**: `003-identity-domain-crate` | **Date**: 2026-06-24 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/003-identity-domain-crate/spec.md`

## Summary

在 #997 冻结签名内兑现 `identity` 域 crate 的 body：domain L0（RBAC `authorize_rbac` + ABAC `evaluate_abac` deny-overrides + 全部 newtype funnel）、application（真实登录 / 会话 L1·L2 / 密码 CAS / 账户安全状态 / 暴破临时阻断 / 角色管理）、ports（`RoleRepo` 已存 + 新增 `CredentialRepo` / `SessionRepo`）、新事件契约（`identity.role-{assigned,revoked}`）+ HTTP handler + contract test。#1833 在该基线之上补齐持久 `AccountSecurityState`、单事务认证漏斗和 refresh pre-mint Active/epoch 门控；`AccountLockout` 不迁移 durable 状态。技术路线：先把单文件 `domain/mod.rs`（556 行）/`application.rs`（291 行）按子域拆模块（PR1 基座），确立各 PR 的**独占文件归属**以解耦并行；其余 PR 在独占模块内填实现 + 表驱动测试。

## Technical Context

**Language/Version**: Rust（workspace 固定 toolchain，见 `rust-toolchain.toml`）

**Primary Dependencies**: `vocab`/`ids`/`secure`/`support`/`runctx`（基础）、`consistency`/`primitives`（引擎）、`authn`/`httpserve`/`bootstrap`/`eventexec`（服务，消费冻结签名）、`diport`（DI port：`Publisher`/`Clock`/`Pdp`）、`generated`（契约派生）；`dynosaur` + `trait-variant`（域形 repo port async dyn）；`thiserror` / `serde_json` / `tracing`；dev：`tokio` / `mockall` / `rstest`

**Storage**: 原 feature 只含 in-mem 替身；#1833 新增 PostgreSQL `account_security_states`，以双向 FK、CHECK、FORCE RLS 和最小 GRANT 保证提交时 credential/security 严格一对一

**Testing**: `cargo nextest run`（进程隔离）+ 表驱动 `rstest`（domain L0）+ `tokio` 异步单测（application）+ `axum::http`/`tower::ServiceExt::oneshot`（handler/contract test）

**Target Platform**: Linux server（rss bins/server 组合根注入；本 feature 是库 crate）

**Project Type**: 域 crate（library，扁平 workspace 成员 `crates/identity`）

**Performance Goals**: domain L0 纯计算无 I/O；授权决策 O(bindings × permissions) 线性，无外部调用

**Constraints**: 跨租 fail-closed；密码不落明文 / 日志 / wire；clippy 认知复杂度 ≤ 15；新增代码覆盖率 ≥ 80%；`-D warnings` 干净

**Scale/Scope**: 单 crate body 兑现，估总净增删 ~7370 行（含测试）跨 5 PR（PR1 ~1250 + PR2 ~1230 + PR3 ~1520 + PR4 ~1520 + PR5a ~1000 + PR5b ~1100 ≈ 7620，减去重叠去重 ≈ 7370）；GoCell accesscore 12 slices 的域侧映射

## Constitution Check

*GATE: 对照 `CLAUDE.md` + `docs/rules/` + `.claude/rules/rss/`（无独立宪法文件）*

| 门 | 结论 |
|----|------|
| 跨域只经 contract（crate 图 + deny.toml） | ✅ 仅消费 `generated` + `diport` + 服务冻结签名；不依赖兄弟域 crate |
| identity → authn（服务层依赖） | ✅ 域可依赖服务层，authn::Principal 已 deny.toml 放行 |
| 域形 repo port 归属（ADR-005 Option 2） | ✅ `CredentialRepo`/`AccountSecurityReadRepo`/`AccountSecurityLifecycle`/`SessionRepo` 定义在 `identity::ports`，非 diport |
| domain 不 derive `Serialize`（`rss_domain_no_serialize`） | ✅ wire 类型只经 contract/generated；domain newtype 字段 `pub(crate)` + funnel |
| 一致性等级在 contract.toml | ✅ session-created/role-* event 的 consistencyLevel 在 `contract.toml`，非 manifest |
| 必填依赖构造器位置参（非 Option）+ Clock 位参 | ✅ `CredentialRepo`/`AccountSecurityReadRepo`/`SessionRepo`/`Publisher`/`Clock` 均位置参 |
| public 降级仅 generated Public evidence + GeneratedPrimaryEndpoint（AUTH-OPTOUT-PRIMARYONLY-01） | ✅ 仅 login/refresh 为 Public；其余端点默认鉴权 |
| 契约扇出闭环（contract-fanout.md） | ✅ 新角色事件走 schema→generated→metadata→test→docs |
| AI-robust 新机制 ≥ Medium | ✅ 不新增 Soft；保留既有 Hard/Medium 守卫，新增覆盖率/契约 governance 为 Medium |

**无违规需 Complexity Tracking。** 模块拆分（PR1）不是新抽象层，而是把单文件按既有子域（rbac/abac/account/session）切开，服务于并行 + 内聚，符合「优雅简洁」。

## Project Structure

### Documentation (this feature)

```text
specs/003-identity-domain-crate/
├── plan.md              # 本文件
├── spec.md              # 用户故事 / 需求 / 成功指标
├── research.md          # 对标（RBAC/ABAC/identity 开源框架）
├── data-model.md        # RBAC/ABAC/凭据/会话 实体
├── tasks.md             # 任务清单 + PR 分组 + wave
├── contracts/           # 新事件契约设计说明（指向 contracts/event/identity）
└── checklists/
    └── requirements.md  # spec 质量自检清单
```

### Source Code（repository root；目标模块布局，PR1 确立拆分）

```text
crates/identity/
├── Cargo.toml                    # +argon2/bcrypt(或经 secure)；dev +rstest
└── src/
    ├── lib.rs                    # facade re-export（PR1 建子模块声明；后续 PR additive += 极少）
    ├── domain/
    │   ├── mod.rs                # 共享 newtype（RoleId/PermissionId/PolicyId/ResourcePattern/AttributeKey/AttributeValue）+ IdentityError + re-export 枢纽 [PR1]
    │   ├── rbac.rs               # Permission/Role/RoleBinding + authorize_rbac [PR1]
    │   ├── abac.rs               # AbacAttribute/PolicyRule(+operator 枚举)/Policy + evaluate_abac(deny-overrides) [PR2]
    │   ├── account.rs            # Credential + 独立的临时 AccountLockout + 密码 CAS 域类型 [PR3/#1833]
    │   ├── account_security.rs   # durable AccountSecurityState + epoch/version + sealed CAS mutation [#1833]
    │   └── session.rs            # Session 域类型 + 生命周期 [PR4]
    ├── application/
    │   ├── mod.rs                # IdentityDomain(bootstrap Domain) + re-export [PR1 微调; PR5 接线路由组]
    │   ├── login.rs              # LoginService 真实登录 + logout + 密码变更 CAS 编排 [PR4]
    │   └── rbac_admin.rs         # 角色分配/撤销 service + 角色事件发布 [PR5]
    ├── handler.rs                # axum handler（login/roles/profile/password/logout）+ contract test [PR5]
    ├── ports.rs                  # Role/Credential/AccountSecurity/Session 最小能力 ports（域形 DI port）
    └── internal/
        ├── mod.rs
        └── mem.rs                # in-mem 替身（各 PR 补自己的）
        # 注：纯域内非可替换 port 暂无，勿建空文件；
        # G1 tracer UserRepo 在 PR3 引入 CredentialRepo 后删除

contracts/event/identity/v1/      # +role-assigned / role-revoked schema+contract.toml [PR5]
contracts/http/identity/v1/       # +roles/profile/password/logout endpoint；login draft→active [PR5]
generated/src/{event,http}/identity_v1.rs   # 扇出派生 [PR5]
```

**Structure Decision**: 沿用 `docs/rules/architecture.md` 域 crate 标准分层（domain/application/handler/ports/internal）+ ADR-005 域形 repo port（`pub mod ports`）。把现有单文件 `domain/mod.rs`/`application.rs` 按子域拆成多文件，使每个 PR 独占其文件（降并行写冲突），唯一共享面是 `lib.rs`/`domain/mod.rs`/`application/mod.rs` 的 `mod` 声明 + re-export（≤5 行 additive，低冲突）。参考已实现域 crate `crates/audit/src/`（handler/application/domain 分层 + 订阅范式）。

## PR 拆分（5 个；≤2000 行净增删，含 ≥80% 覆盖率测试）

| PR | 子 PBI | 用户故事 | 主要文件 | 估行 | label | blocked-by |
|----|--------|---------|---------|------|-------|-----------|
| **PR1** 基座+RBAC | #1186 | US1 | `domain/mod.rs`(拆) `domain/rbac.rs` `lib.rs` | ~1250 | area-auth·type-enhancement·**cx-3**·pri-p1 | （基座；仅承 #1012/#999） |
| **PR2** ABAC | #1187 | US2 | `domain/abac.rs`（+`vocab::Decision` 视需最小改） | ~1230 | area-auth·type-enhancement·cx-3·pri-p1 | PR1 |
| **PR3** 身份/凭据+暴破临时阻断 | #1188 | US3 | `domain/account.rs` `ports.rs`(+CredentialRepo) `internal/mem.rs` | ~1520 | area-auth·type-enhancement·cx-3·pri-p2 | PR1 |
| **PR4** 会话+密码CAS | #1189 | US4 | `application/login.rs` `domain/session.rs` `ports.rs`(+SessionRepo) | ~1520 | area-auth·type-enhancement·cx-3·pri-p2 | PR1, PR3 |
| **PR5a** 角色事件契约+RbacAdminService | #1190 | US5（前半） | `contracts/event/identity/*` `generated/*` `application/rbac_admin.rs` | ~1000 | area-auth·type-enhancement·**cx-4**·pri-p2 | PR1, PR2, PR4 |
| **PR5b** HTTP端点契约+handler+contract test+生命周期升级 | #1190 | US5（后半） | `contracts/http/identity/*` `handler.rs` contract test + 生命周期升级 | ~1100 | area-auth·type-enhancement·cx-4·pri-p2 | PR5a |

> PR5 预定义拆为 PR5a / PR5b（各 ≤2000 行），不再等实际超 2000 才拆。子 PBI #1190 涵盖 5a/5b；若两单独立审查，5b 可另建工作项。覆盖率门命令：`cargo llvm-cov --lib -p identity`（新增代码 diff coverage，非全 crate 历史）。

## 并行 Wave 分析

- **Wave 1**：`PR1`（基座，单独）——确立 newtype + 模块拆分；其余全 blocked-by PR1。
- **Wave 2**：并行组 `PR2` ∥ `PR3`——各占 `domain/abac.rs` vs `domain/account.rs`+`ports.rs`，零业务交叉；唯一共享面 = `lib.rs`/`domain/mod.rs` 的 `mod` 声明（≤5 行 additive），低冲突、可 rebase 解。
- **Wave 3**：`PR4`（blocked-by PR3：消费 `CredentialRepo` 校验密码）。
- **Wave 4**：`PR5`（blocked-by PR4：登录 handler；PR2：authz handler 用 ABAC）。
- **临界路径**：PR1 → PR3 → PR4 → PR5（深度 4）；PR2 随 Wave 2 并行，不占临界路径。

## AI-HARD 约束（每个子 PR 验收硬核查项）

填 `todo!()` 体时**不得弱化既有静态强制**：domain 类型字段保持 `pub(crate)` + funnel 构造器（不放成 `pub`）；**不给 domain 类型加 `#[derive(Serialize)]`**（`rss_domain_no_serialize`，Medium）；port trait 保持 ADR-005 域形范式（不收敛 diport）；保留 #997 冻结签名与 INVARIANT（IDENTITY-AUTHZ-TENANT-01 等，跨租 fail-closed）；新契约走 contract-fanout 闭环（schema→generated→metadata→test→docs）；必填依赖构造器位置参（非 Option）；public 降级仅 generated Public evidence + GeneratedPrimaryEndpoint。

**新增核查项**：

1. **dynosaur/trait-variant wrapper 集合等价（DIPORT-MACRO-CONFINE-01′）**：定义新域形 repo port 后，确认 `deny.toml` `wrappers` 集合 与 xtask `EXTERNAL_CONFINEMENT_WRAPPERS` 两侧相等（identity 已在白名单，作显式核查，防漂移）。
2. **PolicyRule 冻结边界澄清**：#997 冻结的是跨 crate 接缝（`evaluate_abac` 公开签名，PR2 不改）；`PolicyRule` / `Policy` 是 `pub(crate)` 域类型、无跨 crate 消费方、无 public-api golden——PR2 扩 operator/effect 字段 + 同步更新 identity 自己的 `lib.rs` smoke test 属合法 crate 内 body 工作，**无需 ADR amendment**。
3. **#1833 认证安全漏斗**：删除 `lockout_status` 独立预检；`authenticate` 在一次事务中固定锁定 credential→account-security。Active receipt、合法 lifecycle mutation 和 refresh 初始签发入口由私有字段/可见性 Hard 约束；SQL 锁序与生产接线集合事实由并发、故障注入和 anti-vacuity 集成测试作 Medium 载体，不建立 Soft 约束。

## 调度风险备注

若 Wave 3（PR4）因 PR3 merge 延迟受阻，PR4 可先落 `Session` 域类型与 `SessionRepo` port 骨架（不依赖 `CredentialRepo`），待 PR3 merge 后再接入 `LoginService` 密码校验逻辑——降低临界路径串行风险。

## Complexity Tracking

无 Constitution 违规，本节为空。
