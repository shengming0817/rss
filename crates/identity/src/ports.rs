//! identity::ports — 身份域**专属** repo / 领域服务 DI port（Option 2 / ADR-005）。
//!
//! 归属（ADR-005 category line）：provider-agnostic 基建 port（`Clock`/`Signer`/`Publisher`/`AuditSink`…）
//! 在 `diport`；**域形** repo port——签名引用域内实体（`Role`/`RoleId`，域 crate `pub(crate)`/`pub` 类型）——
//! **无法**收敛 `diport`（否则 diport→域 反向依赖、层序倒置、deny 红），故归本域 crate `ports` 模块。
//! adapter（如 `postgres`）依赖 `identity`、以 native AFIT impl 本 port（DIP 内向边，`adapters→域` 单向）。
//! 派发与 diport DI port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 + `#[dynosaur(...)]` `DynX`，
//! 构造器注入 `Box<DynRoleRepo>`（ADR-004 C1/C5）。
//!
//! 跨 crate 可见性：repo port 须 `pub`（独立 adapter crate impl）；签名实体 `Role`/`RoleId`/`IdentityError`
//! 经下方 `pub use` 暴露——字段私有 + 构造经 `pub(crate)` funnel，外部可命名/收发但**不可伪造**（fail-closed）。
//!
//! ref: oxidecomputer/omicron Cargo.toml@main（域 trait + 组合根注入范本，framework-comparison §域运行时/DI）
//! ref: Cockburn Hexagonal Ports&Adapters / Evans DDD Repository（repo 接口归域核心、adapter 经 DIP 实现）

use std::time::SystemTime;

use consistency::Entry;
use diport::{OutboxEmitError, OutboxEnvelopeParts};
use dynosaur::dynosaur;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
// reason: AccountStatus 自 #1277 起不再是任一 port 方法的入/出参（lockout 推进折叠进 `authenticate`，
// 返回 AuthOutcome）；保留 `pub` 导出是为后续账户门控 handler（PR5/W）跨 crate 消费的账户状态闭值集，
// 当前作 `AccountLockout::record_failure` 的域内推进结果类型。其余符号均为现役 port 签名实体。
pub use crate::domain::{
    AccountStatus, AuthOutcome, Credential, IdentityError, LoginIdentifier, Role, RoleId, Session,
    SessionId,
};
pub use vocab::TenantId;

/// 角色仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`RoleRepo`] 是 **Send 变体**（adapter `impl RoleRepo for ...`），[`DynRoleRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynRoleRepo>` 注入）。非 Send 基 trait [`RoleRepoLocal`] 仅供
/// 静态分发窄场景，不在 crate 根 re-export（同 diport `XLocal` 约定）。
///
/// dyn-safe（ADR-003 §4.6）：方法 `&self`、参数/返回为具体类型、supertrait 仅 Send。归属为域形 port
/// （签名引用 `Role`/`RoleId`）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
///
/// ⚠ **范围 = ADR-005 分层放宽的最小编译证明，非完整生产 repo 设计范式（勿照抄查询集）**。本 port 只为
/// 验证 `adapter→域` DIP 内向边 + 域内 dynosaur + `pub` 实体真实编译。安全 scope 已由签名承载：
/// `Role` 按租户内角色建模，repo 方法必须接收 typed `TenantId` 位置参做 RLS / store scope；若后续需要
/// 全局角色定义，须拆独立 `GlobalRoleRepo`，不得复用本租户内 repo 签名。
/// **W 阶段补真实 repo 接缝**（RoleRepo 自身的 roles 表 + RBAC 持久化属后续，与 #1083 session 接缝解耦；
/// session co-tx 接缝已由 sibling [`SessionUnitOfWork`] 交付——#1083/#1192，postgres `PgSessionUnitOfWork`）
/// 时须按需补齐：
/// - **可读 accessor**：adapter impl body 需读取实体时，把 `RoleId::as_str` / `Role::id|name|…` 由
///   `pub(crate)` 按需升 `pub`（accessor body PR1 已写实，仅可见性仍 `pub(crate)`；编译证明阶段不需跨 crate 读）。
///   ——session 实体的同款升 `pub` 已在 [`SessionUnitOfWork`] 落地（[`Session`] accessor 真升 `pub`）。
/// - **查询形态**：按业务补 `list_by_tenant` / `find_by_name` / `exists` 等惯用方法 + 强制分页（`limit≤500`）。
#[trait_variant::make(RoleRepo: Send)]
#[dynosaur(pub DynRoleRepo = dyn(box) RoleRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RoleRepo` 变体 + dynosaur
// `DynRoleRepo` 承载（DI 注入走 Send wrapper）。与 diport DI port 同范式（ADR-003/ADR-004 C1）。body=todo!()
// （签名冻结，ADR-004 C8）。
pub trait RoleRepoLocal {
    /// 按 ID 查角色（不存在返回 `Ok(None)`）。
    async fn find(&self, tenant: TenantId, id: RoleId) -> Result<Option<Role>, IdentityError>;

    /// 持久化角色（upsert）。
    async fn save(&self, tenant: TenantId, role: Role) -> Result<(), IdentityError>;
}

/// 凭据仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`CredentialRepo`] 是 **Send 变体**（adapter `impl CredentialRepo for ...`），[`DynCredentialRepo`]
/// 是其 dyn-compatible wrapper（组合根经 `Box<DynCredentialRepo>` 注入，ADR-004 C1/C5）。归属为域形 port
/// （签名引用 `Credential`/`LoginIdentifier`/`AuthOutcome`）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
///
/// **租户隔离由签名承载（fail-closed）**：所有方法接收 typed `TenantId` 位参做 RLS / store scope；跨租赁
/// 经 tenant-keyed 查找天然失败——`find(t ≠ cred.tenant)` → `None`，`authenticate` → `InvalidUnknown`，
/// 不创建会话、不推进锁定计数（spec 003 US3 跨租红用例）。
///
/// **与 `RoleRepo` 差异**：本 port 在 PR3 已有写实 in-mem 替身（[`crate::internal`]），非纯签名冻结——
/// 锁定态推进是多实例暴破防御的硬需求（内存态多实例不共享则失效），由**原子 port 方法**承载（见下）。
/// 生产 postgres adapter impl 仍留 W（随 #1116 postgres adapter 落地）；届时 `Credential` / `AccountLockout`
/// 的跨 crate 重建 + 只读 accessor 公开化与 `RoleRepo` 同步走 W（accessor 升 `pub` / `from_persisted` funnel，
/// 见 #1258）——本 PR 编译证明阶段无独立 adapter，替身在同 crate 用 `pub(crate)`。
///
/// **租户/主体一致性 = 类型层 Hard（F2）**：携带完整 `Credential` 的写方法（`save` / `bump_version`）**不收**
/// 独立 `tenant`/`login` 参，store key 直接派生自 `credential.tenant()` / `.login()`——错位组合不可表达
/// （零信任租户隔离不靠调用方约定 / debug_assert）。只持标识的方法：`authenticate` / `lockout_status` 收
/// typed `TenantId` + [`LoginIdentifier`]（登录路径，攻击者可控查找键）；`find_by_user_id` 收 `TenantId` +
/// `ids::UserId`（self-scoped 改密路径，认证主体锚点，#1277 F2）——二者皆经 tenant-keyed 查找天然 fail-closed。
///
/// **验签 + 锁定推进原子化（F1+F2，#1277）**：失败计数 = 安全关键状态，**禁**外部「读-改-写」（并发丢更新）。
/// `authenticate` 在 provider 内单次原子完成「恒定成本验签 + 据已知/未知主体分流推进 lockout」，返回
/// [`AuthOutcome`]——已知+正确清零、已知+错推进、未知不动；登录枚举防御（constant-time KDF）与真实账号
/// lockout 推进收进**单一原子结果**，「对未知主体建锁」从此无 API 可表达（F2 Hard：未知主体不可预置锁定、
/// 不撑大 lockout 表）。`lockout_status` 仅做验签前预门控的原子 lazy-unlock 查询。in-mem = 锁内、
/// postgres = 事务/行锁/条件 upsert。
/// ref: kubernetes client-go RetryOnConflict（并发更新显式版本化）。
/// ref: keycloak DefaultBruteForceProtector.java@main（`failedLogin` 入参为已解析 `UserModel` +
/// `permanentUserLockOut` 的 `getUserById != null` guard：brute-force 计数仅对已知主体推进；RSS 以
/// `AuthOutcome` typed 分流强化为类型层 Hard——`InvalidUnknown` 变体在类型层即与计数路径隔离）。
///
/// **owned 参数**：与既有 DI port（diport / `RoleRepo`）一致——async dyn port 用 owned 参规避借用生命周期、简化
/// dynosaur `bridge(dyn)` 装配；消费方调用即弃，代价仅一次 `LoginIdentifier::new`。
#[trait_variant::make(CredentialRepo: Send)]
#[dynosaur(pub DynCredentialRepo = dyn(box) CredentialRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 RoleRepo——base trait 非 Send native AFIT，Send 由 trait_variant `CredentialRepo` 变体 +
// dynosaur `DynCredentialRepo` 承载（ADR-003/ADR-004 C1）。
pub trait CredentialRepoLocal {
    /// 按 canonical user id 查凭据（tenant-scoped；不存在返回 `Ok(None)`）。self-scoped 操作（改密）的身份
    /// 锚点是**认证主体**的 `ids::UserId`，**非**请求可选择的登录标识——调用方不能传 login 串定位他人凭据
    /// （#1277 F2：self-scoped 端点身份锚点 = authenticated subject，类型层杜绝越权改他人密码）。
    async fn find_by_user_id(
        &self,
        tenant: TenantId,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError>;

    /// **恒定成本验签 + 原子锁定记账**（F1+F2+F3，#1277）：无论凭据是否存在，候选明文总跑一次 argon2 KDF
    /// （经 `secure::verify_password_constant_time`）——消除「无此主体（跳 KDF 快返回）」与「密码错（跑 KDF）」
    /// 的登录枚举时序差。provider 内据 `(tenant, login)` 查得凭据与否，**原子**分流返回 [`AuthOutcome`]：
    /// - 已知 + 密码正确 → `Authenticated(user_id)`（canonical actor subject，写 wire/audit）+ 清零失败计数；
    /// - 已知 + 密码错 → `InvalidKnownUser` + 原子推进 lockout（达阈值即锁）；
    /// - 查无凭据 → `InvalidUnknown`，**不建/不动 lockout 态**（F2：未知主体不可被预置锁定、不撑大 lockout 表）。
    ///
    /// `now` 由调用方注入 `Clock` 读出（禁 `SystemTime::now()`，clippy 静态守）。消费方（`LoginService`）对
    /// `InvalidKnownUser` / `InvalidUnknown` 一律对外 `InvalidCredentials`（不向客户端区分以防枚举）。
    ///
    /// **provider 实现要求（postgres adapter W，#1258）**：① 验签 + lockout 推进须在**单次原子**（事务/行锁/
    /// 条件 upsert）内完成；② `InvalidKnownUser` 与 `InvalidUnknown` 的 RTT 差异 SHOULD 不超过 argon2 KDF 噪音
    /// 量级——即 lockout 写（仅已知主体路径有）不得引入主体枚举可观测时序差（必要时未知主体路径补等价空写
    /// 或已知主体路径异步推进）。in-mem 替身经 Mutex 内 KDF 主导，天然满足。
    async fn authenticate(
        &self,
        tenant: TenantId,
        login: LoginIdentifier,
        candidate: String,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError>;

    /// 持久化凭据（upsert）。store key 派生自 `credential`（F2：tenant/login 错位不可表达）。
    async fn save(&self, credential: Credential) -> Result<(), IdentityError>;

    /// 密码变更 CAS：仅当存储版本 == `expected` 时以 `next` 替换；版本不匹配 → `Err(VersionConflict)`，
    /// 查无凭据 → `Err(CredentialNotFound)`（并发密码变更安全）。store key 派生自 `next`（F2）；消费方经
    /// `Credential::rotate`（保持 login/user_id/tenant、version + 1）构造 `next`。
    async fn bump_version(&self, expected: u32, next: Credential) -> Result<(), IdentityError>;

    /// **原子**锁定态查询（F1，验签前门控）：provider 内 RMW 完成「读 → `try_lazy_unlock(now)`（TTL 过则解锁
    /// 并持久化）→ 返回 `is_locked(now)`」。无锁定态（查无）→ `Ok(false)`。`now` 经注入 `Clock`。
    async fn lockout_status(
        &self,
        tenant: TenantId,
        login: LoginIdentifier,
        now: SystemTime,
    ) -> Result<bool, IdentityError>;
}

/// 会话仓储 DI port（域形；provider 可换：prod postgres / test in-mem）。logout 软撤销 + 会话查询。
///
/// 公开 [`SessionRepo`] 是 **Send 变体**（adapter `impl SessionRepo for ...`），[`DynSessionRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynSessionRepo>` 注入）。
///
/// 租户隔离由签名承载（fail-closed，同 `CredentialRepo`）：方法接收 typed `TenantId`，跨租 find→None /
/// revoke→幂等 no-op。
///
/// 会话**创建**不在本 port——登录经 `SessionUnitOfWork` co-tx（L2，session 行+outbox 同一事务）创建；本 port 仅
/// L1 查询/撤销（spec 003 data-model「SessionRepo::create 仅 L1 子步骤、不单独成契约边界」+ OUTBOX-COTX-SESSION-01）。
///
/// ref: oxidecomputer/omicron（域 trait + 组合根 DI）；Cockburn Hexagonal Ports&Adapters（repo 归域核心，adapter DIP 实现）
#[trait_variant::make(SessionRepo: Send)]
#[dynosaur(pub DynSessionRepo = dyn(box) SessionRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 RoleRepo——base trait 非 Send native AFIT，Send 由 trait_variant `SessionRepo` 变体 + dynosaur 承载。
pub trait SessionRepoLocal {
    /// 按 id 查会话（不存在 / 已撤销 / 跨租 → Ok(None)，不泄露存在性）。
    async fn find(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError>;
    /// 域侧**软撤销**会话（logout；幂等——重复/未知/跨租均 Ok 且 no-op）。已颁 JWT 在 TTL 内仍有效（硬吊销延 #1003）。
    async fn revoke(&self, tenant: TenantId, session_id: SessionId) -> Result<(), IdentityError>;
}

/// 会话 **co-tx** Unit-of-Work DI port（async；provider 可换：prod postgres / demo in-mem）。
///
/// L2 OutboxFact 完整语义（FR-003）：一次登录的**业务写**（[`Session`] 持久化）与 **outbox append**
/// （`identity.session-created` 事件行）必须落在**同一个本地事务**——both-or-neither。本 port 以**单个
/// combined 方法**承载该原子性：域只调一次 [`persist_session_and_emit`](SessionUnitOfWorkLocal::persist_session_and_emit)，
/// adapter 在其 impl body 内独占事务边界（begin → 写 session → append_outbox → 单 commit）。
///
/// **为何是 combined 方法、而非「`SessionRepo::save` + `OutboxEmitter::emit` 两调用」或 closure-UoW**：
/// 拆成两个 provider-agnostic 端口调用，域无法把二者绑进同一事务（端口签名不容 `&mut PgConnection`，
/// 否则 `ports`→adapter 反向耦合）；closure-UoW 把事务句柄回传给域，同样泄漏 provider 类型并**重开
/// split-tx 洞**。combined 方法把事务边界完全收进 adapter，域**无 API 可半提交其一**——co-tx 不可拆解
/// 在类型层成立（Hard）。adapter 侧 same-tx 接线由 postgres `PgSessionUnitOfWork` 的
/// **INVARIANT: OUTBOX-COTX-SESSION-01** + 集成测试 anti-vacuity（commit 两行皆在 ↔ rollback 两行皆无）守。
///
/// 失败经 [`OutboxEmitError`]（diport infra 错误，source 已 PII-redacted）冒泡——co-tx 写失败（session
/// INSERT / outbox append / commit 任一步）均不暴露原始错误明文（zero-trust）。复用 `OutboxEmitError` 而非
/// 新增域错误：本 port 签名已桥接 infra 类型（[`Entry`] / [`OutboxEnvelopeParts`]），失败本质是持久化层
/// 错误而非域逻辑错误，语义一致。
///
/// 归属：域形 port（签名引用域内实体 [`Session`]）→ 本 crate `ports`，非 diport（ADR-005 category line，
/// 同 [`RoleRepo`]）。
///
/// ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable）
/// ref: MassTransit Bus Outbox（一应用方法 co-persist 实体 + outbox 经共享事务/scoped DbContext）
#[trait_variant::make(SessionUnitOfWork: Send)]
#[dynosaur(pub DynSessionUnitOfWork = dyn(box) SessionUnitOfWork, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `SessionUnitOfWork` 变体 +
// dynosaur `DynSessionUnitOfWork` 承载（DI 注入走 Send wrapper）。与 RoleRepo / diport DI port 同范式。
pub trait SessionUnitOfWorkLocal {
    /// 把 [`Session`] 行与 outbox(`identity.session-created`) 行**同一本地事务**原子写入（co-tx，FR-003）。
    ///
    /// 域构造 `entry`（事件语义归域：topic + opaque-UUID EventId + 编码 payload）与 `envelope`
    /// （opaque envelope 字段），并提供 `session` 业务实体；adapter 在单事务内先注入 tenant scope
    /// （SET LOCAL）、写 session、`append_outbox`，单 commit。任一步失败 → 整体 rollback（both-or-neither）。
    async fn persist_session_and_emit(
        &self,
        session: Session,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo port 可 native-AFIT impl + mockall mock（非 `#[async_trait]`）均经
    //! `Box<DynRoleRepo>` 装入（PORT-SHAPE-01/02）。
    //!
    //! 与 diport `signer.rs` smoke 的差异：identity 域类型（`RoleId`/`Role`）构造器 **PR1 已写实**，但本 port
    //! 的 repo impl（`NoopRoleRepo` / mock）方法 body 仍 `todo!()`（真实 repo 接缝待 W，issue #1083），故本
    //! smoke **只构造 Dyn wrapper + 断言 `Send`，不 `.await`**（不触 repo `todo!()`）。async future 的 Send + 跨
    //! `tokio::spawn` 调度由 diport `signer.rs` `mockall_mock_loads_into_dyn_signer` 同范式已证（dynosaur Send 变体保证）。
    use super::{
        DynRoleRepo, DynSessionRepo, DynSessionUnitOfWork, Entry, IdentityError, OutboxEmitError,
        OutboxEnvelopeParts, Role, RoleId, RoleRepo, Session, SessionId, SessionRepo,
        SessionUnitOfWork, TenantId,
    };

    struct NoopRoleRepo;
    impl RoleRepo for NoopRoleRepo {
        async fn find(
            &self,
            _tenant: TenantId,
            _id: RoleId,
        ) -> Result<Option<Role>, IdentityError> {
            todo!()
        }
        async fn save(&self, _tenant: TenantId, _role: Role) -> Result<(), IdentityError> {
            todo!()
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体
    // `DynRoleRepo` 且 wrapper `Send`（可跨 spawn 注入）。不调用方法 → 不触 `todo!()`。
    #[test]
    fn role_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynRoleRepo> = DynRoleRepo::new_box(NoopRoleRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynRoleRepo> = DynRoleRepo::new_box(MockTestRoleRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——test-only service 把 `Box<DynRoleRepo>` 作必填
    // 位置参（非 Option），缺失即编译错误（ADR-004 C5）。impl/mock 各注入一次，证明域形 repo port 与
    // 既有 DI port 一致经 `Box<DynX>` 注入（不调用方法 → 不触 `todo!()`）。
    struct RoleService {
        _repo: Box<DynRoleRepo<'static>>,
    }
    impl RoleService {
        fn new(repo: Box<DynRoleRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn role_repo_is_required_ctor_injectable() {
        let from_impl = RoleService::new(DynRoleRepo::new_box(NoopRoleRepo));
        assert_send(&from_impl._repo);
        let from_mock = RoleService::new(DynRoleRepo::new_box(MockTestRoleRepo::new()));
        assert_send(&from_mock._repo);
    }

    // mock 是 native trait impl（`async fn` 直接声明，非 `#[async_trait]`），经 `new_box` 进 `DynRoleRepo`。
    mockall::mock! {
        TestRoleRepo {}
        impl RoleRepo for TestRoleRepo {
            async fn find(
                &self,
                tenant: TenantId,
                id: RoleId,
            ) -> Result<Option<Role>, IdentityError>;
            async fn save(&self, tenant: TenantId, role: Role) -> Result<(), IdentityError>;
        }
    }

    // ── SessionUnitOfWork（co-tx 域形 port）PORT-SHAPE ────────────────────────────
    // 与 RoleRepo 不同：本 port 在 postgres adapter 有**真实 impl**（PgSessionUnitOfWork），但本 smoke 仍
    // 只构造 Dyn wrapper + 断言 `Send`（不 `.await` → 不触 Noop `todo!()`）；co-tx 行为由 adapter 集成测试守。
    struct NoopSessionUoW;
    impl SessionUnitOfWork for NoopSessionUoW {
        async fn persist_session_and_emit(
            &self,
            _session: Session,
            _entry: Entry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            todo!()
        }
    }

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体且 `Send`。
    #[test]
    fn session_uow_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynSessionUnitOfWork> = DynSessionUnitOfWork::new_box(NoopSessionUoW);
        assert_send(&from_impl);
        let from_mock: Box<DynSessionUnitOfWork> =
            DynSessionUnitOfWork::new_box(MockTestSessionUoW::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——`Box<DynSessionUnitOfWork>` 作必填位置参（非 Option），
    // 缺失即编译错误（ADR-004 C5；LoginService 即如此持有，见 application.rs）。
    struct SessionService {
        _uow: Box<DynSessionUnitOfWork<'static>>,
    }
    impl SessionService {
        fn new(uow: Box<DynSessionUnitOfWork<'static>>) -> Self {
            Self { _uow: uow }
        }
    }

    #[test]
    fn session_uow_is_required_ctor_injectable() {
        let from_impl = SessionService::new(DynSessionUnitOfWork::new_box(NoopSessionUoW));
        assert_send(&from_impl._uow);
        let from_mock =
            SessionService::new(DynSessionUnitOfWork::new_box(MockTestSessionUoW::new()));
        assert_send(&from_mock._uow);
    }

    mockall::mock! {
        TestSessionUoW {}
        impl SessionUnitOfWork for TestSessionUoW {
            async fn persist_session_and_emit(
                &self,
                session: Session,
                entry: Entry,
                envelope: OutboxEnvelopeParts,
            ) -> Result<(), OutboxEmitError>;
        }
    }

    // ── SessionRepo（域形会话仓储 port）PORT-SHAPE ────────────────────────────
    // 软撤销（logout）+ 会话查询接缝。创建不在本 port（co-tx 由 SessionUnitOfWork 承载）。
    struct NoopSessionRepo;
    impl SessionRepo for NoopSessionRepo {
        async fn find(
            &self,
            _tenant: TenantId,
            _session_id: SessionId,
        ) -> Result<Option<Session>, IdentityError> {
            todo!()
        }
        async fn revoke(
            &self,
            _tenant: TenantId,
            _session_id: SessionId,
        ) -> Result<(), IdentityError> {
            todo!()
        }
    }

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体
    // `DynSessionRepo` 且 wrapper `Send`（可跨 spawn 注入）。不调用方法 → 不触 `todo!()`。
    #[test]
    fn session_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynSessionRepo> = DynSessionRepo::new_box(NoopSessionRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynSessionRepo> = DynSessionRepo::new_box(MockTestSessionRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——test-only service 把 `Box<DynSessionRepo>` 作必填
    // 位置参（非 Option），缺失即编译错误（ADR-004 C5）。
    struct SessionQueryService {
        _repo: Box<DynSessionRepo<'static>>,
    }
    impl SessionQueryService {
        fn new(repo: Box<DynSessionRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn session_repo_is_required_ctor_injectable() {
        let from_impl = SessionQueryService::new(DynSessionRepo::new_box(NoopSessionRepo));
        assert_send(&from_impl._repo);
        let from_mock =
            SessionQueryService::new(DynSessionRepo::new_box(MockTestSessionRepo::new()));
        assert_send(&from_mock._repo);
    }

    mockall::mock! {
        TestSessionRepo {}
        impl SessionRepo for TestSessionRepo {
            async fn find(
                &self,
                tenant: TenantId,
                session_id: SessionId,
            ) -> Result<Option<Session>, IdentityError>;
            async fn revoke(
                &self,
                tenant: TenantId,
                session_id: SessionId,
            ) -> Result<(), IdentityError>;
        }
    }
}

#[cfg(test)]
mod smoke_credential {
    //! build smoke：`CredentialRepo` 域形 async port 同范式（PORT-SHAPE-01/02）——native-AFIT impl +
    //! mockall mock 均经 `Box<DynCredentialRepo>` 装入 + `Send`。`NoopCredentialRepo` body `todo!()`，
    //! 故只构造 Dyn wrapper + 断言 `Send`，**不 `.await`**（真实行为由 `internal::mem::InMemCredentialRepo`
    //! round-trip 测试覆盖）。
    use super::{
        AuthOutcome, Credential, CredentialRepo, DynCredentialRepo, IdentityError, LoginIdentifier,
        SystemTime, TenantId,
    };

    struct NoopCredentialRepo;
    impl CredentialRepo for NoopCredentialRepo {
        async fn find_by_user_id(
            &self,
            _tenant: TenantId,
            _user_id: ids::UserId,
        ) -> Result<Option<Credential>, IdentityError> {
            todo!()
        }
        async fn authenticate(
            &self,
            _tenant: TenantId,
            _login: LoginIdentifier,
            _candidate: String,
            _now: SystemTime,
        ) -> Result<AuthOutcome, IdentityError> {
            todo!()
        }
        async fn save(&self, _credential: Credential) -> Result<(), IdentityError> {
            todo!()
        }
        async fn bump_version(
            &self,
            _expected: u32,
            _next: Credential,
        ) -> Result<(), IdentityError> {
            todo!()
        }
        async fn lockout_status(
            &self,
            _tenant: TenantId,
            _login: LoginIdentifier,
            _now: SystemTime,
        ) -> Result<bool, IdentityError> {
            todo!()
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    // PORT-SHAPE-01：impl + mock 均经 `new_box` 装入 dynosaur Send 变体 `DynCredentialRepo` 且 `Send`。
    #[test]
    fn credential_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynCredentialRepo> = DynCredentialRepo::new_box(NoopCredentialRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynCredentialRepo> =
            DynCredentialRepo::new_box(MockTestCredentialRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧构造器必填位置参注入（`Box<DynCredentialRepo>` 非 Option，缺失即编译错误）。
    struct CredentialService {
        _repo: Box<DynCredentialRepo<'static>>,
    }
    impl CredentialService {
        fn new(repo: Box<DynCredentialRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn credential_repo_is_required_ctor_injectable() {
        let from_impl = CredentialService::new(DynCredentialRepo::new_box(NoopCredentialRepo));
        assert_send(&from_impl._repo);
        let from_mock =
            CredentialService::new(DynCredentialRepo::new_box(MockTestCredentialRepo::new()));
        assert_send(&from_mock._repo);
    }

    mockall::mock! {
        TestCredentialRepo {}
        impl CredentialRepo for TestCredentialRepo {
            async fn find_by_user_id(&self, tenant: TenantId, user_id: ids::UserId) -> Result<Option<Credential>, IdentityError>;
            async fn authenticate(&self, tenant: TenantId, login: LoginIdentifier, candidate: String, now: SystemTime) -> Result<AuthOutcome, IdentityError>;
            async fn save(&self, credential: Credential) -> Result<(), IdentityError>;
            async fn bump_version(&self, expected: u32, next: Credential) -> Result<(), IdentityError>;
            async fn lockout_status(&self, tenant: TenantId, login: LoginIdentifier, now: SystemTime) -> Result<bool, IdentityError>;
        }
    }
}
