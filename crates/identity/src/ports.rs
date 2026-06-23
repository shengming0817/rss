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

use dynosaur::dynosaur;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
pub use crate::domain::{IdentityError, Role, RoleId};
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
/// **W 阶段补真实 repo 接缝**（issue #1083 已 defer 的「repo/服务接缝 + PORT-SHAPE」）时须按需补齐：
/// - **可读 accessor**：adapter impl body 需读取实体时，把 `RoleId::as_str` / `Role::id|name|…` 由
///   `pub(crate)` 按需升 `pub`（当前 `pub(crate)` + body=`todo!()`，编译证明阶段不需读）。
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

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo port 可 native-AFIT impl + mockall mock（非 `#[async_trait]`）均经
    //! `Box<DynRoleRepo>` 装入（PORT-SHAPE-01/02）。
    //!
    //! 与 diport `signer.rs` smoke 的差异：identity 域类型构造器全为 `todo!()`（签名冻结，ADR-004 C8），
    //! 无法在运行期构造 `RoleId`/`Role`，故本 smoke **只构造 Dyn wrapper + 断言 `Send`，不 `.await`**（不触
    //! `todo!()`）。async future 的 Send + 跨 `tokio::spawn` 调度由 diport `signer.rs`
    //! `mockall_mock_loads_into_dyn_signer` 同范式已证（dynosaur Send 变体保证）。
    use super::{DynRoleRepo, IdentityError, Role, RoleId, RoleRepo, TenantId};

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
}
