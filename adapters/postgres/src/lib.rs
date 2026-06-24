//! postgres — RSS workspace crate（eventexec 持久化基座；P3/#1116）。See docs/rules/architecture.md.
//!
//! sealed-marker [`PgStore`] 持 `sqlx::PgPool`（`pub(crate)`），提供连接池（[`PgStore::connect`]）、
//! 事务运行器（[`PgStore::run_in_transaction`]）、Migrator（[`PgStore::run_migrations`]），并 impl
//! `diport::ManagedResource`（关池接入 `bootstrap::ShutdownStack` 逆序编排）。
//!
//! port 来源两类：provider-agnostic 基建 port 来自 `diport`（`ManagedResource`…）；**域形** repo port 来自
//! 所属域 crate（`identity::ports::RoleRepo`…，Option 2/ADR-005）。事务运行器是**普通 inherent 方法**
//! （非 dynosaur DI port）——签名暴露 `&mut sqlx::PgConnection`，放 provider-agnostic 的 `diport` 会破坏其
//! 不变式（#1116 决策 1）；且为 `pub(crate)`（裸事务非公开 API，review F2）。
//!
//! adapter→域 DIP 内向边（postgres 依赖 identity、impl 其 `RoleRepo`，经 deny.toml identity wrapper +
//! `allows(Adapter,Domain)` 放行；adapter 仍不被域依赖）由 `#[cfg(test)]` 的 **edge proof** 类型承载——
//! **不**让可构造的生产 `PgStore` 挂未实现的 `RoleRepo`（否则运行时 `todo!()` panic，review F3）；真实
//! postgres-backed `RoleRepo` 属 identity 域 W 阶段（需 roles 表 + tenant RLS）。

mod checkpoint;
mod dead_letter;
mod emitter;
mod inbox;
mod migrator;
mod outbox;
mod pool;
mod saga_journal;
mod session_uow;
mod tx;

pub use checkpoint::PgCheckpointStore;
pub use dead_letter::PgDeadLetterStore;
pub use emitter::PgEmitter;
pub use outbox::PgOutbox;
pub use saga_journal::PgSagaJournal;
pub use session_uow::PgSessionUnitOfWork;

#[cfg(all(test, feature = "integration"))]
mod integration_tests;

#[cfg(all(test, feature = "integration"))]
mod test_pg;

pub use inbox::PgInboxStore;
pub use pool::{PgConfig, PgError, PgPassword};
// re-export sqlx 的 TLS 模式枚举，组合根经 `PgConfig::with_ssl_mode` 配置时无需直接依赖 sqlx。
pub use sqlx::postgres::PgSslMode;

use diport::{ManagedResource, ShutdownError};
use sqlx::PgPool;

/// `ManagedResource::name` 稳定标识（日志 / 超时报错用）。
pub(crate) const PG_STORE_NAME: &str = "postgres";

/// PostgreSQL 存储 adapter（sealed-marker）。持 `sqlx::PgPool`（`pub(crate)`，仅 crate 内 repo / tx /
/// migrator impl 取用）；经 [`PgStore::connect`] 构造。
pub struct PgStore {
    pub(crate) pool: PgPool,
}

impl ManagedResource for PgStore {
    fn name(&self) -> &str {
        PG_STORE_NAME
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: graceful 关池（等连接归还后关闭）；sqlx `Pool::close` 不返错，故恒 Ok。
        self.pool.close().await;
        tracing::info!(target: "postgres", name = PG_STORE_NAME, "postgres pool closed");
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言冻结的 DI port trait——生产 `PgStore` impl `diport::ManagedResource`；
    //! adapter→域 DIP 内向边（postgres 可 impl `identity::ports::RoleRepo`，命名其 pub 实体 Role/RoleId）由
    //! `#[cfg(test)]` 的 `RoleRepoEdgeProof` 承载——**不**挂在可构造的生产 `PgStore` 上（避免运行时 todo!()
    //! panic，review F3）。PhantomData 绑定检查，不构造、不执行 body。
    //! INVARIANT: ADAPTER-PORT-FREEZE-06 —— ManagedResource on PgStore + RoleRepo edge proof +
    //! IdempotencyStore on PgInboxStore + SagaJournal on PgSagaJournal +
    //! OwnerCheckpointStore on PgCheckpointStore + SessionUnitOfWork on PgSessionUnitOfWork（真实 impl，#1083/#1192）；
    //! 去掉任一即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    use identity::ports::{IdentityError, Role, RoleId, RoleRepo, TenantId};

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_role_repo<T: identity::ports::RoleRepo>(_: PhantomData<T>) {}
    fn assert_session_uow<T: identity::ports::SessionUnitOfWork>(_: PhantomData<T>) {}
    fn assert_idempotency_store<T: consistency::IdempotencyStore>(_: PhantomData<T>) {}
    fn assert_saga_journal<T: diport::SagaJournal>(_: PhantomData<T>) {}
    fn assert_checkpoint_store<T: diport::OwnerCheckpointStore>(_: PhantomData<T>) {}

    /// adapter→域 DIP 内向边编译证明：postgres 依赖 identity 并 impl 其域形 `RoleRepo`（native AFIT，
    /// 不 invoke dynosaur 宏）。仅作类型级编译证明（PhantomData 绑定），body 永不执行；真实 postgres-backed
    /// `RoleRepo` 属 identity 域 W 阶段（需 roles 表 + tenant RLS）。
    struct RoleRepoEdgeProof;

    impl RoleRepo for RoleRepoEdgeProof {
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

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::PgStore>);
        assert_role_repo(PhantomData::<RoleRepoEdgeProof>);
        // `PgSessionUnitOfWork: SessionUnitOfWork` 真实 impl（非 edge proof）——co-tx UoW（#1083/#1192）。
        assert_session_uow(PhantomData::<super::PgSessionUnitOfWork>);
        // `PgInboxStore: IdempotencyStore` 类型级 anti-vacuity edge proof（不构造、不执行 body）。
        assert_idempotency_store(PhantomData::<super::PgInboxStore>);
        // `PgSagaJournal: SagaJournal` + `PgCheckpointStore: OwnerCheckpointStore` edge proof。
        assert_saga_journal(PhantomData::<super::PgSagaJournal>);
        assert_checkpoint_store(PhantomData::<super::PgCheckpointStore>);
    }

    #[test]
    fn store_name_is_stable() {
        assert_eq!(super::PG_STORE_NAME, "postgres");
    }
}
