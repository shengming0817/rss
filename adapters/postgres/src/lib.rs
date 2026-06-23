//! postgres — RSS workspace crate (signature-frozen; RW-G0.2 PR-5). See docs/rules/architecture.md.
//!
//! 签名冻结（ADR-004 C7）：sealed-marker 以 **native AFIT** impl 已冻 DI port trait，body=`todo!()`。
//! raw client 字段待 W 阶段接后端时填入（届时保持 `pub(crate)`）；crate 保持 forbid(unsafe_code)（继承 workspace lints，不 invoke dynosaur 宏）。
//!
//! port 来源两类：provider-agnostic 基建 port 来自 `diport`（`ManagedResource`…）；**域形** repo port 来自
//! 所属域 crate（`identity::ports::RoleRepo`…，Option 2/ADR-005）。impl 域形 port 需依赖该域 crate
//! （`adapters→域` = DIP 内向边，经 deny.toml identity wrapper + `allows(Adapter,Domain)` 放行）；adapter
//! 仍不被域依赖、自身不 invoke dynosaur 宏。

use diport::{ManagedResource, ShutdownError};
use identity::ports::{IdentityError, Role, RoleId, RoleRepo, TenantId};

/// PostgreSQL 存储 adapter（sealed-marker）。raw client（`sqlx::PgPool` / 连接池句柄）字段待 W 阶段接后端时填入，保持 `pub(crate)`。
pub struct PgStore;

impl ManagedResource for PgStore {
    fn name(&self) -> &str {
        todo!()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        todo!()
    }
}

// 域形 repo port（identity::ports::RoleRepo）的 adapter 实现（ADR-005 Option 2 代表性编译证明）：
// native AFIT、无 #[async_trait]、不 invoke dynosaur 宏；body=todo!()（W 阶段接后端时填 sqlx 查询）。
// 此 impl 即 adapter→域 DIP 内向边的真实编译证明（postgres 依赖 identity、命名其 pub 实体 Role/RoleId）。
impl RoleRepo for PgStore {
    async fn find(&self, _tenant: TenantId, _id: RoleId) -> Result<Option<Role>, IdentityError> {
        todo!()
    }

    async fn save(&self, _tenant: TenantId, _role: Role) -> Result<(), IdentityError> {
        todo!()
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 DI port trait——diport 基建 port
    //! （`ManagedResource`）+ 域形 repo port（`identity::ports::RoleRepo`，adapter→域 DIP 边的编译证明）。
    //! PhantomData 绑定检查，不构造、不执行 `todo!()` body。
    //! INVARIANT: ADAPTER-PORT-FREEZE-06 —— sealed-marker impl 冻结的 DI port trait；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}
    fn assert_role_repo<T: identity::ports::RoleRepo>(_: PhantomData<T>) {}

    #[test]
    fn impls_frozen_ports() {
        assert_managed_resource(PhantomData::<super::PgStore>);
        assert_role_repo(PhantomData::<super::PgStore>);
    }
}
