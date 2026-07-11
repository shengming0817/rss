use std::sync::Arc;

use audit::ports::{
    AuditPortEffect, DynAuditAdminRepo, DynAuditReadRepo, DynAuditWriteRepo,
};
use diport::{CrossTenantPrivilege, LocalPrivilege, ReadEffect, WriteEffect};

fn assert_read<T: AuditPortEffect<Effect = ReadEffect, Privilege = LocalPrivilege> + ?Sized>() {}
fn assert_write<T: AuditPortEffect<Effect = WriteEffect, Privilege = LocalPrivilege> + ?Sized>() {}
fn assert_cross_tenant_read<
    T: AuditPortEffect<Effect = ReadEffect, Privilege = CrossTenantPrivilege> + ?Sized,
>() {
}

fn main() {
    assert_read::<DynAuditReadRepo<'static>>();
    assert_read::<Arc<DynAuditReadRepo<'static>>>();
    assert_read::<Box<DynAuditReadRepo<'static>>>();
    assert_write::<DynAuditWriteRepo<'static>>();
    assert_write::<Arc<DynAuditWriteRepo<'static>>>();
    assert_write::<Box<DynAuditWriteRepo<'static>>>();
    assert_cross_tenant_read::<DynAuditAdminRepo<'static>>();
}
