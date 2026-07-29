//! INVARIANT: AUDIT-PORT-CLASSIFICATION-01 { level = "Hard", exec = "test", source = "trybuild" }

use audit::ports::{AuditPortEffect, DynAuditAdminRepo};
use diport::LocalPrivilege;

fn require_local<T: AuditPortEffect<Privilege = LocalPrivilege> + ?Sized>() {}

fn main() {
    require_local::<DynAuditAdminRepo<'static>>();
}
