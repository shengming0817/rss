use audit::ports::{AuditPortEffect, DynAuditWriteRepo};
use diport::ReadEffect;

fn require_read<T: AuditPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<DynAuditWriteRepo<'static>>();
}
