use diport::ReadEffect;
use identity::ports::{DynRoleWriteRepo, IdentityPortEffect};

fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<DynRoleWriteRepo<'static>>();
}
