use diport::ReadEffect;
use identity::ports::{DynRoleRepo, IdentityPortEffect};

fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<DynRoleRepo<'static>>();
}
