use diport::ReadEffect;
use identity::ports::{DynRoleRepo, IdentityPortEffect};

type AllegedlyRead = DynRoleRepo<'static>;

fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<AllegedlyRead>();
}
