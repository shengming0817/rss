use diport::ReadEffect;
use identity::ports::{DynRoleWriteRepo, IdentityPortEffect};

type AllegedlyRead = DynRoleWriteRepo<'static>;

fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<AllegedlyRead>();
}
