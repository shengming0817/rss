use diport::ReadEffect;
use identity::ports::{DynRoleDefinitionLifecycle, IdentityPortEffect};

type AllegedlyRead = DynRoleDefinitionLifecycle<'static>;

fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<AllegedlyRead>();
}
