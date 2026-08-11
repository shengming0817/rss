use diport::ReadEffect;
use identity::ports::{DynRoleDefinitionLifecycle, IdentityPortEffect};

fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_read::<DynRoleDefinitionLifecycle<'static>>();
}
