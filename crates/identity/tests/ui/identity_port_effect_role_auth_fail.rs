use diport::AuthEffect;
use identity::ports::{DynRoleRepo, IdentityPortEffect};

fn require_auth<T: IdentityPortEffect<Effect = AuthEffect> + ?Sized>() {}

fn main() {
    require_auth::<DynRoleRepo<'static>>();
}
