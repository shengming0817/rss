use diport::AuthEffect;
use identity::ports::{DynRoleReadRepo, IdentityPortEffect};

fn require_auth<T: IdentityPortEffect<Effect = AuthEffect> + ?Sized>() {}

fn main() {
    require_auth::<DynRoleReadRepo<'static>>();
}
