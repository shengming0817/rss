use diport::AuthEffect;
use identity::ports::{DynResourceSecurityFactReadRepo, IdentityPortEffect};

fn require_auth<T: IdentityPortEffect<Effect = AuthEffect> + ?Sized>() {}

fn main() {
    require_auth::<DynResourceSecurityFactReadRepo<'static>>();
}
