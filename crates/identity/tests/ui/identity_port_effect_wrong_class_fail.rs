use diport::BusinessWriteEffect;
use identity::ports::{DynPolicyRepo, IdentityPortEffect};

fn require_write<T: IdentityPortEffect<Effect = BusinessWriteEffect> + ?Sized>() {}

fn main() {
    require_write::<DynPolicyRepo<'static>>();
}
