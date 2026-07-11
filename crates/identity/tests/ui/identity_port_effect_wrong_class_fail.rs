use diport::WriteEffect;
use identity::ports::{DynPolicyRepo, IdentityPortEffect};

fn require_write<T: IdentityPortEffect<Effect = WriteEffect> + ?Sized>() {}

fn main() {
    require_write::<DynPolicyRepo<'static>>();
}
