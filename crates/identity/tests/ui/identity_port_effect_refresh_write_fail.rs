use diport::BusinessWriteEffect;
use identity::ports::{DynRefreshTokenStore, IdentityPortEffect};

fn require_write<T: IdentityPortEffect<Effect = BusinessWriteEffect> + ?Sized>() {}

fn main() {
    require_write::<DynRefreshTokenStore<'static>>();
}
