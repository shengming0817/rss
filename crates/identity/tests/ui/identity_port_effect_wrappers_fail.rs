use std::sync::Arc;

use diport::{AuthEffect, ReadEffect};
use identity::ports::{DynRoleDefinitionLifecycle, DynRoleReadRepo, IdentityPortEffect};

fn require_auth<T: IdentityPortEffect<Effect = AuthEffect> + ?Sized>() {}
fn require_read<T: IdentityPortEffect<Effect = ReadEffect> + ?Sized>() {}

fn main() {
    require_auth::<Arc<DynRoleReadRepo<'static>>>();
    require_read::<Box<DynRoleDefinitionLifecycle<'static>>>();
}
