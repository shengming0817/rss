//! Single-owner PostgreSQL provider for the AuthGrant root and its refresh family.
//!
//! Login composition receives this one value and cannot independently select lifecycle and
//! refresh stores. The two focused implementations remain private implementation details owned by
//! the same verified reader/writer capability bundle.

use identity::ports::AuthGrantProvider;

use crate::{PgAuthGrantLifecycle, PgRefreshTokenStore};

/// Opaque owner used by [`identity::AuthGrantServices`].
pub struct PgAuthGrantProvider {
    lifecycle: PgAuthGrantLifecycle,
    refresh: PgRefreshTokenStore,
}

impl PgAuthGrantProvider {
    pub(crate) fn new(lifecycle: PgAuthGrantLifecycle, refresh: PgRefreshTokenStore) -> Self {
        Self { lifecycle, refresh }
    }
}

impl AuthGrantProvider for PgAuthGrantProvider {
    type Lifecycle = PgAuthGrantLifecycle;
    type RefreshStore = PgRefreshTokenStore;

    fn into_auth_grant_parts(self) -> (Self::Lifecycle, Self::RefreshStore) {
        (self.lifecycle, self.refresh)
    }
}

#[cfg(test)]
mod tests {
    use super::PgAuthGrantProvider;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn provider_owner_is_send_sync() {
        assert_send_sync::<PgAuthGrantProvider>();
    }
}
