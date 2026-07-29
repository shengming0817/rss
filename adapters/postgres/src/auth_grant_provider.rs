//! Single-owner PostgreSQL provider for the AuthGrant root and its refresh family.
//!
//! Login composition receives this one value and cannot independently select lifecycle and
//! refresh stores. The two focused implementations remain private implementation details owned by
//! the same verified reader/writer capability bundle.

use identity::ports::AuthGrantProvider;

use crate::{PgAuthGrantLifecycle, PgIdentitySecurityLifecycle, PgRefreshTokenStore};

/// Opaque owner used by [`identity::AuthGrantServices`].
pub struct PgAuthGrantProvider {
    lifecycle: PgAuthGrantLifecycle,
    refresh: PgRefreshTokenStore,
    security: PgIdentitySecurityLifecycle,
}

impl PgAuthGrantProvider {
    pub(crate) fn new(
        lifecycle: PgAuthGrantLifecycle,
        refresh: PgRefreshTokenStore,
        security: PgIdentitySecurityLifecycle,
    ) -> Self {
        Self {
            lifecycle,
            refresh,
            security,
        }
    }
}

impl AuthGrantProvider for PgAuthGrantProvider {
    type Lifecycle = PgAuthGrantLifecycle;
    type RefreshStore = PgRefreshTokenStore;
    type SecurityLifecycle = PgIdentitySecurityLifecycle;

    fn into_auth_grant_parts(
        self,
    ) -> (Self::Lifecycle, Self::RefreshStore, Self::SecurityLifecycle) {
        (self.lifecycle, self.refresh, self.security)
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
