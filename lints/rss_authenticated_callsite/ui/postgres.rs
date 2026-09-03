// Exact green fixture for the sole persistence hydration impl method.
#![allow(unused)]

mod auth_grant_lifecycle {
    pub(super) struct PgAuthGrantLifecycle;

    impl PgAuthGrantLifecycle {
        pub(super) fn find_active() {
            let _ = authn::AuthGrant::hydrate;
        }
    }
}

mod fake {
    struct PgAuthGrantLifecycle;

    impl PgAuthGrantLifecycle {
        fn find_active() {
            let _ = authn::AuthGrant::hydrate;
        }
    }
}

fn main() {}
