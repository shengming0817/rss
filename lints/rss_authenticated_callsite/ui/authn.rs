#![allow(unused)]

mod grant {
    pub(super) struct AuthGrant;

    impl AuthGrant {
        pub(super) fn new_active() {
            let _ = authn::AuthGrant::hydrate;
        }

        pub(super) fn close() {
            let _ = authn::AuthGrant::hydrate;
        }

        pub(super) fn unrelated() {
            let _ = authn::AuthGrant::hydrate;
        }
    }
}

mod fake {
    struct AuthGrant;

    impl AuthGrant {
        fn close() {
            let _ = authn::AuthGrant::hydrate;
        }
    }
}

fn main() {}
