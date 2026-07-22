// Exact green fixture for the only identity impl methods allowed to consume grant issue funnels.
#![allow(unused)]

mod application {
    pub(super) struct LoginService;

    impl LoginService {
        pub(super) fn login() {
            let _ = authn::AuthGrant::new_active;
        }
    }

    pub(super) struct RefreshService;

    impl RefreshService {
        pub(super) fn prepare_initial<S: diport::Signer + Send + Sync + 'static>() {
            let _ = authn::AuthGrant::access_issue_input;
            let _ = authn::JwtIssuer::<diport::RssAccessProfile, S>::issue_access;
        }

        pub(super) fn rotate<S: diport::Signer + Send + Sync + 'static>() {
            let _ = authn::AuthGrant::access_issue_input;
            let _ = authn::JwtIssuer::<diport::RssAccessProfile, S>::issue_access;
        }
    }
}

mod fake {
    struct LoginService;

    impl LoginService {
        fn login() {
            let _ = authn::AuthGrant::new_active;
        }
    }

    struct RefreshService;

    impl RefreshService {
        fn rotate<S: diport::Signer + Send + Sync + 'static>() {
            let _ = authn::AuthGrant::access_issue_input;
            let _ = authn::JwtIssuer::<diport::RssAccessProfile, S>::issue_access;
        }
    }
}

fn main() {}
