#![allow(dead_code, unused_imports)]

use std::{future::Future, pin::Pin};

fn parent_diagnostic_helper() {
    let _ = diagctx::correlation();
}

mod sibling_helper {
    pub(super) fn diagnostic_value() -> bool {
        diagctx::correlation().is_some()
    }
}

mod pdp_boundary {
    pub(super) fn diagnostic_helper() {
        let _ = diagctx::correlation();
    }

    struct Provider;

    impl diport::Pdp for Provider {
        async fn verify(
            &self,
            _raw: &diport::RawCredential,
        ) -> Result<diport::VerifiedClaims, diport::PdpError> {
            super::parent_diagnostic_helper();
            let _ = super::sibling_helper::diagnostic_value();
            diagnostic_helper();
            todo!()
        }
    }
}

mod route_authorizer_boundary {
    use super::{Future, Pin};

    fn diagnostic_helper() {
        let read = diagctx::current;
        let _ = read();
    }

    struct Authorizer;

    impl httpserve::RouteAuthorizer for Authorizer {
        fn authorize<'a>(
            &'a self,
            _request: httpserve::RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
        {
            diagnostic_helper();
            Box::pin(async { httpserve::RouteAuthorizationDecision::Deny })
        }
    }
}

fn main() {}
