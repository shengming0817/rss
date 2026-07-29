use authn::{Principal, VerifiedFederatedAccess};
use httpserve::Authenticated;

mod auth_bridge {
    use super::*;

    pub fn federated_evidence(access: &VerifiedFederatedAccess) -> Authenticated {
        Authenticated::new_federated(
            access.principal().kind(),
            access.principal().audit_subject(),
            access.principal().tenant(),
            access.permissions(),
        )
    }

    pub fn wrong_wrapper(
        principal: &Principal,
        permissions: &diport::VerifiedFederatedPermissions,
    ) -> Authenticated {
        Authenticated::new_federated(
            principal.kind(),
            principal.audit_subject(),
            principal.tenant(),
            permissions,
        )
    }
}

fn raw_parse_direct(raw: &str) {
    let _ = authn::Jwt::parse(raw);
}

fn raw_parse_alias(raw: &str) {
    let parse = authn::Jwt::parse;
    let _ = parse(raw);
}

fn raw_parse_function_pointer(raw: &str) {
    let parse: fn(&str) -> Result<authn::Jwt, authn::AuthnError> = authn::Jwt::parse;
    let _ = parse(raw);
}

fn main() {
    let _allowed = auth_bridge::federated_evidence;
    let _rejected = auth_bridge::wrong_wrapper;
    raw_parse_direct("header.payload.signature");
    raw_parse_alias("header.payload.signature");
    raw_parse_function_pointer("header.payload.signature");
}
