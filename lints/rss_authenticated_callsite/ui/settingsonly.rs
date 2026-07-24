use authn::Principal;
use httpserve::Authenticated;

mod auth_bridge {
    use super::*;

    pub fn federated_evidence(principal: &Principal) -> Authenticated {
        Authenticated::new_federated(
            principal.kind(),
            principal.audit_subject(),
            principal.tenant(),
        )
    }

    pub fn wrong_wrapper(principal: &Principal) -> Authenticated {
        Authenticated::new_federated(
            principal.kind(),
            principal.audit_subject(),
            principal.tenant(),
        )
    }
}

fn main() {}
