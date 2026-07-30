// identityaudit production bridge: only the exact proof-consuming funnel may mint RSS evidence.
#![allow(unused)]

use authn::Principal;
use httpserve::Authenticated;
use identity::ValidatedAuthGrant;
use vocab::TenantId;

mod auth_bridge {
    use super::*;

    pub fn allow_evidence(
        validated: ValidatedAuthGrant,
        principal: &Principal,
        tenant: TenantId,
    ) -> Authenticated {
        let current = validated.into_current_auth_grant().unwrap();
        let _ = (current, principal);
        Authenticated::new_rss_user(
            authmint::AuthenticatedMint::capability(),
            principal.audit_subject(),
            tenant,
        )
    }

    // Synthetic red: moving the evidence mint away from the exact allow funnel must fail closed.
    pub fn moved_allow_evidence(
        validated: ValidatedAuthGrant,
        principal: &Principal,
        tenant: TenantId,
    ) -> Authenticated {
        let current = validated.into_current_auth_grant().unwrap();
        let _ = current;
        Authenticated::new_rss_user(
            authmint::AuthenticatedMint::capability(),
            principal.audit_subject(),
            tenant,
        )
    }
}

fn main() {}
