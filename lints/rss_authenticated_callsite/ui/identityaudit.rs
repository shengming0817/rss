// identityaudit production bridge: only the exact proof-consuming funnel may mint RSS evidence.
#![allow(unused)]

use authn::Principal;
use httpserve::{Authenticated, CurrentAuthGrant};
use identity::ValidatedAuthGrant;
use vocab::TenantId;

mod auth_bridge {
    use super::*;

    pub fn current_auth_grant(_validated: ValidatedAuthGrant) -> CurrentAuthGrant {
        CurrentAuthGrant::new()
    }

    pub fn allow_evidence(
        validated: ValidatedAuthGrant,
        principal: &Principal,
        tenant: TenantId,
    ) -> Authenticated {
        Authenticated::new_rss_user(
            current_auth_grant(validated),
            principal.audit_subject(),
            tenant,
        )
    }

    // Synthetic red: deleting the durable proof parameter must close the mint funnel.
    pub fn current_auth_grant_without_proof() -> CurrentAuthGrant {
        CurrentAuthGrant::new()
    }

    // Synthetic red: moving the proof consumer away from the exact wrapper must fail closed.
    pub fn moved_current_auth_grant(_validated: ValidatedAuthGrant) -> CurrentAuthGrant {
        CurrentAuthGrant::new()
    }

    // Synthetic red: moving the evidence mint away from the exact allow funnel must fail closed.
    pub fn moved_allow_evidence(
        validated: ValidatedAuthGrant,
        principal: &Principal,
        tenant: TenantId,
    ) -> Authenticated {
        Authenticated::new_rss_user(
            current_auth_grant(validated),
            principal.audit_subject(),
            tenant,
        )
    }
}

fn main() {}
