#![allow(unused)]

use rss_request_context::PrincipalKind;

fn actor_kind_to_db(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "user",
        PrincipalKind::Admin => "admin",
        _ => "unknown",
    }
}

mod cotx {
    pub(super) mod identity {
        use crate::PrincipalKind;

        pub(crate) struct CanonicalDeviceIngressFact;

        impl CanonicalDeviceIngressFact {
            pub(crate) fn from_reviewed_event(kind: PrincipalKind) -> bool {
                kind == PrincipalKind::Device
            }
        }
    }
}

mod shadow {
    use super::PrincipalKind;

    pub(super) struct CanonicalDeviceIngressFact;

    impl CanonicalDeviceIngressFact {
        pub(super) fn from_reviewed_event(kind: PrincipalKind) -> bool {
            kind == PrincipalKind::Device
        }
    }
}

fn handler_local_role_check(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn main() {
    let _ = actor_kind_to_db(PrincipalKind::User);
    let _ = cotx::identity::CanonicalDeviceIngressFact::from_reviewed_event(PrincipalKind::Device);
    let _ = shadow::CanonicalDeviceIngressFact::from_reviewed_event(PrincipalKind::Device);
    let _ = handler_local_role_check(PrincipalKind::Admin);
}
