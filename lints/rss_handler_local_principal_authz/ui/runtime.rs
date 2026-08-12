#![allow(unused)]

use rss_request_context::PrincipalKind;

struct MtlsRouteAuthorizer;

impl MtlsRouteAuthorizer {
    fn authorize(&self, kind: PrincipalKind) -> bool {
        kind == PrincipalKind::Service
    }
}

fn allow_evidence(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::User
}

fn verify_maintenance_operator_subject(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::Service
}

fn verified_service_maintenance_operator(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::Service
}

fn verified_projection_maintenance_operator_subject(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::Service
}

fn handler_local_role_check(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn main() {
    let authorizer = MtlsRouteAuthorizer;
    let _ = authorizer.authorize(PrincipalKind::Service);
    let _ = allow_evidence(PrincipalKind::User);
    let _ = verify_maintenance_operator_subject(PrincipalKind::Service);
    let _ = verified_service_maintenance_operator(PrincipalKind::Service);
    let _ = verified_projection_maintenance_operator_subject(PrincipalKind::Service);
    let _ = handler_local_role_check(PrincipalKind::Admin);
}
