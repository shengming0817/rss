#![allow(unused)]

use vocab::PrincipalKind;

struct MtlsRouteAuthorizer;

impl MtlsRouteAuthorizer {
    fn authorize(&self, kind: PrincipalKind) -> bool {
        kind == PrincipalKind::Service
    }
}

fn verify_maintenance_operator_subject(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::Service
}

fn verified_service_maintenance_operator_subject(kind: PrincipalKind) -> bool {
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
    let _ = verify_maintenance_operator_subject(PrincipalKind::Service);
    let _ = verified_service_maintenance_operator_subject(PrincipalKind::Service);
    let _ = verified_projection_maintenance_operator_subject(PrincipalKind::Service);
    let _ = handler_local_role_check(PrincipalKind::Admin);
}
