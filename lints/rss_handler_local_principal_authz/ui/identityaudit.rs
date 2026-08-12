#![allow(unused)]

use rss_request_context::PrincipalKind;

fn authenticate(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::User
}

fn handler_local_role_check(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn main() {
    let _ = authenticate(PrincipalKind::User);
    let _ = handler_local_role_check(PrincipalKind::Admin);
}
