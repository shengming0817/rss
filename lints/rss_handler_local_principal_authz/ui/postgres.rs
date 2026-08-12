#![allow(unused)]

use rss_request_context::PrincipalKind;

fn actor_kind_to_db(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "user",
        PrincipalKind::Admin => "admin",
        _ => "unknown",
    }
}

fn handler_local_role_check(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn main() {
    let _ = actor_kind_to_db(PrincipalKind::User);
    let _ = handler_local_role_check(PrincipalKind::Admin);
}
