#![allow(unused)]

use vocab::PrincipalKind;

fn privacy_ref(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "user",
        _ => "other",
    }
}

fn current_user_grant_context(kind: PrincipalKind) -> bool {
    kind == PrincipalKind::User
}

fn credential_security_fact(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn handler_local_role_check(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn main() {
    let _ = privacy_ref(PrincipalKind::User);
    let _ = current_user_grant_context(PrincipalKind::User);
    let _ = credential_security_fact(PrincipalKind::Admin);
    let _ = handler_local_role_check(PrincipalKind::Admin);
}
