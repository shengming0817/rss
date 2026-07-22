#![allow(unused)]

use vocab::PrincipalKind;

fn federated_access(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::User | PrincipalKind::Device)
}

fn unrelated(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin)
}

fn main() {
    let _ = federated_access(PrincipalKind::User);
    let _ = unrelated(PrincipalKind::Admin);
}
