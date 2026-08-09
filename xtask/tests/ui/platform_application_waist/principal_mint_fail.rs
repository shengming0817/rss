use platform_application_waist_contract::{PrincipalKind, VerifiedPrincipal};

fn forge() -> VerifiedPrincipal<'static> {
    VerifiedPrincipal {
        kind: PrincipalKind::User,
        subject: "forged",
    }
}

fn main() {
    let _ = forge;
}
