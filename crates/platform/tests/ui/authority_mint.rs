use rss_platform::{PrincipalKind, VerifiedAccess};

fn main() {
    let _ = VerifiedAccess {
        subject: "forged".into(),
        tenant: None,
        kind: PrincipalKind::SuperAdmin,
        permissions: Box::new([]),
    };
}
