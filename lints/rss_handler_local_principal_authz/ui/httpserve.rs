#![allow(unused)]

use httpserve::Authenticated;
use vocab::PrincipalKind;

fn main() {
    let auth = Authenticated::new(
        httpserve::NonRssTestScheme::FederatedAccessToken,
        PrincipalKind::User,
        "user-1",
        None,
    );
    let _kind = auth.principal_kind();
    let _subject = auth.self_scoped_principal_id();
    if auth.principal_kind() == PrincipalKind::Admin {
        let _ = "route gate branch";
    }
    let role_name = "Admin";
    if role_name == "Admin" {
        let _ = "route gate role-name branch";
    }
    match auth.principal_kind() {
        PrincipalKind::Service => {
            let _ = "route gate principal match branch";
        }
        _ => {}
    }
    if matches!(auth.principal_kind(), PrincipalKind::SuperAdmin) {
        let _ = "route gate matches branch";
    }
}
