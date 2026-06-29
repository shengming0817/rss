#![allow(unused)]

use httpserve::Authenticated;
use primitives::RequiredScheme;
use vocab::PrincipalKind;

fn main() {
    let auth = Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User, "user-1", None);
    let _kind = auth.principal_kind();
    let _subject = auth.self_scoped_principal_id();
}
