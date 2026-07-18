#![allow(unused, unknown_lints)]

use httpserve::Authenticated;
use primitives::RequiredScheme;
use vocab::{PrincipalKind, TenantId};

struct LocalContext;

impl LocalContext {
    fn tenant_id(&self) -> Option<TenantId> {
        None
    }

    fn principal_kind(&self) -> PrincipalKind {
        PrincipalKind::User
    }

    fn self_scoped_principal_id(&self) -> &str {
        "local"
    }
}

fn main() {
    let auth = Authenticated::new(
        RequiredScheme::RssAccessToken,
        PrincipalKind::User,
        "user-1",
        None,
    );
    let _tenant = auth.tenant_id();
    let _kind = auth.principal_kind();
    let _subject = auth.self_scoped_principal_id();
    let _tenant_fn: fn(&Authenticated) -> Option<TenantId> = Authenticated::tenant_id;
    let _kind_fn: fn(&Authenticated) -> PrincipalKind = Authenticated::principal_kind;
    let _subject_fn: fn(&Authenticated) -> &str = Authenticated::self_scoped_principal_id;

    let local = LocalContext;
    let _ = local.tenant_id();
    let _ = local.principal_kind();
    let _ = local.self_scoped_principal_id();
    if local.principal_kind() == PrincipalKind::Admin {
        let _ = "bad local admin branch";
    }
    if PrincipalKind::SuperAdmin != local.principal_kind() {
        let _ = "bad local super-admin branch";
    }
    let role_name = "Admin";
    if role_name == "Admin" {
        let _ = "bad role-name branch";
    }
    if "superAdmin" != role_name {
        let _ = "bad super-admin role-name branch";
    }
    match local.principal_kind() {
        PrincipalKind::Admin => {
            let _ = "bad match admin branch";
        }
        _ => {}
    }
    if matches!(local.principal_kind(), PrincipalKind::SuperAdmin) {
        let _ = "bad matches super-admin branch";
    }
    match role_name {
        "service" => {
            let _ = "bad role-name match branch";
        }
        _ => {}
    }

    allowed_by_attr(&auth);
}

#[allow(rss_handler_local_principal_authz)] // reason: UI fixture verifies item-level escape hatch
fn allowed_by_attr(auth: &Authenticated) {
    let _ = auth.principal_kind();
    if auth.principal_kind() == PrincipalKind::Admin {
        let _ = "allowed";
    }
}
