use anyhow::{Result, ensure};
use httpserve::{PrimaryRoute, ResourceProjection, RoutePermission, RouteResourceScope};
use vocab::{ProjectionField, RoutePermissionId};

fn main() -> Result<()> {
    let profile_route = PrimaryRoute::permission(
        "GET".parse()?,
        "/api/v1/identity/profile",
        "identity.profile",
        RoutePermission {
            permission: RoutePermissionId::IdentityProfileRead,
            scope: RouteResourceScope::SelfSubject,
        },
    );
    ensure!(profile_route.route_permission().is_some());

    ensure!(
        ProjectionField::from_obligation_key("audit.actor") == Some(ProjectionField::AuditActor)
    );
    let masked =
        ResourceProjection::default_masked().render(ProjectionField::AuditActor, "actor-1");
    ensure!(masked == "<redacted>");

    println!(
        "checked consumer route declaration and projection vocabulary for {}",
        RoutePermissionId::IdentityProfileRead
    );
    Ok(())
}
