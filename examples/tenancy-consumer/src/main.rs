use anyhow::{Result, ensure};
use httpserve::{ContractMarker, GeneratedPrimaryEndpoint, ResourceProjection};
use vocab::{HttpRouteAuth, HttpRouteBinding, ProjectionField, RoutePermissionId};

enum ProfileRoute {}

fn profile_endpoint<M: 'static, C: vocab::http::HttpConsistencyClass>(
    binding: HttpRouteBinding<M, C>,
) -> Result<GeneratedPrimaryEndpoint<(), C>> {
    let evidence = binding.evidence();
    ensure!(evidence.auth() == HttpRouteAuth::Permission(RoutePermissionId::IdentityProfileRead));
    ensure!(evidence.self_scoped());
    Ok(GeneratedPrimaryEndpoint::new(
        binding,
        |_: ContractMarker<M>| async {},
    )?)
}

fn main() -> Result<()> {
    let _profile_endpoint_factory = profile_endpoint::<ProfileRoute, vocab::http::LocalOnly>;

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
