use anyhow::{Result, ensure};
use generated::http::HttpHeaderMode;
use vocab::{HttpRouteAuth, ProjectionField, RoutePermissionId};

#[test]
fn tenancy_closeout_generated_http_specs_match_consumer_contract() -> Result<()> {
    let login = generated::http::identity_v1::login::SPEC;
    ensure!(login.route.contract_id() == "identity.login");
    ensure!(login.route.auth() == HttpRouteAuth::Public);
    ensure!(
        login
            .headers
            .iter()
            .any(|header| header.name == "X-Tenant-ID"
                && header.mode == HttpHeaderMode::PopulateOnly),
        "login must declare populate-only tenant header"
    );

    let profile = generated::http::identity_v1::profile::SPEC;
    ensure!(
        profile.route.auth() == HttpRouteAuth::Permission(RoutePermissionId::IdentityProfileRead)
    );
    ensure!(profile.route.self_scoped());
    ensure!(
        profile.projection_fields.iter().any(|field| {
            field.field == ProjectionField::IdentityProfileSubject
                && field.permission == ProjectionField::IdentityProfileSubject.permission()
                && field.obligation_key == ProjectionField::IdentityProfileSubject.obligation_key()
                && field.response_path == "data.subject"
        }),
        "profile subject must be an enrolled projection field"
    );

    let audit = generated::http::audit_v1::list_entries::SPEC;
    ensure!(audit.route.contract_id() == "audit.list-entries");
    ensure!(audit.route.auth() == HttpRouteAuth::Permission(RoutePermissionId::AuditRead));
    ensure!(
        audit.projection_fields.iter().any(|field| {
            field.field == ProjectionField::AuditActor
                && field.permission == ProjectionField::AuditActor.permission()
                && field.obligation_key == ProjectionField::AuditActor.obligation_key()
                && field.response_path == "data[].actor"
        }),
        "audit actor must be an enrolled projection field"
    );

    let target = generated::http::audit_v1::list_tenant_entries::SPEC;
    ensure!(target.route.contract_id() == "audit.list-tenant-entries");
    ensure!(target.route.auth() == HttpRouteAuth::Permission(RoutePermissionId::AuditRead));

    Ok(())
}
