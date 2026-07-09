use anyhow::{Context, Result, ensure};
use generated::http::{HttpAuthMode, HttpHeaderMode};
use vocab::{ProjectionField, RoutePermissionId};

#[test]
fn tenancy_closeout_generated_http_specs_match_consumer_contract() -> Result<()> {
    let login = generated::http::identity_v1::login::SPEC;
    ensure!(login.contract_id == "identity.login");
    ensure!(login.auth.mode == HttpAuthMode::Public);
    ensure!(login.auth.permission.is_none());
    ensure!(
        login
            .headers
            .iter()
            .any(|header| header.name == "X-Tenant-ID"
                && header.mode == HttpHeaderMode::PopulateOnly),
        "login must declare populate-only tenant header"
    );

    let profile = generated::http::identity_v1::profile::SPEC;
    let profile_permission = profile
        .auth
        .permission
        .context("identity.profile must declare a route permission")?;
    ensure!(profile.auth.mode == HttpAuthMode::Permission);
    ensure!(profile_permission == RoutePermissionId::IdentityProfileRead);
    ensure!(profile.self_scoped);
    ensure!(
        profile.projection_fields.iter().any(|field| {
            field.field == ProjectionField::IdentityProfileSubject
                && field.permission == ProjectionField::IdentityProfileSubject.permission()
                && field.obligation_key == ProjectionField::IdentityProfileSubject.obligation_key()
                && field.response_path == "data.subject"
        }),
        "profile subject must be an enrolled projection field"
    );

    let audit = generated::http::audit_v1::SPEC;
    ensure!(audit.contract_id == "audit.list-entries");
    ensure!(audit.auth.permission == Some(RoutePermissionId::AuditRead));
    ensure!(
        audit.projection_fields.iter().any(|field| {
            field.field == ProjectionField::AuditActor
                && field.permission == ProjectionField::AuditActor.permission()
                && field.obligation_key == ProjectionField::AuditActor.obligation_key()
                && field.response_path == "data[].actor"
        }),
        "audit actor must be an enrolled projection field"
    );

    Ok(())
}
