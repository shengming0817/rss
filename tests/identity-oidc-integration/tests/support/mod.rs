use rss_identity_core::federation::{ClaimMapping, ProviderSettings, ProviderSettingsInput};
use rss_identity_oidc::TransportPolicy;
use rss_request_context::{Deadline, TenantId};
use std::time::{Duration, Instant};

pub const CALLBACK: &str = "https://host.example.test/callback";
pub fn tenant() -> anyhow::Result<TenantId> {
    Ok(TenantId::parse("11111111-1111-4111-8111-111111111111")?)
}
pub fn policy() -> anyhow::Result<TransportPolicy> {
    Ok(TransportPolicy::new(
        Duration::from_secs(10),
        Duration::from_secs(3),
        1024 * 1024,
        128,
    )?)
}
#[allow(
    clippy::disallowed_methods,
    reason = "Test host supplies a real monotonic deadline"
)]
pub fn deadline() -> Deadline {
    Deadline::at(Instant::now() + Duration::from_secs(15))
}
pub fn settings(issuer: &str) -> anyhow::Result<ProviderSettings> {
    Ok(ProviderSettingsInput {
        issuer: issuer.into(),
        client_id: "identity-test".into(),
        redirect_uri: CALLBACK.into(),
        scopes: vec!["openid".into()],
        claims: ClaimMapping {
            subject: rss_identity_core::entra::SubjectMapping::Oidc,
            profile: Default::default(),
            groups: None,
            department_snapshot: None,
        },
        jit: false,
    }
    .try_into()?)
}

pub const JWK_A: &str =
    include_str!("../../../../crates/identity-oidc/tests/fixtures/entra-a.json");
pub const JWK_B: &str =
    include_str!("../../../../crates/identity-oidc/tests/fixtures/entra-b.json");
pub const KEY_A: &[u8] =
    include_bytes!("../../../../crates/identity-oidc/tests/fixtures/entra-a.der");
pub const KEY_B: &[u8] =
    include_bytes!("../../../../crates/identity-oidc/tests/fixtures/entra-b.der");
