use rss_identity_core::{InstanceId, federation::*};
use rss_request_context::TenantId;

/// Bind a fixture configuration to a stable instance and provider for repeated operations.
pub fn fixture_provider(
    adapter: &crate::HttpOidc,
    tenant: TenantId,
    settings: &ProviderSettings,
    credentials: &ProviderCredentials,
) -> BoundProvider {
    fixture_install(
        adapter,
        ProviderRevision {
            tenant,
            instance: InstanceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            provider: ProviderId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            version: 1,
        },
        settings,
        credentials,
    )
    .unwrap()
}
/// Install a specific test revision with a fresh copy of the fixture credentials.
pub fn fixture_install(
    adapter: &crate::HttpOidc,
    revision: ProviderRevision,
    settings: &ProviderSettings,
    credentials: &ProviderCredentials,
) -> Result<BoundProvider, FederationError> {
    adapter.revisions().install(
        revision,
        settings.clone(),
        ProviderCredentials::new(
            credentials.client_secret().to_owned(),
            credentials.ca_pem().map(str::to_owned),
        )?,
    )
}

use crate::ReusePolicy;
#[path = "../tests/support/policy.rs"]
mod policy;
pub use policy::reuse_policy;
