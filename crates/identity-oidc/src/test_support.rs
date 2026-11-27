use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rss_identity_core::{InstanceId, federation::*};
use rss_request_context::TenantId;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Bind a fixture configuration to a stable instance and provider for repeated operations.
#[allow(clippy::unwrap_used, reason = "test fixture")]
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

/// Install one DNS answer before first use of this fixture adapter. The production
/// resolver still checks the address before reqwest connects. Counts matching lookups.
pub fn fixture_dns(adapter: &mut crate::HttpOidc, host: &str, address: IpAddr) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    adapter.lookup = Arc::new(FixtureDns {
        host: host.to_owned(),
        address: SocketAddr::new(address, 0),
        calls: calls.clone(),
    });
    calls
}

struct FixtureDns {
    host: String,
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
}
impl Resolve for FixtureDns {
    fn resolve(&self, name: Name) -> Resolving {
        if name.as_str() != self.host {
            return Box::pin(async {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
            });
        }
        self.calls.fetch_add(1, Ordering::Relaxed);
        let answer = self.address;
        Box::pin(async move { Ok(Box::new(std::iter::once(answer)) as Addrs) })
    }
}
