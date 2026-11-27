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

/// Supply the first and subsequent DNS answers for one fixture host. Fresh HTTP/1
/// connections let each request exercise the production address filter independently.
pub fn fixture_dns(
    adapter: &mut crate::HttpOidc,
    host: &str,
    answers: [IpAddr; 2],
) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    adapter.fixture_dns = Some(Arc::new(FixtureDns {
        host: host.to_owned(),
        answers,
        calls: calls.clone(),
    }));
    calls
}

struct FixtureDns {
    host: String,
    answers: [IpAddr; 2],
    calls: Arc<AtomicUsize>,
}
impl Resolve for FixtureDns {
    fn resolve(&self, name: Name) -> Resolving {
        if name.as_str() != self.host {
            return Box::pin(async {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
            });
        }
        let subsequent = self.calls.fetch_add(1, Ordering::Relaxed) != 0;
        let answer = SocketAddr::new(self.answers[usize::from(subsequent)], 0);
        Box::pin(async move { Ok(Box::new(std::iter::once(answer)) as Addrs) })
    }
}
