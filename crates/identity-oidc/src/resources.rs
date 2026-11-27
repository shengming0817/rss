//! Instance-local client pools and document capacity.
//! ref: reqwest src/async_impl/client.rs @ v0.12.28.
use super::{ProviderRevision, discovery::Document};
use rss_identity_core::federation::{BoundProvider, FederationError, ProviderId};
use rss_request_context::TenantId;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

/// Host-selected finite budgets for generic OIDC public documents and connection pools.
#[derive(Debug, Clone, Copy)]
pub struct ReusePolicy {
    /// Maximum resident provider bindings, each with at most one pool and two documents.
    pub max_providers: usize,
    /// Total resident document bytes including retained HTTP validators.
    pub max_resident_bytes: usize,
    /// Global simultaneous public-document refreshes.
    pub max_refreshes: usize,
    /// Maximum idle connections for each provider origin.
    pub max_idle_per_host: usize,
    /// Maximum idle connection lifetime.
    pub idle_timeout: Duration,
    /// Maximum discovery freshness, subject to upstream cache directives.
    pub discovery_ttl: Duration,
    /// Maximum signing-key freshness.
    pub jwks_ttl: Duration,
    /// Minimum interval between unknown-key refresh attempts.
    pub refresh_cooldown: Duration,
}
impl ReusePolicy {
    /// Check all capacities before installing a host configuration.
    pub fn validate(self) -> Result<Self, FederationError> {
        if [
            self.max_providers,
            self.max_resident_bytes,
            self.max_idle_per_host,
            self.max_refreshes,
        ]
        .contains(&0)
            || self.max_refreshes > Semaphore::MAX_PERMITS
            || self.max_providers > Semaphore::MAX_PERMITS
            || [
                self.idle_timeout,
                self.discovery_ttl,
                self.jwks_ttl,
                self.refresh_cooldown,
            ]
            .into_iter()
            .any(|d| d.is_zero() || Instant::now().checked_add(d).is_none())
        {
            return Err(FederationError::Configuration);
        }
        Ok(self)
    }
}

type ProviderKey = (uuid::Uuid, TenantId, ProviderId);
fn key(revision: ProviderRevision) -> ProviderKey {
    (
        revision.instance.as_uuid(),
        revision.tenant,
        revision.provider,
    )
}

#[derive(Eq, PartialEq)]
struct Trust {
    issuer: String,
    client: String,
    ca: Option<[u8; 32]>,
}
pub(super) struct ClientPool {
    pub http: reqwest::Client,
    pub _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
pub(super) struct ProviderResources {
    installed: rss_identity_core::federation::InstalledRevision,
    pub discovery: Arc<Document>,

    pub client: Mutex<Option<Arc<ClientPool>>>,
    trust: Trust,
}
struct Entry {
    version: i64,
    last_used: Instant,
    resources: Option<Arc<ProviderResources>>,
}
impl Entry {
    fn retire(&mut self, version: i64) {
        self.resources = None;
        self.version = version;
    }
}

pub(super) struct Resources {
    entries: Mutex<HashMap<ProviderKey, Entry>>,
    bytes: Arc<AtomicUsize>,
    pub refreshes: Arc<Semaphore>,
    clients: Arc<Semaphore>,
    pub policy: ReusePolicy,
    #[cfg(test)]
    offset: Mutex<Duration>,
}
impl Resources {
    pub fn new(policy: ReusePolicy) -> Result<Arc<Self>, FederationError> {
        let policy = policy.validate()?;
        Ok(Arc::new(Self {
            entries: Mutex::default(),
            bytes: Arc::default(),
            refreshes: Arc::new(Semaphore::new(policy.max_refreshes)),
            clients: Arc::new(Semaphore::new(policy.max_providers)),
            policy,
            #[cfg(test)]
            offset: Mutex::default(),
        }))
    }

    #[cfg(test)]
    pub fn resident_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
    pub fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now + *self.offset.lock().unwrap();
        now
    }
    #[cfg(test)]
    pub fn advance(&self, duration: Duration) {
        *self.offset.lock().unwrap() += duration;
    }
    pub fn bind(
        &self,
        provider: &BoundProvider,
    ) -> Result<Arc<ProviderResources>, FederationError> {
        let revision = provider.revision();
        if revision.version <= 0 {
            return Err(FederationError::Configuration);
        }
        let id = key(revision);
        let mut entries = self.entries.lock().unwrap();
        if !entries.contains_key(&id)
            && entries.len() >= self.policy.max_providers
            && !evict_idle(&mut entries)
        {
            return Err(crate::failure(
                rss_identity_core::federation::ProviderStage::Binding,
                rss_identity_core::federation::ProviderReason::Unavailable,
            ));
        }
        let now = Instant::now();
        let entry = entries.entry(id).or_insert_with(|| Entry {
            version: revision.version,
            last_used: now,
            resources: None,
        });
        if revision.version < entry.version {
            return Err(FederationError::StaleConfiguration);
        }
        // A staged mutation can roll back. The new authoritative installation then
        // has the same numeric version, but must not join the retired generation's GET.
        if revision.version > entry.version
            || entry
                .resources
                .as_ref()
                .is_some_and(|r| r.installed.check().is_err())
        {
            entry.retire(revision.version);
        }
        entry.last_used = now;
        // The adapter owns the immutable CIDR policy indexed by (tenant, exact issuer, client).
        let issuer = provider.settings().issuer().as_str();
        let client = provider.settings().client_id().as_str();
        let ca = provider
            .credentials()
            .ca_pem()
            .map(rss_identity_core::federation::digest);
        if let Some(resources) = &entry.resources {
            if resources.trust.issuer != issuer
                || resources.trust.client != client
                || resources.trust.ca != ca
            {
                return Err(FederationError::Configuration);
            }
            return Ok(resources.clone());
        }
        let resources = Arc::new(ProviderResources {
            installed: provider.installed().clone(),
            trust: Trust {
                issuer: issuer.into(),
                client: client.into(),
                ca,
            },

            client: Mutex::default(),
            discovery: Arc::default(),
        });
        entry.resources = Some(resources.clone());
        Ok(resources)
    }

    pub fn client_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, FederationError> {
        let mut entries = self.entries.lock().unwrap();
        loop {
            if let Ok(permit) = self.clients.clone().try_acquire_owned() {
                return Ok(permit);
            }
            if !evict_idle(&mut entries) {
                return Err(crate::failure(
                    crate::ProviderStage::Binding,
                    crate::ProviderReason::Unavailable,
                ));
            }
        }
    }
    pub fn reserve(
        &self,
        bytes: usize,
        replaced: Option<&mut ByteLease>,
    ) -> Result<ByteLease, FederationError> {
        if bytes > self.policy.max_resident_bytes {
            return Err(FederationError::Unavailable);
        }
        let mut entries = self.entries.lock().unwrap();
        let credit = replaced.as_ref().map_or(0, |lease| lease.bytes);
        while self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(credit)?
                    .checked_add(bytes)
                    .filter(|total| *total <= self.policy.max_resident_bytes)
            })
            .is_err()
        {
            if !evict_idle(&mut entries) {
                return Err(FederationError::Unavailable);
            }
        }
        if let Some(lease) = replaced {
            lease.bytes = 0;
        }
        Ok(ByteLease {
            counter: self.bytes.clone(),
            bytes,
        })
    }
}
fn evict_idle(entries: &mut HashMap<ProviderKey, Entry>) -> bool {
    let oldest = entries
        .iter()
        .filter(|(_, entry)| {
            entry
                .resources
                .as_ref()
                .is_none_or(|r| Arc::strong_count(r) == 1)
        })
        .min_by_key(|(_, entry)| entry.last_used)
        .map(|(k, _)| *k);
    if let Some(key) = oldest {
        entries.remove(&key);
        return true;
    }
    false
}

pub(super) struct ByteLease {
    counter: Arc<AtomicUsize>,
    bytes: usize,
}
impl Drop for ByteLease {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
