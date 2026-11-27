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
    /// Budget for parsed public metadata, prepared key material, document structures and
    /// retained HTTP validators. A reader keeps its old representation charged until release.
    /// Refresh admission fails when the new representation cannot fit after idle eviction.
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
            .any(|d| d.is_zero() || d == Duration::MAX)
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
    pub clock: super::ProviderClock,
    entries: Mutex<HashMap<ProviderKey, Entry>>,
    pub(super) bytes: Arc<AtomicUsize>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) decodes: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) verifications: AtomicUsize,
    pub refreshes: Arc<Semaphore>,
    clients: Arc<Semaphore>,
    pub policy: ReusePolicy,
}
impl Resources {
    pub fn new(
        policy: ReusePolicy,
        clock: super::ProviderClock,
    ) -> Result<Arc<Self>, FederationError> {
        let policy = policy.validate()?;
        super::check_durations(
            clock.now(),
            &[
                policy.idle_timeout,
                policy.discovery_ttl,
                policy.jwks_ttl,
                policy.refresh_cooldown,
            ],
        )?;
        Ok(Arc::new(Self {
            clock,
            entries: Mutex::default(),
            bytes: Arc::default(),
            #[cfg(any(test, feature = "test-support"))]
            decodes: AtomicUsize::default(),
            #[cfg(any(test, feature = "test-support"))]
            verifications: AtomicUsize::default(),
            refreshes: Arc::new(Semaphore::new(policy.max_refreshes)),
            clients: Arc::new(Semaphore::new(policy.max_providers)),
            policy,
        }))
    }

    pub fn now(&self) -> Instant {
        self.clock.now()
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
        let ca = provider
            .credentials()
            .ca_pem()
            .map(rss_identity_core::federation::digest);

        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !entries.contains_key(&id)
            && entries.len() >= self.policy.max_providers
            && !evict_idle(&mut entries)
        {
            return Err(crate::failure(
                rss_identity_core::federation::ProviderStage::Binding,
                rss_identity_core::federation::ProviderReason::Unavailable,
            ));
        }
        let now = self.now();
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
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        let _sample = pressure::Locked::start();
        admit(&mut entries, || {
            self.clients.clone().try_acquire_owned().ok()
        })
        .ok_or_else(|| {
            crate::failure(
                crate::ProviderStage::Binding,
                crate::ProviderReason::Unavailable,
            )
        })
    }
    pub fn reserve(
        &self,
        bytes: usize,
        replaced: Option<&mut ByteLease>,
    ) -> Result<ByteLease, FederationError> {
        if bytes > self.policy.max_resident_bytes {
            return Err(FederationError::Unavailable);
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let credit = replaced.as_ref().map_or(0, |lease| lease.bytes);
        admit(&mut entries, || {
            self.bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_sub(credit)?
                        .checked_add(bytes)
                        .filter(|total| *total <= self.policy.max_resident_bytes)
                })
                .ok()
        })
        .ok_or(FederationError::Unavailable)?;
        if let Some(lease) = replaced {
            lease.bytes = 0;
        }
        Ok(ByteLease {
            counter: self.bytes.clone(),
            bytes,
        })
    }
}
fn idle(entry: &Entry) -> bool {
    entry
        .resources
        .as_ref()
        .is_none_or(|resources| Arc::strong_count(resources) == 1)
}

fn admit<T>(
    entries: &mut HashMap<ProviderKey, Entry>,
    mut acquire: impl FnMut() -> Option<T>,
) -> Option<T> {
    if let Some(value) = acquire() {
        return Some(value);
    }
    // A single or double eviction costs less than sorting the idle set (pressure fixture).
    for _ in 0..2 {
        if !evict_idle(entries) {
            return None;
        }
        if let Some(value) = acquire() {
            return Some(value);
        }
    }
    // All new bindings take this lock. An idle resource cannot acquire a new external owner here.
    #[cfg(test)]
    pressure::scan(entries.len());
    let mut idle_entries: Vec<_> = entries
        .iter()
        .filter(|(_, entry)| idle(entry))
        .map(|(key, entry)| (entry.last_used, *key))
        .collect();
    idle_entries.sort_unstable_by_key(|(last_used, _)| *last_used);
    for (_, key) in idle_entries {
        entries.remove(&key);
        if let Some(value) = acquire() {
            return Some(value);
        }
    }
    // A holder may have released its resource while we were traversing the original idle set.
    while evict_idle(entries) {
        if let Some(value) = acquire() {
            return Some(value);
        }
    }
    None
}
fn evict_idle(entries: &mut HashMap<ProviderKey, Entry>) -> bool {
    #[cfg(test)]
    pressure::scan(entries.len());
    let oldest = entries
        .iter()
        .filter(|(_, entry)| idle(entry))
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

#[cfg(test)]
mod pressure;
