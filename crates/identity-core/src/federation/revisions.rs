//! Outbound snapshots are installed under an authoritative read or host configuration lock.
use super::{
    FederationError, ProviderCredentials, ProviderId, ProviderReason, ProviderRevision,
    ProviderSettings, ProviderStage,
};
use rss_request_context::TenantId;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};
use tokio_util::sync::CancellationToken;

type Key = (uuid::Uuid, TenantId, ProviderId);
type Entries = Mutex<HashMap<Key, Weak<Generation>>>;
fn key(r: ProviderRevision) -> Key {
    (r.instance.as_uuid(), r.tenant, r.provider)
}
struct Generation {
    version: i64,
    retired: CancellationToken,
}

/// Instance-local registry of live authoritative snapshots. HTTP cache eviction is independent.
pub struct ProviderRevisions {
    entries: Arc<Entries>,
    limit: usize,
}
impl ProviderRevisions {
    pub fn new(max_live: usize) -> Self {
        Self {
            entries: Arc::default(),
            limit: max_live,
        }
    }

    /// Install the exact settings and credentials in the same authoritative read/installation
    /// as their revision. The resulting snapshot can be cloned but cannot be rebound.
    pub fn install(
        &self,
        revision: ProviderRevision,
        settings: ProviderSettings,
        credentials: ProviderCredentials,
    ) -> Result<BoundProvider, FederationError> {
        if revision.version <= 0 {
            return Err(FederationError::Configuration);
        }
        let mut entries = self.entries.lock().unwrap();
        let id = key(revision);
        let active = entries.get(&id).and_then(Weak::upgrade);
        let current = match active {
            Some(current) if current.version > revision.version => {
                return Err(FederationError::StaleConfiguration);
            }
            Some(current) if current.version == revision.version => current,
            previous => {
                if let Some(previous) = previous {
                    previous.retired.cancel();
                }
                if entries.len() >= self.limit && !entries.contains_key(&id) {
                    entries.retain(|_, v| v.strong_count() > 0);
                    if entries.len() >= self.limit {
                        return Err(FederationError::provider(
                            ProviderStage::Binding,
                            ProviderReason::Unavailable,
                        ));
                    }
                }
                let current = Arc::new(Generation {
                    version: revision.version,
                    retired: CancellationToken::new(),
                });
                entries.insert(id, Arc::downgrade(&current));
                current
            }
        };
        Ok(BoundProvider {
            installed: InstalledRevision {
                revision,
                current,
                owner: Arc::downgrade(&self.entries),
            },
            material: Arc::new(Material {
                settings,
                credentials,
            }),
        })
    }

    /// Retire snapshots older than the new authoritative host revision.
    pub fn observe(&self, new: ProviderRevision) {
        self.retire_through(new, new.version.saturating_sub(1));
    }

    /// Seal already-issued snapshots of this version under the PG row lock before settlement.
    /// A fresh authoritative read after rollback can reinstall the original version.
    pub fn retire(&self, old: ProviderRevision) {
        self.retire_through(old, old.version);
    }

    fn retire_through(&self, r: ProviderRevision, last: i64) {
        let mut entries = self.entries.lock().unwrap();
        let id = key(r);
        if let Some(generation) = entries.get(&id).and_then(Weak::upgrade)
            && generation.version <= last
        {
            generation.retired.cancel();
            entries.remove(&id);
        }
    }
    pub fn check(&self, snapshot: &BoundProvider) -> Result<(), FederationError> {
        if !snapshot
            .installed
            .owner
            .ptr_eq(&Arc::downgrade(&self.entries))
        {
            return Err(FederationError::Configuration);
        }
        snapshot.check()
    }
}
/// Nonsecret retirement signal for this installed configuration.
#[derive(Clone)]
pub struct InstalledRevision {
    revision: ProviderRevision,
    current: Arc<Generation>,
    owner: Weak<Entries>,
}
impl InstalledRevision {
    pub fn revision(&self) -> ProviderRevision {
        self.revision
    }
    pub fn check(&self) -> Result<(), FederationError> {
        if self.current.retired.is_cancelled() {
            Err(FederationError::StaleConfiguration)
        } else {
            Ok(())
        }
    }
    pub async fn retired(&self) {
        self.current.retired.cancelled().await
    }
}

struct Material {
    settings: ProviderSettings,
    credentials: ProviderCredentials,
}
/// Immutable provider operation input. Only the host's authoritative installation creates it.
#[derive(Clone)]
pub struct BoundProvider {
    installed: InstalledRevision,
    material: Arc<Material>,
}
impl BoundProvider {
    pub fn installed(&self) -> &InstalledRevision {
        &self.installed
    }
    pub fn revision(&self) -> ProviderRevision {
        self.installed.revision()
    }
    pub fn settings(&self) -> &ProviderSettings {
        &self.material.settings
    }
    pub fn credentials(&self) -> &ProviderCredentials {
        &self.material.credentials
    }
    pub fn check(&self) -> Result<(), FederationError> {
        self.installed.check()
    }
}
