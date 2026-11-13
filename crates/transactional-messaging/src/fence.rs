//! Immutable execution scope supplied by the trusted host, never discovered from restored data.
use rss_request_context::TenantId;

/// Invalid or ambiguous execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid execution binding")]
pub struct InvalidBinding;

/// Positive tenant execution generation, distinct from per-message recovery versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Epoch(i64);
impl Epoch {
    /// Validate the persisted positive bigint domain.
    pub const fn new(value: i64) -> Result<Self, InvalidBinding> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(InvalidBinding)
        }
    }
    /// Canonical storage value.
    pub const fn get(self) -> i64 {
        self.0
    }
    /// Checked next generation.
    pub fn next(self) -> Result<Self, InvalidBinding> {
        self.0
            .checked_add(1)
            .ok_or(InvalidBinding)
            .and_then(Self::new)
    }
}

/// Exact physical restore unit and externally established lineage. These values are identifiers,
/// not authentication: the host must obtain them outside the database's restore boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StorageIdentity {
    target: [u8; 16],
    lineage: [u8; 16],
}
impl StorageIdentity {
    /// Bind nonzero storage and lineage identities after the host verified their authority.
    pub fn new(target: [u8; 16], lineage: [u8; 16]) -> Result<Self, InvalidBinding> {
        if target == [0; 16] || lineage == [0; 16] {
            return Err(InvalidBinding);
        }
        Ok(Self { target, lineage })
    }
    /// Exact restore unit identity.
    pub const fn target(self) -> [u8; 16] {
        self.target
    }
    /// Exact externally established lineage identity.
    pub const fn lineage(self) -> [u8; 16] {
        self.lineage
    }
}
impl std::fmt::Debug for StorageIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StorageIdentity([redacted])")
    }
}

/// Exact execution identity for one operation, supplied by the trusted host.
/// This value neither authenticates a tenant nor discovers its current database epoch.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExecutionBinding {
    storage: StorageIdentity,
    tenant: TenantId,
    epoch: Epoch,
}
impl ExecutionBinding {
    /// Combine validated coordinates without acquiring resources or admitting execution.
    pub const fn new(storage: StorageIdentity, tenant: TenantId, epoch: Epoch) -> Self {
        Self {
            storage,
            tenant,
            epoch,
        }
    }
    /// Exact physical restore unit and externally established lineage.
    pub const fn storage(self) -> StorageIdentity {
        self.storage
    }
    /// Tenant selected for this operation.
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
    /// Expected generation; never refreshed from durable state.
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }
}
impl std::fmt::Debug for ExecutionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExecutionBinding([redacted])")
    }
}
