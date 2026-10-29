use crate::{Error, ErrorKind, model::name};
use rss_request_context::TenantId;

/// Tenant-bound opaque exclusive resources. This is scheduling metadata, not authorization.
#[derive(Clone, PartialEq, Eq)]
pub struct ResourceSet {
    tenant: TenantId,
    keys: Vec<String>,
}
impl std::fmt::Debug for ResourceSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResourceSet(<redacted>)")
    }
}
impl ResourceSet {
    /// Sort and deduplicate at most 1000 validated resource keys within one tenant.
    pub fn new<I, S>(tenant: TenantId, keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut canonical = Vec::new();
        for key in keys {
            if canonical.len() == 1000 {
                return Err(Error::new(ErrorKind::InvalidInput));
            }
            canonical.push(name(key.into())?);
        }
        canonical.sort();
        canonical.dedup();
        Ok(Self {
            tenant,
            keys: canonical,
        })
    }
    /// Explicitly declare that this work needs no exclusive resource.
    pub fn empty(tenant: TenantId) -> Self {
        Self {
            tenant,
            keys: Vec::new(),
        }
    }
    /// Tenant selected by the caller's trusted context.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Canonical opaque keys; explicit access does not authorize logging them.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }
}

/// A business step either produced its value or must yield without consuming failures.
#[derive(Debug)]
pub enum ReconcileStep<T> {
    Ready(T),
    /// Persist a positive whole-millisecond delay (at most one day).
    Deferred(std::time::Duration),
}

/// Bounded provider scan. Only returned claims occupy execution slots.
pub struct ClaimBatch<C> {
    pub claims: Vec<C>,
    /// Another bounded page remains in this scan round. It is not claim authority.
    pub more: bool,
}
