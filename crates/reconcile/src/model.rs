use rss_redact::RedactedSource;
use rss_request_context::TenantId;
use std::{sync::Arc, time::Duration};
/// Stable recovery classifications. Unknown settlement is never a rollback proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    StorageContract,
    Transient,
    Permanent,
    Invariant,
    Fenced,
    Cancelled,
    Deadline,
    CommitUnknown,
    RollbackFailed,
}
/// Safe error; provider text is never exposed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("reconcile operation failed: {kind:?}")]
pub struct Error {
    kind: ErrorKind,
    #[source]
    source: Option<Arc<RedactedSource>>,
}
impl Error {
    /// Construct a closed classification.
    pub const fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }
    /// Wrap a provider error without disclosing credentials or data.
    pub fn provider<E: std::error::Error + Send + Sync + 'static>(
        kind: ErrorKind,
        source: E,
    ) -> Self {
        Self {
            kind,
            source: Some(Arc::new(RedactedSource::new(source))),
        }
    }
    /// Recovery decision.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
    /// Interrupted mutation may already have committed.
    pub fn uncertain(mut self) -> Self {
        if matches!(self.kind, ErrorKind::Cancelled | ErrorKind::Deadline) {
            self.kind = ErrorKind::CommitUnknown;
        }
        self
    }
}
fn name(value: String) -> Result<String, Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
    {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(value)
}
/// Explicit tenant and controller boundary, not an authentication credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope {
    tenant: TenantId,
    reconciler: String,
}
impl Scope {
    /// Caller selects the tenant from authenticated application context.
    pub fn new(tenant: TenantId, reconciler: impl Into<String>) -> Result<Self, Error> {
        Ok(Self {
            tenant,
            reconciler: name(reconciler.into())?,
        })
    }
    /// Bound tenant.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Controller identity.
    pub fn reconciler(&self) -> &str {
        &self.reconciler
    }
}
/// One durable work identity; never an ambient or tenantless key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    scope: Scope,
    entity: String,
}
impl Target {
    /// Construct an independently scheduled target.
    pub fn new(scope: Scope, entity: impl Into<String>) -> Result<Self, Error> {
        Ok(Self {
            scope,
            entity: name(entity.into())?,
        })
    }
    /// Scope for all reads and writes.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }
    /// Opaque canonical entity identity.
    pub fn entity(&self) -> &str {
        &self.entity
    }
}
/// Persisted next scheduling decision. Only observation can produce Converged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// Observed desired and actual equal; wait for the next durable wake.
    Converged,
    /// Action submitted; re-observe after a bounded positive delay.
    Reobserve(Duration),
    /// Retry a failed attempt, retaining its failure count across restart.
    Retry { after: Duration, failures: u32 },
    /// No automatic retries until a new durable wake.
    Suspended { failures: u32 },
}
