use crate::{Batch, Coverage, Error, Scope};
use rss_request_context::TenantId;
/// Exact product-owned authorization request; every variant carries its required context.
#[derive(Clone, Copy, Debug)]
pub enum Access<'a> {
    /// Read durable receipts or historical state in one stream.
    Read {
        /// Exact stream.
        scope: &'a Scope,
    },
    /// Submit a report within the exact coverage.
    Submit {
        /// Exact stream.
        scope: &'a Scope,
        /// Authorized collection boundary.
        coverage: &'a Coverage,
    },
    /// Activate the requested registration and producer epoch.
    Activate {
        /// Exact stream.
        scope: &'a Scope,
    },
    /// Read all historically applicable records in this tenant's journal.
    ReadJournal {
        /// Trusted tenant selected by the host, never inferred from a report.
        tenant: TenantId,
    },
}
/// Product authorization using authenticated context. No blocking I/O or implicit grants.
pub trait Authority: Send + Sync {
    /// Authorize the exact operation. Submission authority does not grant journal access.
    fn authorize(&self, request: Access<'_>) -> Result<(), Error>;
}
/// Product-authorized tenant journal read. Reauthorize at each host operation boundary;
/// cancel/join a long-lived worker before revoking its in-process grant.
#[derive(Debug)]
pub struct JournalReadGrant {
    tenant: TenantId,
}
impl JournalReadGrant {
    /// Obtain explicit tenant-wide historical journal authority.
    pub fn verify(authority: &impl Authority, tenant: TenantId) -> Result<Self, Error> {
        authority.authorize(Access::ReadJournal { tenant })?;
        Ok(Self { tenant })
    }
    /// Exact authorized tenant.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
}
/// Input bound to an exact successful product authority decision and core-computed fingerprint.
pub struct VerifiedBatch {
    scope: Scope,
    batch: Batch,
    fingerprint: [u8; 32],
}
impl std::fmt::Debug for VerifiedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedBatch(<redacted>)")
    }
}
impl VerifiedBatch {
    /// Authorize the exact scope/coverage for submission, then compute the V1 fingerprint.
    /// The authority is trusted product code; this does not authenticate credentials itself.
    /// Reauthorize each external request instead of retaining this capability across revocation.
    pub fn verify(authority: &impl Authority, scope: Scope, batch: Batch) -> Result<Self, Error> {
        authority.authorize(Access::Submit {
            scope: &scope,
            coverage: batch.coverage(),
        })?;
        let fingerprint = batch.fingerprint(&scope)?;
        Ok(Self {
            scope,
            batch,
            fingerprint,
        })
    }
    /// Exact tenant, registration, producer and epoch bound by the authority decision.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }
    /// Immutable validated report; accessing its content is an explicit unredacted read.
    pub const fn batch(&self) -> &Batch {
        &self.batch
    }
    /// Core-computed SHA-256 over the complete trusted scope and normalized report.
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}
macro_rules! grant {
    ($name:ident,$access:ident,$doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name {
            scope: Scope,
        }
        impl $name {
            /// Check this exact scope through the corresponding product authority operation.
            /// This records a successful decision; it neither authenticates a device nor activates storage.
            pub fn verify(authority: &impl Authority, scope: Scope) -> Result<Self, Error> {
                authority.authorize(Access::$access { scope: &scope })?;
                Ok(Self { scope })
            }
            /// Exact scope approved by the product authority.
            pub const fn scope(&self) -> &Scope {
                &self.scope
            }
        }
    };
}
grant!(
    ReadGrant,
    Read,
    "Product-authorized read of receipts and historical state in one exact scope."
);
grant!(
    LifecycleGrant,
    Activate,
    "Product-authorized lifecycle activation; the provider still enforces revision CAS and retirement fences."
);
