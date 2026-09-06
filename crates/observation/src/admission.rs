use crate::{Batch, Coverage, Error, Scope};
/// Product-owned authority checks are trusted code, not a credential or device verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    /// Read durable receipts or historical stream state.
    Read,
    /// Submit a report within the exact authorized coverage.
    Submit,
    /// Activate the requested registration and producer epoch using lifecycle CAS.
    Activate,
}
/// Trusted product authorization boundary, normally backed by already authenticated context.
/// Implementations must validate the requested access and coverage; this synchronous method
/// must not perform blocking provider I/O. Returning success grants the exact requested scope.
pub trait Authority: Send + Sync {
    /// Verify this exact scope and (for submission) coverage against trusted context.
    fn authorize(
        &self,
        scope: &Scope,
        coverage: Option<&Coverage>,
        access: Access,
    ) -> Result<(), Error>;
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
        authority.authorize(&scope, Some(batch.coverage()), Access::Submit)?;
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
                authority.authorize(&scope, None, Access::$access)?;
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
