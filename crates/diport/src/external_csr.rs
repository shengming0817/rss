//! Private, read-only acquisition seam for CSR evidence already owned by an external device system.

use dynosaur::dynosaur;

/// Closed request coordinates. The request is intentionally move-only.
#[derive(Debug)]
pub struct ExternalCsrRequest {
    tenant: rss_request_context::TenantId,
    device: ids::DeviceId,
    generation: crate::PkiRequestGeneration,
    policy_digest: crate::PkiPolicyDigest,
    authorization_receipt: crate::PkiAuthorizationReceipt,
}

impl ExternalCsrRequest {
    #[must_use]
    pub const fn new(
        tenant: rss_request_context::TenantId,
        device: ids::DeviceId,
        generation: crate::PkiRequestGeneration,
        policy_digest: crate::PkiPolicyDigest,
        authorization_receipt: crate::PkiAuthorizationReceipt,
    ) -> Self {
        Self {
            tenant,
            device,
            generation,
            policy_digest,
            authorization_receipt,
        }
    }
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }
    pub const fn device(&self) -> ids::DeviceId {
        self.device
    }
    pub const fn generation(&self) -> crate::PkiRequestGeneration {
        self.generation
    }
    pub const fn policy_digest(&self) -> &crate::PkiPolicyDigest {
        &self.policy_digest
    }
    pub const fn authorization_receipt(&self) -> &crate::PkiAuthorizationReceipt {
        &self.authorization_receipt
    }
}

/// Coordinate-bound CSR evidence. PEM is redacted and bounded at construction.
#[derive(Debug)]
pub struct ExternalCsrEvidence {
    request: ExternalCsrRequest,
    csr_pem: crate::RedactedBytes,
}

impl ExternalCsrEvidence {
    pub fn new(request: ExternalCsrRequest, csr_pem: Vec<u8>) -> Result<Self, ExternalCsrError> {
        if csr_pem.is_empty() || csr_pem.len() > crate::MAX_PKI_CSR_BYTES {
            return Err(ExternalCsrError::Rejected);
        }
        Ok(Self {
            request,
            csr_pem: csr_pem.into(),
        })
    }
    pub const fn request(&self) -> &ExternalCsrRequest {
        &self.request
    }
    pub fn csr_pem(&self) -> &[u8] {
        self.csr_pem.as_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExternalCsrError {
    #[error("external csr resolver unavailable")]
    Unavailable,
    #[error("external csr evidence rejected")]
    Rejected,
    #[error("external csr evidence binding mismatch")]
    BindingMismatch,
    #[error("external csr resolver misconfigured")]
    Misconfigured,
}

#[trait_variant::make(ExternalCsrResolver: Send + Sync)]
#[dynosaur(pub DynExternalCsrResolver = dyn(box) ExternalCsrResolver, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait ExternalCsrResolverLocal {
    async fn resolve(
        &self,
        request: ExternalCsrRequest,
    ) -> Result<ExternalCsrEvidence, ExternalCsrError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_is_bounded_and_redacted() {
        let request = ExternalCsrRequest::new(
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
            ids::DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            crate::PkiRequestGeneration::try_new(1).unwrap(),
            crate::PkiPolicyDigest::new([1; 32]),
            crate::PkiAuthorizationReceipt::try_new([2; 16]).unwrap(),
        );
        let evidence = ExternalCsrEvidence::new(request, b"secret-csr".to_vec()).unwrap();
        assert!(!format!("{evidence:?}").contains("secret-csr"));
    }

    #[test]
    fn request_coordinates_reject_zero_generation_and_nil_receipt_before_construction() {
        assert!(crate::PkiRequestGeneration::try_new(0).is_err());
        assert!(crate::PkiAuthorizationReceipt::try_new([0; 16]).is_err());
    }
}
