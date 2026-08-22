//! Controlled join between provider-neutral verified PKI evidence and identity authorization.

use std::time::Duration;

use diport::{
    ExternalPkiProviderClosure, PkiArtifactError, PkiArtifactErrorKind, PkiArtifactRequest,
    PkiExtendedKeyUsage, PkiSanRef, VerifiedExternalPkiArtifactEvidence,
    canonical_pki_chain_artifact,
};
use identity::ports::device_certificate::{
    ArtifactDigest, AuthorizedCertificateArtifact, CertificateArtifactAcquisition,
    CertificateArtifactError, CertificateArtifactId, CertificateArtifactMaterial,
    CertificateArtifactRequest, CertificatePublicKeyDigest, ProductionEligibility,
    ProviderCertificateCandidate, ReportedStateHash,
};

use crate::encoding::lowercase_hex;

/// Preserve the external-PKI transport outcome without leaking provider diagnostics or collapsing
/// an indeterminate sign into a retryable pre-send outage.
pub const fn classify_external_pki_artifact_error(
    error: &PkiArtifactError,
) -> CertificateArtifactError {
    match error.kind() {
        PkiArtifactErrorKind::Unavailable => CertificateArtifactError::Unavailable,
        PkiArtifactErrorKind::OutcomeUnknown => CertificateArtifactError::OutcomeUnknown,
        PkiArtifactErrorKind::Forbidden | PkiArtifactErrorKind::Rejected => {
            CertificateArtifactError::Rejected
        }
        PkiArtifactErrorKind::Misconfigured => CertificateArtifactError::Misconfigured,
        PkiArtifactErrorKind::InvalidResponse => CertificateArtifactError::BindingMismatch,
    }
}

/// Validate all desired-policy and durable-receipt coordinates before external provider I/O.
pub fn validate_external_pki_artifact_request(
    acquisition: &CertificateArtifactAcquisition,
    request: &PkiArtifactRequest,
) -> Result<(), CertificateArtifactError> {
    let expected_receipt = acquisition.authorization_receipt_id().as_uuid();
    let expected_common_name = acquisition.scope().device().as_uuid().to_string();
    let durations = acquisition.policy().durations();
    let mut expected_sans = acquisition
        .policy()
        .sans()
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let mut request_sans = request
        .sans()
        .iter()
        .map(|san| match san.as_ref() {
            PkiSanRef::Dns(value) | PkiSanRef::Email(value) | PkiSanRef::Uri(value) => {
                value.to_owned()
            }
            PkiSanRef::Ip(value) => value.to_string(),
            PkiSanRef::Utf8OtherName { oid, value } => format!("{oid};UTF8:{value}"),
        })
        .collect::<Vec<_>>();
    expected_sans.sort_unstable();
    request_sans.sort_unstable();
    let mut expected_usages = acquisition
        .policy()
        .key_usages()
        .iter()
        .map(|usage| usage.as_label())
        .collect::<Vec<_>>();
    let mut request_usages = request
        .extended_key_usages()
        .iter()
        .map(|usage| match usage {
            PkiExtendedKeyUsage::ClientAuth => "clientAuth",
            PkiExtendedKeyUsage::ServerAuth => "serverAuth",
        })
        .collect::<Vec<_>>();
    expected_usages.sort_unstable();
    request_usages.sort_unstable();
    if request.scope().tenant() != acquisition.scope().tenant()
        || request.scope().device() != acquisition.scope().device()
        || request.generation().get() != acquisition.generation().get()
        || request.policy_digest().as_bytes() != acquisition.policy_hash().as_bytes()
        || request.authorization_receipt().as_bytes() != expected_receipt.as_bytes()
        || request.common_name().as_str() != expected_common_name
        || request.requested_validity()
            != Duration::from_secs(u64::from(durations.validity().get()))
        || request.renew_before() != Duration::from_secs(u64::from(durations.renew_before().get()))
        || request_sans != expected_sans
        || request_usages != expected_usages
    {
        return Err(CertificateArtifactError::BindingMismatch);
    }
    Ok(())
}

/// Consume locally verified external-PKI evidence and mint one production artifact only after its
/// request is joined to the current desired authorization receipt and the separately sealed
/// provider/configuration closure.
pub fn mint_external_pki_production_artifact(
    closure: &ExternalPkiProviderClosure,
    acquisition: CertificateArtifactAcquisition,
    evidence: VerifiedExternalPkiArtifactEvidence,
) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError> {
    validate_external_pki_artifact_request(&acquisition, evidence.request())?;
    let artifact = canonical_pki_chain_artifact(
        evidence.leaf_der().as_bytes(),
        evidence
            .issuer_chain_der()
            .iter()
            .map(|certificate| certificate.as_bytes()),
    );
    let artifact_digest = ArtifactDigest::restore(evidence.chain_digest().as_bytes())
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let expected_reported_state_hash =
        ReportedStateHash::restore(evidence.chain_digest().as_bytes())
            .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let public_key_digest =
        CertificatePublicKeyDigest::restore(evidence.request().spki_digest().as_bytes())?;
    let artifact_id = CertificateArtifactId::parse(&format!(
        "vault-pki-sha256:{}",
        lowercase_hex(evidence.chain_digest().as_bytes())
    ))?;
    let cert_scope = evidence.request().scope();
    let serial = evidence.serial().clone();
    let not_after = evidence.not_after();
    let expected = CertificateArtifactRequest::for_external_pki_provider(
        &acquisition,
        CertificateArtifactMaterial::new(
            public_key_digest,
            artifact_digest,
            expected_reported_state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        ),
    )?;
    ProviderCertificateCandidate::new(artifact, expected.binding().clone())
        .authorize_production(closure, evidence, &expected)
}
