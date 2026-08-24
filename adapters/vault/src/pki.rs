//! Vault PKI caller-owned CSR signing transport.
//!
//! The only wire operation is role-selected `/v1/{mount}/sign/{role}`. The adapter verifies every
//! returned certificate locally before producing transport evidence.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use diport::{
    CertNotAfter, CertSerial, Clock, ExternalPkiProviderClosure, MAX_PKI_CERT_BYTES,
    MAX_PKI_ISSUER_CERTS, PkiArtifactError, PkiArtifactErrorKind, PkiArtifactRequest,
    PkiArtifactValueError, PkiChainDigest, PkiExtendedKeyUsage, PkiProviderConfigDigest, PkiSan,
    PkiSanRef, RedactedBytes, VerifiedExternalPkiArtifactEvidence, canonical_pki_chain_artifact,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

use crate::{VaultConfigError, VaultToken, parse_mount_segments, validate_vault_base_url};

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CLOCK_SKEW: Duration = Duration::from_secs(300);

/// Vault PKI CSR-sign transport.
pub struct VaultPkiTransport {
    client: reqwest::Client,
    tls_roots_digest: [u8; 32],
    base: reqwest::Url,
    token: VaultToken,
    mount_segments: Vec<String>,
    role: String,
    trust_roots_der: Vec<Vec<u8>>,
    timeout: Duration,
    clock: Arc<dyn Clock>,
}

/// Assembly-wide Vault PKI closure plus the exact transport whose validated production
/// configuration it seals.
///
/// The closure is reusable across commands, but each [`Self::sign_csr`] consumes a separately
/// receipt-bound request and returns move-only locally verified transport evidence. Identity-owned
/// desired authorization remains a separate consuming funnel.
pub struct VaultExternalPkiProviderClosure {
    transport: VaultPkiTransport,
    provider_closure: ExternalPkiProviderClosure,
}

impl std::fmt::Debug for VaultExternalPkiProviderClosure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultExternalPkiProviderClosure(<sealed>)")
    }
}

/// Validated Vault PKI mount path.
#[derive(Clone)]
pub struct VaultPkiMount(Vec<String>);

impl VaultPkiMount {
    /// Validates a Vault mount path without accepting traversal segments.
    pub fn try_new(value: impl Into<String>) -> Result<Self, VaultConfigError> {
        parse_mount_segments(&value.into()).map(Self)
    }
}

/// Validated Vault PKI signing role.
#[derive(Clone)]
pub struct VaultPkiRole(String);

impl VaultPkiRole {
    /// Validates a single Vault PKI role segment.
    pub fn try_new(value: impl Into<String>) -> Result<Self, VaultConfigError> {
        validate_role(value.into()).map(Self)
    }
}

/// Named construction input for one Vault PKI transport.
pub struct VaultPkiTransportConfig {
    addr: String,
    token: String,
    mount: VaultPkiMount,
    role: VaultPkiRole,
    trust_roots_pem: Vec<RedactedBytes>,
    timeout: Duration,
}

impl VaultPkiTransportConfig {
    /// Creates named transport configuration from already-distinct mount and role types.
    pub fn new(
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: VaultPkiMount,
        role: VaultPkiRole,
        trust_roots_pem: Vec<RedactedBytes>,
        timeout: Duration,
    ) -> Self {
        Self {
            addr: addr.into(),
            token: token.into(),
            mount,
            role,
            trust_roots_pem,
            timeout,
        }
    }
}

/// Material minted only after the Vault adapter has verified CSR, chain, policy, and expiry.
pub struct VaultPkiArtifactEvidence {
    verified: VerifiedExternalPkiArtifactEvidence,
}

impl VaultPkiArtifactEvidence {
    fn from_verified_transport_material(
        provider_config_digest: PkiProviderConfigDigest,
        request: PkiArtifactRequest,
        leaf_der: RedactedBytes,
        issuer_chain_der: Vec<RedactedBytes>,
        chain_digest: PkiChainDigest,
        serial: CertSerial,
        not_after: CertNotAfter,
    ) -> Result<Self, PkiArtifactValueError> {
        Ok(Self {
            verified: VerifiedExternalPkiArtifactEvidence::seal_vault_csr_sign(
                pkiauthmint::ExternalPkiProviderMint::capability(),
                provider_config_digest,
                request,
                leaf_der,
                issuer_chain_der,
                chain_digest,
                serial,
                not_after,
            )?,
        })
    }

    /// Returns the exact request consumed by the verified attempt.
    pub const fn request(&self) -> &PkiArtifactRequest {
        self.verified.request()
    }
    /// Returns the verified leaf certificate DER.
    pub const fn leaf_der(&self) -> &RedactedBytes {
        self.verified.leaf_der()
    }
    /// Returns the verified issuer chain ordered toward the trust root.
    pub fn issuer_chain_der(&self) -> &[RedactedBytes] {
        self.verified.issuer_chain_der()
    }
    /// Returns the canonical verified-chain digest.
    pub const fn chain_digest(&self) -> &PkiChainDigest {
        self.verified.chain_digest()
    }
    /// Returns the verified leaf serial.
    pub const fn serial(&self) -> &CertSerial {
        self.verified.serial()
    }
    /// Returns the verified leaf expiry.
    pub const fn not_after(&self) -> CertNotAfter {
        self.verified.not_after()
    }

    /// Consume the Vault-specific wrapper into provider-neutral verified material for the identity
    /// production mint. This remains transport evidence and carries no desired-state authority.
    pub fn into_verified(self) -> VerifiedExternalPkiArtifactEvidence {
        self.verified
    }
}

impl std::fmt::Debug for VaultPkiArtifactEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultPkiArtifactEvidence(<redacted>)")
    }
}

/// HTTPS-only, redirect-free client capability for the Vault PKI transport.
///
/// Construction is intentionally narrow: callers may add explicit trust roots, but cannot
/// enable redirects, plaintext HTTP, or invalid-certificate acceptance.
#[derive(Clone)]
pub struct VaultPkiHttpClient {
    client: reqwest::Client,
    tls_roots_digest: [u8; 32],
}

impl VaultPkiHttpClient {
    /// Builds a hardened client that trusts only the supplied Vault server roots.
    pub fn with_root_certificates(
        roots_pem: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<Self, VaultConfigError> {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .pool_max_idle_per_host(0);
        let mut canonical_roots = Vec::new();
        for root_pem in roots_pem {
            let root_pem = root_pem.as_ref();
            let root_der = parse_one_pem(root_pem, "CERTIFICATE")
                .map_err(|_| VaultConfigError::InvalidPkiTrustRoot)?;
            let root = reqwest::Certificate::from_pem(root_pem)
                .map_err(|_| VaultConfigError::InvalidPkiTrustRoot)?;
            canonical_roots.push(root_der);
            builder = builder.add_root_certificate(root);
        }
        if canonical_roots.is_empty() {
            return Err(VaultConfigError::InvalidPkiTrustRoot);
        }
        canonical_roots.sort_unstable();
        let mut hasher = Sha256::new();
        hash_frame(&mut hasher, b"rss.vault.pki-http-tls-roots.v1");
        for root in canonical_roots {
            hash_frame(&mut hasher, &root);
        }
        let client = builder
            .build()
            .map_err(|_| VaultConfigError::InvalidPkiTrustRoot)?;
        Ok(Self {
            client,
            tls_roots_digest: hasher.finalize().into(),
        })
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    fn allow_http_for_test() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test client");
        Self {
            client,
            tls_roots_digest: Sha256::digest(b"rss.vault.pki-http-test-only.v1").into(),
        }
    }
}

impl VaultPkiTransport {
    /// Creates an HTTPS-only CSR-sign transport from named, validated configuration.
    pub fn new(
        clock: Arc<dyn Clock>,
        client: VaultPkiHttpClient,
        config: VaultPkiTransportConfig,
    ) -> Result<Self, VaultConfigError> {
        Self::build(clock, client, config, false)
    }

    #[cfg(test)]
    pub(crate) fn new_allow_http_for_test(
        clock: Arc<dyn Clock>,
        client: VaultPkiHttpClient,
        config: VaultPkiTransportConfig,
    ) -> Result<Self, VaultConfigError> {
        Self::build(clock, client, config, true)
    }

    fn build(
        clock: Arc<dyn Clock>,
        client: VaultPkiHttpClient,
        config: VaultPkiTransportConfig,
        allow_http: bool,
    ) -> Result<Self, VaultConfigError> {
        let VaultPkiTransportConfig {
            addr,
            token,
            mount,
            role,
            trust_roots_pem,
            timeout,
        } = config;
        let token = VaultToken::new(token);
        if token.as_str().trim().is_empty() {
            return Err(VaultConfigError::EmptyToken);
        }
        if timeout.is_zero() {
            return Err(VaultConfigError::ZeroTimeout);
        }
        let base = validate_vault_base_url(&addr, allow_http).map_err(VaultConfigError::from)?;
        let mount_segments = mount.0;
        let role = role.0;
        if trust_roots_pem.is_empty() {
            return Err(VaultConfigError::EmptyPkiTrustRoots);
        }
        let trust_roots_der = trust_roots_pem
            .iter()
            .map(|pem| {
                parse_one_pem(pem.as_bytes(), "CERTIFICATE")
                    .map_err(|_| VaultConfigError::InvalidPkiTrustRoot)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for root in &trust_roots_der {
            let root_cert = parse_cert(root).map_err(|_| VaultConfigError::InvalidPkiTrustRoot)?;
            let constraints = root_cert
                .basic_constraints()
                .map_err(|_| VaultConfigError::InvalidPkiTrustRoot)?;
            if !constraints.is_some_and(|value| value.value.ca)
                || root_cert.verify_signature(None).is_err()
            {
                return Err(VaultConfigError::InvalidPkiTrustRoot);
            }
        }
        Ok(Self {
            client: client.client,
            tls_roots_digest: client.tls_roots_digest,
            base,
            token,
            mount_segments,
            role,
            trust_roots_der,
            timeout,
            clock,
        })
    }

    fn endpoint(&self) -> Result<reqwest::Url, PkiArtifactError> {
        let mut url = self.base.clone();
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| invalid_response("invalid base url"))?;
        segments
            .pop_if_empty()
            .push("v1")
            .extend(&self.mount_segments)
            .push("sign")
            .push(&self.role);
        drop(segments);
        Ok(url)
    }
}

impl VaultExternalPkiProviderClosure {
    /// Construct the HTTPS-only transport and seal its non-secret production configuration in one
    /// consuming boundary.
    pub fn new(
        clock: Arc<dyn Clock>,
        client: VaultPkiHttpClient,
        config: VaultPkiTransportConfig,
    ) -> Result<Self, VaultConfigError> {
        let transport = VaultPkiTransport::new(clock, client, config)?;
        Ok(Self::from_transport(transport))
    }

    fn from_transport(transport: VaultPkiTransport) -> Self {
        let digest = production_config_digest(&transport);
        let provider_closure = ExternalPkiProviderClosure::seal_vault_csr_sign(
            pkiauthmint::ExternalPkiProviderMint::capability(),
            digest,
        );
        Self {
            transport,
            provider_closure,
        }
    }

    /// Sign and locally verify one caller-owned CSR through the exact transport sealed by this
    /// provider closure.
    pub async fn sign_csr(
        &self,
        request: PkiArtifactRequest,
    ) -> Result<VaultPkiArtifactEvidence, PkiArtifactError> {
        self.transport.sign_csr(request).await
    }

    /// Verify that the configured token may read the exact PKI role used by this closure.
    /// This is side-effect free and exercises DNS, TLS, Vault availability, mount, role, and ACL.
    pub async fn is_capability_ready(&self) -> bool {
        self.transport.is_capability_ready().await
    }

    /// Borrow the provider-neutral assembly closure for construction/drift inspection.
    pub const fn provider_closure(&self) -> &ExternalPkiProviderClosure {
        &self.provider_closure
    }
}

fn production_config_digest(transport: &VaultPkiTransport) -> PkiProviderConfigDigest {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"rss.vault.external-pki-provider.v1");
    hash_frame(&mut hasher, transport.base.as_str().as_bytes());
    for segment in &transport.mount_segments {
        hash_frame(&mut hasher, segment.as_bytes());
    }
    hash_frame(&mut hasher, transport.role.as_bytes());
    hash_frame(&mut hasher, &transport.tls_roots_digest);
    for root in &transport.trust_roots_der {
        hash_frame(&mut hasher, root);
    }
    hash_frame(&mut hasher, &transport.timeout.as_secs().to_be_bytes());
    hash_frame(&mut hasher, &transport.timeout.subsec_nanos().to_be_bytes());
    PkiProviderConfigDigest::new(hasher.finalize().into())
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_role(role: String) -> Result<String, VaultConfigError> {
    let trimmed = role.trim();
    if trimmed.is_empty() {
        return Err(VaultConfigError::EmptyPkiRole);
    }
    if trimmed != role
        || role.contains('/')
        || role == "."
        || role == ".."
        || role.contains(['\0', '\r', '\n'])
    {
        return Err(VaultConfigError::InvalidPkiRole);
    }
    Ok(role)
}

impl VaultPkiTransport {
    async fn is_capability_ready(&self) -> bool {
        let mut url = self.base.clone();
        let Ok(mut segments) = url.path_segments_mut() else {
            return false;
        };
        segments
            .pop_if_empty()
            .push("v1")
            .extend(&self.mount_segments)
            .push("roles")
            .push(&self.role);
        drop(segments);
        self.client
            .get(url)
            .header(VAULT_TOKEN_HEADER, self.token.as_str())
            .send()
            .await
            .is_ok_and(|response| response.status() == reqwest::StatusCode::OK)
    }

    /// Signs one caller-owned CSR and returns evidence minted only after local verification.
    #[tracing::instrument(skip_all, fields(target = "vault", operation = "pki-sign"))]
    pub async fn sign_csr(
        &self,
        request: PkiArtifactRequest,
    ) -> Result<VaultPkiArtifactEvidence, PkiArtifactError> {
        let result = self.sign_csr_attempt(request).await;
        trace_pki_attempt(result.as_ref().err());
        result.map_err(|failure| failure.error)
    }

    async fn sign_csr_attempt(
        &self,
        request: PkiArtifactRequest,
    ) -> Result<VaultPkiArtifactEvidence, PkiAttemptFailure> {
        let request_failure = |error| {
            PkiAttemptFailure::new(
                error,
                "request-validation",
                "invalid-request",
                "not-applied",
            )
        };
        let csr_der = parse_one_pem(request.csr_pem().as_bytes(), "CERTIFICATE REQUEST")
            .map_err(request_failure)?;
        let csr = parse_csr_der(&csr_der).map_err(request_failure)?;
        csr.verify_signature()
            .map_err(|_| invalid_response("CSR signature verification failed"))
            .map_err(request_failure)?;
        verify_csr_bindings(&request, &csr).map_err(request_failure)?;
        let observed_common_name =
            unique_common_name(&csr.certification_request_info.subject).map_err(request_failure)?;
        if observed_common_name != request.common_name().as_str() {
            return Err(request_failure(invalid_response(
                "CSR common name does not match request",
            )));
        }
        let body = build_sign_body(&request);
        let body = serde_json::to_vec(&body)
            .map_err(|_| invalid_response("request encoding failed"))
            .map_err(|error| {
                PkiAttemptFailure::new(error, "request-encoding", "encoding-failed", "not-applied")
            })?;
        let endpoint = self.endpoint().map_err(|error| {
            PkiAttemptFailure::new(
                error,
                "request-preparation",
                "invalid-endpoint",
                "not-applied",
            )
        })?;
        let response = self
            .client
            .post(endpoint)
            .header(VAULT_TOKEN_HEADER, self.token.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(self.timeout)
            .body(body)
            .send()
            .await
            .map_err(classify_send_error)
            .map_err(PkiAttemptFailure::from_send)?;
        let status = response.status();
        if !status.is_success() {
            return Err(PkiAttemptFailure::from_status(status));
        }
        let raw = read_bounded(response)
            .await
            .map_err(|error| PkiAttemptFailure::from_response(error, "response-body"))?;
        verify_and_normalize(
            request,
            &raw,
            self.clock.now(),
            &self.trust_roots_der,
            production_config_digest(self),
        )
        .map_err(|error| PkiAttemptFailure::from_response(error, "response-verification"))
    }
}

fn trace_pki_attempt(failure: Option<&PkiAttemptFailure>) {
    match failure {
        None => tracing::debug!(
            phase = "response-verification",
            reason = "verified",
            outcome = "verified",
            category = "verified",
            status = "success",
            "Vault PKI attempt settled"
        ),
        Some(failure) => tracing::warn!(
            phase = failure.phase,
            reason = failure.reason,
            outcome = failure.outcome,
            category = failure.category,
            status = "failure",
            "Vault PKI attempt settled"
        ),
    }
}

struct PkiAttemptFailure {
    error: PkiArtifactError,
    phase: &'static str,
    reason: &'static str,
    outcome: &'static str,
    category: &'static str,
}

impl PkiAttemptFailure {
    fn new(
        error: PkiArtifactError,
        phase: &'static str,
        reason: &'static str,
        outcome: &'static str,
    ) -> Self {
        let category = error_kind_label(error.kind());
        Self {
            error,
            phase,
            reason,
            outcome,
            category,
        }
    }

    fn from_send(error: PkiArtifactError) -> Self {
        let outcome = if error.kind() == PkiArtifactErrorKind::Unavailable {
            "not-applied"
        } else {
            "unknown"
        };
        Self::new(error, "transport", "request-failed", outcome)
    }

    fn from_status(status: reqwest::StatusCode) -> Self {
        let error = status_error(status);
        let outcome = if error.kind() == PkiArtifactErrorKind::OutcomeUnknown {
            "unknown"
        } else {
            "rejected"
        };
        Self::new(error, "response-status", status_reason(status), outcome)
    }

    fn from_response(error: PkiArtifactError, phase: &'static str) -> Self {
        let outcome = if error.kind() == PkiArtifactErrorKind::OutcomeUnknown {
            "unknown"
        } else {
            "provider-applied-invalid-response"
        };
        Self::new(error, phase, "invalid-response", outcome)
    }
}

const fn error_kind_label(kind: PkiArtifactErrorKind) -> &'static str {
    match kind {
        PkiArtifactErrorKind::Rejected => "rejected",
        PkiArtifactErrorKind::Forbidden => "forbidden",
        PkiArtifactErrorKind::Misconfigured => "misconfigured",
        PkiArtifactErrorKind::Unavailable => "unavailable",
        PkiArtifactErrorKind::OutcomeUnknown => "outcome-unknown",
        PkiArtifactErrorKind::InvalidResponse => "invalid-response",
    }
}

fn status_reason(status: reqwest::StatusCode) -> &'static str {
    match status.as_u16() {
        401 | 403 => "authorization-denied",
        404 => "mount-or-role-missing",
        429 => "rate-limited",
        400..=499 => "request-rejected",
        500..=599 => "provider-error",
        _ => "unexpected-status",
    }
}

fn build_sign_body(request: &PkiArtifactRequest) -> Value {
    let mut alt_names = Vec::new();
    let mut ip_sans = Vec::new();
    let mut uri_sans = Vec::new();
    let mut other_sans = Vec::new();
    for san in request.sans() {
        match san.as_ref() {
            PkiSanRef::Dns(value) | PkiSanRef::Email(value) => alt_names.push(value.to_owned()),
            PkiSanRef::Ip(value) => ip_sans.push(value.to_string()),
            PkiSanRef::Uri(value) => uri_sans.push(value.to_owned()),
            PkiSanRef::Utf8OtherName { oid, value } => {
                other_sans.push(format!("{oid};UTF8:{value}"))
            }
        }
    }
    serde_json::json!({
        "csr": std::str::from_utf8(request.csr_pem().as_bytes()).unwrap_or_default(),
        "common_name": request.common_name().as_str(),
        "alt_names": alt_names.join(","),
        "ip_sans": ip_sans.join(","),
        "uri_sans": uri_sans.join(","),
        "other_sans": other_sans.join(","),
        "ttl": format!("{}s", request.requested_validity().as_secs()),
        "format": "pem",
        "exclude_cn_from_sans": true,
    })
}

async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, PkiArtifactError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(invalid_response("response body exceeds limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(classify_body_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(invalid_response("response body exceeds limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn verify_and_normalize(
    request: PkiArtifactRequest,
    raw: &[u8],
    now: SystemTime,
    trust_roots: &[Vec<u8>],
    provider_config_digest: PkiProviderConfigDigest,
) -> Result<VaultPkiArtifactEvidence, PkiArtifactError> {
    let wire: Value = serde_json::from_slice(raw).map_err(|_| invalid_response("invalid JSON"))?;
    let data = wire
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_response("missing data"))?;
    if data.contains_key("private_key") {
        return Err(invalid_response("private key in response"));
    }
    let leaf_der = parse_wire_cert(data.get("certificate"))?;
    let issuing_ca = parse_wire_cert(data.get("issuing_ca"))?;
    let ca_chain = data
        .get("ca_chain")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response("missing CA chain"))?;
    if ca_chain.is_empty() || ca_chain.len() > MAX_PKI_ISSUER_CERTS {
        return Err(invalid_response("invalid CA chain size"));
    }
    let mut response_issuers = Vec::with_capacity(ca_chain.len() + 1);
    response_issuers.push(issuing_ca.clone());
    for value in ca_chain {
        response_issuers.push(parse_wire_cert(Some(value))?);
    }
    dedup_exact(&mut response_issuers);
    // Vault versions differ on whether `ca_chain` repeats the leaf. The canonical transport
    // representation always stores the leaf once, followed only by its issuer path.
    response_issuers.retain(|der| der != &leaf_der);

    let leaf = parse_cert(&leaf_der)?;
    verify_leaf(&request, &leaf, now)?;
    let serial_text = data
        .get("serial_number")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_response("missing serial"))?;
    let serial_bytes = parse_serial(serial_text)?;
    if leaf.raw_serial() != serial_bytes.as_slice() {
        return Err(invalid_response("serial mismatch"));
    }
    let serial =
        CertSerial::try_new(serial_bytes).map_err(|_| invalid_response("invalid serial"))?;
    let expiration = parse_expiration(data.get("expiration"))?;
    if expiration != leaf.validity().not_after.timestamp() {
        return Err(invalid_response("expiration mismatch"));
    }

    let issuer_chain = canonical_chain(&leaf, &response_issuers, trust_roots, now)?;
    let not_after = CertNotAfter::try_from_system_time(
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(
                expiration
                    .try_into()
                    .map_err(|_| invalid_response("invalid expiration"))?,
            ),
    )
    .map_err(|_| invalid_response("invalid expiration"))?;
    let chain_digest = chain_digest(&leaf_der, &issuer_chain);
    VaultPkiArtifactEvidence::from_verified_transport_material(
        provider_config_digest,
        request,
        RedactedBytes::new(leaf_der),
        issuer_chain.into_iter().map(RedactedBytes::new).collect(),
        PkiChainDigest::new(chain_digest),
        serial,
        not_after,
    )
    .map_err(|_| invalid_response("invalid evidence material"))
}

fn verify_csr_bindings(
    request: &PkiArtifactRequest,
    csr: &X509CertificationRequest<'_>,
) -> Result<(), PkiArtifactError> {
    let actual_digest: [u8; 32] =
        Sha256::digest(csr.certification_request_info.subject_pki.raw).into();
    if request.spki_digest().as_bytes() != &actual_digest {
        return Err(invalid_response("CSR SPKI mismatch"));
    }
    let mut sans = None;
    let mut key_usage = None;
    let mut extended_key_usage = None;
    for extension in csr
        .requested_extensions()
        .ok_or_else(|| invalid_response("CSR extensions missing"))?
    {
        match extension {
            ParsedExtension::SubjectAlternativeName(value) => sans = Some(value),
            ParsedExtension::KeyUsage(value) => key_usage = Some(value),
            ParsedExtension::ExtendedKeyUsage(value) => extended_key_usage = Some(value),
            ParsedExtension::UnsupportedExtension { .. }
            | ParsedExtension::ParseError { .. }
            | ParsedExtension::Unparsed => {
                return Err(invalid_response("unsupported CSR extension"));
            }
            _ => {}
        }
    }
    compare_sans(
        request.sans(),
        &sans
            .ok_or_else(|| invalid_response("CSR SAN missing"))?
            .general_names,
    )?;
    let usage = key_usage.ok_or_else(|| invalid_response("CSR key usage missing"))?;
    if !usage.digital_signature()
        || usage.non_repudiation()
        || usage.key_encipherment()
        || usage.data_encipherment()
        || usage.key_agreement()
        || usage.key_cert_sign()
        || usage.crl_sign()
        || usage.encipher_only()
        || usage.decipher_only()
    {
        return Err(invalid_response("CSR key usage mismatch"));
    }
    verify_eku(
        request,
        extended_key_usage.ok_or_else(|| invalid_response("CSR EKU missing"))?,
    )
}

fn verify_leaf(
    request: &PkiArtifactRequest,
    leaf: &X509Certificate<'_>,
    now: SystemTime,
) -> Result<(), PkiArtifactError> {
    let csr_der = parse_one_pem(request.csr_pem().as_bytes(), "CERTIFICATE REQUEST")?;
    let csr = parse_csr_der(&csr_der)?;
    if semantic_subject(leaf.subject())?
        != semantic_subject(&csr.certification_request_info.subject)?
    {
        return Err(invalid_response("subject mismatch"));
    }
    let digest: [u8; 32] = Sha256::digest(leaf.public_key().raw).into();
    if request.spki_digest().as_bytes() != &digest {
        return Err(invalid_response("leaf SPKI mismatch"));
    }
    let sans = leaf
        .subject_alternative_name()
        .map_err(|_| invalid_response("invalid SAN"))?
        .ok_or_else(|| invalid_response("missing SAN"))?;
    compare_sans(request.sans(), &sans.value.general_names)?;
    let constraints = leaf
        .basic_constraints()
        .map_err(|_| invalid_response("invalid basic constraints"))?;
    if constraints.is_none_or(|value| value.value.ca) {
        return Err(invalid_response("leaf is a CA"));
    }
    let usage = leaf
        .key_usage()
        .map_err(|_| invalid_response("invalid key usage"))?
        .ok_or_else(|| invalid_response("missing key usage"))?;
    if !usage.value.digital_signature()
        || usage.value.non_repudiation()
        || usage.value.key_encipherment()
        || usage.value.data_encipherment()
        || usage.value.key_agreement()
        || usage.value.key_cert_sign()
        || usage.value.crl_sign()
        || usage.value.encipher_only()
        || usage.value.decipher_only()
    {
        return Err(invalid_response("invalid leaf key usage"));
    }
    let eku = leaf
        .extended_key_usage()
        .map_err(|_| invalid_response("invalid EKU"))?
        .ok_or_else(|| invalid_response("missing EKU"))?;
    verify_eku(request, eku.value)?;
    reject_unhandled_critical_extensions(leaf, false)?;
    let now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invalid_response("clock before epoch"))?
        .as_secs();
    let now_secs: i64 = now_secs
        .try_into()
        .map_err(|_| invalid_response("clock out of range"))?;
    let skew = CLOCK_SKEW.as_secs() as i64;
    if leaf.validity().not_before.timestamp() > now_secs.saturating_add(skew)
        || leaf.validity().not_before.timestamp() < now_secs.saturating_sub(skew)
        || leaf.validity().not_after.timestamp() <= now_secs
    {
        return Err(invalid_response("certificate outside validity"));
    }
    let remaining = u64::try_from(leaf.validity().not_after.timestamp() - now_secs)
        .map_err(|_| invalid_response("invalid lifetime"))?;
    let actual_lifetime = u64::try_from(
        leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
    )
    .map_err(|_| invalid_response("invalid certificate lifetime"))?;
    if actual_lifetime
        > request
            .requested_validity()
            .as_secs()
            .saturating_add(CLOCK_SKEW.as_secs())
        || remaining <= request.renew_before().as_secs()
    {
        return Err(invalid_response("certificate lifetime mismatch"));
    }
    Ok(())
}

fn verify_eku(
    request: &PkiArtifactRequest,
    eku: &x509_parser::extensions::ExtendedKeyUsage<'_>,
) -> Result<(), PkiArtifactError> {
    let want_client = request
        .extended_key_usages()
        .contains(&PkiExtendedKeyUsage::ClientAuth);
    let want_server = request
        .extended_key_usages()
        .contains(&PkiExtendedKeyUsage::ServerAuth);
    if eku.client_auth != want_client
        || eku.server_auth != want_server
        || eku.any
        || eku.code_signing
        || eku.email_protection
        || eku.time_stamping
        || eku.ocsp_signing
        || !eku.other.is_empty()
    {
        return Err(invalid_response("EKU mismatch"));
    }
    Ok(())
}

fn canonical_chain(
    leaf: &X509Certificate<'_>,
    response: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: SystemTime,
) -> Result<Vec<Vec<u8>>, PkiArtifactError> {
    let mut candidates = response.to_vec();
    for root in roots {
        if !candidates.contains(root) {
            candidates.push(root.clone());
        }
    }
    let response_set: HashSet<&[u8]> = response.iter().map(Vec::as_slice).collect();
    let mut used_response = HashSet::new();
    let mut chain = Vec::new();
    let mut issuer = leaf.issuer().as_raw().to_vec();
    loop {
        let matches: Vec<&Vec<u8>> = candidates
            .iter()
            .filter(|der| {
                parse_cert(der).is_ok_and(|cert| cert.subject().as_raw() == issuer.as_slice())
            })
            .collect();
        if matches.len() != 1 {
            return Err(invalid_response("ambiguous or missing issuer"));
        }
        let der = matches[0];
        if chain.contains(der) {
            return Err(invalid_response("issuer loop"));
        }
        let cert = parse_cert(der)?;
        reject_unhandled_critical_extensions(&cert, true)?;
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| invalid_response("clock before epoch"))?
            .as_secs();
        let now = x509_parser::time::ASN1Time::from_timestamp(
            now.try_into()
                .map_err(|_| invalid_response("clock out of range"))?,
        )
        .map_err(|_| invalid_response("clock out of range"))?;
        if !cert.validity().is_valid_at(now) {
            return Err(invalid_response("issuer outside validity"));
        }
        if let Some(previous) = chain.last() {
            parse_cert(previous)?.verify_signature(Some(cert.public_key()))
        } else {
            leaf.verify_signature(Some(cert.public_key()))
        }
        .map_err(|_| invalid_response("certificate signature mismatch"))?;
        let bc = cert
            .basic_constraints()
            .map_err(|_| invalid_response("invalid issuer constraints"))?;
        let ku = cert
            .key_usage()
            .map_err(|_| invalid_response("invalid issuer key usage"))?;
        if !bc.as_ref().is_some_and(|value| value.value.ca)
            || !ku.is_some_and(|value| value.value.key_cert_sign())
        {
            return Err(invalid_response("issuer is not a signing CA"));
        }
        if bc
            .as_ref()
            .and_then(|value| value.value.path_len_constraint)
            .is_some_and(|limit| chain.len() as u32 > limit)
        {
            return Err(invalid_response("issuer path length exceeded"));
        }
        if response_set.contains(der.as_slice()) {
            used_response.insert(der.as_slice());
        }
        chain.push(der.clone());
        if cert.subject().as_raw() == cert.issuer().as_raw() {
            cert.verify_signature(None)
                .map_err(|_| invalid_response("invalid root signature"))?;
            if !roots.contains(der) {
                return Err(invalid_response("untrusted root"));
            }
            break;
        }
        issuer = cert.issuer().as_raw().to_vec();
        if chain.len() > MAX_PKI_ISSUER_CERTS {
            return Err(invalid_response("chain too long"));
        }
    }
    if used_response.len() != response_set.len() {
        return Err(invalid_response("unrelated response certificate"));
    }
    Ok(chain)
}

fn reject_unhandled_critical_extensions(
    cert: &X509Certificate<'_>,
    issuer: bool,
) -> Result<(), PkiArtifactError> {
    if cert.extensions().iter().any(|extension| {
        if !extension.critical {
            return false;
        }
        if issuer {
            !matches!(
                extension.parsed_extension(),
                ParsedExtension::BasicConstraints(_) | ParsedExtension::KeyUsage(_)
            )
        } else {
            !matches!(
                extension.parsed_extension(),
                ParsedExtension::BasicConstraints(_)
                    | ParsedExtension::KeyUsage(_)
                    | ParsedExtension::ExtendedKeyUsage(_)
                    | ParsedExtension::SubjectAlternativeName(_)
            )
        }
    }) {
        return Err(invalid_response("unhandled critical certificate extension"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ObservedSan {
    Dns(String),
    Email(String),
    Ip(IpAddr),
    Uri(String),
    Other(String, Vec<u8>),
}

fn compare_sans(expected: &[PkiSan], actual: &[GeneralName<'_>]) -> Result<(), PkiArtifactError> {
    let actual_count = actual.len();
    let expected: HashSet<ObservedSan> = expected
        .iter()
        .map(expected_san)
        .collect::<Result<_, _>>()?;
    let actual: HashSet<ObservedSan> = actual.iter().map(observed_san).collect::<Result<_, _>>()?;
    if expected.len() != actual_count || actual.len() != actual_count || expected != actual {
        return Err(invalid_response("SAN mismatch"));
    }
    Ok(())
}

fn expected_san(san: &PkiSan) -> Result<ObservedSan, PkiArtifactError> {
    Ok(match san.as_ref() {
        PkiSanRef::Dns(value) => ObservedSan::Dns(value.to_owned()),
        PkiSanRef::Email(value) => ObservedSan::Email(value.to_owned()),
        PkiSanRef::Ip(value) => ObservedSan::Ip(value),
        PkiSanRef::Uri(value) => ObservedSan::Uri(value.to_owned()),
        PkiSanRef::Utf8OtherName { oid, value } => {
            ObservedSan::Other(oid.to_owned(), explicit_utf8_der(value.as_bytes())?)
        }
    })
}

fn observed_san(san: &GeneralName<'_>) -> Result<ObservedSan, PkiArtifactError> {
    Ok(match san {
        GeneralName::DNSName(value) => ObservedSan::Dns((*value).to_owned()),
        GeneralName::RFC822Name(value) => ObservedSan::Email((*value).to_owned()),
        GeneralName::IPAddress(bytes) => {
            let bytes = *bytes;
            if bytes.len() == 4 {
                ObservedSan::Ip(IpAddr::V4(Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                )))
            } else if bytes.len() == 16 {
                let octets: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| invalid_response("invalid IP SAN"))?;
                ObservedSan::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
            } else {
                return Err(invalid_response("invalid IP SAN"));
            }
        }
        GeneralName::URI(value) => ObservedSan::Uri((*value).to_owned()),
        GeneralName::OtherName(oid, bytes) => {
            ObservedSan::Other(oid.to_id_string(), bytes.to_vec())
        }
        _ => return Err(invalid_response("unsupported SAN")),
    })
}

fn explicit_utf8_der(value: &[u8]) -> Result<Vec<u8>, PkiArtifactError> {
    let mut inner = vec![0x0c];
    encode_len(value.len(), &mut inner)?;
    inner.extend_from_slice(value);
    let mut outer = vec![0xa0];
    encode_len(inner.len(), &mut outer)?;
    outer.extend(inner);
    Ok(outer)
}

fn encode_len(len: usize, out: &mut Vec<u8>) -> Result<(), PkiArtifactError> {
    if len < 128 {
        out.push(len as u8);
        return Ok(());
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| invalid_response("invalid DER length"))?;
    let used = &bytes[first..];
    out.push(0x80 | u8::try_from(used.len()).map_err(|_| invalid_response("invalid DER length"))?);
    out.extend_from_slice(used);
    Ok(())
}

fn parse_csr_der(der: &[u8]) -> Result<X509CertificationRequest<'_>, PkiArtifactError> {
    let (remaining, csr) =
        X509CertificationRequest::from_der(der).map_err(|_| invalid_response("invalid CSR DER"))?;
    if !remaining.is_empty() {
        return Err(invalid_response("trailing CSR DER"));
    }
    Ok(csr)
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, PkiArtifactError> {
    let (remaining, cert) =
        X509Certificate::from_der(der).map_err(|_| invalid_response("invalid certificate DER"))?;
    if !remaining.is_empty() {
        return Err(invalid_response("trailing certificate DER"));
    }
    Ok(cert)
}

fn parse_one_pem(input: &[u8], label: &str) -> Result<Vec<u8>, PkiArtifactError> {
    let (remaining, pem) = parse_x509_pem(input).map_err(|_| invalid_response("invalid PEM"))?;
    if !remaining.iter().all(u8::is_ascii_whitespace)
        || (pem.label != label
            && !(label == "CERTIFICATE REQUEST" && pem.label == "NEW CERTIFICATE REQUEST"))
        || pem.contents.is_empty()
        || pem.contents.len() > MAX_PKI_CERT_BYTES
    {
        return Err(invalid_response("unexpected PEM"));
    }
    Ok(pem.contents)
}

fn parse_wire_cert(value: Option<&Value>) -> Result<Vec<u8>, PkiArtifactError> {
    let pem = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_response("missing certificate"))?;
    parse_one_pem(pem.as_bytes(), "CERTIFICATE")
}

fn unique_common_name<'a>(
    name: &'a x509_parser::x509::X509Name<'a>,
) -> Result<&'a str, PkiArtifactError> {
    let mut names = name.iter_common_name();
    let first = names
        .next()
        .ok_or_else(|| invalid_response("missing common name"))?;
    if names.next().is_some() {
        return Err(invalid_response("multiple common names"));
    }
    first
        .as_str()
        .map_err(|_| invalid_response("invalid common name"))
}

fn semantic_subject(
    name: &x509_parser::x509::X509Name<'_>,
) -> Result<Vec<Vec<(String, String)>>, PkiArtifactError> {
    name.iter_rdn()
        .map(|rdn| {
            let mut attributes = rdn
                .iter()
                .map(|attribute| {
                    Ok((
                        attribute.attr_type().to_id_string(),
                        attribute
                            .as_str()
                            .map_err(|_| invalid_response("invalid subject attribute"))?
                            .to_owned(),
                    ))
                })
                .collect::<Result<Vec<_>, PkiArtifactError>>()?;
            attributes.sort();
            Ok(attributes)
        })
        .collect()
}

fn parse_serial(value: &str) -> Result<Vec<u8>, PkiArtifactError> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.is_empty() || parts.iter().any(|part| part.len() != 2) {
        return Err(invalid_response("invalid serial metadata"));
    }
    parts
        .into_iter()
        .map(|part| {
            u8::from_str_radix(part, 16).map_err(|_| invalid_response("invalid serial metadata"))
        })
        .collect()
}

fn parse_expiration(value: Option<&Value>) -> Result<i64, PkiArtifactError> {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .ok_or_else(|| invalid_response("invalid expiration")),
        Some(Value::String(text)) => text
            .parse()
            .map_err(|_| invalid_response("invalid expiration")),
        _ => Err(invalid_response("missing expiration")),
    }
}

fn chain_digest(leaf: &[u8], issuers: &[Vec<u8>]) -> [u8; 32] {
    Sha256::digest(canonical_pki_chain_artifact(
        leaf,
        issuers.iter().map(Vec::as_slice),
    ))
    .into()
}

fn dedup_exact(certs: &mut Vec<Vec<u8>>) {
    let mut seen = HashSet::new();
    certs.retain(|cert| seen.insert(cert.clone()));
}

fn status_error(status: reqwest::StatusCode) -> PkiArtifactError {
    let kind = match status.as_u16() {
        401 | 403 => PkiArtifactErrorKind::Forbidden,
        404 => PkiArtifactErrorKind::Misconfigured,
        429 => PkiArtifactErrorKind::Unavailable,
        400..=499 => PkiArtifactErrorKind::Rejected,
        500..=599 => PkiArtifactErrorKind::OutcomeUnknown,
        _ => PkiArtifactErrorKind::Rejected,
    };
    PkiArtifactError::new(
        kind,
        std::io::Error::other("Vault PKI returned non-success status"),
    )
}

fn classify_send_error(error: reqwest::Error) -> PkiArtifactError {
    let kind = if error.is_connect() {
        PkiArtifactErrorKind::Unavailable
    } else {
        PkiArtifactErrorKind::OutcomeUnknown
    };
    PkiArtifactError::new(kind, std::io::Error::other("Vault PKI request failed"))
}

fn classify_body_error(_: reqwest::Error) -> PkiArtifactError {
    PkiArtifactError::new(
        PkiArtifactErrorKind::OutcomeUnknown,
        std::io::Error::other("Vault PKI response read failed"),
    )
}

fn invalid_response(message: &'static str) -> PkiArtifactError {
    PkiArtifactError::new(
        PkiArtifactErrorKind::InvalidResponse,
        std::io::Error::other(message),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use deviceloop::{
        CertificateKeyUsage, CertificatePolicy, CertificatePolicyDurations,
        CertificateRenewBeforeSeconds, CertificateSan, CertificateValiditySeconds,
    };
    use diport::{
        CertScope, PkiAuthorizationReceipt, PkiCommonName, PkiPolicyDigest, PkiRequestGeneration,
        PkiSpkiDigest,
    };
    use identity_composition::{
        CertificateArtifactAcquisition, CertificateArtifactError, DeviceCertificateScope,
        DevicePolicyAuthorizationReceiptId, ExpectedGeneration, PolicyHash,
        classify_external_pki_artifact_error, mint_external_pki_production_artifact,
        validate_external_pki_artifact_request,
    };
    use ids::DeviceId;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SerialNumber,
        date_time_ymd,
    };
    use rss_request_context::TenantId;
    use tracing::Event;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context as LayerContext, Layer};
    use tracing_subscriber::prelude::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DEVICE_COMMON_NAME: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_699_920_000)
        }
    }

    fn lowercase_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }

    fn provider_config_digest() -> PkiProviderConfigDigest {
        PkiProviderConfigDigest::new([0x42; 32])
    }

    #[derive(Clone, Default)]
    struct EventRecorder(Arc<Mutex<Vec<String>>>);

    impl EventRecorder {
        fn records(&self) -> Vec<String> {
            self.0.lock().expect("event recorder lock").clone()
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for EventRecorder {
        fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
            let mut visitor = EventFieldRecorder::default();
            event.record(&mut visitor);
            visitor
                .fields
                .push(format!("level={}", event.metadata().level()));
            self.0
                .lock()
                .expect("event recorder lock")
                .push(visitor.fields.join(" "));
        }
    }

    #[test]
    fn successful_attempt_is_debug_not_terminal_info() {
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::TRACE)
            .with(recorder.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        trace_pki_attempt(None);

        let records = recorder.records().join("\n");
        assert!(records.contains("level=DEBUG"), "records={records}");
        assert!(records.contains("status=\"success\""), "records={records}");
    }

    #[derive(Default)]
    struct EventFieldRecorder {
        fields: Vec<String>,
    }

    impl Visit for EventFieldRecorder {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }

    #[test]
    fn status_mapping_is_closed_and_error_is_redacted() {
        let cases = [
            (
                401,
                PkiArtifactErrorKind::Forbidden,
                CertificateArtifactError::Rejected,
            ),
            (
                403,
                PkiArtifactErrorKind::Forbidden,
                CertificateArtifactError::Rejected,
            ),
            (
                404,
                PkiArtifactErrorKind::Misconfigured,
                CertificateArtifactError::Misconfigured,
            ),
            (
                400,
                PkiArtifactErrorKind::Rejected,
                CertificateArtifactError::Rejected,
            ),
            (
                429,
                PkiArtifactErrorKind::Unavailable,
                CertificateArtifactError::Unavailable,
            ),
            (
                500,
                PkiArtifactErrorKind::OutcomeUnknown,
                CertificateArtifactError::OutcomeUnknown,
            ),
        ];
        for (status, expected, domain_expected) in cases {
            let error = status_error(reqwest::StatusCode::from_u16(status).expect("status"));
            assert_eq!(error.kind(), expected);
            assert_eq!(error.to_string(), "PKI artifact transport failed");
            assert!(format!("{error:?}").contains("<redacted>"));
            assert_eq!(
                classify_external_pki_artifact_error(&error),
                domain_expected
            );
        }
    }

    #[test]
    fn production_constructor_rejects_plaintext_and_bad_role_before_io() {
        let client = VaultPkiHttpClient::allow_http_for_test();
        let no_roots = Vec::new();
        assert!(matches!(
            VaultPkiTransport::new(
                Arc::new(FixedClock),
                client,
                VaultPkiTransportConfig::new(
                    "http://127.0.0.1:8200",
                    "token",
                    VaultPkiMount::try_new("pki").expect("mount"),
                    VaultPkiRole::try_new("role").expect("role"),
                    no_roots,
                    Duration::from_secs(1),
                )
            ),
            Err(VaultConfigError::InsecureScheme)
        ));
        assert!(matches!(
            VaultPkiRole::try_new("../role"),
            Err(VaultConfigError::InvalidPkiRole)
        ));
    }

    fn root_pem() -> String {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().expect("root key");
        params.self_signed(&key).expect("root certificate").pem()
    }

    #[test]
    fn provider_closure_digest_binds_the_actual_https_trust_roots() {
        let pki_root = root_pem();
        let tls_root_a = root_pem();
        let tls_root_b = root_pem();
        let closure = |tls_root: &str| {
            VaultExternalPkiProviderClosure::new(
                Arc::new(FixedClock),
                VaultPkiHttpClient::with_root_certificates([tls_root.as_bytes()])
                    .expect("TLS client"),
                VaultPkiTransportConfig::new(
                    "https://vault.example",
                    "token",
                    VaultPkiMount::try_new("pki").expect("mount"),
                    VaultPkiRole::try_new("role").expect("role"),
                    vec![RedactedBytes::new(pki_root.as_bytes().to_vec())],
                    Duration::from_secs(1),
                ),
            )
            .expect("provider closure")
        };

        let first = closure(&tls_root_a);
        let second = closure(&tls_root_b);
        assert_ne!(
            first.provider_closure().config_digest(),
            second.provider_closure().config_digest()
        );
    }

    fn request() -> PkiArtifactRequest {
        let key = KeyPair::generate().expect("request key");
        let mut params = CertificateParams::new(vec!["device.example".to_owned()]).expect("params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, DEVICE_COMMON_NAME);
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr = params.serialize_request(&key).expect("CSR");
        PkiArtifactRequest::try_new(
            CertScope::new(
                TenantId::parse("11111111-2222-4333-8444-555555555555").expect("tenant"),
                DeviceId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("device"),
            ),
            PkiRequestGeneration::try_new(1).expect("generation"),
            PkiPolicyDigest::new([1; 32]),
            PkiAuthorizationReceipt::try_new([1; 16]).expect("receipt"),
            RedactedBytes::new(csr.pem().expect("PEM").into_bytes()),
            PkiSpkiDigest::new(Sha256::digest(key.subject_public_key_info()).into()),
            PkiCommonName::try_new(DEVICE_COMMON_NAME).expect("common name"),
            vec![PkiSan::dns("device.example").expect("DNS")],
            vec![PkiExtendedKeyUsage::ClientAuth],
            Duration::from_secs(3600),
            Duration::from_secs(300),
        )
        .expect("request")
    }

    fn verified_fixture() -> (PkiArtifactRequest, Value, Vec<Vec<u8>>) {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut root_subject = DistinguishedName::new();
        root_subject.push(DnType::CommonName, "Test Root");
        root_params.distinguished_name = root_subject;
        root_params.not_before = date_time_ymd(2020, 1, 1);
        root_params.not_after = date_time_ymd(2030, 1, 1);
        let root =
            CertifiedIssuer::self_signed(root_params, KeyPair::generate().expect("root key"))
                .expect("root certificate");

        let mut issuer_params = CertificateParams::default();
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut issuer_subject = DistinguishedName::new();
        issuer_subject.push(DnType::CommonName, "Test Issuer");
        issuer_params.distinguished_name = issuer_subject;
        issuer_params.not_before = date_time_ymd(2020, 1, 1);
        issuer_params.not_after = date_time_ymd(2029, 1, 1);
        let issuer = CertifiedIssuer::signed_by(
            issuer_params,
            KeyPair::generate().expect("issuer key"),
            &root,
        )
        .expect("issuer certificate");

        let request_key = KeyPair::generate().expect("request key");
        let mut csr_params =
            CertificateParams::new(vec!["device.example".to_owned()]).expect("CSR parameters");
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, DEVICE_COMMON_NAME);
        csr_params.distinguished_name = subject;
        csr_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr = csr_params
            .serialize_request(&request_key)
            .expect("signed CSR");

        let mut leaf_params =
            CertificateParams::new(vec!["device.example".to_owned()]).expect("leaf parameters");
        let mut leaf_subject = DistinguishedName::new();
        leaf_subject.push(DnType::CommonName, DEVICE_COMMON_NAME);
        leaf_params.distinguished_name = leaf_subject;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.serial_number = Some(SerialNumber::from(42_u64));
        leaf_params.not_before = date_time_ymd(2023, 11, 14);
        leaf_params.not_after = date_time_ymd(2023, 11, 15);
        let leaf = leaf_params
            .signed_by(&request_key, &issuer)
            .expect("leaf certificate");
        let (_, parsed_leaf) = X509Certificate::from_der(leaf.der()).expect("parse leaf");
        assert_eq!(parsed_leaf.raw_serial(), &[0x2a], "fixture serial encoding");

        let request = PkiArtifactRequest::try_new(
            CertScope::new(
                TenantId::parse("11111111-2222-4333-8444-555555555555").expect("tenant"),
                DeviceId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("device"),
            ),
            PkiRequestGeneration::try_new(7).expect("generation"),
            PkiPolicyDigest::new([7; 32]),
            PkiAuthorizationReceipt::try_new([7; 16]).expect("receipt"),
            RedactedBytes::new(csr.pem().expect("CSR PEM").into_bytes()),
            PkiSpkiDigest::new(Sha256::digest(request_key.subject_public_key_info()).into()),
            PkiCommonName::try_new(DEVICE_COMMON_NAME).expect("common name"),
            vec![PkiSan::dns("device.example").expect("DNS")],
            vec![PkiExtendedKeyUsage::ClientAuth],
            Duration::from_secs(86_400),
            Duration::from_secs(300),
        )
        .expect("request");
        let response = serde_json::json!({
            "data": {
                "certificate": leaf.pem(),
                "issuing_ca": issuer.pem(),
                "ca_chain": [issuer.pem(), root.pem()],
                "serial_number": "2a",
                "expiration": parsed_leaf.validity().not_after.timestamp()
            }
        });
        (request, response, vec![root.der().to_vec()])
    }

    fn unrelated_chain_pems() -> (String, String) {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut root_subject = DistinguishedName::new();
        root_subject.push(DnType::CommonName, "Unrelated Root");
        root_params.distinguished_name = root_subject;
        root_params.not_before = date_time_ymd(2020, 1, 1);
        root_params.not_after = date_time_ymd(2030, 1, 1);
        let root = CertifiedIssuer::self_signed(
            root_params,
            KeyPair::generate().expect("unrelated root key"),
        )
        .expect("unrelated root");

        let mut issuer_params = CertificateParams::default();
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut issuer_subject = DistinguishedName::new();
        issuer_subject.push(DnType::CommonName, "Test Issuer");
        issuer_params.distinguished_name = issuer_subject;
        issuer_params.not_before = date_time_ymd(2020, 1, 1);
        issuer_params.not_after = date_time_ymd(2029, 1, 1);
        let issuer = CertifiedIssuer::signed_by(
            issuer_params,
            KeyPair::generate().expect("unrelated issuer key"),
            &root,
        )
        .expect("unrelated issuer");
        (issuer.pem(), root.pem())
    }

    fn acquisition(receipt: [u8; 16]) -> CertificateArtifactAcquisition {
        acquisition_with_usages(receipt, vec![CertificateKeyUsage::ClientAuth])
    }

    fn acquisition_with_usages(
        receipt: [u8; 16],
        key_usages: Vec<CertificateKeyUsage>,
    ) -> CertificateArtifactAcquisition {
        let scope = DeviceCertificateScope::for_test(
            TenantId::parse("11111111-2222-4333-8444-555555555555").expect("tenant"),
            DeviceId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("device"),
        );
        let policy = CertificatePolicy::new(
            CertificatePolicyDurations::new(
                CertificateValiditySeconds::try_new(86_400).expect("validity"),
                CertificateRenewBeforeSeconds::try_new(300).expect("renew-before"),
            )
            .expect("durations"),
            key_usages,
            vec![CertificateSan::parse("device.example").expect("SAN")],
        )
        .expect("policy");
        CertificateArtifactAcquisition::for_test(
            scope,
            ExpectedGeneration::try_new(7).expect("generation"),
            PolicyHash::restore(&[7; 32]).expect("policy hash"),
            DevicePolicyAuthorizationReceiptId::restore(uuid::Uuid::from_bytes(receipt))
                .expect("receipt"),
            policy,
        )
    }

    #[test]
    fn verified_vault_evidence_mints_only_the_receipt_bound_production_artifact() {
        let (request, response, roots) = verified_fixture();
        let evidence = verify_and_normalize(
            request,
            &serde_json::to_vec(&response).expect("response"),
            FixedClock.now(),
            &roots,
            provider_config_digest(),
        )
        .expect("verified evidence");
        let acquisition = acquisition([7; 16]);
        let closure = ExternalPkiProviderClosure::seal_vault_csr_sign(
            pkiauthmint::ExternalPkiProviderMint::capability(),
            provider_config_digest(),
        );

        let authorization_receipt_id = acquisition.authorization_receipt_id();
        let authorized =
            mint_external_pki_production_artifact(&closure, acquisition, evidence.into_verified())
                .expect("receipt-bound artifact");
        let snapshot = authorized.into_append_authorization().into_snapshot();

        assert_eq!(
            snapshot.authorization_receipt_id(),
            authorization_receipt_id
        );
        assert_eq!(
            snapshot.artifact_id().as_str(),
            format!(
                "vault-pki-sha256:{}",
                lowercase_hex(snapshot.artifact_digest().as_bytes())
            )
        );
        assert_eq!(
            format!("{closure:?}"),
            "ExternalPkiProviderClosure(<sealed>)"
        );
    }

    #[test]
    fn provider_closure_cannot_authorize_evidence_from_a_different_config() {
        let (request, response, roots) = verified_fixture();
        let evidence = verify_and_normalize(
            request,
            &serde_json::to_vec(&response).expect("response"),
            FixedClock.now(),
            &roots,
            provider_config_digest(),
        )
        .expect("verified evidence");
        let different_closure = ExternalPkiProviderClosure::seal_vault_csr_sign(
            pkiauthmint::ExternalPkiProviderMint::capability(),
            PkiProviderConfigDigest::new([0x43; 32]),
        );

        assert!(matches!(
            mint_external_pki_production_artifact(
                &different_closure,
                acquisition([7; 16]),
                evidence.into_verified(),
            ),
            Err(CertificateArtifactError::BindingMismatch)
        ));
    }

    #[test]
    fn swapped_authorization_receipt_is_rejected_before_provider_io() {
        let (request, _, _) = verified_fixture();
        assert_eq!(
            validate_external_pki_artifact_request(&acquisition([8; 16]), &request),
            Err(CertificateArtifactError::BindingMismatch)
        );
    }

    #[test]
    fn common_name_must_be_authorized_by_the_current_device_scope() {
        let (request, _, _) = verified_fixture();
        let request = rebuild_with_matching_csr_common_name(&request, "other.example");
        assert_eq!(
            validate_external_pki_artifact_request(&acquisition([7; 16]), &request),
            Err(CertificateArtifactError::BindingMismatch)
        );
    }

    #[test]
    fn equivalent_eku_set_order_preserves_receipt_binding() {
        let (request, _, _) = verified_fixture();
        let request = rebuild_request(
            &request,
            *request.spki_digest(),
            request.sans().to_vec(),
            vec![
                PkiExtendedKeyUsage::ServerAuth,
                PkiExtendedKeyUsage::ClientAuth,
            ],
        );
        let acquisition = acquisition_with_usages(
            [7; 16],
            vec![
                CertificateKeyUsage::ClientAuth,
                CertificateKeyUsage::ServerAuth,
            ],
        );
        assert_eq!(
            validate_external_pki_artifact_request(&acquisition, &request),
            Ok(())
        );
    }

    fn rebuild_request(
        request: &PkiArtifactRequest,
        spki_digest: PkiSpkiDigest,
        sans: Vec<PkiSan>,
        ekus: Vec<PkiExtendedKeyUsage>,
    ) -> PkiArtifactRequest {
        PkiArtifactRequest::try_new(
            request.scope(),
            request.generation(),
            *request.policy_digest(),
            request.authorization_receipt(),
            RedactedBytes::new(request.csr_pem().as_bytes().to_vec()),
            spki_digest,
            request.common_name().clone(),
            sans,
            ekus,
            request.requested_validity(),
            request.renew_before(),
        )
        .expect("rebuilt request")
    }

    fn rebuild_common_name(request: &PkiArtifactRequest, value: &str) -> PkiArtifactRequest {
        PkiArtifactRequest::try_new(
            request.scope(),
            request.generation(),
            *request.policy_digest(),
            request.authorization_receipt(),
            RedactedBytes::new(request.csr_pem().as_bytes().to_vec()),
            *request.spki_digest(),
            PkiCommonName::try_new(value).expect("common name"),
            request.sans().to_vec(),
            request.extended_key_usages().to_vec(),
            request.requested_validity(),
            request.renew_before(),
        )
        .expect("rebuilt request")
    }

    fn rebuild_with_matching_csr_common_name(
        request: &PkiArtifactRequest,
        value: &str,
    ) -> PkiArtifactRequest {
        let key = KeyPair::generate().expect("request key");
        let mut params = CertificateParams::new(vec!["device.example".to_owned()]).expect("params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, value);
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr = params.serialize_request(&key).expect("CSR");
        PkiArtifactRequest::try_new(
            request.scope(),
            request.generation(),
            *request.policy_digest(),
            request.authorization_receipt(),
            RedactedBytes::new(csr.pem().expect("PEM").into_bytes()),
            PkiSpkiDigest::new(Sha256::digest(key.subject_public_key_info()).into()),
            PkiCommonName::try_new(value).expect("common name"),
            request.sans().to_vec(),
            request.extended_key_usages().to_vec(),
            request.requested_validity(),
            request.renew_before(),
        )
        .expect("rebuilt request")
    }

    #[test]
    fn evidence_material_boundaries_are_closed() {
        let serial = || CertSerial::try_new([1]).expect("serial");
        let not_after = || {
            CertNotAfter::try_from_system_time(SystemTime::UNIX_EPOCH + Duration::from_secs(4_000))
                .expect("not after")
        };
        for leaf_size in [0, MAX_PKI_CERT_BYTES + 1] {
            assert!(matches!(
                VaultPkiArtifactEvidence::from_verified_transport_material(
                    provider_config_digest(),
                    request(),
                    RedactedBytes::new(vec![1; leaf_size]),
                    vec![RedactedBytes::new([2])],
                    PkiChainDigest::new([3; 32]),
                    serial(),
                    not_after(),
                ),
                Err(PkiArtifactValueError::InvalidCertificateMaterial)
            ));
        }
        assert!(
            VaultPkiArtifactEvidence::from_verified_transport_material(
                provider_config_digest(),
                request(),
                RedactedBytes::new(vec![1; MAX_PKI_CERT_BYTES]),
                vec![RedactedBytes::new([2]); MAX_PKI_ISSUER_CERTS],
                PkiChainDigest::new([3; 32]),
                serial(),
                not_after(),
            )
            .is_ok()
        );
        for issuer_count in [0, MAX_PKI_ISSUER_CERTS + 1] {
            assert!(matches!(
                VaultPkiArtifactEvidence::from_verified_transport_material(
                    provider_config_digest(),
                    request(),
                    RedactedBytes::new([1]),
                    vec![RedactedBytes::new([2]); issuer_count],
                    PkiChainDigest::new([3; 32]),
                    serial(),
                    not_after(),
                ),
                Err(PkiArtifactValueError::InvalidIssuerChain)
            ));
        }
        for issuer in [Vec::new(), vec![2; MAX_PKI_CERT_BYTES + 1]] {
            assert!(matches!(
                VaultPkiArtifactEvidence::from_verified_transport_material(
                    provider_config_digest(),
                    request(),
                    RedactedBytes::new([1]),
                    vec![RedactedBytes::new(issuer)],
                    PkiChainDigest::new([3; 32]),
                    serial(),
                    not_after(),
                ),
                Err(PkiArtifactValueError::InvalidCertificateMaterial)
            ));
        }
    }

    #[test]
    fn verified_response_binds_material_and_normalizes_repeated_leaf() {
        let (request, mut response, roots) = verified_fixture();
        let leaf = response
            .pointer("/data/certificate")
            .cloned()
            .expect("leaf");
        response
            .pointer_mut("/data/ca_chain")
            .and_then(Value::as_array_mut)
            .expect("chain")
            .insert(0, leaf);
        let evidence = verify_and_normalize(
            request,
            &serde_json::to_vec(&response).expect("JSON"),
            FixedClock.now(),
            &roots,
            provider_config_digest(),
        )
        .expect("verified evidence");
        assert_eq!(evidence.request().generation().get(), 7);
        assert_eq!(
            evidence.request().policy_digest(),
            &PkiPolicyDigest::new([7; 32])
        );
        assert_eq!(evidence.issuer_chain_der().len(), 2);
    }

    #[test]
    fn verified_response_rejects_each_material_binding_mismatch() {
        for mutation in ["serial", "expiration", "spki", "san", "eku", "chain"] {
            let (original, mut response, roots) = verified_fixture();
            let request = match mutation {
                "spki" => rebuild_request(
                    &original,
                    PkiSpkiDigest::new([0; 32]),
                    original.sans().to_vec(),
                    original.extended_key_usages().to_vec(),
                ),
                "san" => rebuild_request(
                    &original,
                    *original.spki_digest(),
                    vec![PkiSan::dns("other.example").expect("DNS")],
                    original.extended_key_usages().to_vec(),
                ),
                "eku" => rebuild_request(
                    &original,
                    *original.spki_digest(),
                    original.sans().to_vec(),
                    vec![PkiExtendedKeyUsage::ServerAuth],
                ),
                _ => original,
            };
            match mutation {
                "serial" => response["data"]["serial_number"] = Value::String("2b".to_owned()),
                "expiration" => {
                    let expiration = response["data"]["expiration"].as_i64().expect("expiration");
                    response["data"]["expiration"] = Value::from(expiration + 1);
                }
                "chain" => {
                    let (issuer, root) = unrelated_chain_pems();
                    response["data"]["issuing_ca"] = Value::String(issuer.clone());
                    response["data"]["ca_chain"] = serde_json::json!([issuer, root]);
                }
                _ => {}
            }
            let error = verify_and_normalize(
                request,
                &serde_json::to_vec(&response).expect("JSON"),
                FixedClock.now(),
                &roots,
                provider_config_digest(),
            )
            .expect_err("binding mismatch must fail closed");
            assert_eq!(
                error.kind(),
                PkiArtifactErrorKind::InvalidResponse,
                "{mutation}"
            );
        }
    }

    fn test_transport(server: &MockServer) -> VaultPkiTransport {
        VaultPkiTransport::new_allow_http_for_test(
            Arc::new(FixedClock),
            VaultPkiHttpClient::allow_http_for_test(),
            VaultPkiTransportConfig::new(
                server.uri(),
                "sensitive-token-marker",
                VaultPkiMount::try_new("team/pki").expect("mount"),
                VaultPkiRole::try_new("device-role").expect("role"),
                vec![RedactedBytes::new(root_pem().into_bytes())],
                Duration::from_secs(2),
            ),
        )
        .expect("transport")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn common_name_is_explicit_and_terminal_failure_is_observable() {
        let server = MockServer::start().await;
        let recorder = EventRecorder::default();
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let request = rebuild_common_name(&request(), "other.example");
        let error = test_transport(&server)
            .sign_csr(request)
            .await
            .expect_err("CSR and request common name mismatch must fail before I/O");
        assert_eq!(error.kind(), PkiArtifactErrorKind::InvalidResponse);
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
        let records = recorder.records().join("\n");
        for field in [
            "level=WARN",
            "phase=\"request-validation\"",
            "reason=\"invalid-request\"",
            "outcome=\"not-applied\"",
            "category=\"invalid-response\"",
            "status=\"failure\"",
        ] {
            assert!(records.contains(field), "missing {field}: {records}");
        }
        assert!(!records.contains("other.example"));
        assert!(!records.contains("sensitive-token-marker"));
    }

    #[tokio::test]
    async fn wire_request_is_fixed_to_sign_path_and_typed_body() {
        let server = MockServer::start().await;
        let request = request();
        let csr = std::str::from_utf8(request.csr_pem().as_bytes())
            .expect("CSR UTF-8")
            .to_owned();
        Mock::given(method("POST"))
            .and(path("/v1/team/pki/sign/device-role"))
            .and(header(VAULT_TOKEN_HEADER, "sensitive-token-marker"))
            .and(body_json(serde_json::json!({
                "csr": csr, "common_name": DEVICE_COMMON_NAME, "alt_names": "device.example",
                "ip_sans": "", "uri_sans": "", "other_sans": "", "ttl": "3600s",
                "format": "pem", "exclude_cn_from_sans": true
            })))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let error = test_transport(&server)
            .sign_csr(request)
            .await
            .expect_err("policy deny");
        assert_eq!(error.kind(), PkiArtifactErrorKind::Forbidden);
    }

    #[tokio::test]
    async fn private_key_response_is_rejected_without_disclosure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/team/pki/sign/device-role"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"private_key": "private-key-marker"}
            })))
            .mount(&server)
            .await;
        let error = test_transport(&server)
            .sign_csr(request())
            .await
            .expect_err("private key must fail closed");
        assert_eq!(error.kind(), PkiArtifactErrorKind::InvalidResponse);
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("private-key-marker"));
        assert!(!diagnostic.contains("sensitive-token-marker"));
    }

    #[tokio::test]
    async fn redirects_are_not_followed_with_token_or_csr() {
        let source = MockServer::start().await;
        let sink = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", format!("{}/capture", sink.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;
        let error = test_transport(&source)
            .sign_csr(request())
            .await
            .expect_err("redirect must fail closed");
        assert_eq!(error.kind(), PkiArtifactErrorKind::Rejected);
        assert!(
            sink.received_requests()
                .await
                .expect("sink requests")
                .is_empty()
        );
    }

    #[test]
    fn stale_unexpired_leaf_cannot_bind_to_a_fresh_request() {
        let (request, response, roots) = verified_fixture();
        let error = verify_and_normalize(
            request,
            &serde_json::to_vec(&response).expect("JSON"),
            FixedClock.now() + Duration::from_secs(3600),
            &roots,
            provider_config_digest(),
        )
        .expect_err("stale leaf must not be rebound");
        assert_eq!(error.kind(), PkiArtifactErrorKind::InvalidResponse);
    }
}
