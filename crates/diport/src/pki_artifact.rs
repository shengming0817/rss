//! Provider-neutral values for caller-owned CSR signing.

use std::collections::HashSet;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::time::Duration;

use crate::{CertScope, RedactedBytes, RedactedSource};

/// Maximum accepted PEM CSR size.
pub const MAX_PKI_CSR_BYTES: usize = 64 * 1024;
/// Maximum DER size of one certificate material value.
pub const MAX_PKI_CERT_BYTES: usize = 128 * 1024;
/// Maximum issuer certificates accepted in one verified chain.
pub const MAX_PKI_ISSUER_CERTS: usize = 16;

/// Positive desired certificate generation carried as request correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PkiRequestGeneration(NonZeroU64);

impl PkiRequestGeneration {
    /// Creates a positive request generation.
    pub fn try_new(raw: u64) -> Result<Self, PkiArtifactValueError> {
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or(PkiArtifactValueError::ZeroGeneration)
    }

    /// Returns the canonical integer value.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

macro_rules! pki_digest {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates a digest from its canonical SHA-256 bytes.
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Borrows the canonical SHA-256 bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<sha256>)"))
            }
        }
    };
}

pki_digest!(PkiPolicyDigest, "Canonical certificate-policy digest.");
pki_digest!(PkiSpkiDigest, "Canonical caller public-key SPKI digest.");
pki_digest!(
    PkiChainDigest,
    "Canonical verified certificate-chain digest."
);

/// A typed subject alternative name requested from the provider.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PkiSan(PkiSanValue);

/// Explicit X.509 common name required by the signing request contract.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PkiCommonName(String);

impl PkiCommonName {
    /// Creates a bounded, delimiter-safe common name.
    pub fn try_new(value: impl Into<String>) -> Result<Self, PkiArtifactValueError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || value.trim() != value
            || value.contains([',', '\0', '\r', '\n'])
        {
            return Err(PkiArtifactValueError::InvalidCommonName);
        }
        Ok(Self(value))
    }

    /// Borrows the validated common name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PkiCommonName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PkiCommonName(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum PkiSanValue {
    Dns(String),
    Email(String),
    Ip(IpAddr),
    Uri(String),
    Utf8OtherName { oid: String, value: String },
}

/// Read-only view of a validated SAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiSanRef<'a> {
    Dns(&'a str),
    Email(&'a str),
    Ip(IpAddr),
    Uri(&'a str),
    Utf8OtherName { oid: &'a str, value: &'a str },
}

impl std::fmt::Debug for PkiSan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.0 {
            PkiSanValue::Dns(_) => "dns",
            PkiSanValue::Email(_) => "email",
            PkiSanValue::Ip(_) => "ip",
            PkiSanValue::Uri(_) => "uri",
            PkiSanValue::Utf8OtherName { .. } => "utf8-other-name",
        };
        f.debug_tuple("PkiSan")
            .field(&kind)
            .field(&"<redacted>")
            .finish()
    }
}

impl PkiSan {
    /// Creates a DNS SAN.
    pub fn dns(value: impl Into<String>) -> Result<Self, PkiArtifactValueError> {
        let value = validate_text(value.into())?;
        if !valid_dns_name(&value) {
            return Err(PkiArtifactValueError::InvalidSan);
        }
        Ok(Self(PkiSanValue::Dns(value)))
    }

    /// Creates an email SAN.
    pub fn email(value: impl Into<String>) -> Result<Self, PkiArtifactValueError> {
        let value = validate_text(value.into())?;
        if !valid_email_address(&value) {
            return Err(PkiArtifactValueError::InvalidSan);
        }
        Ok(Self(PkiSanValue::Email(value)))
    }

    /// Creates an IP SAN.
    pub const fn ip(value: IpAddr) -> Self {
        Self(PkiSanValue::Ip(value))
    }

    /// Creates a URI SAN.
    pub fn uri(value: impl Into<String>) -> Result<Self, PkiArtifactValueError> {
        let value = validate_text(value.into())?;
        if !valid_absolute_uri(&value) {
            return Err(PkiArtifactValueError::InvalidSan);
        }
        Ok(Self(PkiSanValue::Uri(value)))
    }

    /// Creates a Vault UTF8 otherName SAN.
    pub fn utf8_other_name(
        oid: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, PkiArtifactValueError> {
        let oid = validate_oid(oid.into())?;
        let value = validate_text(value.into())?;
        Ok(Self(PkiSanValue::Utf8OtherName { oid, value }))
    }

    /// Returns a borrowed, exhaustively typed view.
    pub fn as_ref(&self) -> PkiSanRef<'_> {
        match &self.0 {
            PkiSanValue::Dns(value) => PkiSanRef::Dns(value),
            PkiSanValue::Email(value) => PkiSanRef::Email(value),
            PkiSanValue::Ip(value) => PkiSanRef::Ip(*value),
            PkiSanValue::Uri(value) => PkiSanRef::Uri(value),
            PkiSanValue::Utf8OtherName { oid, value } => PkiSanRef::Utf8OtherName { oid, value },
        }
    }
}

fn validate_text(value: String) -> Result<String, PkiArtifactValueError> {
    if value.is_empty() || value.trim() != value || value.contains([',', '\0', '\r', '\n']) {
        return Err(PkiArtifactValueError::InvalidSan);
    }
    Ok(value)
}

fn valid_dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.is_ascii()
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_email_address(value: &str) -> bool {
    if value.len() > 254 || !value.is_ascii() {
        return false;
    }
    let mut parts = value.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'.'
                )
        })
        && valid_dns_name(domain)
}

fn valid_absolute_uri(value: &str) -> bool {
    value.len() <= 2_048 && url::Url::parse(value).is_ok()
}

fn validate_oid(value: String) -> Result<String, PkiArtifactValueError> {
    let parts = value.split('.').collect::<Vec<_>>();
    let valid = parts.iter().all(|part| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (*part == "0" || !part.starts_with('0'))
    });
    let arcs_valid = parts.len() >= 2
        && parts[0].parse::<u8>().is_ok_and(|first| first <= 2)
        && parts[1]
            .parse::<u64>()
            .is_ok_and(|second| parts[0] == "2" || second <= 39);
    if !valid || !arcs_valid {
        return Err(PkiArtifactValueError::InvalidSan);
    }
    Ok(value)
}

/// Closed extended-key-usage set supported by the device certificate transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PkiExtendedKeyUsage {
    /// TLS client authentication.
    ClientAuth,
    /// TLS server authentication.
    ServerAuth,
}

/// Request construction failed before provider I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PkiArtifactValueError {
    /// Generation zero has no valid desired-state meaning.
    #[error("PKI request generation must be positive")]
    ZeroGeneration,
    /// CSR must be non-empty and bounded.
    #[error("PKI CSR is empty or exceeds the size limit")]
    InvalidCsrSize,
    /// Common name must be non-empty, bounded, and safe for the provider wire.
    #[error("PKI common name is invalid")]
    InvalidCommonName,
    /// At least one unique SAN is required.
    #[error("PKI SAN set is empty, invalid, or contains duplicates")]
    InvalidSan,
    /// At least one unique supported EKU is required.
    #[error("PKI extended-key-usage set is empty or contains duplicates")]
    InvalidExtendedKeyUsage,
    /// Requested lifetime must exceed the renewal lead time.
    #[error("PKI validity must be positive and exceed renew-before")]
    InvalidValidity,
    /// Certificate bytes are empty or exceed their bound.
    #[error("PKI certificate material is empty or exceeds the size limit")]
    InvalidCertificateMaterial,
    /// Issuer chain is empty or exceeds its bound.
    #[error("PKI issuer chain is empty or exceeds the size limit")]
    InvalidIssuerChain,
}

/// Move-only provider-neutral CSR signing request.
pub struct PkiArtifactRequest {
    scope: CertScope,
    generation: PkiRequestGeneration,
    policy_digest: PkiPolicyDigest,
    csr_pem: RedactedBytes,
    spki_digest: PkiSpkiDigest,
    common_name: PkiCommonName,
    sans: Vec<PkiSan>,
    extended_key_usages: Vec<PkiExtendedKeyUsage>,
    requested_validity: Duration,
    renew_before: Duration,
}

impl PkiArtifactRequest {
    /// Validates and creates a complete request coordinate.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        scope: CertScope,
        generation: PkiRequestGeneration,
        policy_digest: PkiPolicyDigest,
        csr_pem: RedactedBytes,
        spki_digest: PkiSpkiDigest,
        common_name: PkiCommonName,
        sans: Vec<PkiSan>,
        extended_key_usages: Vec<PkiExtendedKeyUsage>,
        requested_validity: Duration,
        renew_before: Duration,
    ) -> Result<Self, PkiArtifactValueError> {
        if csr_pem.is_empty() || csr_pem.len() > MAX_PKI_CSR_BYTES {
            return Err(PkiArtifactValueError::InvalidCsrSize);
        }
        if sans.is_empty() || sans.iter().collect::<HashSet<_>>().len() != sans.len() {
            return Err(PkiArtifactValueError::InvalidSan);
        }
        if extended_key_usages.is_empty()
            || extended_key_usages.iter().collect::<HashSet<_>>().len() != extended_key_usages.len()
        {
            return Err(PkiArtifactValueError::InvalidExtendedKeyUsage);
        }
        if requested_validity.is_zero()
            || requested_validity <= renew_before
            || requested_validity.subsec_nanos() != 0
            || renew_before.subsec_nanos() != 0
        {
            return Err(PkiArtifactValueError::InvalidValidity);
        }
        Ok(Self {
            scope,
            generation,
            policy_digest,
            csr_pem,
            spki_digest,
            common_name,
            sans,
            extended_key_usages,
            requested_validity,
            renew_before,
        })
    }

    /// Returns the tenant/device correlation scope.
    pub const fn scope(&self) -> CertScope {
        self.scope
    }
    /// Returns the desired generation correlation.
    pub const fn generation(&self) -> PkiRequestGeneration {
        self.generation
    }
    /// Returns the canonical policy digest.
    pub const fn policy_digest(&self) -> &PkiPolicyDigest {
        &self.policy_digest
    }
    /// Borrows the redacted PEM CSR wrapper.
    pub const fn csr_pem(&self) -> &RedactedBytes {
        &self.csr_pem
    }
    /// Returns the expected SPKI digest.
    pub const fn spki_digest(&self) -> &PkiSpkiDigest {
        &self.spki_digest
    }
    /// Returns the explicitly admitted X.509 common name.
    pub const fn common_name(&self) -> &PkiCommonName {
        &self.common_name
    }
    /// Returns the exact requested SAN set.
    pub fn sans(&self) -> &[PkiSan] {
        &self.sans
    }
    /// Returns the exact requested EKU set.
    pub fn extended_key_usages(&self) -> &[PkiExtendedKeyUsage] {
        &self.extended_key_usages
    }
    /// Returns the requested maximum validity.
    pub const fn requested_validity(&self) -> Duration {
        self.requested_validity
    }
    /// Returns the minimum renewal lead time.
    pub const fn renew_before(&self) -> Duration {
        self.renew_before
    }
}

impl std::fmt::Debug for PkiArtifactRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PkiArtifactRequest(<redacted>)")
    }
}

/// Closed failure classification for CSR-signing transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PkiArtifactErrorKind {
    /// Provider policy rejected the request.
    Rejected,
    /// Provider authentication or authorization denied the request.
    Forbidden,
    /// Provider mount or role is not configured.
    Misconfigured,
    /// Provider was unavailable before a known result.
    Unavailable,
    /// The request may have been accepted before the outcome became unknown.
    OutcomeUnknown,
    /// Local CSR, response material, or binding validation failed.
    InvalidResponse,
}

/// Redacted PKI transport failure.
#[derive(Debug, thiserror::Error)]
#[error("PKI artifact transport failed")]
pub struct PkiArtifactError {
    kind: PkiArtifactErrorKind,
    #[source]
    source: RedactedSource,
}

impl PkiArtifactError {
    /// Wraps an internal error without exposing it through diagnostics.
    pub fn new<E>(kind: PkiArtifactErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    /// Returns the closed error category.
    pub const fn kind(&self) -> PkiArtifactErrorKind {
        self.kind
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use ids::DeviceId;
    use rss_request_context::TenantId;

    fn scope() -> CertScope {
        CertScope::new(
            TenantId::parse("00000000-0000-0000-0000-000000000001").expect("tenant"),
            DeviceId::parse("00000000-0000-0000-0000-000000000002").expect("device"),
        )
    }

    fn generation() -> PkiRequestGeneration {
        PkiRequestGeneration::try_new(1).expect("positive generation")
    }

    fn request(
        sans: Vec<PkiSan>,
        ekus: Vec<PkiExtendedKeyUsage>,
    ) -> Result<PkiArtifactRequest, PkiArtifactValueError> {
        PkiArtifactRequest::try_new(
            scope(),
            generation(),
            PkiPolicyDigest::new([1; 32]),
            RedactedBytes::new(b"sensitive-csr-marker".to_vec()),
            PkiSpkiDigest::new([2; 32]),
            PkiCommonName::try_new("device.example").expect("common name"),
            sans,
            ekus,
            Duration::from_secs(3600),
            Duration::from_secs(600),
        )
    }

    #[test]
    fn request_coordinates_are_required_unique_and_redacted() {
        assert_eq!(
            PkiRequestGeneration::try_new(0),
            Err(PkiArtifactValueError::ZeroGeneration)
        );
        let san = PkiSan::uri("spiffe://tenant/device").expect("URI");
        assert_eq!(
            request(vec![], vec![PkiExtendedKeyUsage::ClientAuth]).unwrap_err(),
            PkiArtifactValueError::InvalidSan
        );
        assert_eq!(
            request(
                vec![san.clone(), san],
                vec![PkiExtendedKeyUsage::ClientAuth]
            )
            .unwrap_err(),
            PkiArtifactValueError::InvalidSan
        );
        let request = request(
            vec![PkiSan::dns("device.example").expect("DNS")],
            vec![PkiExtendedKeyUsage::ClientAuth],
        )
        .expect("request");
        assert_eq!(format!("{request:?}"), "PkiArtifactRequest(<redacted>)");
        assert!(!format!("{:?}", request.sans()).contains("device.example"));
    }

    #[test]
    fn san_kinds_reject_values_outside_their_wire_grammar() {
        for invalid in ["-device.example", "device..example", "device.example-"] {
            assert_eq!(PkiSan::dns(invalid), Err(PkiArtifactValueError::InvalidSan));
        }
        for invalid in ["device.example", "@example.com", "device@@example.com"] {
            assert_eq!(
                PkiSan::email(invalid),
                Err(PkiArtifactValueError::InvalidSan)
            );
        }
        for invalid in ["relative/path", ":missing-scheme", "https://bad host"] {
            assert_eq!(PkiSan::uri(invalid), Err(PkiArtifactValueError::InvalidSan));
        }
        assert_eq!(
            PkiSan::dns(format!("{}.example", "a".repeat(64))),
            Err(PkiArtifactValueError::InvalidSan)
        );
        assert_eq!(
            PkiSan::email(format!("{}@example.com", "a".repeat(65))),
            Err(PkiArtifactValueError::InvalidSan)
        );
        assert_eq!(
            PkiSan::uri(format!("https://example.com/{}", "a".repeat(2_048))),
            Err(PkiArtifactValueError::InvalidSan)
        );
        assert!(PkiSan::email("device+rotation@example.com").is_ok());
        assert!(PkiSan::uri("urn:device:rotation").is_ok());
    }

    #[test]
    fn request_boundaries_are_closed() {
        let build = |csr: Vec<u8>, ekus: Vec<PkiExtendedKeyUsage>, validity, renew_before| {
            PkiArtifactRequest::try_new(
                scope(),
                generation(),
                PkiPolicyDigest::new([1; 32]),
                RedactedBytes::new(csr),
                PkiSpkiDigest::new([2; 32]),
                PkiCommonName::try_new("device.example").expect("common name"),
                vec![PkiSan::dns("device.example").expect("DNS")],
                ekus,
                validity,
                renew_before,
            )
        };
        for size in [0, MAX_PKI_CSR_BYTES + 1] {
            assert_eq!(
                build(
                    vec![1; size],
                    vec![PkiExtendedKeyUsage::ClientAuth],
                    Duration::from_secs(3600),
                    Duration::from_secs(600),
                )
                .unwrap_err(),
                PkiArtifactValueError::InvalidCsrSize
            );
        }
        assert!(
            build(
                vec![1; MAX_PKI_CSR_BYTES],
                vec![PkiExtendedKeyUsage::ClientAuth],
                Duration::from_secs(3600),
                Duration::from_secs(600),
            )
            .is_ok()
        );
        assert_eq!(
            build(
                vec![1],
                vec![
                    PkiExtendedKeyUsage::ClientAuth,
                    PkiExtendedKeyUsage::ClientAuth,
                ],
                Duration::from_secs(3600),
                Duration::from_secs(600),
            )
            .unwrap_err(),
            PkiArtifactValueError::InvalidExtendedKeyUsage
        );
        assert_eq!(
            build(
                vec![1],
                vec![],
                Duration::from_secs(3600),
                Duration::from_secs(600),
            )
            .unwrap_err(),
            PkiArtifactValueError::InvalidExtendedKeyUsage
        );
        for (validity, renew_before) in [
            (Duration::ZERO, Duration::ZERO),
            (Duration::from_secs(600), Duration::from_secs(600)),
            (Duration::from_nanos(1), Duration::ZERO),
            (Duration::from_secs(601), Duration::from_nanos(1)),
        ] {
            assert_eq!(
                build(
                    vec![1],
                    vec![PkiExtendedKeyUsage::ClientAuth],
                    validity,
                    renew_before,
                )
                .unwrap_err(),
                PkiArtifactValueError::InvalidValidity
            );
        }
    }
}
