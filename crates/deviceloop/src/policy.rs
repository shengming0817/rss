//! Closed certificate-policy vocabulary and canonical representation.

const MAX_SAN_COUNT: usize = 32;
const MAX_SAN_CHARS: usize = 253;

/// A certificate policy duration or relation was invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificatePolicyError {
    /// Certificate validity must be between five minutes and one year.
    #[error("certificate validity must be in 300..=31536000 seconds")]
    InvalidValidity,
    /// Renewal lead time must be between one minute and one year minus one second.
    #[error("certificate renew-before must be in 60..=31535999 seconds")]
    InvalidRenewBefore,
    /// Renewal must begin strictly before the certificate expires.
    #[error("certificate renew-before must be less than validity")]
    RenewBeforeNotLessThanValidity,
    /// At least one closed key usage is required.
    #[error("certificate policy requires at least one key usage")]
    EmptyKeyUsages,
    /// A key usage appeared more than once.
    #[error("certificate policy contains a duplicate key usage")]
    DuplicateKeyUsage,
    /// A raw key-usage label was outside the closed vocabulary.
    #[error("certificate key usage is invalid")]
    InvalidKeyUsage,
    /// A SAN was empty, padded, too long, or contained a control character.
    #[error("certificate SAN is not canonical")]
    InvalidSan,
    /// A policy exceeded the closed SAN cardinality bound.
    #[error("certificate policy contains more than 32 SANs")]
    TooManySans,
    /// A canonical SAN appeared more than once.
    #[error("certificate policy contains a duplicate SAN")]
    DuplicateSan,
}

/// Closed certificate key-usage vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateKeyUsage {
    /// Device authenticates as a TLS client.
    ClientAuth,
    /// Device terminates an authorized TLS server connection.
    ServerAuth,
}

impl CertificateKeyUsage {
    /// Exact closed set in canonical order.
    pub const ALL: [Self; 2] = [Self::ClientAuth, Self::ServerAuth];

    /// Parse the stable persistence/wire label.
    pub fn parse_label(raw: &str) -> Result<Self, CertificatePolicyError> {
        match raw {
            "clientAuth" => Ok(Self::ClientAuth),
            "serverAuth" => Ok(Self::ServerAuth),
            _ => Err(CertificatePolicyError::InvalidKeyUsage),
        }
    }

    /// Stable persistence/wire label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ClientAuth => "clientAuth",
            Self::ServerAuth => "serverAuth",
        }
    }
}

/// Canonical bounded SAN policy value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateSan(String);

impl CertificateSan {
    /// Parse one provider-authorized SAN value without assigning it a signer-specific kind.
    pub fn parse(raw: &str) -> Result<Self, CertificatePolicyError> {
        let char_count = raw.chars().count();
        if char_count == 0
            || char_count > MAX_SAN_CHARS
            || raw.trim() != raw
            || raw.chars().any(char::is_control)
        {
            return Err(CertificatePolicyError::InvalidSan);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the canonical SAN value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated certificate lifetime in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateValiditySeconds(u32);

impl CertificateValiditySeconds {
    /// Minimum accepted lifetime: five minutes.
    pub const MIN: u32 = 300;
    /// Maximum accepted lifetime: 365 days.
    pub const MAX: u32 = 31_536_000;

    /// Validate raw policy input.
    pub fn try_new(seconds: u64) -> Result<Self, CertificatePolicyError> {
        let seconds =
            u32::try_from(seconds).map_err(|_| CertificatePolicyError::InvalidValidity)?;
        if (Self::MIN..=Self::MAX).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(CertificatePolicyError::InvalidValidity)
        }
    }

    /// Validated number of seconds.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Validated lead time before certificate expiry, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CertificateRenewBeforeSeconds(u32);

impl CertificateRenewBeforeSeconds {
    /// Minimum accepted renewal lead time: one minute.
    pub const MIN: u32 = 60;
    /// Maximum accepted renewal lead time: one year minus one second.
    pub const MAX: u32 = 31_535_999;

    /// Validate raw policy input.
    pub fn try_new(seconds: u64) -> Result<Self, CertificatePolicyError> {
        let seconds =
            u32::try_from(seconds).map_err(|_| CertificatePolicyError::InvalidRenewBefore)?;
        if (Self::MIN..=Self::MAX).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(CertificatePolicyError::InvalidRenewBefore)
        }
    }

    /// Validated number of seconds.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Cross-field validated certificate lifetime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificatePolicyDurations {
    validity: CertificateValiditySeconds,
    renew_before: CertificateRenewBeforeSeconds,
}

impl CertificatePolicyDurations {
    /// Bind validated durations and enforce `renew_before < validity`.
    pub fn new(
        validity: CertificateValiditySeconds,
        renew_before: CertificateRenewBeforeSeconds,
    ) -> Result<Self, CertificatePolicyError> {
        if renew_before.get() >= validity.get() {
            return Err(CertificatePolicyError::RenewBeforeNotLessThanValidity);
        }
        Ok(Self {
            validity,
            renew_before,
        })
    }

    /// Certificate lifetime.
    pub fn validity(self) -> CertificateValiditySeconds {
        self.validity
    }

    /// Renewal lead time.
    pub fn renew_before(self) -> CertificateRenewBeforeSeconds {
        self.renew_before
    }
}

/// Canonically ordered certificate policy owned by the DeviceLatent domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePolicy {
    durations: CertificatePolicyDurations,
    key_usages: Vec<CertificateKeyUsage>,
    sans: Vec<CertificateSan>,
}

impl CertificatePolicy {
    /// Seal a policy after enforcing the complete closed vocabulary.
    pub fn new(
        durations: CertificatePolicyDurations,
        mut key_usages: Vec<CertificateKeyUsage>,
        mut sans: Vec<CertificateSan>,
    ) -> Result<Self, CertificatePolicyError> {
        if key_usages.is_empty() {
            return Err(CertificatePolicyError::EmptyKeyUsages);
        }
        key_usages.sort_unstable();
        if key_usages.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CertificatePolicyError::DuplicateKeyUsage);
        }
        if sans.len() > MAX_SAN_COUNT {
            return Err(CertificatePolicyError::TooManySans);
        }
        sans.sort_unstable();
        if sans.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CertificatePolicyError::DuplicateSan);
        }
        Ok(Self {
            durations,
            key_usages,
            sans,
        })
    }

    /// Restore raw persistence labels through the canonical constructor.
    pub fn restore(
        validity_seconds: u64,
        renew_before_seconds: u64,
        key_usages: Vec<String>,
        sans: Vec<String>,
    ) -> Result<Self, CertificatePolicyError> {
        let durations = CertificatePolicyDurations::new(
            CertificateValiditySeconds::try_new(validity_seconds)?,
            CertificateRenewBeforeSeconds::try_new(renew_before_seconds)?,
        )?;
        let key_usages = key_usages
            .iter()
            .map(|value| CertificateKeyUsage::parse_label(value))
            .collect::<Result<Vec<_>, _>>()?;
        let sans = sans
            .iter()
            .map(|value| CertificateSan::parse(value))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(durations, key_usages, sans)
    }

    /// Validated duration relation.
    #[must_use]
    pub const fn durations(&self) -> CertificatePolicyDurations {
        self.durations
    }

    /// Canonically ordered usages.
    #[must_use]
    pub fn key_usages(&self) -> &[CertificateKeyUsage] {
        &self.key_usages
    }

    /// Canonically ordered SANs.
    #[must_use]
    pub fn sans(&self) -> &[CertificateSan] {
        &self.sans
    }

    /// Stable length-prefixed bytes used by the database-owned SHA-256 calculation.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = b"rss.deviceloop.device-certificate-policy.v1\0".to_vec();
        output.extend_from_slice(&self.durations.validity().get().to_be_bytes());
        output.extend_from_slice(&self.durations.renew_before().get().to_be_bytes());
        append_values(
            &mut output,
            self.key_usages.iter().map(|usage| usage.as_label()),
        );
        append_values(&mut output, self.sans.iter().map(CertificateSan::as_str));
        output
    }
}

fn append_values<'a>(output: &mut Vec<u8>, values: impl ExactSizeIterator<Item = &'a str>) {
    output.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn validity_boundaries_are_exact() {
        for value in [
            CertificateValiditySeconds::MIN as u64,
            CertificateValiditySeconds::MAX as u64,
        ] {
            assert_eq!(
                CertificateValiditySeconds::try_new(value).unwrap().get() as u64,
                value
            );
        }
        for value in [0, 299, CertificateValiditySeconds::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                CertificateValiditySeconds::try_new(value),
                Err(CertificatePolicyError::InvalidValidity)
            );
        }
    }

    #[test]
    fn renew_before_boundaries_are_exact() {
        for value in [
            CertificateRenewBeforeSeconds::MIN as u64,
            CertificateRenewBeforeSeconds::MAX as u64,
        ] {
            assert_eq!(
                CertificateRenewBeforeSeconds::try_new(value).unwrap().get() as u64,
                value
            );
        }
        for value in [
            0,
            59,
            CertificateRenewBeforeSeconds::MAX as u64 + 1,
            u64::MAX,
        ] {
            assert_eq!(
                CertificateRenewBeforeSeconds::try_new(value),
                Err(CertificatePolicyError::InvalidRenewBefore)
            );
        }
    }

    #[test]
    fn cross_field_relation_is_strict() {
        let validity = CertificateValiditySeconds::try_new(300).unwrap();
        let valid_renew = CertificateRenewBeforeSeconds::try_new(299).unwrap();
        let equal_renew = CertificateRenewBeforeSeconds::try_new(300).unwrap();
        assert_eq!(
            CertificatePolicyDurations::new(validity, valid_renew)
                .unwrap()
                .renew_before(),
            valid_renew
        );
        assert_eq!(
            CertificatePolicyDurations::new(validity, equal_renew),
            Err(CertificatePolicyError::RenewBeforeNotLessThanValidity)
        );
        let larger_renew = CertificateRenewBeforeSeconds::try_new(301).unwrap();
        assert_eq!(
            CertificatePolicyDurations::new(validity, larger_renew),
            Err(CertificatePolicyError::RenewBeforeNotLessThanValidity)
        );
    }

    #[test]
    fn complete_policy_is_closed_and_canonical() {
        let durations = CertificatePolicyDurations::new(
            CertificateValiditySeconds::try_new(3_600).unwrap(),
            CertificateRenewBeforeSeconds::try_new(300).unwrap(),
        )
        .unwrap();
        let first = CertificatePolicy::new(
            durations,
            vec![
                CertificateKeyUsage::ServerAuth,
                CertificateKeyUsage::ClientAuth,
            ],
            vec![
                CertificateSan::parse("z.example").unwrap(),
                CertificateSan::parse("a.example").unwrap(),
            ],
        )
        .unwrap();
        let restored = CertificatePolicy::restore(
            3_600,
            300,
            vec!["clientAuth".to_owned(), "serverAuth".to_owned()],
            vec!["a.example".to_owned(), "z.example".to_owned()],
        )
        .unwrap();
        assert_eq!(first, restored);
        assert_eq!(first.canonical_bytes(), restored.canonical_bytes());
        assert!(
            first
                .canonical_bytes()
                .starts_with(b"rss.deviceloop.device-certificate-policy.v1\0")
        );
        assert_eq!(first.key_usages(), CertificateKeyUsage::ALL.as_slice());
        assert!(CertificatePolicy::new(durations, vec![], vec![]).is_err());
        assert!(CertificateSan::parse(" padded.example ").is_err());
    }
}
