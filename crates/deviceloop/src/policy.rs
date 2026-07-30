//! Closed certificate policy duration vocabulary.

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
}
