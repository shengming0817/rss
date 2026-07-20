//! Signing key ring: Active-only mint selection with Next/Retiring lifecycle classification.
//!
//! INVARIANT: AUTHN-SIGNING-KEYRING-01 { level = "Hard", exec = "native-compile", source = "code", native = "typed single active field; no next/retiring sign API" }
//!
//! ref: maxlambrecht/rust-spiffe JWT bundle kid selection

use std::collections::HashSet;
use std::time::Duration;

use diport::KeyId;

/// Rotation urgency mode for overlap validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationMode {
    /// Full overlap window required.
    Planned,
    /// Overlap check exempt (emergency cutover).
    Emergency,
}

/// Overlap policy inputs for planned rotation verify windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationOverlapPolicy {
    /// Maximum access-token TTL admitted by the profile.
    pub max_access_ttl: Duration,
    /// Allowed clock skew between issuer and verifiers.
    pub clock_skew: Duration,
    /// JWKS propagation SLO before old keys may retire.
    pub jwks_propagation_slo: Duration,
    /// Extra safety margin.
    pub margin: Duration,
}

impl RotationOverlapPolicy {
    /// Minimum verify overlap for planned rotation: ttl + skew + jwks SLO + margin.
    pub fn min_overlap(&self) -> Duration {
        self.max_access_ttl
            .saturating_add(self.clock_skew)
            .saturating_add(self.jwks_propagation_slo)
            .saturating_add(self.margin)
    }

    /// Validate `verify_until - rotated_at` against [`Self::min_overlap`].
    ///
    /// Planned: exact boundary passes; one second short fails. Emergency: always ok.
    pub fn validate_overlap(
        &self,
        rotated_at: i64,
        verify_until: i64,
        mode: RotationMode,
    ) -> Result<(), KeyRingError> {
        match mode {
            RotationMode::Emergency => Ok(()),
            RotationMode::Planned => {
                let overlap_secs = verify_until
                    .checked_sub(rotated_at)
                    .ok_or(KeyRingError::InsufficientOverlap)?;
                let min_secs = i64::try_from(self.min_overlap().as_secs())
                    .map_err(|_| KeyRingError::InsufficientOverlap)?;
                if overlap_secs < min_secs {
                    return Err(KeyRingError::InsufficientOverlap);
                }
                Ok(())
            }
        }
    }
}

/// Signing key ring construction / overlap validation failure.
///
/// Messages contain no key id or key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRingError {
    /// A key id in the ring was empty.
    #[error("signing key id must not be empty")]
    EmptyKeyId,
    /// `active` / `next` / `retiring` key ids were not mutually exclusive.
    #[error("signing key ids in the ring must be unique")]
    DuplicateKeyId,
    /// Planned rotation verify window shorter than [`RotationOverlapPolicy::min_overlap`].
    #[error("rotation verify overlap is insufficient")]
    InsufficientOverlap,
}

/// Active-only signing key ring for JWT mint.
///
/// Holds at most one mint key ([`Self::active`]). `next` and `retiring` are lifecycle metadata
/// only — there is no public API that selects them for signing. Lifecycle roles are Active (mint),
/// Next (staged), Retiring (verify until deadline), and Retired (rejected).
///
/// INVARIANT: AUTHN-SIGNING-KEYRING-01 { level = "Hard", exec = "native-compile", source = "code", native = "typed single active field; no next/retiring sign API" }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyRing {
    active: KeyId,
    next: Option<KeyId>,
    retiring: Vec<(KeyId, i64)>,
}

impl SigningKeyRing {
    /// Build a single-key ring. Empty `active` is rejected.
    pub fn single(active: KeyId) -> Result<Self, KeyRingError> {
        Self::with_rotation(active, None, Vec::new())
    }

    /// Build a ring with optional staged / retiring keys.
    ///
    /// Rejects empty key ids and duplicate kids across `active` / `next` / `retiring`.
    pub fn with_rotation(
        active: KeyId,
        next: Option<KeyId>,
        retiring: Vec<(KeyId, i64)>,
    ) -> Result<Self, KeyRingError> {
        reject_empty(&active)?;
        let mut seen = HashSet::new();
        seen.insert(active.as_str().to_owned());
        if let Some(ref staged) = next {
            reject_empty(staged)?;
            if !seen.insert(staged.as_str().to_owned()) {
                return Err(KeyRingError::DuplicateKeyId);
            }
        }
        for (kid, _) in &retiring {
            reject_empty(kid)?;
            if !seen.insert(kid.as_str().to_owned()) {
                return Err(KeyRingError::DuplicateKeyId);
            }
        }
        Ok(Self {
            active,
            next,
            retiring,
        })
    }

    /// The sole mint key.
    pub fn active(&self) -> &KeyId {
        &self.active
    }

    /// Staged next key (read-only; not selectable for mint).
    pub fn next(&self) -> Option<&KeyId> {
        self.next.as_ref()
    }

    /// Retiring keys with verify-until unix seconds (read-only; not selectable for mint).
    pub fn retiring(&self) -> &[(KeyId, i64)] {
        &self.retiring
    }
}

fn reject_empty(kid: &KeyId) -> Result<(), KeyRingError> {
    if kid.as_str().is_empty() {
        Err(KeyRingError::EmptyKeyId)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kid(id: &str) -> KeyId {
        KeyId::new(id)
    }

    fn policy(ttl_secs: u64) -> RotationOverlapPolicy {
        RotationOverlapPolicy {
            max_access_ttl: Duration::from_secs(ttl_secs),
            clock_skew: Duration::from_secs(30),
            jwks_propagation_slo: Duration::from_secs(60),
            margin: Duration::from_secs(10),
        }
    }

    #[test]
    fn single_constructs_with_active_only() {
        let ring = SigningKeyRing::single(kid("active-1")).expect("non-empty active");
        assert_eq!(ring.active().as_str(), "active-1");
        assert!(ring.next().is_none());
        assert!(ring.retiring().is_empty());
    }

    #[test]
    fn single_rejects_empty_active() {
        assert_eq!(
            SigningKeyRing::single(kid("")),
            Err(KeyRingError::EmptyKeyId)
        );
    }

    #[test]
    fn with_rotation_rejects_duplicate_kids() {
        let cases = [
            SigningKeyRing::with_rotation(kid("a"), Some(kid("a")), Vec::new()),
            SigningKeyRing::with_rotation(kid("a"), Some(kid("b")), vec![(kid("a"), 1)]),
            SigningKeyRing::with_rotation(kid("a"), Some(kid("b")), vec![(kid("b"), 1)]),
            SigningKeyRing::with_rotation(kid("a"), None, vec![(kid("r1"), 1), (kid("r1"), 2)]),
        ];
        for result in cases {
            assert_eq!(result, Err(KeyRingError::DuplicateKeyId));
        }
    }

    #[test]
    fn with_rotation_rejects_empty_next_or_retiring() {
        assert_eq!(
            SigningKeyRing::with_rotation(kid("a"), Some(kid("")), Vec::new()),
            Err(KeyRingError::EmptyKeyId)
        );
        assert_eq!(
            SigningKeyRing::with_rotation(kid("a"), None, vec![(kid(""), 1)]),
            Err(KeyRingError::EmptyKeyId)
        );
    }

    #[test]
    fn with_rotation_accepts_disjoint_kids() {
        let ring = SigningKeyRing::with_rotation(
            kid("active"),
            Some(kid("next")),
            vec![(kid("retiring"), 99)],
        )
        .expect("disjoint kids");
        assert_eq!(ring.active().as_str(), "active");
        assert_eq!(ring.next().map(KeyId::as_str), Some("next"));
        assert_eq!(ring.retiring().len(), 1);
        assert_eq!(ring.retiring()[0].0.as_str(), "retiring");
        assert_eq!(ring.retiring()[0].1, 99);
    }

    #[test]
    fn planned_overlap_exact_boundary_passes_short_fails() {
        let policy = policy(900);
        // min = 900 + 30 + 60 + 10 = 1000
        assert_eq!(policy.min_overlap(), Duration::from_secs(1000));
        let rotated_at = 1_700_000_000_i64;
        assert!(
            policy
                .validate_overlap(rotated_at, rotated_at + 1000, RotationMode::Planned)
                .is_ok()
        );
        assert_eq!(
            policy.validate_overlap(rotated_at, rotated_at + 999, RotationMode::Planned),
            Err(KeyRingError::InsufficientOverlap)
        );
    }

    #[test]
    fn planned_overlap_checked_sub_underflow_is_insufficient() {
        let policy = policy(900);
        // verify_until < rotated_at → checked_sub yields None → InsufficientOverlap.
        assert_eq!(
            policy.validate_overlap(1_700_000_000, 1_699_999_999, RotationMode::Planned),
            Err(KeyRingError::InsufficientOverlap)
        );
    }

    #[test]
    fn emergency_overlap_is_exempt() {
        let policy = policy(900);
        let rotated_at = 1_700_000_000_i64;
        assert!(
            policy
                .validate_overlap(rotated_at, rotated_at, RotationMode::Emergency)
                .is_ok()
        );
    }

    #[test]
    fn key_ring_error_messages_omit_key_material() {
        for error in [
            KeyRingError::EmptyKeyId,
            KeyRingError::DuplicateKeyId,
            KeyRingError::InsufficientOverlap,
        ] {
            let message = error.to_string();
            assert!(!message.is_empty());
            assert!(!message.contains("kid"));
            assert!(!message.contains("secret"));
        }
    }
}
