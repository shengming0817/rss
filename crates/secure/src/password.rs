//! Typed password policy, Argon2id hashing and bounded verification with a current-work floor.
//! New passwords require [`ValidatedPassword`]; rehash requires [`VerifiedPassword`] (RustCrypto Argon2 0.5.3).

use std::collections::HashSet;
use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{
    PasswordHash as PhcHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

const MIN_CODE_POINTS: usize = 15;
const MAX_CODE_POINTS: usize = 64;

#[derive(Clone, Copy)]
struct PasswordProfile {
    algorithm: Algorithm,
    version: Version,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
    min_salt_len: usize,
}

const CURRENT_PROFILE: PasswordProfile = PasswordProfile {
    algorithm: Algorithm::Argon2id,
    version: Version::V0x13,
    m_cost: 19 * 1024,
    t_cost: 2,
    p_cost: 1,
    output_len: 32,
    min_salt_len: 16,
};

// Stored profiles above this closed ceiling fail before allocating attacker-selected work.
const MAX_SUPPORTED_PROFILE: PasswordProfile = PasswordProfile {
    algorithm: Algorithm::Argon2id,
    version: Version::V0x13,
    m_cost: 2 * CURRENT_PROFILE.m_cost,
    t_cost: 2 * CURRENT_PROFILE.t_cost,
    p_cost: 2 * CURRENT_PROFILE.p_cost,
    output_len: 2 * CURRENT_PROFILE.output_len,
    min_salt_len: CURRENT_PROFILE.min_salt_len,
};

impl PasswordProfile {
    fn argon2(self) -> Result<Argon2<'static>, PasswordError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(self.output_len))
            .map_err(|_| PasswordError::Hash)?;
        Ok(self.argon2_with(params))
    }

    fn argon2_with(self, params: Params) -> Argon2<'static> {
        Argon2::new(self.algorithm, self.version, params)
    }

    const fn work(self) -> KdfWork {
        KdfWork {
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            output_len: self.output_len,
        }
    }
}

/// Password processing failure. Display messages contain no password, digest or PHC material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordError {
    #[error("password hash failed")]
    Hash,
    #[error("stored password hash is invalid")]
    InvalidStoredHash,
    #[error("stored password hash profile is unsupported")]
    UnsupportedProfile,
}

/// New-password policy rejection reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PasswordPolicyError {
    #[error("password is too short")]
    TooShort,
    #[error("password is too long")]
    TooLong,
    #[error("password is compromised")]
    Compromised,
}

impl PasswordPolicyError {
    /// Stable, non-secret reason suitable for a 4xx public detail.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::Compromised => "compromised",
        }
    }
}

/// Owned password candidate with its presented length and NFC-normalized secret.
/// It is not yet approved for a new credential.
pub struct RawPassword {
    normalized: zeroize::Zeroizing<String>,
    presented_code_points: usize,
}

impl RawPassword {
    /// Take ownership and normalize once at the input boundary.
    pub fn new(value: String) -> Self {
        let original = zeroize::Zeroizing::new(value);
        let presented_code_points = original.chars().count();
        Self {
            normalized: zeroize::Zeroizing::new(original.nfc().collect()),
            presented_code_points,
        }
    }

    fn expose(&self) -> &str {
        &self.normalized
    }
}

impl std::fmt::Debug for RawPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RawPassword(<redacted>)")
    }
}

/// Non-empty immutable set of whole-password SHA-256 digests.
///
/// There is no empty/default constructor and no provider trait to implement. File format and I/O
/// validation remain adapter responsibilities; the concrete value is the only policy dependency.
pub struct DigestPasswordBlocklist {
    digests: HashSet<[u8; 32]>,
}

impl DigestPasswordBlocklist {
    /// Construct the concrete value from a statically non-empty digest stream.
    #[must_use]
    pub fn from_nonempty_sha256_digests(
        first: [u8; 32],
        remaining: impl IntoIterator<Item = [u8; 32]>,
    ) -> Self {
        let mut digests = HashSet::from([first]);
        digests.extend(remaining);
        Self { digests }
    }

    fn contains(&self, digest: &[u8; 32]) -> bool {
        self.digests.contains(digest)
    }
}

impl std::fmt::Debug for DigestPasswordBlocklist {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DigestPasswordBlocklist(<redacted>)")
    }
}

/// Mandatory single-factor password policy.
#[derive(Clone)]
pub struct PasswordPolicy {
    blocklist: Arc<DigestPasswordBlocklist>,
}

impl PasswordPolicy {
    /// Construct a policy with a mandatory blocklist provider.
    pub fn new(blocklist: Arc<DigestPasswordBlocklist>) -> Self {
        Self { blocklist }
    }

    /// Construct an explicit plaintext fixture; absent from production builds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(first: &str, remaining: &[&str]) -> Self {
        let first = Sha256::digest(first.nfc().collect::<String>().as_bytes()).into();
        let digests = remaining
            .iter()
            .map(|raw| Sha256::digest(raw.nfc().collect::<String>().as_bytes()).into())
            .collect::<Vec<[u8; 32]>>();
        Self::new(Arc::new(
            DigestPasswordBlocklist::from_nonempty_sha256_digests(first, digests),
        ))
    }

    /// Validate an NFC password and mint the only production hash input type.
    pub fn validate(
        &self,
        candidate: RawPassword,
    ) -> Result<ValidatedPassword, PasswordPolicyError> {
        if candidate.presented_code_points < MIN_CODE_POINTS {
            return Err(PasswordPolicyError::TooShort);
        }
        if candidate.presented_code_points > MAX_CODE_POINTS {
            return Err(PasswordPolicyError::TooLong);
        }
        let normalized_code_points = candidate.expose().chars().count();
        if normalized_code_points < MIN_CODE_POINTS {
            return Err(PasswordPolicyError::TooShort);
        }
        if normalized_code_points > MAX_CODE_POINTS {
            return Err(PasswordPolicyError::TooLong);
        }
        let digest: [u8; 32] = Sha256::digest(candidate.expose().as_bytes()).into();
        if self.blocklist.contains(&digest) {
            return Err(PasswordPolicyError::Compromised);
        }
        Ok(ValidatedPassword(candidate))
    }
}

/// Policy-approved new password. Private fields make construction outside this module impossible.
pub struct ValidatedPassword(RawPassword);

impl std::fmt::Debug for ValidatedPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValidatedPassword(<redacted>)")
    }
}

/// Argon2id PHC string. The owned material is zeroized and always redacted in Debug output.
#[derive(Clone, PartialEq, Eq, rss_redact::Redact)]
pub struct PasswordHash(#[redact(sensitivity = secret)] zeroize::Zeroizing<String>);

impl PasswordHash {
    /// Hash a policy-approved password using the current profile and a new random salt.
    pub fn from_validated(password: ValidatedPassword) -> Result<Self, PasswordError> {
        hash_with(password.0.expose(), CURRENT_PROFILE.argon2()?)
    }

    /// Parse a stored PHC under the closed supported profile set.
    pub fn parse(phc: &str) -> Result<Self, PasswordError> {
        let parsed = PhcHash::new(phc).map_err(|_| PasswordError::InvalidStoredHash)?;
        classify_profile(&parsed)?;
        Ok(Self(zeroize::Zeroizing::new(phc.to_string())))
    }

    /// Persisted PHC representation.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether a successful verification should replace this PHC with the current profile.
    pub fn needs_rehash(&self) -> Result<bool, PasswordError> {
        let parsed = self.parsed()?;
        Ok(matches!(
            classify_profile(&parsed)?.state,
            ProfileState::NeedsRehash
        ))
    }

    fn parsed(&self) -> Result<PhcHash<'_>, PasswordError> {
        PhcHash::new(self.0.as_str()).map_err(|_| PasswordError::InvalidStoredHash)
    }

    /// Test/demo-only credential constructor; absent from production builds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(password: RawPassword) -> Result<Self, PasswordError> {
        hash_with(password.expose(), CURRENT_PROFILE.argon2()?)
    }

    /// Test-only lower-profile constructor used to prove login-time migration.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test_with_params(
        password: RawPassword,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Self, PasswordError> {
        let params = Params::new(m_cost, t_cost, p_cost, Some(CURRENT_PROFILE.output_len))
            .map_err(|_| PasswordError::Hash)?;
        hash_with(
            password.expose(),
            Argon2::new(CURRENT_PROFILE.algorithm, CURRENT_PROFILE.version, params),
        )
    }
}

/// Closed verification result. Only the secure module can mint the successful receipt.
pub enum PasswordVerification {
    Verified(VerifiedPassword),
    Invalid,
}

/// Proof that a candidate matched a stored hash, optionally carrying its precomputed upgrade.
pub struct VerifiedPassword {
    upgraded_hash: Option<PasswordHash>,
}

impl VerifiedPassword {
    /// Return the current-profile replacement already computed as weak-profile work padding.
    pub fn upgraded_hash(self) -> Option<PasswordHash> {
        self.upgraded_hash
    }
}

impl std::fmt::Debug for VerifiedPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPassword(<redacted>)")
    }
}

/// Bounded verification with at least one current-profile KDF worth of work.
///
/// Missing credentials execute the current profile. Weaker stored profiles execute their own
/// verification plus current-profile padding; current and bounded-stronger profiles execute their
/// stored work. Stronger dimensions are capped at twice the current values. This prevents legacy
/// weak hashes from creating a faster authentication path without claiming strict wall-clock
/// equality between different Argon2 parameter sets.
pub fn verify_password(
    candidate: RawPassword,
    stored: Option<&PasswordHash>,
) -> Result<PasswordVerification, PasswordError> {
    let Some(stored) = stored else {
        execute_current_work(candidate.expose())?;
        return Ok(PasswordVerification::Invalid);
    };
    let parsed = stored.parsed()?;
    let profile = classify_profile(&parsed)?;
    record_verification_work(VerificationWork::Stored(profile.work));
    let matches = CURRENT_PROFILE
        .argon2()?
        .verify_password(candidate.expose().as_bytes(), &parsed)
        .is_ok();
    let upgraded_hash = matches!(profile.state, ProfileState::NeedsRehash)
        .then(|| execute_current_work(candidate.expose()))
        .transpose()?;
    if !matches {
        return Ok(PasswordVerification::Invalid);
    }
    Ok(PasswordVerification::Verified(VerifiedPassword {
        upgraded_hash,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileState {
    CurrentOrStronger,
    NeedsRehash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClassifiedProfile {
    state: ProfileState,
    work: KdfWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfWork {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationWork {
    Stored(KdfWork),
    CurrentFloor(KdfWork),
}

fn execute_current_work(password: &str) -> Result<PasswordHash, PasswordError> {
    record_verification_work(VerificationWork::CurrentFloor(CURRENT_PROFILE.work()));
    hash_with(password, CURRENT_PROFILE.argon2()?)
}

#[cfg(not(test))]
const fn record_verification_work(_work: VerificationWork) {}

#[cfg(test)]
std::thread_local! {
    static VERIFICATION_WORK: std::cell::RefCell<Option<Vec<VerificationWork>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
fn record_verification_work(work: VerificationWork) {
    VERIFICATION_WORK.with(|recorded| {
        if let Some(recorded) = recorded.borrow_mut().as_mut() {
            recorded.push(work);
        }
    });
}

fn hash_with(password: &str, argon2: Argon2<'_>) -> Result<PasswordHash, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let phc = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| PasswordError::Hash)?
        .to_string();
    Ok(PasswordHash(zeroize::Zeroizing::new(phc)))
}

fn classify_profile(parsed: &PhcHash<'_>) -> Result<ClassifiedProfile, PasswordError> {
    if parsed.algorithm.as_str() != CURRENT_PROFILE.algorithm.as_str()
        || parsed.version != Some(u32::from(CURRENT_PROFILE.version))
    {
        return Err(PasswordError::UnsupportedProfile);
    }
    let params = Params::try_from(parsed).map_err(|_| PasswordError::InvalidStoredHash)?;
    if !params.keyid().is_empty() || !params.data().is_empty() {
        return Err(PasswordError::UnsupportedProfile);
    }
    let salt = parsed.salt.ok_or(PasswordError::InvalidStoredHash)?;
    let mut salt_bytes = [0_u8; 64];
    if salt
        .decode_b64(&mut salt_bytes)
        .map_err(|_| PasswordError::InvalidStoredHash)?
        .len()
        < CURRENT_PROFILE.min_salt_len
    {
        return Err(PasswordError::UnsupportedProfile);
    }
    let output_len = parsed
        .hash
        .as_ref()
        .ok_or(PasswordError::InvalidStoredHash)?
        .len();
    let work = KdfWork {
        m_cost: params.m_cost(),
        t_cost: params.t_cost(),
        p_cost: params.p_cost(),
        output_len,
    };
    let current = CURRENT_PROFILE.work();
    let maximum = MAX_SUPPORTED_PROFILE.work();
    let values = [
        (
            work.m_cost as u64,
            current.m_cost as u64,
            maximum.m_cost as u64,
        ),
        (
            work.t_cost as u64,
            current.t_cost as u64,
            maximum.t_cost as u64,
        ),
        (
            work.p_cost as u64,
            current.p_cost as u64,
            maximum.p_cost as u64,
        ),
        (
            work.output_len as u64,
            current.output_len as u64,
            maximum.output_len as u64,
        ),
    ];
    if values.iter().any(|(stored, _, maximum)| stored > maximum) {
        return Err(PasswordError::UnsupportedProfile);
    }
    let all_at_most = values.iter().all(|(stored, current, _)| stored <= current);
    let any_lower = values.iter().any(|(stored, current, _)| stored < current);
    let all_at_least = values.iter().all(|(stored, current, _)| stored >= current);
    let state = if all_at_most && any_lower {
        ProfileState::NeedsRehash
    } else if all_at_least {
        ProfileState::CurrentOrStronger
    } else {
        return Err(PasswordError::UnsupportedProfile);
    };
    Ok(ClassifiedProfile { state, work })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn policy(blocked: &[&str]) -> PasswordPolicy {
        const UNLISTED_FIXTURE: &str = "this fixture is never a candidate";
        let (first, remaining) = blocked.split_first().unwrap_or((&UNLISTED_FIXTURE, &[]));
        PasswordPolicy::for_test(first, remaining)
    }

    fn approved(raw: &str) -> ValidatedPassword {
        policy(&[])
            .validate(RawPassword::new(raw.to_string()))
            .expect("approved password")
    }

    fn hash_for_profile(m_cost: u32, output_len: usize) -> PasswordHash {
        let params = Params::new(
            m_cost,
            CURRENT_PROFILE.t_cost,
            CURRENT_PROFILE.p_cost,
            Some(output_len),
        )
        .expect("valid profile fixture");
        hash_with(
            "profile-classification-password",
            CURRENT_PROFILE.argon2_with(params),
        )
        .expect("profile fixture")
    }

    fn recorded_work<T>(action: impl FnOnce() -> T) -> (T, Vec<VerificationWork>) {
        VERIFICATION_WORK.with(|work| assert!(work.borrow_mut().replace(Vec::new()).is_none()));
        let result = action();
        let work =
            VERIFICATION_WORK.with(|work| work.borrow_mut().take().expect("active recorder"));
        (result, work)
    }

    #[test]
    fn policy_enforces_code_point_bounds_and_no_composition_rule() {
        let p = policy(&[]);
        for (raw, expected) in [
            (String::new(), Some(PasswordPolicyError::TooShort)),
            ("界".repeat(14), Some(PasswordPolicyError::TooShort)),
            ("x".repeat(15), None),
            ("界".repeat(64), None),
            ("x".repeat(65), Some(PasswordPolicyError::TooLong)),
            (
                format!("{}e\u{301}", "x".repeat(63)),
                Some(PasswordPolicyError::TooLong),
            ),
        ] {
            let result = p.validate(RawPassword::new(raw));
            assert_eq!(result.err(), expected);
        }
    }

    #[test]
    fn nfc_precedes_length_digest_and_hashing() {
        let composed = "é".repeat(15);
        let decomposed = "e\u{301}".repeat(15);
        let p = policy(&[&composed]);
        assert_eq!(
            p.validate(RawPassword::new(decomposed)).err(),
            Some(PasswordPolicyError::Compromised)
        );
    }

    #[test]
    fn blocklist_matches_only_the_normalized_whole_password() {
        let blocked = "this is blocked!";
        let p = policy(&[blocked]);
        assert_eq!(
            p.validate(RawPassword::new(blocked.to_string())).err(),
            Some(PasswordPolicyError::Compromised)
        );
        for allowed in [
            "THIS IS BLOCKED!",
            "this is blocked! suffix",
            " this is blocked!",
        ] {
            assert!(
                p.validate(RawPassword::new(allowed.to_string())).is_ok(),
                "policy must not trim, case-fold, or substring-match"
            );
        }
    }

    #[test]
    fn validated_hash_verifies_and_debug_is_redacted() {
        let raw = RawPassword::new("correct horse battery staple".to_string());
        assert_eq!(format!("{raw:?}"), "RawPassword(<redacted>)");
        let validated = policy(&[]).validate(raw).expect("approved password");
        assert_eq!(format!("{validated:?}"), "ValidatedPassword(<redacted>)");
        let hash = PasswordHash::from_validated(validated).expect("hash");
        let result = verify_password(
            RawPassword::new("correct horse battery staple".to_string()),
            Some(&hash),
        )
        .expect("verify");
        assert!(matches!(&result, PasswordVerification::Verified(_)));
        let PasswordVerification::Verified(receipt) = result else {
            return;
        };
        assert_eq!(format!("{receipt:?}"), "VerifiedPassword(<redacted>)");
        assert_eq!(format!("{hash:?}"), "PasswordHash(<redacted>)");
    }

    #[test]
    fn current_hash_has_the_exact_target_profile_and_fresh_salt() {
        let first = PasswordHash::from_validated(approved("correct horse battery staple"))
            .expect("first hash");
        let second = PasswordHash::from_validated(approved("correct horse battery staple"))
            .expect("second hash");
        let parsed = first.parsed().expect("generated PHC");
        let params = Params::try_from(&parsed).expect("generated params");
        assert_eq!(
            parsed.algorithm.as_str(),
            CURRENT_PROFILE.algorithm.as_str()
        );
        assert_eq!(parsed.version, Some(u32::from(CURRENT_PROFILE.version)));
        assert_eq!(params.m_cost(), CURRENT_PROFILE.m_cost);
        assert_eq!(params.t_cost(), CURRENT_PROFILE.t_cost);
        assert_eq!(params.p_cost(), CURRENT_PROFILE.p_cost);
        assert_eq!(
            parsed.hash.expect("output").len(),
            CURRENT_PROFILE.output_len
        );
        let salt = parsed.salt.expect("salt");
        let mut decoded = [0_u8; 64];
        assert_eq!(salt.decode_b64(&mut decoded).expect("salt bytes").len(), 16);
        assert_ne!(
            salt,
            second.parsed().expect("second PHC").salt.expect("salt")
        );
    }

    #[test]
    fn wrong_and_missing_credentials_are_invalid() {
        let hash =
            PasswordHash::from_validated(approved("correct horse battery staple")).expect("hash");
        assert!(matches!(
            verify_password(RawPassword::new("wrong".to_string()), Some(&hash)).expect("verify"),
            PasswordVerification::Invalid
        ));
        assert!(matches!(
            verify_password(RawPassword::new("anything".to_string()), None).expect("dummy"),
            PasswordVerification::Invalid
        ));
    }

    #[test]
    fn weaker_hash_rehashes_after_success() {
        let weak = PasswordHash::for_test_with_params(
            RawPassword::new("legacy-short".to_string()),
            8 * 1024,
            1,
            1,
        )
        .expect("weak hash");
        let result = verify_password(RawPassword::new("legacy-short".to_string()), Some(&weak))
            .expect("verify");
        assert!(matches!(&result, PasswordVerification::Verified(_)));
        let PasswordVerification::Verified(receipt) = result else {
            return;
        };
        let upgraded: Option<PasswordHash> = receipt.upgraded_hash();
        let upgraded = upgraded.expect("upgrade required");
        assert!(!upgraded.needs_rehash().expect("current profile"));
    }

    #[test]
    fn weak_current_stronger_and_missing_profiles_have_bounded_work() {
        let password = "work-budget-password";
        let weak_work = KdfWork {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            output_len: CURRENT_PROFILE.output_len,
        };
        let stronger_work = KdfWork {
            m_cost: CURRENT_PROFILE.m_cost + 1024,
            ..CURRENT_PROFILE.work()
        };
        let weak = PasswordHash::for_test_with_params(
            RawPassword::new(password.to_string()),
            weak_work.m_cost,
            weak_work.t_cost,
            weak_work.p_cost,
        )
        .expect("weak fixture");
        let current = PasswordHash::for_test(RawPassword::new(password.to_string()))
            .expect("current fixture");
        let stronger = PasswordHash::for_test_with_params(
            RawPassword::new(password.to_string()),
            stronger_work.m_cost,
            stronger_work.t_cost,
            stronger_work.p_cost,
        )
        .expect("stronger fixture");

        let (upgraded, weak_success_work) = recorded_work(|| {
            match verify_password(RawPassword::new(password.to_string()), Some(&weak))
                .expect("weak verification")
            {
                PasswordVerification::Verified(receipt) => receipt.upgraded_hash(),
                PasswordVerification::Invalid => None,
            }
        });
        assert!(upgraded.is_some());
        assert_eq!(
            weak_success_work,
            vec![
                VerificationWork::Stored(weak_work),
                VerificationWork::CurrentFloor(CURRENT_PROFILE.work()),
            ]
        );
        let (_, weak_failure_work) = recorded_work(|| {
            verify_password(RawPassword::new("wrong-password".to_string()), Some(&weak))
                .expect("weak rejection")
        });
        assert_eq!(weak_failure_work, weak_success_work);
        assert_eq!(
            recorded_work(|| {
                verify_password(
                    RawPassword::new("wrong-password".to_string()),
                    Some(&current),
                )
                .expect("current rejection")
            })
            .1,
            vec![VerificationWork::Stored(CURRENT_PROFILE.work())]
        );
        assert_eq!(
            recorded_work(|| {
                verify_password(
                    RawPassword::new("wrong-password".to_string()),
                    Some(&stronger),
                )
                .expect("stronger rejection")
            })
            .1,
            vec![VerificationWork::Stored(stronger_work)]
        );
        assert_eq!(
            recorded_work(|| {
                verify_password(RawPassword::new("wrong-password".to_string()), None)
                    .expect("missing rejection")
            })
            .1,
            vec![VerificationWork::CurrentFloor(CURRENT_PROFILE.work())]
        );
    }

    #[test]
    fn output_length_profiles_are_classified_without_downgrade() {
        let output = CURRENT_PROFILE.output_len;
        assert!(
            hash_for_profile(CURRENT_PROFILE.m_cost, output - 1)
                .needs_rehash()
                .expect("lower output")
        );
        assert!(
            !hash_for_profile(CURRENT_PROFILE.m_cost, output + 1)
                .needs_rehash()
                .expect("higher output")
        );
        assert!(matches!(
            hash_for_profile(CURRENT_PROFILE.m_cost + 1, output - 1).needs_rehash(),
            Err(PasswordError::UnsupportedProfile)
        ));
    }

    #[test]
    fn stored_profile_work_is_capped_before_verification() {
        let current =
            PasswordHash::for_test(RawPassword::new("bounded-profile-password".to_string()))
                .expect("current fixture");
        for unsupported in [
            current.as_str().replacen(
                &format!("m={}", CURRENT_PROFILE.m_cost),
                &format!("m={}", MAX_SUPPORTED_PROFILE.m_cost + 1),
                1,
            ),
            current.as_str().replacen(
                &format!("t={}", CURRENT_PROFILE.t_cost),
                &format!("t={}", MAX_SUPPORTED_PROFILE.t_cost + 1),
                1,
            ),
            current.as_str().replacen(
                &format!("p={}", CURRENT_PROFILE.p_cost),
                &format!("p={}", MAX_SUPPORTED_PROFILE.p_cost + 1),
                1,
            ),
        ] {
            assert!(matches!(
                PasswordHash::parse(&unsupported),
                Err(PasswordError::UnsupportedProfile)
            ));
        }
    }

    #[test]
    fn unsupported_algorithm_and_version_are_rejected() {
        let current = PasswordHash::for_test(RawPassword::new("legacy-profile-input".to_string()))
            .expect("current fixture");
        for unsupported in [
            current.as_str().replacen("$argon2id$", "$argon2i$", 1),
            current.as_str().replacen("v=19", "v=16", 1),
            current.as_str().replacen("p=1$", "p=1,x=1$", 1),
        ] {
            assert!(PasswordHash::parse(&unsupported).is_err());
        }
    }
}
