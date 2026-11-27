//! Instance-local session policy; one current credential, no refresh-token history.
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or expired session")]
pub struct SessionError;

/// Owned browser session secret. Never serialize, clone or log it; expose only at the HTTP boundary.
/// ```compile_fail
/// fn copy(s: rss_identity_core::session::SessionSecret) { let _ = s.clone(); }
/// ```
pub struct SessionSecret(Zeroizing<String>);
impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}
impl SessionSecret {
    pub fn generate() -> Result<Self, SessionError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| SessionError)?;
        Ok(Self(Zeroizing::new(hex(bytes.as_ref()))))
    }
    pub fn parse(value: String) -> Result<Self, SessionError> {
        let value = Zeroizing::new(value);
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SessionError);
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Persistence-only authentication digest; not a bearer credential.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
    pub fn csrf(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"rss-identity.session.csrf.v1\0");
        hash.update(self.0.as_bytes());
        hex(&hash.finalize())
    }
    pub fn check_csrf(&self, presented: &str) -> bool {
        bool::from(self.csrf().as_bytes().ct_eq(presented.as_bytes()))
    }
}
/// The presentation selected at issuance; persisted and checked on every credential lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Cookie,
    Bearer,
}
impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cookie => "cookie",
            Self::Bearer => "bearer",
        }
    }
}

/// Programmatic credential, separate from browser cookies. Never serialized or cloned.
#[derive(Debug)]
pub struct BearerSecret(SessionSecret);
impl BearerSecret {
    pub fn parse(value: String) -> Result<Self, SessionError> {
        SessionSecret::parse(value).map(Self)
    }
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.0.digest()
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        value.push(DIGITS[(b >> 4) as usize] as char);
        value.push(DIGITS[(b & 15) as usize] as char);
    }
    value
}

/// Host-selected, positive and ordered session limits, measured in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    idle: i64,
    absolute: i64,
}
impl SessionPolicy {
    pub fn new(idle_seconds: i64, absolute_seconds: i64) -> Result<Self, SessionError> {
        if idle_seconds <= 0 || absolute_seconds < idle_seconds {
            return Err(SessionError);
        }
        Ok(Self {
            idle: idle_seconds,
            absolute: absolute_seconds,
        })
    }
    pub fn idle_seconds(self) -> i64 {
        self.idle
    }
    pub fn absolute_seconds(self) -> i64 {
        self.absolute
    }
}

/// Validated times from the authoritative clock. Not an authentication proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLifetime {
    policy: SessionPolicy,
    issued_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
}
impl SessionLifetime {
    pub fn new(now: i64, policy: SessionPolicy) -> Result<Self, SessionError> {
        let (idle, absolute) = (policy.idle, policy.absolute);
        Self::restore(
            now,
            now.checked_add(idle).ok_or(SessionError)?,
            now.checked_add(absolute).ok_or(SessionError)?,
            policy,
        )
    }
    pub fn restore(
        issued_at: i64,
        idle_expires_at: i64,
        absolute_expires_at: i64,
        policy: SessionPolicy,
    ) -> Result<Self, SessionError> {
        if issued_at <= 0
            || idle_expires_at <= issued_at
            || idle_expires_at > absolute_expires_at
            || absolute_expires_at
                .checked_sub(issued_at)
                .is_none_or(|duration| duration != policy.absolute)
        {
            return Err(SessionError);
        }
        Ok(Self {
            policy,
            issued_at,
            idle_expires_at,
            absolute_expires_at,
        })
    }
    pub fn valid_at(self, now: i64) -> bool {
        now >= self.issued_at && now < self.idle_expires_at && now < self.absolute_expires_at
    }
    /// Renew only idle expiry within the original absolute deadline.
    pub fn renew(&mut self, now: i64) -> Result<(), SessionError> {
        if !self.valid_at(now) {
            return Err(SessionError);
        }
        self.idle_expires_at = self.idle_expires_at.max(
            now.checked_add(self.policy.idle)
                .ok_or(SessionError)?
                .min(self.absolute_expires_at),
        );
        Ok(())
    }
    pub fn issued_at(self) -> i64 {
        self.issued_at
    }
    pub fn idle_expires_at(self) -> i64 {
        self.idle_expires_at
    }
    pub fn absolute_expires_at(self) -> i64 {
        self.absolute_expires_at
    }
}

/// Authentication origin is independent of credential presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationSource {
    LocalPassword,
    Oidc,
    Platform,
}
