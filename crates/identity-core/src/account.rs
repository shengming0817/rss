//! Tenant-local account values and bounded password computation.
//! ref: RustCrypto/password-hashes argon2/src/{lib,params}.rs @ argon2-v0.5.3.
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand_core::OsRng;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct LoginKey(String);
impl LoginKey {
    pub fn parse(value: &str) -> Result<Self, PasswordError> {
        if value.is_empty()
            || value.len() > 255
            || !value.is_ascii()
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(PasswordError::Invalid);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for LoginKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginKey(<redacted>)")
    }
}

/// No Clone or serialization: callers must deliberately supply each secret.
pub struct Password(Zeroizing<String>);
impl Password {
    pub fn new(value: String) -> Result<Self, PasswordError> {
        let value = Zeroizing::new(value);
        if value.len() > PasswordPolicy::MAX_PASSWORD_BYTES
            || value.chars().count() < PasswordPolicy::MIN_CHARACTERS
        {
            return Err(PasswordError::Invalid);
        }
        Ok(Self(value))
    }
}
impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// Bounded, redacted PHC storage representation; not an authentication proof.
#[derive(Clone)]
pub struct PasswordEncoding(Zeroizing<String>);
impl PasswordEncoding {
    pub fn from_storage(value: String) -> Result<Self, PasswordError> {
        let value = Zeroizing::new(value);
        PasswordPolicy::validate_encoding(&value)?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for PasswordEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordEncoding(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    #[error("invalid account input")]
    Invalid,
    #[error("password computation capacity exhausted")]
    Busy,
    #[error("password computation unavailable")]
    Unavailable,
}

/// The single supported password security contract; resource capacity never lowers it.
pub struct PasswordPolicy;
impl PasswordPolicy {
    pub const MIN_CHARACTERS: usize = 15;
    pub const MAX_PASSWORD_BYTES: usize = 1024;
    pub const MEMORY_KIB: u32 = 19456;
    pub const MEMORY_BYTES: u64 = Self::MEMORY_KIB as u64 * 1024;
    pub const ITERATIONS: u32 = 2;
    pub const PARALLELISM: u32 = 1;
    pub const SALT_BYTES: usize = 16;
    pub const HASH_BYTES: usize = 32;
    fn argon2() -> Argon2<'static> {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                Self::MEMORY_KIB,
                Self::ITERATIONS,
                Self::PARALLELISM,
                Some(Self::HASH_BYTES),
            )
            .expect("fixed Argon2 policy"),
        )
    }
    fn validate_encoding(value: &str) -> Result<(), PasswordError> {
        use base64::Engine;
        if value.len() > 256 {
            return Err(PasswordError::Unavailable);
        }
        let hash = PasswordHash::new(value).map_err(|_| PasswordError::Unavailable)?;
        let salt = hash.salt.ok_or(PasswordError::Unavailable)?;
        let output = hash.hash.ok_or(PasswordError::Unavailable)?;
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(salt.as_str())
            .map_err(|_| PasswordError::Unavailable)?;
        if hash.algorithm.as_str() != "argon2id"
            || hash.version != Some(19)
            || hash.params.to_string()
                != format!(
                    "m={},t={},p={}",
                    Self::MEMORY_KIB,
                    Self::ITERATIONS,
                    Self::PARALLELISM
                )
            || decoded.len() != Self::SALT_BYTES
            || output.len() != Self::HASH_BYTES
            || base64::engine::general_purpose::STANDARD_NO_PAD.encode(&decoded) != salt.as_str()
            || value
                != format!(
                    "$argon2id$v=19$m={},t={},p={}${}${}",
                    Self::MEMORY_KIB,
                    Self::ITERATIONS,
                    Self::PARALLELISM,
                    salt,
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(output.as_bytes())
                )
        {
            return Err(PasswordError::Unavailable);
        }
        Ok(())
    }
}

const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Clone)]
pub struct PasswordKdf {
    gate: Arc<Semaphore>,
    admission: Arc<Mutex<bool>>,
    tasks: tokio_util::task::TaskTracker,
}
impl PasswordKdf {
    /// Reserve a finite number of equal-cost jobs in this process. All clones share the gate.
    /// Memory above the nominal Argon2 working sets is a host reservation for overhead,
    /// not an allocator limit or a process RSS guarantee.
    pub fn new(
        max_concurrency: std::num::NonZeroUsize,
        reserved_memory_bytes: std::num::NonZeroU64,
    ) -> Result<Self, PasswordError> {
        let count = max_concurrency.get();
        let nominal = u64::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(PasswordPolicy::MEMORY_BYTES));
        if count > Semaphore::MAX_PERMITS
            || nominal.is_none_or(|bytes| bytes >= reserved_memory_bytes.get())
        {
            return Err(PasswordError::Invalid);
        }
        Ok(Self {
            gate: Arc::new(Semaphore::new(count)),
            admission: Arc::new(Mutex::new(true)),
            tasks: tokio_util::task::TaskTracker::new(),
        })
    }
    /// Permanently close work admission. Existing blocking closures retain their tokens.
    pub fn close(&self) {
        let mut open = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        *open = false;
        self.tasks.close();
    }
    /// Wait for real closure completion after close; the application supplies the drain budget.
    pub async fn wait_closed(&self) {
        self.tasks.wait().await;
    }
    async fn compute<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, PasswordError> + Send + 'static,
    ) -> Result<T, PasswordError> {
        let (permit, tracked) = {
            let open = self
                .admission
                .lock()
                .map_err(|_| PasswordError::Unavailable)?;
            if !*open {
                return Err(PasswordError::Unavailable);
            }
            let permit = self
                .gate
                .clone()
                .try_acquire_owned()
                .map_err(|_| PasswordError::Busy)?;
            (permit, self.tasks.token())
        };
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _tracked = tracked;
            work()
        })
        .await
        .map_err(|_| PasswordError::Unavailable)?
    }
    pub async fn hash(&self, secret: Password) -> Result<PasswordEncoding, PasswordError> {
        self.compute(move || {
            let salt = SaltString::generate(&mut OsRng);
            PasswordPolicy::argon2()
                .hash_password(secret.0.as_bytes(), &salt)
                .map(|h| PasswordEncoding(Zeroizing::new(h.to_string())))
                .map_err(|_| PasswordError::Unavailable)
        })
        .await
    }
    pub async fn verify(
        &self,
        secret: Password,
        encoded: PasswordEncoding,
    ) -> Result<bool, PasswordError> {
        self.compute(move || {
            let hash =
                PasswordHash::new(encoded.as_str()).map_err(|_| PasswordError::Unavailable)?;
            Ok(PasswordPolicy::argon2()
                .verify_password(secret.0.as_bytes(), &hash)
                .is_ok())
        })
        .await
    }
    pub async fn dummy(&self, secret: Password) -> Result<(), PasswordError> {
        self.verify(secret, PasswordEncoding::from_storage(DUMMY.into())?)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closing_kdf_waits_for_actual_work_and_rejects_new_work() {
        let kdf = Arc::new(
            PasswordKdf::new(
                std::num::NonZeroUsize::new(4).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        );
        let (started, seen) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let worker = kdf.clone();
        let caller = tokio::spawn(async move {
            worker
                .compute(move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    Ok(())
                })
                .await
        });
        seen.await.unwrap();
        caller.abort();
        kdf.close();
        assert!(matches!(
            kdf.compute(|| Ok(())).await,
            Err(PasswordError::Unavailable)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), kdf.wait_closed())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), kdf.wait_closed())
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn cancelled_waiter_does_not_release_running_work() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (end_tx, end_rx) = std::sync::mpsc::channel();
        let kdf = Arc::new(
            PasswordKdf::new(
                std::num::NonZeroUsize::new(2).unwrap(),
                std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        );
        let worker = kdf.clone();
        let task = tokio::spawn(async move {
            worker
                .compute(move || {
                    started_tx.send(()).unwrap();
                    end_rx
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        task.abort();
        let remaining = kdf.gate.clone().try_acquire_many_owned(1).unwrap();
        assert!(matches!(
            kdf.compute(|| Ok(())).await,
            Err(PasswordError::Busy)
        ));
        end_tx.send(()).unwrap();
        drop(remaining);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while kdf.gate.available_permits() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            kdf.compute::<()>(|| panic!("test worker failure")).await,
            Err(PasswordError::Unavailable)
        ));
        assert_eq!(kdf.gate.available_permits(), 2);
    }
}

mod policy;
pub use policy::{
    AccountChange, AccountKey, AccountRuleError, AccountState, LocalChange, SecurityAction,
};
