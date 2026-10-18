use crate::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Host-owned UTC clock used only for the attempt signature, not execution budgets.
pub trait WallClock: Send + Sync {
    /// Current Unix seconds. Negative observations fail closed.
    fn unix_seconds(&self) -> i64;
}
/// Endpoint-specific HMAC secret; zeroized on drop and never printed.
pub struct SigningKey(Zeroizing<Vec<u8>>);
impl SigningKey {
    /// Consume 24–64 random bytes supplied by the host's key store.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        let bytes = Zeroizing::new(bytes);
        if !(24..=64).contains(&bytes.len()) {
            return Err(Error::Signing);
        }
        Ok(Self(bytes))
    }
    /// Decode the Standard Webhooks customer-facing secret format.
    pub fn from_encoded(encoded: &str) -> Result<Self, Error> {
        if encoded.len() > 94 {
            return Err(Error::Signing);
        }
        let encoded = encoded.strip_prefix("whsec_").ok_or(Error::Signing)?;
        Self::new(STANDARD.decode(encoded).map_err(|_| Error::Signing)?)
    }
    fn sign(&self, id: &str, timestamp: &str, body: &[u8]) -> Result<String, Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| Error::Signing)?;
        for part in [id.as_bytes(), b".", timestamp.as_bytes(), b".", body] {
            mac.update(part);
        }
        Ok(format!(
            "v1,{}",
            STANDARD.encode(mac.finalize().into_bytes())
        ))
    }
}
impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}
/// One current key and optionally one retiring key, selected atomically by the host.
#[derive(Debug)]
pub struct SigningKeys {
    current: SigningKey,
    retiring: Option<SigningKey>,
}
impl SigningKeys {
    /// Supply a bounded rotation snapshot. Keys remain scoped to the authorized endpoint.
    pub const fn new(current: SigningKey, retiring: Option<SigningKey>) -> Self {
        Self { current, retiring }
    }
    pub(crate) fn sign(
        &self,
        id: &str,
        seconds: i64,
        body: &[u8],
    ) -> Result<(String, String), Error> {
        if seconds < 0 {
            return Err(Error::Signing);
        }
        let timestamp = seconds.to_string();
        let mut signature = self.current.sign(id, &timestamp, body)?;
        if let Some(key) = &self.retiring {
            signature.push(' ');
            signature.push_str(&key.sign(id, &timestamp, body)?);
        }
        Ok((timestamp, signature))
    }
}
