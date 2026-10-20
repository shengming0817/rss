use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rss_contract::PageCursor;
use rss_timeseries::{Continuation, Digest, Error, Id, Sample};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
/// Deployment-injected HMAC key. The host shares it only between the same storage deployment.
/// No Debug/serialization surface; key storage and replacement belong to the product.
#[derive(Clone)]
pub struct CursorKey(zeroize::Zeroizing<[u8; 32]>);
impl CursorKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }
    fn mac(&self) -> Result<Hmac<Sha256>, Error> {
        Hmac::<Sha256>::new_from_slice(self.0.as_ref()).map_err(|_| Error::Invariant)
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Position {
    pub series: [u8; 32],
    pub source: Id,
    pub generation: Id,
    pub time: i64,
    pub sequence: u64,
    pub id: Id,
}
impl Position {
    pub fn of(sample: &Sample) -> Result<Self, Error> {
        let i = sample.input();
        Ok(Self {
            series: *i.series.digest()?.as_bytes(),
            source: i.stream.source().clone(),
            generation: i.stream.generation().clone(),
            time: i.observed_at.micros(),
            sequence: i.sequence,
            id: i.id.clone(),
        })
    }
}
/// Separate domains prevent raw, aggregate and maintenance token substitution.
impl CursorKey {
    pub(crate) fn seal<T: Serialize>(
        &self,
        domain: &[u8],
        binding: Digest,
        instance: &str,
        expires: i64,
        value: &T,
    ) -> Result<Continuation, Error> {
        let mut payload = serde_json::to_vec(&(2u8, binding, instance, expires, value))
            .map_err(|_| Error::Invariant)?;
        let mut mac = self.mac()?;
        mac.update(domain);
        mac.update(&payload);
        payload.extend_from_slice(&mac.finalize().into_bytes());
        Ok(Continuation::new(
            binding,
            PageCursor::parse(&URL_SAFE_NO_PAD.encode(payload))
                .map_err(|_| Error::BudgetExceeded)?,
        ))
    }
    pub(crate) fn open<T: serde::de::DeserializeOwned>(
        &self,
        domain: &[u8],
        cursor: &Continuation,
        binding: Digest,
        instance: &str,
        now: i64,
    ) -> Result<(i64, T), Error> {
        let bytes = URL_SAFE_NO_PAD
            .decode(cursor.verify(binding)?.as_str())
            .map_err(|_| Error::InvalidCursor)?;
        if bytes.len() < 32 {
            return Err(Error::InvalidCursor);
        }
        let (payload, tag) = bytes.split_at(bytes.len() - 32);
        let mut mac = self.mac()?;
        mac.update(domain);
        mac.update(payload);
        mac.verify_slice(tag).map_err(|_| Error::InvalidCursor)?;
        let (version, b, inst, expires, value): (u8, Digest, String, i64, T) =
            serde_json::from_slice(payload).map_err(|_| Error::InvalidCursor)?;
        if version != 2 || b != binding || inst != instance || expires <= now {
            return Err(Error::InvalidCursor);
        }
        Ok((expires, value))
    }
}
