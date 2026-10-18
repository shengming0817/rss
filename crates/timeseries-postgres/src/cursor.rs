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
    pub(crate) fn encode(
        &self,
        binding: Digest,
        instance: &str,
        expires: i64,
        last: Position,
    ) -> Result<Continuation, Error> {
        let token = Token {
            version: 1,
            binding: *binding.as_bytes(),
            instance: instance.to_owned(),
            expires,
            last,
        };
        let mut bytes = serde_json::to_vec(&token).map_err(|_| Error::Invariant)?;
        let mut mac = self.mac()?;
        mac.update(b"rss.timeseries.pg.cursor.v1\0");
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        let cursor =
            PageCursor::parse(&URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| Error::BudgetExceeded)?;
        Ok(Continuation::new(binding, cursor))
    }
    pub(crate) fn decode(
        &self,
        cursor: &Continuation,
        binding: Digest,
        instance: &str,
        now: i64,
    ) -> Result<Token, Error> {
        let encoded = cursor.verify(binding)?.as_str();
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::InvalidCursor)?;
        if bytes.len() < 32 {
            return Err(Error::InvalidCursor);
        }
        let (payload, tag) = bytes.split_at(bytes.len() - 32);
        let mut mac = self.mac()?;
        mac.update(b"rss.timeseries.pg.cursor.v1\0");
        mac.update(payload);
        mac.verify_slice(tag).map_err(|_| Error::InvalidCursor)?;
        let token: Token = serde_json::from_slice(payload).map_err(|_| Error::InvalidCursor)?;
        if token.version != 1
            || token.binding != *binding.as_bytes()
            || token.instance != instance
            || token.expires <= now
        {
            return Err(Error::InvalidCursor);
        }
        Ok(token)
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
    pub fn group(&self) -> ([u8; 32], &Id, &Id) {
        (self.series, &self.source, &self.generation)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Token {
    version: u8,
    binding: [u8; 32],
    instance: String,
    pub expires: i64,
    pub last: Position,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_cursor_binds_query_instance_and_expiry() -> anyhow::Result<()> {
        let key = CursorKey::new([4; 32]);
        let binding = Digest::from_bytes([5; 32]);
        let p = Position {
            series: [1; 32],
            source: Id::new("s")?,
            generation: Id::new("g")?,
            time: 1,
            sequence: u64::MAX,
            id: Id::new("i")?,
        };
        let cursor = key.encode(binding, "db", 100, p)?;
        assert_eq!(
            key.decode(&cursor, binding, "db", 99)?.last.sequence,
            u64::MAX
        );
        assert!(key.decode(&cursor, binding, "db", 100).is_err());
        assert!(key.decode(&cursor, binding, "other", 0).is_err());
        assert!(
            key.decode(&cursor, Digest::from_bytes([6; 32]), "db", 0)
                .is_err()
        );
        assert!(
            CursorKey::new([0; 32])
                .decode(&cursor, binding, "db", 0)
                .is_err()
        );
        let mut bytes = URL_SAFE_NO_PAD.decode(cursor.verify(binding)?.as_str())?;
        bytes[0] ^= 1;
        let altered =
            Continuation::new(binding, PageCursor::parse(&URL_SAFE_NO_PAD.encode(bytes))?);
        assert!(key.decode(&altered, binding, "db", 0).is_err());
        Ok(())
    }
}
