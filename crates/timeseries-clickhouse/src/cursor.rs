use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use ring::{
    aead, hkdf,
    rand::{SecureRandom, SystemRandom},
};
use rss_contract::PageCursor;
use rss_timeseries::{Continuation, Digest, Error, Id, Sample};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
/// Deployment-injected secret for authenticated cursors and dependency proofs. The host shares it only between the same storage deployment.
/// No Debug/serialization surface; key storage and replacement belong to the product.
#[derive(Clone)]
pub struct CursorKey(zeroize::Zeroizing<[u8; 32]>);
impl CursorKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }
    fn encryption_key(&self) -> Result<aead::LessSafeKey, Error> {
        let salt = hkdf::Salt::new(
            hkdf::HKDF_SHA256,
            b"rss.timeseries.clickhouse.cursor-key.v1",
        );
        let prk = salt.extract(self.0.as_ref());
        let info = [b"aead".as_slice()];
        let key = prk
            .expand(&info, &aead::CHACHA20_POLY1305)
            .map_err(|_| Error::Invariant)?;
        Ok(aead::LessSafeKey::new(aead::UnboundKey::from(key)))
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
    /// Opaque equality proof for the request's control dependencies.
    pub(crate) fn page_state(
        &self,
        domain: &[u8],
        binding: Digest,
        instance: &str,
        dependencies: &impl Serialize,
    ) -> Result<[u8; 32], Error> {
        let mut mac = self.mac()?;
        mac.update(b"rss.timeseries.clickhouse.page-state.v1");
        mac.update(domain);
        mac.update(binding.as_bytes());
        mac.update(instance.as_bytes());
        mac.update(&crate::transaction::bytes(dependencies)?);
        Ok(mac.finalize().into_bytes().into())
    }
    pub(crate) fn seal<T: Serialize>(
        &self,
        domain: &[u8],
        binding: Digest,
        instance: &str,
        expires: i64,
        value: &T,
    ) -> Result<Continuation, Error> {
        let mut payload = serde_json::to_vec(&(3u8, binding, instance, expires, value))
            .map_err(|_| Error::Invariant)?;
        // ref: rustls crypto/ring/ticketer.rs@v/0.23.37: random nonce avoids a counter leak.
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Unavailable)?;
        self.encryption_key()?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(domain),
                &mut payload,
            )
            .map_err(|_| Error::Invariant)?;
        let mut encrypted = nonce.to_vec();
        encrypted.extend(payload);
        Ok(Continuation::new(
            binding,
            PageCursor::parse(&URL_SAFE_NO_PAD.encode(encrypted))
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
        if bytes.len() < 28 {
            return Err(Error::InvalidCursor);
        }
        let (nonce, payload) = bytes.split_at(12);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::InvalidCursor)?;
        let mut payload = payload.to_vec();
        let key = self.encryption_key()?;
        let payload = key
            .open_in_place(nonce, aead::Aad::from(domain), &mut payload)
            .map_err(|_| Error::InvalidCursor)?;
        let (version, b, inst, expires, value): (u8, Digest, String, i64, T) =
            serde_json::from_slice(payload).map_err(|_| Error::InvalidCursor)?;
        if version != 3 || b != binding || inst != instance || expires <= now {
            return Err(Error::InvalidCursor);
        }
        Ok((expires, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_cursors_hide_internal_state_and_authenticate_every_binding() -> Result<(), Error> {
        let key = CursorKey::new([19; 32]);
        let binding = Digest::from_bytes([7; 32]);
        let domain = b"test.cursor";
        let token = key.seal(
            domain,
            binding,
            "installation",
            100,
            &"private-published-ceiling",
        )?;
        let second = key.seal(
            domain,
            binding,
            "installation",
            100,
            &"private-published-ceiling",
        )?;
        let encoded = token.verify(binding)?.as_str();
        assert_ne!(encoded, second.verify(binding)?.as_str());
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Invariant)?;
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err());
        assert!(
            !bytes
                .windows(b"private-published-ceiling".len())
                .any(|w| w == b"private-published-ceiling")
        );
        assert_eq!(
            key.open::<String>(domain, &token, binding, "installation", 0)?
                .1,
            "private-published-ceiling"
        );
        for at in [0, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[at] ^= 1;
            let token = Continuation::new(
                binding,
                PageCursor::parse(&URL_SAFE_NO_PAD.encode(tampered))
                    .map_err(|_| Error::Invariant)?,
            );
            assert!(matches!(
                key.open::<String>(domain, &token, binding, "installation", 0),
                Err(Error::InvalidCursor)
            ));
        }
        for (domain, instance, now) in [
            (b"other".as_slice(), "installation", 0),
            (domain.as_slice(), "other", 0),
            (domain.as_slice(), "installation", 100),
        ] {
            assert!(matches!(
                key.open::<String>(domain, &token, binding, instance, now),
                Err(Error::InvalidCursor)
            ));
        }
        assert!(matches!(
            CursorKey::new([20; 32]).open::<String>(domain, &token, binding, "installation", 0),
            Err(Error::InvalidCursor)
        ));
        Ok(())
    }
}
