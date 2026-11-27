//! ref: RustCrypto/MACs hmac/src/lib.rs@hmac-v0.12.1
use crate::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// One exact key identity and injected secret. Key rotation is owned by the product.
pub struct Authenticator {
    key_id: KeyId,
    key: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authenticator([redacted])")
    }
}
impl Authenticator {
    /// Adopt at least 32 secret bytes. Rejected keys are zeroized as well.
    pub fn new(key_id: KeyId, key: Vec<u8>) -> Result<Self, Error> {
        let key = Zeroizing::new(key);
        if key.len() < 32 {
            return Err(Error::InvalidKey);
        }
        Ok(Self { key_id, key })
    }
    /// Configured identity; never implies a supported rotation policy.
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    /// Exact canonical authentication input, suitable for independent protocol implementations.
    pub fn canonical_bytes(entry: &Entry) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(entry.encoded_len() - entry.tag().as_bytes().len());
        bytes.extend_from_slice(b"rss.ledger.entry\0");
        bytes.extend_from_slice(&entry.encoding().get().to_be_bytes());
        bytes.extend_from_slice(&entry.ledger().tenant().octets());
        field(&mut bytes, entry.ledger().chain().as_str())?;
        bytes.extend_from_slice(&entry.sequence().get().to_be_bytes());
        field(&mut bytes, entry.record_id().as_str())?;
        field(&mut bytes, entry.key_id().as_str())?;
        bytes.extend_from_slice(entry.previous_tag().as_bytes());
        bytes.extend_from_slice(
            &u64::try_from(entry.payload().len())
                .map_err(|_| Error::InvalidInput)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(entry.payload());
        Ok(bytes)
    }
    fn mac(&self, entry: &Entry) -> Result<Hmac<Sha256>, Error> {
        if entry.key_id() != &self.key_id {
            return Err(Error::UnsupportedKey);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| Error::InvalidKey)?;
        mac.update(&Self::canonical_bytes(entry)?);
        Ok(mac)
    }
    /// Authenticate one entry; this alone says nothing about its position in a complete chain.
    pub fn verify(&self, entry: &Entry) -> Result<(), Error> {
        #[cfg(feature = "integration")]
        tracing::trace!(target: "batch_cost::verify", "verify");
        self.mac(entry)?
            .verify_slice(entry.tag().as_bytes())
            .map_err(|_| Error::Authentication)
    }
    /// Link after a verified predecessor, or start at genesis. No persistence is performed.
    pub fn append(
        &self,
        request: &AppendRequest,
        previous: Option<&Entry>,
    ) -> Result<Entry, Error> {
        self.appender(request.ledger(), previous)?.append(request)
    }
    /// Start a same-chain signer from genesis or an authenticated predecessor.
    pub fn appender<'a>(
        &'a self,
        ledger: &'a LedgerId,
        previous: Option<&Entry>,
    ) -> Result<ChainAppender<'a>, Error> {
        if let Some(entry) = previous {
            if entry.ledger() != ledger {
                return Err(Error::ScopeMismatch);
            }
            self.verify(entry)?;
        }
        Ok(ChainAppender {
            auth: self,
            ledger,
            tail: previous.map(|entry| (entry.sequence(), entry.tag())),
        })
    }
    /// Verify from genesis through all supplied entries, without proving absence of truncation.
    pub fn verify_chain(
        &self,
        ledger: &LedgerId,
        entries: &[Entry],
    ) -> Result<Verification, Error> {
        self.verify_range(ledger, None, entries)
    }
    /// Verify a contiguous window. A supplied predecessor is authenticated but its source must
    /// be assessed by the caller; a same-database anchor is not an external checkpoint.
    /// Empty input verifies zero entries, never proving that the ledger itself is empty.
    pub fn verify_window(
        &self,
        ledger: &LedgerId,
        predecessor: Option<&Entry>,
        entries: Vec<Entry>,
    ) -> Result<VerifiedWindow, Error> {
        let verification = self.verify_range(ledger, predecessor, &entries)?;
        Ok(VerifiedWindow {
            ledger: ledger.clone(),
            entries,
            verification,
        })
    }

    fn verify_range(
        &self,
        ledger: &LedgerId,
        predecessor: Option<&Entry>,
        entries: &[Entry],
    ) -> Result<Verification, Error> {
        if let Some(p) = predecessor {
            if p.ledger() != ledger {
                return Err(Error::ScopeMismatch);
            }
            self.verify(p)?;
        }
        let mut previous = predecessor;
        for entry in entries {
            if entry.ledger() != ledger {
                return Err(Error::ScopeMismatch);
            }
            let (seq, tag) = match previous {
                Some(p) => (p.sequence().next()?, p.tag()),
                None => (Sequence::new(0), AuthenticationTag::genesis()),
            };
            if entry.sequence() != seq || entry.previous_tag() != tag {
                return Err(Error::SequenceGap);
            }
            self.verify(entry)?;
            previous = Some(entry);
        }
        Ok(Verification {
            count: entries.len(),
            first: entries.first().map(Entry::sequence),
            last: entries.last().map(Entry::sequence),
            tag: entries.last().map(Entry::tag),
        })
    }
}
/// Signs consecutive entries after a checked anchor without reauthenticating its own output.
pub struct ChainAppender<'a> {
    auth: &'a Authenticator,
    ledger: &'a LedgerId,
    tail: Option<(Sequence, AuthenticationTag)>,
}
impl ChainAppender<'_> {
    /// Last sequence already authenticated or signed by this appender.
    pub fn sequence(&self) -> Option<Sequence> {
        self.tail.map(|(seq, _)| seq)
    }
    /// Produce one authenticated link. Only successful signing advances the local tail.
    pub fn append(&mut self, request: &AppendRequest) -> Result<Entry, Error> {
        if request.ledger() != self.ledger {
            return Err(Error::ScopeMismatch);
        }
        let (sequence, previous) = match self.tail {
            Some((seq, tag)) => (seq.next()?, tag),
            None => (Sequence::new(0), AuthenticationTag::genesis()),
        };
        let mut entry = Entry::from_parts(
            request.clone(),
            sequence,
            previous,
            AuthenticationTag::genesis(),
            EncodingVersion::V1,
            self.auth.key_id.clone(),
        );
        #[cfg(feature = "integration")]
        tracing::trace!(target: "batch_cost::sign", "sign");
        entry.tag = AuthenticationTag::new(self.auth.mac(&entry)?.finalize().into_bytes().into());
        self.tail = Some((sequence, entry.tag()));
        Ok(entry)
    }
}
fn field(bytes: &mut Vec<u8>, value: &str) -> Result<(), Error> {
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Error::InvalidInput)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
/// The immutable entries authenticated for exactly one ledger, including its identity for empty ranges.
pub struct VerifiedWindow {
    ledger: LedgerId,
    entries: Vec<Entry>,
    verification: Verification,
}

impl std::fmt::Debug for VerifiedWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedWindow")
            .field("verification", &self.verification)
            .finish_non_exhaustive()
    }
}

impl VerifiedWindow {
    /// Ledger supplied to the authenticator.
    pub const fn ledger(&self) -> &LedgerId {
        &self.ledger
    }
    /// Authenticated entries in ascending order, excluding the anchor.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Summary of authentication for this exact range.
    pub const fn verification(&self) -> &Verification {
        &self.verification
    }
}

/// Evidence limited to the supplied authenticated range; not a persistence or completeness proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    count: usize,
    first: Option<Sequence>,
    last: Option<Sequence>,
    tag: Option<AuthenticationTag>,
}
impl Verification {
    /// Number of verified window entries, excluding the predecessor.
    pub const fn count(&self) -> usize {
        self.count
    }
    /// First checked sequence.
    pub const fn first(&self) -> Option<Sequence> {
        self.first
    }
    /// Last checked sequence.
    pub const fn last(&self) -> Option<Sequence> {
        self.last
    }
    /// Last checked authentication value.
    pub const fn tail_tag(&self) -> Option<AuthenticationTag> {
        self.tag
    }
}
