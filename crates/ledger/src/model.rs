use crate::Error;
use rss_request_context::TenantId;

/// Maximum exact payload size in encoding V1.
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Box<str>);
        impl $name {
            /// Parse a nonempty UTF-8 identity of at most 255 bytes, without NUL.
            pub fn parse(value: &str) -> Result<Self, Error> {
                if value.is_empty() || value.len() > 255 || value.contains('\0') {
                    return Err(Error::InvalidInput);
                }
                Ok(Self(value.into()))
            }
            /// Original identity bytes; no normalization is performed.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}
identity!(ChainId, "Chain identity scoped to one tenant.");
identity!(RecordId, "Stable record identity scoped to one chain.");
identity!(
    KeyId,
    "Exact injected key identity; not a rotation implementation."
);

/// Globally scoped ledger identity; does not grant access authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LedgerId {
    tenant: TenantId,
    chain: ChainId,
}
impl LedgerId {
    /// Combine a tenant with its chain.
    pub const fn new(tenant: TenantId, chain: ChainId) -> Self {
        Self { tenant, chain }
    }
    /// Tenant supplied by the trusted caller.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Chain within the tenant.
    pub const fn chain(&self) -> &ChainId {
        &self.chain
    }
}
/// Zero-based sequence; providers may impose a narrower checked storage range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sequence(u64);
impl Sequence {
    /// Construct a protocol sequence.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    /// Numeric value.
    pub const fn get(self) -> u64 {
        self.0
    }
    /// Next sequence, rejecting exhaustion.
    pub fn next(self) -> Result<Self, Error> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(Error::SequenceExhausted)
    }
}
/// Closed canonical encoding identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingVersion {
    /// Domain-separated length-prefixed HMAC-SHA256 input.
    V1,
}
impl EncodingVersion {
    /// Reject unknown stored versions before using their contents.
    pub fn parse(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(Error::UnsupportedEncoding),
        }
    }
    /// Durable numeric identity.
    pub const fn get(self) -> u16 {
        1
    }
}
/// Fixed full-length authentication output. Not proof of verification by itself.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationTag([u8; 32]);
impl AuthenticationTag {
    /// Decode exact-size stored output; malformed lengths are rejected.
    pub fn from_bytes(value: &[u8]) -> Result<Self, Error> {
        Ok(Self(value.try_into().map_err(|_| Error::InvalidInput)?))
    }
    /// Authentication bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub(crate) const fn genesis() -> Self {
        Self([0; 32])
    }
    pub(crate) const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }
}
impl std::fmt::Debug for AuthenticationTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticationTag([redacted])")
    }
}
/// Exact idempotent append input. Sequence and authentication are assigned by the ledger.
#[derive(Clone, PartialEq, Eq)]
pub struct AppendRequest {
    ledger: LedgerId,
    record_id: RecordId,
    payload: Box<[u8]>,
}
impl AppendRequest {
    /// Validate bounded input without changing any payload bytes.
    pub fn new(ledger: LedgerId, record_id: RecordId, payload: Vec<u8>) -> Result<Self, Error> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            ledger,
            record_id,
            payload: payload.into_boxed_slice(),
        })
    }
    /// Ledger identity.
    pub const fn ledger(&self) -> &LedgerId {
        &self.ledger
    }
    /// Stable record identity.
    pub const fn record_id(&self) -> &RecordId {
        &self.record_id
    }
    /// Exact payload bytes; caller owns their confidentiality.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
impl std::fmt::Debug for AppendRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppendRequest([redacted])")
    }
}
/// Decoded entry. Construction is not authentication or durable-commit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    request: AppendRequest,
    sequence: Sequence,
    previous_tag: AuthenticationTag,
    tag: AuthenticationTag,
    encoding: EncodingVersion,
    key_id: KeyId,
}
impl Entry {
    /// Rehydrate bounded persisted fields; call `Authenticator::verify` before trusting them.
    pub const fn from_parts(
        request: AppendRequest,
        sequence: Sequence,
        previous_tag: AuthenticationTag,
        tag: AuthenticationTag,
        encoding: EncodingVersion,
        key_id: KeyId,
    ) -> Self {
        Self {
            request,
            sequence,
            previous_tag,
            tag,
            encoding,
            key_id,
        }
    }
    /// Ledger identity.
    pub const fn ledger(&self) -> &LedgerId {
        self.request.ledger()
    }
    /// Stable record identity.
    pub const fn record_id(&self) -> &RecordId {
        self.request.record_id()
    }
    /// Exact authenticated payload.
    pub fn payload(&self) -> &[u8] {
        self.request.payload()
    }
    /// Position within the chain.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }
    /// Authentication of the immediately preceding entry, or zero for genesis.
    pub const fn previous_tag(&self) -> AuthenticationTag {
        self.previous_tag
    }
    /// Full authentication output.
    pub const fn tag(&self) -> AuthenticationTag {
        self.tag
    }
    /// Canonical encoding.
    pub const fn encoding(&self) -> EncodingVersion {
        self.encoding
    }
    /// Exact key identity.
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    /// Exact identity and content comparison for stable-id retries.
    pub fn matches(&self, request: &AppendRequest) -> bool {
        self.request == *request
    }
}
