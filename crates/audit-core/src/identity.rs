use crate::{Error, Field, MAX_RECORD_BYTES};
use rss_contract::{ContractId, ContractVersion, SchemaDigest};
use rss_redact::RedactedBytes;

const TOKEN_MAX_BYTES: usize = 255;
const REFERENCE_MAX_BYTES: usize = 512;

fn validate_token(
    value: &str,
    field: Field,
    max: usize,
    lowercase_only: bool,
) -> Result<Box<str>, Error> {
    if value.is_empty() {
        return Err(Error::Empty(field));
    }
    if value.len() > max {
        return Err(Error::TooLong(field));
    }
    let valid = value.bytes().enumerate().all(|(index, byte)| {
        let alpha = if lowercase_only {
            byte.is_ascii_lowercase()
        } else {
            byte.is_ascii_alphabetic()
        };
        let base = alpha || byte.is_ascii_digit();
        if index == 0 {
            base
        } else {
            base || matches!(byte, b'.' | b'_' | b'-')
        }
    });
    if !valid {
        return Err(Error::InvalidCharacter(field));
    }
    Ok(value.into())
}

fn validate_reference(value: &str, field: Field) -> Result<Box<str>, Error> {
    if value.is_empty() {
        return Err(Error::Empty(field));
    }
    if value.len() > REFERENCE_MAX_BYTES {
        return Err(Error::TooLong(field));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidCharacter(field));
    }
    Ok(value.into())
}

macro_rules! token_type {
    ($name:ident, $field:expr, $max:expr, $lower:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(Box<str>);

        impl $name {
            /// Maximum accepted token length in bytes.
            pub const MAX_BYTES: usize = $max;

            /// Parse a canonical bounded token without normalization.
            pub fn parse(value: &str) -> Result<Self, Error> {
                validate_token(value, $field, Self::MAX_BYTES, $lower).map(Self)
            }

            /// Borrow the exact validated token.
            #[must_use]
            pub const fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

macro_rules! reference_type {
    ($name:ident, $field:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(Box<str>);

        impl $name {
            /// Maximum accepted reference length in bytes.
            pub const MAX_BYTES: usize = REFERENCE_MAX_BYTES;

            /// Parse a nonempty UTF-8 reference of at most 512 bytes without control characters.
            pub fn parse(value: &str) -> Result<Self, Error> {
                validate_reference(value, $field).map(Self)
            }

            /// Borrow the exact reference. Callers must preserve its confidentiality.
            #[must_use]
            pub const fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

token_type!(
    SourceId,
    Field::SourceId,
    TOKEN_MAX_BYTES,
    true,
    "Stable producer identity. It is not proof that the producer is authentic."
);
token_type!(
    EventId,
    Field::EventId,
    TOKEN_MAX_BYTES,
    false,
    "Stable event identity within one source. Retries must preserve it."
);
token_type!(
    ActorKind,
    Field::ActorKind,
    TOKEN_MAX_BYTES,
    true,
    "Source-owned actor reference kind."
);
token_type!(
    Action,
    Field::Action,
    TOKEN_MAX_BYTES,
    false,
    "Source-owned action identity; Audit does not define a global action vocabulary."
);
token_type!(
    ResourceKind,
    Field::ResourceKind,
    TOKEN_MAX_BYTES,
    true,
    "Source-owned resource reference kind."
);
token_type!(
    OperationId,
    Field::OperationId,
    TOKEN_MAX_BYTES,
    false,
    "Optional stable operation coordinate."
);
reference_type!(
    ActorId,
    Field::ActorId,
    "Stable, non-secret actor reference."
);
reference_type!(
    ResourceId,
    Field::ResourceId,
    "Stable, non-secret resource reference."
);

/// Exact source contract identity carried with a record.
#[derive(Clone)]
pub struct SourceContract {
    id: ContractId,
    version: ContractVersion,
    schema_digest: SchemaDigest,
}

impl SourceContract {
    /// Combine already validated contract facts. Acceptance remains adapter-owned.
    #[must_use]
    pub const fn new(
        id: ContractId,
        version: ContractVersion,
        schema_digest: SchemaDigest,
    ) -> Self {
        Self {
            id,
            version,
            schema_digest,
        }
    }

    /// Contract identifier.
    #[must_use]
    pub const fn id(&self) -> &ContractId {
        &self.id
    }

    /// Contract major version.
    #[must_use]
    pub const fn version(&self) -> ContractVersion {
        self.version
    }

    /// Exact schema digest.
    #[must_use]
    pub const fn schema_digest(&self) -> &SchemaDigest {
        &self.schema_digest
    }
}

impl std::fmt::Debug for SourceContract {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SourceContract([redacted])")
    }
}

/// Producer and source contract identity.
#[derive(Clone)]
pub struct SourceIdentity {
    source_id: SourceId,
    contract: SourceContract,
}

impl SourceIdentity {
    /// Bind a stable source to its exact authored contract.
    #[must_use]
    pub const fn new(source_id: SourceId, contract: SourceContract) -> Self {
        Self {
            source_id,
            contract,
        }
    }

    /// Stable source identity.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Exact source contract.
    #[must_use]
    pub const fn contract(&self) -> &SourceContract {
        &self.contract
    }
}

impl std::fmt::Debug for SourceIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SourceIdentity([redacted])")
    }
}

/// Actor reference supplied by the source contract.
pub struct ActorRef {
    kind: ActorKind,
    id: ActorId,
}

impl ActorRef {
    /// Combine the actor kind and identifier.
    #[must_use]
    pub const fn new(kind: ActorKind, id: ActorId) -> Self {
        Self { kind, id }
    }

    /// Actor kind.
    #[must_use]
    pub const fn kind(&self) -> &ActorKind {
        &self.kind
    }

    /// Actor identifier.
    #[must_use]
    pub const fn id(&self) -> &ActorId {
        &self.id
    }
}

impl std::fmt::Debug for ActorRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ActorRef([redacted])")
    }
}

/// Resource reference supplied by the source contract.
pub struct ResourceRef {
    kind: ResourceKind,
    id: ResourceId,
}

impl ResourceRef {
    /// Combine the resource kind and identifier.
    #[must_use]
    pub const fn new(kind: ResourceKind, id: ResourceId) -> Self {
        Self { kind, id }
    }

    /// Resource kind.
    #[must_use]
    pub const fn kind(&self) -> &ResourceKind {
        &self.kind
    }

    /// Resource identifier.
    #[must_use]
    pub const fn id(&self) -> &ResourceId {
        &self.id
    }
}

impl std::fmt::Debug for ResourceRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResourceRef([redacted])")
    }
}

/// Bounded exact payload whose formatting never exposes its bytes.
///
/// This type does not prove that a source removed sensitive values; it only makes accidental
/// `Debug`/`Display` disclosure unavailable at this boundary.
pub struct AuditPayload(RedactedBytes);

impl AuditPayload {
    /// Adopt exact payload bytes within the complete-record bound.
    /// Preparation also charges all headers and identities, so a payload of this size
    /// alone cannot fit in a canonical record.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(Error::RecordTooLarge);
        }
        Ok(Self(RedactedBytes::new(bytes)))
    }

    /// Borrow exact payload bytes for canonical encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for AuditPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditPayload([redacted])")
    }
}
