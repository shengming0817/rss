use crate::{Error, ErrorKind};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
macro_rules! identity {
    ($name:ident,$doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            /// Validate 1–256 UTF-8 bytes without control characters; otherwise return InvalidInput.
            /// The value is preserved exactly, with no normalization or implicit authority.
            pub fn new(value: impl Into<String>) -> Result<Self, Error> {
                let value = value.into();
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                    return Err(ErrorKind::InvalidInput.into());
                }
                Ok(Self(value))
            }
            /// The original validated identifier. Explicit access is not redacted.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
        impl TryFrom<String> for $name {
            type Error = Error;
            fn try_from(v: String) -> Result<Self, Error> {
                Self::new(v)
            }
        }
        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}
identity!(
    Id,
    "Bounded opaque identifier for batches, facts, sources, datasets and product references."
);
identity!(
    Registration,
    "Product registration instance, distinct from producer epochs and command authority."
);
identity!(
    Epoch,
    "Producer stream incarnation; requires trusted activation and cannot revive a retired incarnation."
);
/// Full observation ordering and deduplication domain. No command authority is represented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    #[serde(with = "tenant")]
    tenant: TenantId,
    object: Id,
    registration: Registration,
    source: Id,
    dataset: Id,
    epoch: Epoch,
}
impl Scope {
    /// Bind an ordering/deduplication scope without granting authority.
    /// Registration identifies a product registration instance; epoch identifies a producer stream
    /// incarnation. Neither is a command fencing token.
    pub const fn new(
        tenant: TenantId,
        object: Id,
        registration: Registration,
        source: Id,
        dataset: Id,
        epoch: Epoch,
    ) -> Self {
        Self {
            tenant,
            object,
            registration,
            source,
            dataset,
            epoch,
        }
    }
    /// Tenant namespace used by authorization and provider isolation.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Product-owned observation subject identifier within this tenant.
    pub const fn object(&self) -> &Id {
        &self.object
    }
    /// Registration instance, independent of the stable subject identifier.
    pub const fn registration(&self) -> &Registration {
        &self.registration
    }
    /// Independent producer/source namespace; cross-source priority belongs to the product.
    pub const fn source(&self) -> &Id {
        &self.source
    }
    /// Product-owned dataset namespace within this source.
    pub const fn dataset(&self) -> &Id {
        &self.dataset
    }
    /// Producer stream incarnation whose activation must be authorized separately.
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Encode the canonical V1 scope representation used in fingerprints and storage keys.
    /// Encoding identity does not establish authorization or lifecycle activation.
    pub fn encode(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
}
mod tenant {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &TenantId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<TenantId, D::Error> {
        let raw = String::deserialize(d)?;
        TenantId::parse(&raw).map_err(serde::de::Error::custom)
    }
}
