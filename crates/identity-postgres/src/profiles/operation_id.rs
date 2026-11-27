use crate::AuthorityError;
use serde::{Deserialize, Serialize};
use uuid::{Uuid, Variant, Version};

/// A Profile mutation identity. Generate once when submitting and retain for recovery.
/// ref: uuid-rs/uuid src/v7.rs; RFC 9562 §5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Uuid", into = "Uuid")]
pub struct ProfileOperationId(Uuid);

impl ProfileOperationId {
    pub fn now() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    pub(super) fn unix_millis(self) -> i64 {
        // RFC 9562 encodes the unsigned 48-bit millisecond timestamp first.
        (self.0.as_u128() >> 80) as i64
    }
}

impl TryFrom<Uuid> for ProfileOperationId {
    type Error = AuthorityError;

    fn try_from(id: Uuid) -> Result<Self, Self::Error> {
        if id.get_variant() == Variant::RFC4122 && id.get_version() == Some(Version::SortRand) {
            Ok(Self(id))
        } else {
            Err(AuthorityError::InvalidInput)
        }
    }
}

impl From<ProfileOperationId> for Uuid {
    fn from(id: ProfileOperationId) -> Self {
        id.0
    }
}
