//! Identity account, session and protocol policy. Authentication is owned by the authority.
pub mod account;
pub mod assurance;
pub mod department;
pub mod directory;
pub mod entra;
pub mod facts;
pub mod federation;
pub mod groups;
pub mod session;
use uuid::Uuid;

/// Non-nil Identity InstanceId; bound to the persisted authentication instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceId(Uuid);
impl InstanceId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
    /// Parse a non-nil UUID from the authoritative source.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let id = Uuid::parse_str(value).map_err(|_| ValidationError::InvalidValue)?;
        if id.is_nil() {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(id))
    }
}

/// Non-nil Identity PrincipalId; never inferred from browser claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrincipalId(Uuid);
impl PrincipalId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
    /// Parse a non-nil UUID from the authoritative source.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let id = Uuid::parse_str(value).map_err(|_| ValidationError::InvalidValue)?;
        if id.is_nil() {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(id))
    }
}

/// Non-nil Identity SessionId; parsing a value never authenticates its holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct SessionId(Uuid);
impl SessionId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
    /// Parse a non-nil UUID from the authoritative source.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let id = Uuid::parse_str(value).map_err(|_| ValidationError::InvalidValue)?;
        if id.is_nil() {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(id))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl<'de> serde::Deserialize<'de> for SessionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Exact registered IssuerId; URL policy remains with the protocol adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerId(String);
impl IssuerId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reject empty, surrounding whitespace and control characters.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value.into()))
    }
}

/// Exact registered ClientId; URL policy remains with the protocol adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId(String);
impl ClientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reject empty, surrounding whitespace and control characters.
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(ValidationError::InvalidValue);
        }
        Ok(Self(value.into()))
    }
}

/// Closed rule failures; HTTP error projection belongs to I06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid identity value")]
    InvalidValue,
}

impl serde::Serialize for IssuerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl serde::Serialize for ClientId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl std::fmt::Display for InstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

pub mod profile;

pub mod enterprise;
pub mod step_up;
