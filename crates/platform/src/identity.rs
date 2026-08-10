use std::error::Error;
use std::fmt;

const NAME_MAX_BYTES: usize = 64;
const REQUEST_ID_MAX_BYTES: usize = 128;

macro_rules! name_type {
    ($name:ident, $max:expr) => {
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name(Box<str>);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, IdentifierError> {
                parse_name(value, $max).map(Self)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

name_type!(ApplicationName, NAME_MAX_BYTES);
name_type!(ModuleName, NAME_MAX_BYTES);
name_type!(RequestId, REQUEST_ID_MAX_BYTES);

fn parse_name(value: &str, max: usize) -> Result<Box<str>, IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > max {
        return Err(IdentifierError::TooLong);
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(IdentifierError::InvalidFormat);
    }
    Ok(value.into())
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContractId(&'static str);

impl ContractId {
    pub const fn from_static(value: &'static str) -> Self {
        assert!(valid_contract_id(value), "invalid contract id");
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

const fn valid_contract_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return false;
    }
    let mut index = 0;
    let mut segment_start = true;
    while index < bytes.len() {
        let byte = bytes[index];
        if segment_start {
            if !byte.is_ascii_lowercase() {
                return false;
            }
            segment_start = false;
        } else if byte == b'.' {
            segment_start = true;
        } else if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return false;
        }
        index += 1;
    }
    !segment_start
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContractVersion {
    major: u16,
    minor: u16,
}

impl ContractVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
    pub const fn major(self) -> u16 {
        self.major
    }
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SchemaDigest(&'static str);

impl SchemaDigest {
    pub const fn from_static(value: &'static str) -> Self {
        assert!(valid_schema_digest(value), "invalid schema digest");
        Self(value)
    }
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

const fn valid_schema_digest(value: &str) -> bool {
    let bytes = value.as_bytes();
    let prefix = b"sha256:";
    if bytes.len() != prefix.len() + 64 {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')) {
            return false;
        }
        index += 1;
    }
    true
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TenantId(Box<str>);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, TenantIdError> {
        if value.is_empty() {
            return Err(TenantIdError::Empty);
        }
        if !valid_uuid(value.as_bytes()) {
            return Err(TenantIdError::InvalidFormat);
        }
        if value.bytes().all(|byte| byte == b'0' || byte == b'-') {
            return Err(TenantIdError::Nil);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_uuid(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (*byte >= b'a' && *byte <= b'f')
            }
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IdentifierError {
    Empty,
    TooLong,
    InvalidFormat,
}
impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid platform identifier")
    }
}
impl Error for IdentifierError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TenantIdError {
    Empty,
    Nil,
    InvalidFormat,
}
impl fmt::Display for TenantIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid tenant identifier")
    }
}
impl Error for TenantIdError {}
