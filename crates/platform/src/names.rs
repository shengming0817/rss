use std::error::Error;
use std::fmt;

const NAME_MAX_BYTES: usize = 64;

macro_rules! name_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $name(Box<str>);
        impl $name {
            pub fn parse(value: &str) -> Result<Self, NameError> {
                validate(value)?;
                Ok(Self(value.into()))
            }
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
name_type!(ApplicationName);
name_type!(ModuleName);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NameError {
    Empty,
    TooLong,
    InvalidFormat,
}
impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "platform name is empty",
            Self::TooLong => "platform name is too long",
            Self::InvalidFormat => "platform name has invalid format",
        })
    }
}
impl Error for NameError {}

fn validate(value: &str) -> Result<(), NameError> {
    if value.is_empty() {
        return Err(NameError::Empty);
    }
    if value.len() > NAME_MAX_BYTES {
        return Err(NameError::TooLong);
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(NameError::InvalidFormat);
    }
    Ok(())
}
