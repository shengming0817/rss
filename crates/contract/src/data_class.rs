use std::fmt;

/// Closed vocabulary for classifying data at public Foundation boundaries.
///
/// This type says what data is. Redaction mechanisms and policy remain owned by
/// the security layer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DataClass {
    /// Data explicitly safe for public output.
    Public,
    /// Data restricted to trusted server-side handling.
    Internal,
    /// Personally identifiable information.
    Pii,
    /// Credentials, keys, tokens, and equivalent secret material.
    Secret,
}

impl DataClass {
    /// Return the stable lower-kebab label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Pii => "pii",
            Self::Secret => "secret",
        }
    }
}

impl fmt::Display for DataClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
