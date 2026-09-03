//! Saga step identity shared by contract authoring and runtime execution.

/// Canonical saga step name. Values are valid ASCII Rust identifiers and are never keywords.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepName(String);

/// `StepName` parse failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StepNameError {
    #[error("saga step name is empty")]
    Empty,
    #[error("saga step name is not a valid ASCII Rust identifier")]
    NotIdent,
}

impl StepName {
    /// Parse one authoring/runtime step name through the canonical fail-closed grammar.
    pub fn parse(raw: &str) -> Result<Self, StepNameError> {
        if raw.is_empty() {
            return Err(StepNameError::Empty);
        }
        if !is_rust_ident(raw) {
            return Err(StepNameError::NotIdent);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the canonical string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StepName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for StepName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl serde::Serialize for StepName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for StepName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

fn is_rust_ident(value: &str) -> bool {
    if value == "_" || is_rust_keyword(value) {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

const RUST_STRICT_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "gen", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "async", "await",
];

const RUST_RESERVED_KEYWORDS: &[&str] = &[
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try",
];

fn is_rust_keyword(value: &str) -> bool {
    RUST_STRICT_KEYWORDS.contains(&value) || RUST_RESERVED_KEYWORDS.contains(&value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{RUST_RESERVED_KEYWORDS, RUST_STRICT_KEYWORDS, StepName, StepNameError};

    #[test]
    fn accepts_canonical_ascii_identifiers() {
        for raw in [
            "reserve_funds",
            "capture",
            "Step2",
            "_private",
            "function",
            "r",
        ] {
            let parsed = StepName::parse(raw).expect("canonical step name");
            assert_eq!(parsed.as_str(), raw);
        }
    }

    #[test]
    fn distinguishes_empty_from_non_identifier_failures() {
        assert!(matches!(StepName::parse(""), Err(StepNameError::Empty)));

        for raw in ["_", "r#fn", "bad-name", "9bad", "föö"] {
            assert!(
                matches!(StepName::parse(raw), Err(StepNameError::NotIdent)),
                "raw={raw:?}"
            );
        }
    }

    #[test]
    fn rejects_every_rust_keyword_and_bare_underscore() {
        for raw in RUST_STRICT_KEYWORDS
            .iter()
            .chain(RUST_RESERVED_KEYWORDS)
            .copied()
            .chain(std::iter::once("_"))
        {
            assert!(
                matches!(StepName::parse(raw), Err(StepNameError::NotIdent)),
                "keyword or reserved identifier escaped: {raw:?}"
            );
        }
    }

    #[test]
    fn serde_is_the_same_fail_closed_authoring_funnel() {
        let parsed: StepName =
            serde_json::from_str("\"reserve_funds\"").expect("canonical authoring step name");
        assert_eq!(parsed.as_str(), "reserve_funds");
        for raw in [
            "\"\"",
            "\"_\"",
            "\"9bad\"",
            "\"bad-name\"",
            "\"fn\"",
            "\"föö\"",
        ] {
            assert!(serde_json::from_str::<StepName>(raw).is_err(), "raw={raw}");
        }
    }
}
