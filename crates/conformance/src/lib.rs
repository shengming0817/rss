//! Provider-neutral conformance assertions for RSS engine primitives.
//!
//! The initial public surface covers LocalTx settlement and no-write behavior only. It does not
//! define adapters, provider drivers, fixtures, schedulers, artifact selectors, CI receipts, or
//! T3/product maturity.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod localtx;

/// Closed, low-cardinality provider error category shared by conformance helpers.
///
/// The category is safe to render in diagnostics. Provider messages, tenant identifiers, keys,
/// credentials, and payloads must remain in the opaque provider error value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConformanceErrorCategory {
    Storage,
    Transient,
    Conflict,
    Permanent,
    OwnershipLost,
    Validation,
    Authorization,
    CommitUnknown,
    RollbackFailed,
    Other,
}

impl ConformanceErrorCategory {
    /// Returns the stable, low-cardinality diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Transient => "transient",
            Self::Conflict => "conflict",
            Self::Permanent => "permanent",
            Self::OwnershipLost => "ownership-lost",
            Self::Validation => "validation",
            Self::Authorization => "authorization",
            Self::CommitUnknown => "commit-unknown",
            Self::RollbackFailed => "rollback-failed",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for ConformanceErrorCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::ConformanceErrorCategory;

    #[test]
    fn category_labels_are_closed_and_safe() {
        let cases = [
            (ConformanceErrorCategory::Storage, "storage"),
            (ConformanceErrorCategory::Transient, "transient"),
            (ConformanceErrorCategory::Conflict, "conflict"),
            (ConformanceErrorCategory::Permanent, "permanent"),
            (ConformanceErrorCategory::OwnershipLost, "ownership-lost"),
            (ConformanceErrorCategory::Validation, "validation"),
            (ConformanceErrorCategory::Authorization, "authorization"),
            (ConformanceErrorCategory::CommitUnknown, "commit-unknown"),
            (ConformanceErrorCategory::RollbackFailed, "rollback-failed"),
            (ConformanceErrorCategory::Other, "other"),
        ];
        for (category, expected) in cases {
            assert_eq!(category.as_str(), expected);
            assert_eq!(category.to_string(), expected);
        }
    }
}
