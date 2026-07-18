//! Closed service-to-service caller identities.

/// A service-token caller domain admitted by the current production architecture.
///
/// The production set contains only the existing maintenance CLI operator. There is no production
/// Internal HTTP caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceCallerDomain {
    /// Existing operator shared by projection, audit, DLQ, reconcile, and settings maintenance.
    MaintenanceOperator,
}

impl ServiceCallerDomain {
    /// Canonical JWT `sub` value for this closed caller domain.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaintenanceOperator => "rss-maintenance-operator",
        }
    }

    /// Pure canonical mapping from a subject string into the closed caller set.
    ///
    /// This function performs no token verification; the authn funnel must verify the token before
    /// consuming this mapping.
    #[must_use]
    pub fn from_subject(subject: &str) -> Option<Self> {
        match subject {
            "rss-maintenance-operator" => Some(Self::MaintenanceOperator),
            _ => None,
        }
    }
}
