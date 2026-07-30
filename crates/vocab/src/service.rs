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

#[cfg(test)]
mod tests {
    use super::ServiceCallerDomain;

    // INVARIANT: from_subject is fail-closed — only the closed allowlist maps to Some;
    // empty and unknown subjects must return None; the canonical operator subject must
    // map (anti-vacuity) so a broken match arm cannot silently pass.
    #[test]
    fn from_subject_fail_closed_tripwire() {
        let cases: &[(&str, Option<ServiceCallerDomain>)] = &[
            ("", None),
            ("unknown-caller", None),
            (
                "rss-maintenance-operator",
                Some(ServiceCallerDomain::MaintenanceOperator),
            ),
        ];

        for &(subject, expected) in cases {
            assert_eq!(
                ServiceCallerDomain::from_subject(subject),
                expected,
                "subject={subject:?}"
            );
        }
    }

    #[test]
    fn from_subject_denied_when_empty_or_unknown() {
        // INVARIANT: empty / unknown subjects are never admitted.
        for subject in ["", " ", "rss-internal", "RSS-MAINTENANCE-OPERATOR"] {
            assert_eq!(
                ServiceCallerDomain::from_subject(subject),
                None,
                "subject={subject:?} must be denied"
            );
        }
    }
}
