//! Framework-owned HTTP route registration and serving validation.

use crate::{KernelError, Registry};
use httpserve::UnfinalizedRoutes;
use primitives::ListenerKind;
use vocab::HttpRouteEvidence;

/// Assembly-owned registration root for framework-neutral routes.
pub trait FrameworkRoutes {
    fn register(&self, registry: &mut Registry) -> Result<(), KernelError>;
}

/// One typed framework HTTP route expected by an assembly manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameworkHttpRoute {
    listener: ListenerKind,
    evidence: HttpRouteEvidence,
}

impl FrameworkHttpRoute {
    /// Bind generated framework-owned route evidence into an assembly expected set.
    ///
    /// # Panics
    ///
    /// Panics in const evaluation for domain-owned evidence.
    #[must_use]
    pub const fn new(listener: ListenerKind, evidence: HttpRouteEvidence) -> Self {
        assert!(
            evidence.owner().is_framework(),
            "framework serving declarations require framework-owned HTTP evidence"
        );
        Self { listener, evidence }
    }

    #[must_use]
    pub const fn evidence(self) -> HttpRouteEvidence {
        self.evidence
    }

    #[must_use]
    pub const fn listener(self) -> ListenerKind {
        self.listener
    }
}

/// Closed exact-set validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameworkServingError {
    #[error("framework contract is missing from mounted routes: {contract_id}")]
    Missing { contract_id: &'static str },
    #[error("framework contract is mounted more than once: {contract_id}")]
    Duplicate { contract_id: &'static str },
    #[error("mounted framework route differs from generated evidence: {contract_id}")]
    Mismatch { contract_id: &'static str },
    #[error("mounted framework contract is not declared by the assembly: {contract_id}")]
    Extra { contract_id: &'static str },
}

/// Compare assembly declarations with actual mounted framework routes before auth finalization.
pub fn validate_framework_serving(
    routes: &[(ListenerKind, UnfinalizedRoutes)],
    expected: &[FrameworkHttpRoute],
) -> Result<(), FrameworkServingError> {
    let actual = routes
        .iter()
        .flat_map(|(listener, routes)| {
            routes
                .route_evidence()
                .iter()
                .copied()
                .map(|evidence| (*listener, evidence))
        })
        .filter(|(_, evidence)| evidence.owner().is_framework())
        .collect::<Vec<_>>();
    validate_framework_evidence(&actual, expected)
}

fn validate_framework_evidence(
    actual: &[(ListenerKind, HttpRouteEvidence)],
    expected: &[FrameworkHttpRoute],
) -> Result<(), FrameworkServingError> {
    for expected_route in expected {
        let expected_evidence = expected_route.evidence();
        let matches = actual
            .iter()
            .filter(|(_, actual)| actual.contract_id() == expected_evidence.contract_id())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => {
                return Err(FrameworkServingError::Missing {
                    contract_id: expected_evidence.contract_id(),
                });
            }
            [actual] if actual.0 == expected_route.listener() && actual.1 == expected_evidence => {}
            [_] => {
                return Err(FrameworkServingError::Mismatch {
                    contract_id: expected_evidence.contract_id(),
                });
            }
            _ => {
                return Err(FrameworkServingError::Duplicate {
                    contract_id: expected_evidence.contract_id(),
                });
            }
        }
    }
    if let Some(extra) = actual.iter().find(|(_, actual)| {
        !expected
            .iter()
            .any(|expected| expected.evidence().contract_id() == actual.contract_id())
    }) {
        return Err(FrameworkServingError::Extra {
            contract_id: extra.1.contract_id(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vocab::{
        ContractBinding, HttpConsistencyLevel, HttpContractOwner, HttpEffectKind,
        HttpEffectProfile, HttpIdempotency, HttpRouteAuth, HttpSuccessStatus,
    };

    const EFFECTS: &[HttpEffectKind] = &[HttpEffectKind::Read];

    const fn route(contract_id: &'static str, path: &'static str) -> HttpRouteEvidence {
        HttpRouteEvidence::from_static(
            HttpContractOwner::framework(),
            ContractBinding::from_static(
                "framework",
                contract_id,
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            path,
            "GET",
            &[],
            HttpSuccessStatus::new(200),
            HttpIdempotency::Idempotent,
            HttpRouteAuth::ServiceOwned,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            HttpConsistencyLevel::LocalOnly,
            HttpEffectProfile::new(EFFECTS),
        )
    }

    #[test]
    fn exact_framework_serving_set_is_required() {
        const EXPECTED_EVIDENCE: HttpRouteEvidence = route("framework.status", "/status");
        const EXPECTED: &[FrameworkHttpRoute] = &[FrameworkHttpRoute::new(
            ListenerKind::Admin,
            EXPECTED_EVIDENCE,
        )];

        assert_eq!(
            validate_framework_evidence(&[(ListenerKind::Admin, EXPECTED_EVIDENCE)], EXPECTED),
            Ok(())
        );
        assert_eq!(
            validate_framework_evidence(&[], EXPECTED),
            Err(FrameworkServingError::Missing {
                contract_id: "framework.status"
            })
        );
        assert_eq!(
            validate_framework_evidence(
                &[
                    (ListenerKind::Admin, EXPECTED_EVIDENCE),
                    (ListenerKind::Admin, EXPECTED_EVIDENCE),
                ],
                EXPECTED,
            ),
            Err(FrameworkServingError::Duplicate {
                contract_id: "framework.status"
            })
        );
        assert_eq!(
            validate_framework_evidence(
                &[(ListenerKind::Admin, route("framework.status", "/other"))],
                EXPECTED,
            ),
            Err(FrameworkServingError::Mismatch {
                contract_id: "framework.status"
            })
        );
        assert_eq!(
            validate_framework_evidence(&[(ListenerKind::Admin, EXPECTED_EVIDENCE)], &[]),
            Err(FrameworkServingError::Extra {
                contract_id: "framework.status"
            })
        );
        assert_eq!(
            validate_framework_evidence(&[(ListenerKind::Primary, EXPECTED_EVIDENCE)], EXPECTED),
            Err(FrameworkServingError::Mismatch {
                contract_id: "framework.status"
            })
        );
    }
}
