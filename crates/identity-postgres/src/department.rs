//! Borrowed department facts; source comes only from the checked session origin.
use crate::{auth_facts::DepartmentObservation, session_storage::TimeSample, transaction::reject};
use rss_identity_core::{
    InstanceId,
    account::AccountKey,
    department::{DepartmentSnapshot, DepartmentUnavailableReason},
    facts::FactSource,
};
use rss_transactional_messaging_postgres::PgError;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DepartmentAccessError {
    #[error("authentication proof expired")]
    ProofExpired,
    #[error("department snapshot expired")]
    SnapshotExpired,
}

pub(crate) enum DepartmentFacts {
    Unavailable(DepartmentUnavailableReason),
    Expired,
    Available {
        source: FactSource,
        provider_config_version: i64,
        snapshot_id: Uuid,
        observed_at: i64,
        expires_at: i64,
        snapshot: DepartmentSnapshot,
        expires: Instant,
    },
}
impl DepartmentFacts {
    pub(crate) fn new(
        snapshot: DepartmentObservation,
        source: FactSource,
        version: i64,
        sample: &TimeSample,
    ) -> Result<Self, PgError> {
        Ok(match snapshot {
            DepartmentObservation::Unavailable { reason } => Self::Unavailable(reason),
            DepartmentObservation::Available {
                snapshot_id,
                observed_at,
                expires_at,
                snapshot,
            } => {
                if observed_at <= 0 || sample.seconds() <= 0 {
                    return Err(reject());
                }
                if sample.seconds() < observed_at {
                    return Ok(Self::Unavailable(DepartmentUnavailableReason::NotYetValid));
                }
                if sample.seconds() >= expires_at {
                    return Ok(Self::Expired);
                }
                Self::Available {
                    source,
                    provider_config_version: version,
                    snapshot_id,
                    observed_at,
                    expires_at,
                    snapshot,
                    expires: sample.deadline(expires_at)?,
                }
            }
        })
    }
    pub(crate) fn view(
        &self,
        instance: InstanceId,
        account: AccountKey,
        proof: Instant,
    ) -> Result<VerifiedDepartmentSnapshot<'_>, DepartmentAccessError> {
        self.view_at(instance, account, proof, Instant::now())
    }
    fn view_at(
        &self,
        instance: InstanceId,
        account: AccountKey,
        proof: Instant,
        now: Instant,
    ) -> Result<VerifiedDepartmentSnapshot<'_>, DepartmentAccessError> {
        if now >= proof {
            return Err(DepartmentAccessError::ProofExpired);
        }
        Ok(match self {
            Self::Unavailable(reason) => VerifiedDepartmentSnapshot::Unavailable(*reason),
            Self::Expired => VerifiedDepartmentSnapshot::Expired,
            Self::Available { expires, .. } if now >= *expires => {
                VerifiedDepartmentSnapshot::Expired
            }
            Self::Available {
                source,
                provider_config_version,
                snapshot_id,
                observed_at,
                expires_at,
                snapshot,
                expires,
            } => VerifiedDepartmentSnapshot::Available(TrustedDepartmentSnapshot {
                instance,
                account,
                source,
                provider_config_version: *provider_config_version,
                snapshot_id: *snapshot_id,
                observed_at: *observed_at,
                expires_at: *expires_at,
                snapshot,
                proof,
                expires: *expires,
            }),
        })
    }
}

/// Only Available contains a component-issued snapshot, including explicit no-department.
pub enum VerifiedDepartmentSnapshot<'a> {
    Available(TrustedDepartmentSnapshot<'a>),
    Unavailable(DepartmentUnavailableReason),
    Expired,
}
/// Metadata identifies an observation; value access checks both fixed deadlines.
/// A copied value or completed authorization remains the host's responsibility.
/// ```compile_fail
/// let fact: rss_identity_postgres::TrustedDepartmentSnapshot<'_> = serde_json::from_str("{}").unwrap();
/// ```
pub struct TrustedDepartmentSnapshot<'a> {
    instance: InstanceId,
    account: AccountKey,
    source: &'a FactSource,
    provider_config_version: i64,
    snapshot_id: Uuid,
    observed_at: i64,
    expires_at: i64,
    snapshot: &'a DepartmentSnapshot,
    proof: Instant,
    expires: Instant,
}
impl TrustedDepartmentSnapshot<'_> {
    pub fn instance(&self) -> InstanceId {
        self.instance
    }
    pub fn account(&self) -> AccountKey {
        self.account
    }
    pub fn provider_id(&self) -> Uuid {
        self.source.provider_id()
    }
    pub fn issuer(&self) -> &str {
        self.source.issuer()
    }
    pub fn provider_config_version(&self) -> i64 {
        self.provider_config_version
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    /// Access always rechecks both deadlines. Empty memberships explicitly mean unassigned.
    pub fn snapshot(&self) -> Result<&DepartmentSnapshot, DepartmentAccessError> {
        self.snapshot_at(Instant::now())
    }
    fn snapshot_at(&self, now: Instant) -> Result<&DepartmentSnapshot, DepartmentAccessError> {
        if now >= self.proof {
            return Err(DepartmentAccessError::ProofExpired);
        }
        if now >= self.expires {
            return Err(DepartmentAccessError::SnapshotExpired);
        }
        Ok(self.snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn account() -> AccountKey {
        AccountKey {
            tenant: rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111")
                .unwrap(),
            principal: rss_identity_core::PrincipalId::generate(),
        }
    }
    #[test]
    fn assigned_and_absent_retained_views_check_both_deadlines() {
        let start = Instant::now();
        let expiry = start + Duration::from_secs(1);
        let proof = expiry + Duration::from_secs(1);
        let instance = InstanceId::generate();
        let account = account();
        for members in [serde_json::json!(["dept"]), serde_json::json!([])] {
            let snapshot = serde_json::from_value(serde_json::json!({"version":1,"sourceRevision":"r1",
                "nodes":[{"id":"dept","displayName":"Department","parentId":null}],"memberships":members})).unwrap();
            let absent = members.as_array().unwrap().is_empty();
            let facts = DepartmentFacts::Available {
                source: FactSource::new(Uuid::new_v4(), "https://idp.test".into()).unwrap(),
                provider_config_version: 1,
                snapshot_id: Uuid::new_v4(),
                observed_at: 100,
                expires_at: 101,
                snapshot,
                expires: expiry,
            };
            let VerifiedDepartmentSnapshot::Available(view) =
                facts.view_at(instance, account, proof, start).unwrap()
            else {
                panic!("available");
            };
            assert_eq!(
                view.snapshot_at(start).unwrap().memberships().is_empty(),
                absent
            );
            assert_eq!(view.instance(), instance);
            assert_eq!(view.account(), account);
            assert!(view.snapshot_at(expiry - Duration::from_nanos(1)).is_ok());
            assert_eq!(
                view.snapshot_at(expiry),
                Err(DepartmentAccessError::SnapshotExpired)
            );
            assert_eq!(
                view.snapshot_at(proof),
                Err(DepartmentAccessError::ProofExpired)
            );
            assert!(matches!(
                facts.view_at(instance, account, proof, expiry),
                Ok(VerifiedDepartmentSnapshot::Expired)
            ));
            for earlier in [start + Duration::from_millis(500), expiry] {
                let VerifiedDepartmentSnapshot::Available(view) =
                    facts.view_at(instance, account, earlier, start).unwrap()
                else {
                    panic!("available");
                };
                assert_eq!(
                    view.snapshot_at(earlier),
                    Err(DepartmentAccessError::ProofExpired)
                );
            }
        }
        for reason in [
            DepartmentUnavailableReason::LocalIdentity,
            DepartmentUnavailableReason::NotConfigured,
            DepartmentUnavailableReason::ClaimMissing,
            DepartmentUnavailableReason::NotYetValid,
        ] {
            let facts = DepartmentFacts::Unavailable(reason);
            assert!(
                matches!(facts.view_at(instance, account, proof, start), Ok(VerifiedDepartmentSnapshot::Unavailable(r)) if r == reason)
            );
            assert!(matches!(
                facts.view_at(instance, account, proof, proof),
                Err(DepartmentAccessError::ProofExpired)
            ));
        }
    }
}
