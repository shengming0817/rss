//! Borrowed group access bounded by both the request proof and the signed snapshot.
use crate::{session_storage::TimeSample, transaction::corrupt};
use rss_identity_core::{
    facts::{FactSource, FactUnavailableReason},
    groups::Groups,
};
use rss_transactional_messaging_postgres::PgError;
use std::time::Instant;

/// Access checks the proof first, including when both deadlines have elapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupAccessError {
    #[error("authentication proof expired")]
    ProofExpired,
    #[error("group snapshot expired")]
    SnapshotExpired,
}

pub(crate) struct GroupFacts {
    facts: Groups,
    expires: Instant,
}
impl GroupFacts {
    pub(crate) fn new(facts: Groups, sample: &TimeSample) -> Result<Self, PgError> {
        if !facts.structurally_valid_at(sample.seconds()) {
            return Err(corrupt());
        }
        let expires = match &facts {
            Groups::Available { expires_at, .. } => sample.deadline(*expires_at)?,
            _ => sample.started(),
        };
        Ok(Self { facts, expires })
    }
    pub(crate) fn view(&self, proof: Instant) -> Result<VerifiedGroups<'_>, GroupAccessError> {
        self.view_at(proof, Instant::now())
    }
    fn view_at(
        &self,
        proof: Instant,
        now: Instant,
    ) -> Result<VerifiedGroups<'_>, GroupAccessError> {
        if now >= proof {
            return Err(GroupAccessError::ProofExpired);
        }
        Ok(match &self.facts {
            Groups::Unavailable { reason, .. } => VerifiedGroups::Unavailable(*reason),
            Groups::Expired { .. } => VerifiedGroups::Expired,
            Groups::Available { .. } if now >= self.expires => VerifiedGroups::Expired,
            Groups::Available {
                source,
                snapshot_id,
                provider_config_version,
                observed_at,
                expires_at,
                values,
                ..
            } => VerifiedGroups::Available(TrustedGroups {
                source,
                snapshot_id: *snapshot_id,
                provider_config_version: *provider_config_version,
                observed_at: *observed_at,
                expires_at: *expires_at,
                values,
                proof,
                expires: self.expires,
            }),
        })
    }
}

/// Groups are borrowed from a checked identity; there is no standalone proof constructor.
pub enum VerifiedGroups<'a> {
    Available(TrustedGroups<'a>),
    Unavailable(FactUnavailableReason),
    Expired,
}
/// Every values access checks both deadlines, even if this wrapper was retained.
/// Metadata describes the snapshot; it does not grant authorization.
/// A previously copied value or authorization decision remains the host's responsibility.
/// ```compile_fail
/// let groups: rss_identity_postgres::TrustedGroups<'_> = serde_json::from_str("{}").unwrap();
/// ```
pub struct TrustedGroups<'a> {
    source: &'a FactSource,
    snapshot_id: uuid::Uuid,
    provider_config_version: i64,
    observed_at: i64,
    expires_at: i64,
    values: &'a [String],
    proof: Instant,
    expires: Instant,
}
impl TrustedGroups<'_> {
    pub fn source(&self) -> &FactSource {
        self.source
    }
    pub fn snapshot_id(&self) -> uuid::Uuid {
        self.snapshot_id
    }
    pub fn provider_config_version(&self) -> i64 {
        self.provider_config_version
    }
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn values(&self) -> Result<&[String], GroupAccessError> {
        self.values_at(Instant::now())
    }
    fn values_at(&self, now: Instant) -> Result<&[String], GroupAccessError> {
        if now >= self.proof {
            return Err(GroupAccessError::ProofExpired);
        }
        if now >= self.expires {
            return Err(GroupAccessError::SnapshotExpired);
        }
        Ok(self.values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn retained_values_check_exact_deadlines_and_proof_wins() {
        let start = Instant::now();
        let snapshot = start + Duration::from_secs(1);
        let proof = start + Duration::from_secs(2);
        for values in [vec![], vec!["staff".into()]] {
            let facts = GroupFacts {
                facts: Groups::Available {
                    version: 1,
                    source: FactSource::new(uuid::Uuid::new_v4(), "https://issuer.test".into())
                        .unwrap(),
                    snapshot_id: uuid::Uuid::new_v4(),
                    provider_config_version: 1,
                    observed_at: 100,
                    expires_at: 101,
                    values: values.clone(),
                },
                expires: snapshot,
            };
            let VerifiedGroups::Available(groups) = facts.view_at(proof, start).unwrap() else {
                panic!("fresh")
            };
            assert_eq!(
                groups.values_at(snapshot - Duration::from_nanos(1)),
                Ok(values.as_slice())
            );
            assert_eq!(
                groups.values_at(snapshot),
                Err(GroupAccessError::SnapshotExpired)
            );
            assert_eq!(groups.values_at(proof), Err(GroupAccessError::ProofExpired));
            assert!(matches!(
                facts.view_at(proof, snapshot),
                Ok(VerifiedGroups::Expired)
            ));
            assert!(matches!(
                facts.view_at(proof, proof),
                Err(GroupAccessError::ProofExpired)
            ));
            let earlier = start + Duration::from_millis(500);
            let VerifiedGroups::Available(early) = facts.view_at(earlier, start).unwrap() else {
                panic!("fresh")
            };
            assert_eq!(
                early.values_at(earlier),
                Err(GroupAccessError::ProofExpired)
            );
            let VerifiedGroups::Available(short) = facts.view_at(snapshot, start).unwrap() else {
                panic!("fresh")
            };
            assert_eq!(
                short.values_at(snapshot),
                Err(GroupAccessError::ProofExpired)
            );
        }
    }
    #[test]
    fn unavailable_is_not_promoted_and_still_requires_live_proof() {
        let start = Instant::now();
        let proof = start + Duration::from_secs(10);
        for reason in [
            FactUnavailableReason::LocalIdentity,
            FactUnavailableReason::NotConfigured,
            FactUnavailableReason::ClaimMissing,
            FactUnavailableReason::NotYetValid,
        ] {
            let facts = GroupFacts {
                facts: Groups::unavailable(reason),
                expires: start,
            };
            assert!(
                matches!(facts.view_at(proof, proof - Duration::from_nanos(1)), Ok(VerifiedGroups::Unavailable(r)) if r == reason)
            );
            assert!(matches!(
                facts.view_at(proof, proof),
                Err(GroupAccessError::ProofExpired)
            ));
        }
    }
}
