//! Inbox semantic model for consumer-side idempotency.
//!
//! This module freezes the pure state machine behind durable inbox implementations. It deliberately
//! does not own storage, clocks, broker settle, DLX, or runtime renewal loops; those stay in
//! adapters and `eventexec`. The storage shape is absent row -> `claimed` -> `done`, while
//! `absent` exists only as an engine state, not as a persisted status label.
//!
//! ref: MassTransit/MassTransit src/Persistence/MassTransit.EntityFrameworkCoreIntegration/EntityFrameworkCoreIntegration/InboxState.cs@develop

use crate::idempotency::{LeaseOutcome, LeaseToken, SeenState};

/// Persisted inbox row status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxStatus {
    /// A consumer currently owns the claim lease.
    Claimed,
    /// The message has reached a terminal dedup state.
    Done,
}

impl InboxStatus {
    /// Stable storage/metrics label for persisted statuses.
    pub fn as_label(self) -> &'static str {
        match self {
            InboxStatus::Claimed => "claimed",
            InboxStatus::Done => "done",
        }
    }

    /// Parse a persisted inbox status label.
    pub fn parse_label(raw: &str) -> Result<Self, InboxStatusError> {
        match raw {
            "claimed" => Ok(Self::Claimed),
            "done" => Ok(Self::Done),
            _ => Err(InboxStatusError::Unknown),
        }
    }
}

/// Inbox status parse error.
///
/// The unknown input is intentionally not retained: status labels can be sourced from durable
/// storage and should not be reflected into logs/errors as runtime strings.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxStatusError {
    /// The status label is not in the closed inbox status set.
    #[error("unknown inbox status label")]
    Unknown,
}

/// Lease freshness as evaluated by the storage adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxLeaseFreshness {
    /// Lease is still valid; another claim must be treated as duplicate.
    Active,
    /// Lease is stale enough to be reclaimed.
    Expired,
}

impl InboxLeaseFreshness {
    /// Stable low-cardinality label for freshness observations.
    pub fn as_label(self) -> &'static str {
        match self {
            InboxLeaseFreshness::Active => "active",
            InboxLeaseFreshness::Expired => "expired",
        }
    }
}

/// A claimed inbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxClaim {
    lease: LeaseToken,
    freshness: InboxLeaseFreshness,
}

impl InboxClaim {
    /// Build an active claim held by `lease`.
    pub fn active(lease: LeaseToken) -> Self {
        Self {
            lease,
            freshness: InboxLeaseFreshness::Active,
        }
    }

    /// Build an expired claim held by `lease`.
    pub fn expired(lease: LeaseToken) -> Self {
        Self {
            lease,
            freshness: InboxLeaseFreshness::Expired,
        }
    }

    /// Borrow the lease token associated with this claim.
    pub fn lease(&self) -> &LeaseToken {
        &self.lease
    }

    /// Current lease freshness observation.
    pub fn freshness(&self) -> InboxLeaseFreshness {
        self.freshness
    }

    fn lease_matches(&self, lease: &LeaseToken) -> bool {
        &self.lease == lease
    }
}

/// Pure inbox state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboxState {
    /// No durable inbox row exists.
    Absent,
    /// A claimed row exists and carries a lease token.
    Claimed(InboxClaim),
    /// Terminal dedup row exists.
    Done,
}

impl InboxState {
    /// Persisted status for this state, if any.
    pub fn status(&self) -> Option<InboxStatus> {
        match self {
            Self::Absent => None,
            Self::Claimed(_) => Some(InboxStatus::Claimed),
            Self::Done => Some(InboxStatus::Done),
        }
    }

    /// Claim or reclaim the state with `lease`.
    pub fn try_claim(self, lease: LeaseToken) -> (SeenState, Self) {
        match self {
            Self::Absent => (SeenState::Fresh, Self::Claimed(InboxClaim::active(lease))),
            Self::Claimed(claim) if claim.freshness() == InboxLeaseFreshness::Expired => {
                (SeenState::Fresh, Self::Claimed(InboxClaim::active(lease)))
            }
            Self::Claimed(claim) => (SeenState::Duplicate, Self::Claimed(claim)),
            Self::Done => (SeenState::Duplicate, Self::Done),
        }
    }

    /// Extend the matching claim lease.
    pub fn extend(&self, lease: &LeaseToken) -> LeaseOutcome {
        match self {
            Self::Claimed(claim) if claim.lease_matches(lease) => LeaseOutcome::Held,
            _ => LeaseOutcome::Lost,
        }
    }

    /// Commit a matching claim into the terminal dedup state.
    pub fn commit(self, lease: &LeaseToken) -> (LeaseOutcome, Self) {
        match self {
            Self::Claimed(claim) if claim.lease_matches(lease) => (LeaseOutcome::Held, Self::Done),
            state => (LeaseOutcome::Lost, state),
        }
    }

    /// Release a matching claim back to absent.
    pub fn release(self, lease: &LeaseToken) -> Self {
        match self {
            Self::Claimed(claim) if claim.lease_matches(lease) => Self::Absent,
            state => state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InboxClaim, InboxLeaseFreshness, InboxState, InboxStatus, InboxStatusError};
    use crate::{LeaseOutcome, LeaseToken, SeenState};

    fn token_pair() -> (LeaseToken, LeaseToken) {
        (LeaseToken::mint(), LeaseToken::mint())
    }

    #[test]
    fn inbox_status_labels_are_stable_and_parseable() {
        let cases = [
            (InboxStatus::Claimed, "claimed"),
            (InboxStatus::Done, "done"),
        ];
        for (status, expected) in cases {
            assert_eq!(status.as_label(), expected);
            assert_eq!(InboxStatus::parse_label(expected), Ok(status));
        }
        assert_ne!(
            InboxStatus::Claimed.as_label(),
            InboxStatus::Done.as_label()
        );
        assert_eq!(
            InboxStatus::parse_label("absent"),
            Err(InboxStatusError::Unknown)
        );
        assert_eq!(
            InboxStatus::parse_label("CLAIMED"),
            Err(InboxStatusError::Unknown)
        );
    }

    #[test]
    fn inbox_lease_freshness_labels_are_stable_and_distinct() {
        assert_eq!(InboxLeaseFreshness::Active.as_label(), "active");
        assert_eq!(InboxLeaseFreshness::Expired.as_label(), "expired");
        assert_ne!(
            InboxLeaseFreshness::Active.as_label(),
            InboxLeaseFreshness::Expired.as_label()
        );
    }

    #[test]
    fn inbox_claim_constructors_set_freshness_and_redact_debug() {
        let lease = LeaseToken::mint();
        let active = InboxClaim::active(lease.clone());
        let expired = InboxClaim::expired(lease.clone());

        assert_eq!(active.lease(), &lease);
        assert_eq!(active.freshness(), InboxLeaseFreshness::Active);
        assert_eq!(expired.lease(), &lease);
        assert_eq!(expired.freshness(), InboxLeaseFreshness::Expired);

        let debug = format!("{active:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(lease.as_str()));
    }

    #[test]
    fn inbox_state_status_maps_only_persisted_states() {
        let (lease, _) = token_pair();
        assert_eq!(InboxState::Absent.status(), None);
        assert_eq!(
            InboxState::Claimed(InboxClaim::active(lease)).status(),
            Some(InboxStatus::Claimed)
        );
        assert_eq!(InboxState::Done.status(), Some(InboxStatus::Done));
    }

    #[test]
    fn claim_absent_returns_fresh_and_active_claim() {
        let (lease, _) = token_pair();
        let (seen, state) = InboxState::Absent.try_claim(lease.clone());

        assert_eq!(seen, SeenState::Fresh);
        assert!(matches!(state, InboxState::Claimed(_)));
        if let InboxState::Claimed(claim) = state {
            assert_eq!(claim.lease(), &lease);
            assert_eq!(claim.freshness(), InboxLeaseFreshness::Active);
        }
    }

    #[test]
    fn claim_active_claim_is_duplicate_and_preserves_lease() {
        let (held, contender) = token_pair();
        let state = InboxState::Claimed(InboxClaim::active(held.clone()));

        let (seen, state) = state.try_claim(contender);

        assert_eq!(seen, SeenState::Duplicate);
        assert!(matches!(state, InboxState::Claimed(_)));
        if let InboxState::Claimed(claim) = state {
            assert_eq!(claim.lease(), &held);
        }
    }

    #[test]
    fn claim_expired_claim_reclaims_with_new_active_lease() {
        let (stale, new_lease) = token_pair();
        let state = InboxState::Claimed(InboxClaim::expired(stale));

        let (seen, state) = state.try_claim(new_lease.clone());

        assert_eq!(seen, SeenState::Fresh);
        assert!(matches!(state, InboxState::Claimed(_)));
        if let InboxState::Claimed(claim) = state {
            assert_eq!(claim.lease(), &new_lease);
            assert_eq!(claim.freshness(), InboxLeaseFreshness::Active);
        }
    }

    #[test]
    fn claim_done_is_duplicate_and_preserves_done() {
        let (lease, _) = token_pair();

        let (seen, state) = InboxState::Done.try_claim(lease);

        assert_eq!(seen, SeenState::Duplicate);
        assert_eq!(state, InboxState::Done);
    }

    #[test]
    fn extend_requires_matching_claim_lease_even_when_expired() {
        let (held, other) = token_pair();
        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));
        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));

        assert_eq!(claimed.extend(&held), LeaseOutcome::Held);
        assert_eq!(claimed.extend(&other), LeaseOutcome::Lost);
        assert_eq!(expired.extend(&held), LeaseOutcome::Held);
        assert_eq!(expired.extend(&other), LeaseOutcome::Lost);
        assert_eq!(InboxState::Absent.extend(&held), LeaseOutcome::Lost);
        assert_eq!(InboxState::Done.extend(&held), LeaseOutcome::Lost);
    }

    #[test]
    fn commit_requires_matching_claim_lease_even_when_expired() {
        let (held, other) = token_pair();
        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));

        let (outcome, state) = claimed.commit(&held);
        assert_eq!(outcome, LeaseOutcome::Held);
        assert_eq!(state, InboxState::Done);

        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));
        let (outcome, state) = claimed.commit(&other);
        assert_eq!(outcome, LeaseOutcome::Lost);
        assert_eq!(state.status(), Some(InboxStatus::Claimed));

        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));
        let (outcome, state) = expired.commit(&held);
        assert_eq!(outcome, LeaseOutcome::Held);
        assert_eq!(state, InboxState::Done);

        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));
        let (outcome, state) = expired.commit(&other);
        assert_eq!(outcome, LeaseOutcome::Lost);
        assert_eq!(state.status(), Some(InboxStatus::Claimed));

        assert_eq!(
            InboxState::Absent.commit(&held),
            (LeaseOutcome::Lost, InboxState::Absent)
        );
        assert_eq!(
            InboxState::Done.commit(&held),
            (LeaseOutcome::Lost, InboxState::Done)
        );
    }

    #[test]
    fn release_requires_matching_claim_lease_even_when_expired() {
        let (held, other) = token_pair();
        let claimed = InboxState::Claimed(InboxClaim::active(held.clone()));
        let expired = InboxState::Claimed(InboxClaim::expired(held.clone()));

        assert_eq!(claimed.clone().release(&held), InboxState::Absent);
        assert_eq!(claimed.clone().release(&other), claimed);
        assert_eq!(expired.clone().release(&held), InboxState::Absent);
        assert_eq!(expired.clone().release(&other), expired);
        assert_eq!(InboxState::Absent.release(&held), InboxState::Absent);
        assert_eq!(InboxState::Done.release(&held), InboxState::Done);
    }
}
