// ref: kube-rs/kube kube-runtime/src/watcher.rs@2.0.1 (complete init and resnapshot).
use crate::{Batch, Body, Coverage, Error, ErrorKind, Id};
use serde::{Deserialize, Serialize};
/// Explicit minimum replay retention and independently bounded baseline lifetime (seconds).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "PolicyWire")]
pub struct Policy {
    version: u8,
    retry_seconds: u64,
    safety_seconds: u64,
    baseline_seconds: u64,
}
impl Policy {
    /// Bind positive retry-retention, safety and baseline-validity durations in whole seconds.
    /// Reject zero, retry+safety overflow or values outside the supported i64-second range.
    /// Retention is a minimum guarantee; it does not expire an existing durable receipt.
    pub fn new(
        retry_seconds: u64,
        safety_seconds: u64,
        baseline_seconds: u64,
    ) -> Result<Self, Error> {
        if retry_seconds == 0
            || safety_seconds == 0
            || baseline_seconds == 0
            || retry_seconds
                .checked_add(safety_seconds)
                .is_none_or(|n| n > i64::MAX as u64)
            || baseline_seconds > i64::MAX as u64
        {
            return Err(ErrorKind::InvalidInput.into());
        }
        Ok(Self {
            version: 1,
            retry_seconds,
            safety_seconds,
            baseline_seconds,
        })
    }
    /// Encode the explicit V1 policy representation for immutable lifecycle/receipt storage.
    pub fn encode(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
    /// Restore a V1 policy through the same validation as new; unknown versions fail closed.
    pub fn decode(raw: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(raw)?)
    }
    /// Baseline validity in seconds, measured from authoritative provider receipt time.
    pub const fn baseline_seconds(&self) -> u64 {
        self.baseline_seconds
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Persisted reasons an incremental chain cannot safely advance.
pub enum NeedSnapshot {
    /// No complete snapshot has established this stream baseline.
    MissingBaseline,
    /// Snapshot reference, coverage or collection-definition binding differs from the active baseline.
    BaselineMismatch,
    /// The supplied predecessor or sequence does not continue the applicable cursor.
    Gap,
    /// Provider receipt time has reached the baseline validity boundary.
    BaselineExpired,
    /// A newer incomplete collection invalidated incremental continuity.
    Partial,
    /// A newer failed collection invalidated incremental continuity.
    CollectionFailed,
}
/// Immutable historical classification, distinct from current stream completeness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncOutcome {
    /// A new complete snapshot established a baseline and applicable cursor.
    Snapshot,
    /// A contiguous, matching-baseline delta advanced the applicable cursor.
    Delta,
    /// This report cannot be applied; facts and applicable cursor are retained.
    NeedSnapshot(NeedSnapshot),
    /// Sequence is not above the recorded high-water; no fact or resynchronization state is reset.
    Stale,
}
impl SyncOutcome {
    /// Whether this historical decision admits facts for later application; the sole outcome mapping owner.
    pub const fn is_applicable(&self) -> bool {
        matches!(self, Self::Snapshot | Self::Delta)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Baseline {
    id: Id,
    coverage: Coverage,
    expires_at: u64,
}
/// Pure integrity state. The provider must bind it to one exact stream and serialize transitions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "StateWire")]
pub struct State {
    version: u8,
    revision: u64,
    high_water: Option<u64>,
    cursor: Option<u64>,
    baseline: Option<Baseline>,
    need: Option<NeedSnapshot>,
}
impl State {
    /// An activated stream with revision zero, no observations and no complete baseline.
    pub const fn initial() -> Self {
        Self {
            version: 1,
            revision: 0,
            high_water: None,
            cursor: None,
            baseline: None,
            need: None,
        }
    }
    /// Last applicable producer sequence, retained while newer reports require resynchronization.
    pub const fn cursor(&self) -> Option<u64> {
        self.cursor
    }
    /// Provider CAS revision, incremented for each recorded transition, not a producer coordinate.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Persisted resynchronization reason; only a newer complete snapshot clears it.
    pub const fn needs_snapshot(&self) -> Option<&NeedSnapshot> {
        self.need.as_ref()
    }
    /// Encode the V1 integrity state, including degraded-state evidence.
    pub fn encode(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
    /// Trusted provider restore boundary. This does not attest to database durability.
    pub fn decode(raw: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(raw)?)
    }

    /// Compute one pure transition after the provider has resolved duplicate identities.
    /// The provider must bind this state to the report stream and serialize the transition.
    /// received_at is authoritative Unix seconds; this function neither authenticates nor persists.
    /// Sequence gaps, failed/partial collection and invalid baselines retain cursor and require a snapshot.
    pub fn advance(
        &self,
        batch: &Batch,
        received_at: u64,
        policy: &Policy,
    ) -> Result<Decision, Error> {
        let mut next = self.clone();
        next.revision = self.revision.checked_add(1).ok_or(ErrorKind::Invariant)?;
        let outcome = if self.high_water.is_some_and(|h| batch.sequence() <= h) {
            SyncOutcome::Stale
        } else {
            next.high_water = Some(batch.sequence());
            next.apply_new(batch, received_at, policy)?
        };
        Ok(Decision {
            version: 1,
            before: self.clone(),
            after: next,
            outcome,
        })
    }
    fn apply_new(
        &mut self,
        batch: &Batch,
        received_at: u64,
        policy: &Policy,
    ) -> Result<SyncOutcome, Error> {
        match batch.body() {
            Body::Snapshot(_) => {
                let expires_at = received_at
                    .checked_add(policy.baseline_seconds)
                    .ok_or(ErrorKind::InvalidInput)?;
                self.baseline = Some(Baseline {
                    id: batch.id().clone(),
                    coverage: batch.coverage().clone(),
                    expires_at,
                });
                self.cursor = Some(batch.sequence());
                self.need = None;
                Ok(SyncOutcome::Snapshot)
            }
            Body::Partial(_) => Ok(self.require(NeedSnapshot::Partial)),
            Body::Failed { .. } => Ok(self.require(NeedSnapshot::CollectionFailed)),
            Body::Delta {
                baseline, previous, ..
            } => {
                if let Some(reason) = self.delta_failure(batch, baseline, *previous, received_at) {
                    return Ok(self.require(reason));
                }
                self.cursor = Some(batch.sequence());
                Ok(SyncOutcome::Delta)
            }
        }
    }
    fn require(&mut self, reason: NeedSnapshot) -> SyncOutcome {
        self.need = Some(reason.clone());
        SyncOutcome::NeedSnapshot(reason)
    }
    fn delta_failure(
        &self,
        batch: &Batch,
        baseline: &Id,
        previous: u64,
        now: u64,
    ) -> Option<NeedSnapshot> {
        if let Some(reason) = &self.need {
            return Some(reason.clone());
        }
        let Some(active) = &self.baseline else {
            return Some(NeedSnapshot::MissingBaseline);
        };
        if now >= active.expires_at {
            return Some(NeedSnapshot::BaselineExpired);
        }
        if &active.id != baseline || &active.coverage != batch.coverage() {
            return Some(NeedSnapshot::BaselineMismatch);
        }
        if self.cursor != Some(previous) || previous.checked_add(1) != Some(batch.sequence()) {
            return Some(NeedSnapshot::Gap);
        }
        None
    }
}
/// Core-owned transition, including immutable before/after evidence for later exact readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    version: u8,
    before: State,
    after: State,
    outcome: SyncOutcome,
}
impl Decision {
    /// Resulting integrity state to commit atomically with this batch.
    pub const fn state(&self) -> &State {
        &self.after
    }
    /// Exact prior state required by provider CAS; immutable evidence for later recovery.
    pub const fn before(&self) -> &State {
        &self.before
    }
    /// Historical sync classification, separate from current stream status and projection completion.
    pub const fn outcome(&self) -> &SyncOutcome {
        &self.outcome
    }
    /// Encode the explicit V1 transition evidence.
    pub fn encode(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
    /// Restore V1 only if its before/after states and outcome exactly recompute for this batch, time and policy.
    /// Malformed versions/states fail closed; mismatched transition evidence returns Invariant.
    /// The provider must separately establish that this evidence is durable.
    pub fn restore(
        raw: &str,
        batch: &Batch,
        received_at: u64,
        policy: &Policy,
    ) -> Result<Self, Error> {
        let wire: DecisionWire = serde_json::from_str(raw)?;
        if wire.version != 1 {
            return Err(ErrorKind::InvalidInput.into());
        }
        let d = Self {
            version: wire.version,
            before: wire.before,
            after: wire.after,
            outcome: wire.outcome,
        };
        if d.before.advance(batch, received_at, policy)? != d {
            return Err(ErrorKind::Invariant.into());
        }
        Ok(d)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyWire {
    version: u8,
    retry_seconds: u64,
    safety_seconds: u64,
    baseline_seconds: u64,
}
impl TryFrom<PolicyWire> for Policy {
    type Error = Error;
    fn try_from(w: PolicyWire) -> Result<Self, Error> {
        if w.version != 1 {
            return Err(ErrorKind::InvalidInput.into());
        }
        Self::new(w.retry_seconds, w.safety_seconds, w.baseline_seconds)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateWire {
    version: u8,
    revision: u64,
    high_water: Option<u64>,
    cursor: Option<u64>,
    baseline: Option<Baseline>,
    need: Option<NeedSnapshot>,
}
impl TryFrom<StateWire> for State {
    type Error = Error;
    fn try_from(w: StateWire) -> Result<Self, Error> {
        let state = Self {
            version: w.version,
            revision: w.revision,
            high_water: w.high_water,
            cursor: w.cursor,
            baseline: w.baseline,
            need: w.need,
        };
        state.validate()?;
        Ok(state)
    }
}
impl State {
    fn validate(&self) -> Result<(), Error> {
        if self.version != 1 {
            return Err(ErrorKind::InvalidInput.into());
        }
        if self.revision == 0 {
            return if self == &Self::initial() {
                Ok(())
            } else {
                Err(ErrorKind::Invariant.into())
            };
        }
        if self.high_water.is_none()
            || self.cursor.is_some() != self.baseline.is_some()
            || !self.valid_baseline()
        {
            return Err(ErrorKind::Invariant.into());
        }
        Ok(())
    }
    fn valid_baseline(&self) -> bool {
        match (&self.baseline, self.cursor, &self.need) {
            (
                None,
                None,
                Some(
                    NeedSnapshot::MissingBaseline
                    | NeedSnapshot::Partial
                    | NeedSnapshot::CollectionFailed,
                ),
            ) => true,
            (Some(b), Some(c), None) => b.expires_at > 0 && self.high_water == Some(c),
            (Some(b), Some(c), Some(reason)) => {
                b.expires_at > 0
                    && *reason != NeedSnapshot::MissingBaseline
                    && self.high_water.is_some_and(|h| h > c)
            }
            _ => false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionWire {
    version: u8,
    before: State,
    after: State,
    outcome: SyncOutcome,
}
