use crate::{Action, AuditEventV1, Error, EventFacts, Outcome, RecordIdentity, codec};
use rss_contract::Timepoint;
use std::{borrow::Cow, sync::Arc};

/// Provider-free exact Audit bytes and their structurally validated summary.
#[derive(Clone)]
pub struct PreparedAuditV1(Arc<RecordData>);
struct RecordData {
    identity: RecordIdentity,
    recorded_at: Timepoint,
    occurred_at: Timepoint,
    action: Action,
    outcome: Outcome,
    canonical: bytes::Bytes,
}
impl PreparedAuditV1 {
    /// Restore a canonical record. An owned buffer is adopted after validation.
    pub fn from_canonical_bytes<'a>(bytes: impl Into<Cow<'a, [u8]>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        let parsed = codec::parse(&bytes)?;
        let (identity, facts, recorded_at) = (parsed.identity, parsed.facts, parsed.recorded_at);
        Ok(Self::new(identity, &facts, recorded_at, bytes.into_owned()))
    }
    fn new(
        identity: RecordIdentity,
        facts: &EventFacts,
        recorded_at: Timepoint,
        canonical: Vec<u8>,
    ) -> Self {
        Self(Arc::new(RecordData {
            identity,
            action: facts.action().clone(),
            outcome: facts.outcome(),
            occurred_at: facts.occurred_at(),
            recorded_at,
            canonical: canonical.into(),
        }))
    }
    /// Stable tenant, source and event identity.
    pub fn identity(&self) -> &RecordIdentity {
        &self.0.identity
    }
    /// Source action in the exact record.
    pub fn action(&self) -> &Action {
        &self.0.action
    }
    /// Source outcome in the exact record.
    pub fn outcome(&self) -> Outcome {
        self.0.outcome
    }
    /// Source occurrence time.
    pub fn occurred_at(&self) -> Timepoint {
        self.0.occurred_at
    }
    /// Recording time supplied by the recorder authority.
    pub fn recorded_at(&self) -> Timepoint {
        self.0.recorded_at
    }
    #[cfg(feature = "ledger")]
    pub(crate) fn shared_bytes(&self) -> bytes::Bytes {
        self.0.canonical.clone()
    }
    /// Exact retry bytes, including the original recording time.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0.canonical
    }
}
impl std::fmt::Debug for PreparedAuditV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedAuditV1([redacted])")
    }
}
/// Encode an audit record. The caller owns the recording-time authority.
pub fn prepare(event: AuditEventV1, recorded_at: Timepoint) -> Result<PreparedAuditV1, Error> {
    let canonical = codec::encode(&event, recorded_at)?;
    Ok(PreparedAuditV1::new(
        event.identity().clone(),
        event.facts(),
        recorded_at,
        canonical,
    ))
}
