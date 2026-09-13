//! Finite V1 history accounting shared by admission and provider validation.
//! ref: restatedev/restate crates/worker-api/src/invoker/invocation_reader.rs@7fcc614c75fac74d051b68b118e87421e90467cc
use crate::{Error, ErrorKind, Progress};
use serde::{Deserialize, Serialize};

/// Conservative bytes for a receipt-free event, including its persisted effect key.
pub const EVENT_BYTES: u64 = 256;
/// Existing V1 maximum plaintext bytes, also the conservative work charged per authentication.
pub const PLAINTEXT_BYTES: u64 = 1024 * 1024;
/// Largest accepted V1 AAD. Definition name/identity bounds fit within this envelope.
pub const AAD_BYTES: usize = 4096;
/// Maximum V1 protected receipt accounting, including JSON byte-array expansion and key escaping.
pub const RECEIPT_BYTES: u64 = 1024 + 6 * (1024 + 64) + 5 * (2 * 1024 * 1024 + 4096 + 32);
/// Maximum encoded definition returned by a provider before typed decoding.
pub const DEFINITION_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "CapacityWire")]
/// Explicit finite per-instance capacity. Resource configuration does not change effect identity.
pub struct HistoryCapacity {
    max_entries: u64,
    max_encoded_bytes: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapacityWire {
    max_entries: u64,
    max_encoded_bytes: u64,
}
impl TryFrom<CapacityWire> for HistoryCapacity {
    type Error = Error;
    fn try_from(w: CapacityWire) -> Result<Self, Error> {
        Self::new(w.max_entries, w.max_encoded_bytes)
    }
}
impl HistoryCapacity {
    /// Select positive capacities representable by the PostgreSQL owner and core.
    pub fn new(max_entries: u64, max_encoded_bytes: u64) -> Result<Self, Error> {
        if max_entries == 0
            || max_encoded_bytes == 0
            || max_entries > i64::MAX as u64
            || max_encoded_bytes > i64::MAX as u64
        {
            return Err(ErrorKind::InvalidBudget.into());
        }
        Ok(Self {
            max_entries,
            max_encoded_bytes,
        })
    }
    /// Maximum committed events plus mandatory reserved events.
    pub const fn max_entries(self) -> u64 {
        self.max_entries
    }
    /// Maximum charged encoded bytes plus mandatory reserved bytes.
    pub const fn max_encoded_bytes(self) -> u64 {
        self.max_encoded_bytes
    }
    /// Whether both measured coordinates fit.
    pub const fn contains(self, entries: u64, bytes: u64) -> bool {
        entries <= self.max_entries && bytes <= self.max_encoded_bytes
    }
    /// Validate monotonic explicit growth; the provider additionally checks lease and CAS.
    pub fn extends(self, previous: Self) -> bool {
        self.max_entries >= previous.max_entries
            && self.max_encoded_bytes >= previous.max_encoded_bytes
            && self != previous
    }
}
#[derive(Debug, Clone, Copy)]
/// Per-read memory/replay and authentication work limits; never reset between replay stages.
pub struct ReadBudget {
    history: HistoryCapacity,
    authentication_bytes: u64,
}
impl ReadBudget {
    /// Bound loaded history and conservative authenticated plaintext work separately.
    pub fn new(history: HistoryCapacity, authentication_bytes: u64) -> Result<Self, Error> {
        if authentication_bytes == 0 || authentication_bytes > i64::MAX as u64 {
            return Err(ErrorKind::InvalidBudget.into());
        }
        Ok(Self {
            history,
            authentication_bytes,
        })
    }
    /// Loaded event and encoded-byte bounds.
    pub const fn history(self) -> HistoryCapacity {
        self.history
    }
    /// Work bound; every receipt reserves the existing maximum plaintext size before opening it.
    pub const fn authentication_bytes(self) -> u64 {
        self.authentication_bytes
    }
    pub(crate) fn check(self, entries: u64, bytes: u64, receipts: usize) -> Result<(), Error> {
        let work = (receipts as u64)
            .checked_mul(PLAINTEXT_BYTES)
            .ok_or(ErrorKind::HistoryReadLimit)?;
        if !self.history.contains(entries, bytes) || work > self.authentication_bytes {
            return Err(ErrorKind::HistoryReadLimit.into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Small provider metadata. Recovery independently replays history and compares this entire projection.
pub struct HistoryHead {
    /// Journal sequence/count; growth does not change it.
    pub revision: u64,
    /// V1 conservative encoded history bytes.
    pub encoded_bytes: u64,
    /// Durable finite instance capacity.
    pub capacity: HistoryCapacity,
    /// Current transition projection, atomically maintained with the journal.
    pub progress: Progress,
}
impl HistoryHead {
    /// Check observed history before requesting any payload.
    pub fn check_read(&self, read: ReadBudget) -> Result<(), Error> {
        read.check(self.revision, self.encoded_bytes, self.progress.forward)
    }
    /// Required event/byte reserve for all already admitted obligations.
    pub fn reserve(&self) -> Result<(u64, u64), Error> {
        self.progress.reserve()
    }
    /// Check admission against durable capacity and the worker's ability to recover its settlement.
    pub fn check_admission(&self, read: ReadBudget) -> Result<(), Error> {
        let (entries, bytes) = self.reserve()?;
        let entries = self
            .revision
            .checked_add(entries)
            .ok_or(ErrorKind::HistoryLimited)?;
        let bytes = self
            .encoded_bytes
            .checked_add(bytes)
            .ok_or(ErrorKind::HistoryLimited)?;
        if !self.capacity.contains(entries, bytes) {
            return Err(ErrorKind::HistoryLimited.into());
        }
        let receipts = self.progress.forward
            + usize::from(
                self.progress.pending.is_some()
                    || self.progress.last_kind == Some(crate::EventKind::Resume),
            );
        read.check(entries, bytes, receipts)
            .map_err(|_| ErrorKind::HistoryLimited.into())
    }
}
