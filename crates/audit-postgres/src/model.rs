use crate::Error;
use rss_audit_core::PreparedAuditV1;
use rss_request_context::TenantId;

/// Tenant-bound ordinary keyset cursor. It is not a ledger coordinate or checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    tenant: TenantId,
    pub(crate) after: i64,
    pub(crate) through: Option<i64>,
}
impl Cursor {
    /// Start before the first persisted record.
    pub const fn start(tenant: TenantId) -> Self {
        Self {
            tenant,
            after: -1,
            through: None,
        }
    }
    /// Resume within the original inclusive upper bound. This is navigation, not evidence.
    pub fn resume(tenant: TenantId, position: u64, through: u64) -> Result<Self, Error> {
        if position >= through {
            return Err(Error::InvalidBound);
        }
        Ok(Self {
            tenant,
            after: i64::try_from(position).map_err(|_| Error::InvalidBound)?,
            through: Some(i64::try_from(through).map_err(|_| Error::InvalidBound)?),
        })
    }
    /// Continuation coordinates, absent for a fresh first page.
    pub fn continuation(self) -> Option<(u64, u64)> {
        self.through
            .map(|through| (self.after as u64, through as u64))
    }
    /// Tenant bound into this cursor.
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
}

/// Explicit complete-page row and canonical-byte bounds.
#[derive(Clone, Copy, Debug)]
pub struct ReadLimit {
    pub(crate) rows: i64,
    pub(crate) bytes: i64,
}
impl ReadLimit {
    /// Maximum complete-page row capacity shared by protocol adapters.
    pub const MAX_ROWS: u32 = 1024;
    /// Select 1..=1024 rows and a positive PostgreSQL-representable byte budget.
    pub fn new(rows: u32, bytes: u64) -> Result<Self, Error> {
        if !(1..=Self::MAX_ROWS).contains(&rows) || bytes == 0 {
            return Err(Error::InvalidBound);
        }
        Ok(Self {
            rows: i64::from(rows),
            bytes: i64::try_from(bytes).map_err(|_| Error::InvalidBound)?,
        })
    }
    /// Maximum rows authorized for this read.
    pub const fn rows(&self) -> u32 {
        self.rows as u32
    }
    /// Maximum total canonical bytes authorized for the complete selected page.
    pub const fn bytes(&self) -> u64 {
        self.bytes as u64
    }
}

/// Structurally validated stored bytes, not authenticated ledger evidence.
#[derive(Clone, Debug)]
pub struct Record {
    pub(crate) position: i64,
    pub(crate) prepared: PreparedAuditV1,
    pub(crate) ledger_sequence: Option<u64>,
}
impl Record {
    /// Stable navigation position, allowing gaps and out-of-order commits; never a consumption offset.
    pub fn position(&self) -> u64 {
        self.position as u64
    }
    /// Exact persisted canonical request, suitable for unchanged retry.
    pub const fn prepared(&self) -> &PreparedAuditV1 {
        &self.prepared
    }
    /// Actual persisted integrity coordinate. Presence alone does not authenticate the row.
    pub const fn ledger_sequence(&self) -> Option<u64> {
        self.ledger_sequence
    }
}

/// An append staged in the enclosing transaction; never commit evidence.
#[derive(Debug)]
pub struct StagedAppend {
    pub(crate) record: Record,
    pub(crate) inserted: bool,
}
impl StagedAppend {
    /// Persisted or staged record associated with the stable identity.
    pub const fn record(&self) -> &Record {
        &self.record
    }
    /// Whether this transaction inserted rather than replayed an existing record.
    pub const fn inserted(&self) -> bool {
        self.inserted
    }
}

/// Ordinary page within a fixed first-page upper bound; not a fixed membership or MVCC snapshot.
/// A lower position committed after it was passed may appear only in a fresh query.
#[derive(Debug)]
pub struct Page {
    pub(crate) records: Vec<Record>,
    pub(crate) next: Option<Cursor>,
}
impl Page {
    /// Structurally checked records; no cryptographic integrity claim.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    /// Resume within the fixed upper bound; absent on the final or empty page.
    pub const fn next(&self) -> Option<Cursor> {
        self.next
    }
}
