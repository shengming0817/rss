use crate::{Access, Authority, Error, ErrorKind, Scope};
use rss_request_context::Deadline;
use std::future::Future;

/// One host-authorized maintenance operation. Reauthorize each page; the host owns
/// checkpoint completeness, baseline coverage, generation admission and scheduling.
#[derive(Debug)]
pub struct MaintenanceGrant {
    scope: Scope,
    cutoff: i64,
    release_through: i64,
}
impl MaintenanceGrant {
    /// Validate the exact scope and bounds against the host authority.
    pub fn verify(
        authority: &impl Authority,
        scope: Scope,
        cutoff: i64,
        release_through: i64,
    ) -> Result<Self, Error> {
        if cutoff < 0 || release_through < 0 {
            return Err(ErrorKind::InvalidInput.into());
        }
        authority.authorize(Access::Maintain {
            scope: &scope,
            cutoff,
            release_through,
        })?;
        Ok(Self {
            scope,
            cutoff,
            release_through,
        })
    }
    /// The sole stream whose content can be released.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }
    /// Latest eligible expiry, in server Unix seconds.
    pub const fn cutoff(&self) -> i64 {
        self.cutoff
    }
    /// Highest journal position whose content can be released.
    pub const fn release_through(&self) -> i64 {
        self.release_through
    }
}

/// Exclusive producer sequence and bounded number of candidate identities.
#[derive(Debug, Clone, Copy)]
pub struct ScanWindow {
    after: Option<u64>,
    limit: u8,
}
impl ScanWindow {
    /// Start at None; resume after the last examined sequence.
    pub fn new(after: Option<u64>, limit: u8) -> Result<Self, Error> {
        if !(1..=64).contains(&limit) {
            return Err(ErrorKind::InvalidInput.into());
        }
        Ok(Self { after, limit })
    }
    /// Last examined sequence of the prior confirmed page.
    pub const fn after(self) -> Option<u64> {
        self.after
    }
    /// Maximum number of candidate identities to examine.
    pub const fn limit(self) -> u8 {
        self.limit
    }
}

/// Statistics for this acknowledged transaction. Repeated pages only count new releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPage {
    /// Last sequence inspected; None if this page was empty.
    pub last_examined: Option<u64>,
    /// Whether this sweep has proven the stream exhausted.
    pub finished: bool,
    /// Number of identity headers visited, including ineligible and expired rows.
    pub scanned: u32,
    /// Number of bodies released by this transaction.
    pub reclaimed: u32,
    /// Logical canonical report bytes released.
    pub released_bytes: u64,
}
/// Host-scheduled, bounded maintenance. Retrying the same window is safe after uncertain settlement.
pub trait ObservationMaintenance: Send + Sync {
    /// Reclaim one page under the original deadline and product authority.
    fn reclaim(
        &self,
        grant: MaintenanceGrant,
        window: ScanWindow,
        deadline: Deadline,
    ) -> impl Future<Output = Result<RetentionPage, Error>> + Send;
}
