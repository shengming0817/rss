//! Inbound HTTP server request budget.
//!
//! The budget is a non-zero millisecond value and is consumed by the only bindable HTTP route
//! funnel. A zero or missing production value is therefore rejected before any listener binds;
//! there is no unbounded compatibility path.

use std::num::NonZeroU64;
use std::time::Duration;

/// Non-zero wall-clock budget for one complete inbound HTTP request.
///
/// The timer covers body processing, authentication, authorization, the handler, and every
/// downstream future below the server edge. Expiry drops that entire future and returns the shared
/// 503 envelope with `retryable=false` because the request outcome is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerRequestBudget(NonZeroU64);

impl ServerRequestBudget {
    /// Construct a budget from a non-zero millisecond count.
    pub const fn from_millis(millis: NonZeroU64) -> Self {
        Self(millis)
    }

    /// Millisecond value used for configuration and low-cardinality telemetry.
    pub const fn millis(self) -> NonZeroU64 {
        self.0
    }

    pub(crate) const fn duration(self) -> Duration {
        Duration::from_millis(self.0.get())
    }

    /// Long test budget for ordinary request tests. Production code cannot call this constructor.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn for_test() -> Self {
        match NonZeroU64::new(30_000) {
            Some(millis) => Self(millis),
            None => unreachable!(),
        }
    }
}
