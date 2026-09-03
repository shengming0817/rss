//! Inbound HTTP server request budget.
//!
//! The budget is a non-zero millisecond value and is consumed by the only bindable HTTP route
//! funnel. A zero or missing production value is therefore rejected before any listener binds;
//! there is no unbounded compatibility path.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

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

/// Read-only projection of the one transport-owned request budget and cancellation source.
///
/// Only the sealed server middleware constructs this carrier. Downstream authorization and
/// Platform bridges may observe it, but cannot cancel a request or extend its deadline.
#[derive(Debug)]
pub struct RequestControl {
    deadline: Instant,
    cancellation: CancellationToken,
}

impl RequestControl {
    #[allow(
        clippy::disallowed_methods,
        reason = "transport middleware owns the monotonic request deadline source"
    )]
    pub(crate) fn start(budget: ServerRequestBudget) -> Arc<Self> {
        Arc::new(Self {
            deadline: Instant::now() + budget.duration(),
            cancellation: CancellationToken::new(),
        })
    }

    #[must_use]
    pub fn deadline(&self) -> rss_request_context::Deadline {
        rss_request_context::Deadline::at(self.deadline)
    }

    pub(crate) fn cancel(&self) {
        self.cancellation.cancel();
    }

    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test() -> Arc<Self> {
        Self::start(ServerRequestBudget::for_test())
    }
}

impl rss_request_context::CancellationObserver for RequestControl {
    fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn cancelled(
        &self,
        deadline: rss_request_context::Deadline,
    ) -> rss_request_context::CancellationFuture<'_> {
        let deadline = self.deadline.min(deadline.instant());
        Box::pin(async move {
            tokio::select! {
                () = self.cancellation.cancelled() => {
                    rss_request_context::CancellationReason::Cancelled
                }
                () = tokio::time::sleep_until(deadline.into()) => {
                    rss_request_context::CancellationReason::DeadlineExceeded
                }
            }
        })
    }
}

pub(crate) struct CancelRequestOnDrop(pub(crate) Arc<RequestControl>);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
