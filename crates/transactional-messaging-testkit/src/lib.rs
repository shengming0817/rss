//! Provider-neutral transactional messaging conformance and deterministic test doubles.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod localtx;

#[cfg(feature = "producer")]
pub mod outbox;

#[cfg(feature = "consumer")]
pub mod inbox;

#[cfg(feature = "consumer")]
pub mod consumer;

pub mod memory;

use std::future::Future;
use std::task::Poll;

use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging::policy::{AbsoluteDeadline, ExecutionBudget, ExecutionTimer};

/// One provider-neutral conformance assertion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceError {
    detail: ErrorDetail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorDetail {
    Mismatch {
        stage: &'static str,
        expected: &'static str,
        actual: &'static str,
    },
    Count {
        stage: &'static str,
        expected: usize,
        actual: usize,
    },
    Provider {
        stage: &'static str,
        phase: ProviderPhase,
        kind: MessagingErrorKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderPhase {
    Fixture,
    Connect,
    Publish,
    Delivery,
    Settlement,
    Shutdown,
}

impl ConformanceError {
    pub(crate) const fn mismatch(
        stage: &'static str,
        expected: &'static str,
        actual: &'static str,
    ) -> Self {
        Self {
            detail: ErrorDetail::Mismatch {
                stage,
                expected,
                actual,
            },
        }
    }

    pub(crate) const fn count(stage: &'static str, expected: usize, actual: usize) -> Self {
        Self {
            detail: ErrorDetail::Count {
                stage,
                expected,
                actual,
            },
        }
    }

    #[cfg(any(feature = "consumer", feature = "producer"))]
    pub(crate) const fn provider(stage: &'static str, kind: MessagingErrorKind) -> Self {
        Self::mismatch(stage, "provider-operation-success", kind.as_label())
    }

    /// Construct a provider-neutral fixture-phase failure.
    #[must_use]
    pub const fn fixture(kind: MessagingErrorKind) -> Self {
        Self::provider_phase(ProviderPhase::Fixture, kind)
    }

    /// Construct a provider-neutral connection-phase failure.
    #[must_use]
    pub const fn connect(kind: MessagingErrorKind) -> Self {
        Self::provider_phase(ProviderPhase::Connect, kind)
    }

    /// Construct a provider-neutral publication-phase failure.
    #[must_use]
    pub const fn publish(kind: MessagingErrorKind) -> Self {
        Self::provider_phase(ProviderPhase::Publish, kind)
    }

    /// Construct a provider-neutral delivery-phase failure.
    #[must_use]
    pub const fn delivery(kind: MessagingErrorKind) -> Self {
        Self::provider_phase(ProviderPhase::Delivery, kind)
    }

    /// Construct a provider-neutral settlement-phase failure.
    #[must_use]
    pub const fn settlement(kind: MessagingErrorKind) -> Self {
        Self::provider_phase(ProviderPhase::Settlement, kind)
    }

    /// Construct a provider-neutral shutdown-phase failure.
    #[must_use]
    pub const fn shutdown(kind: MessagingErrorKind) -> Self {
        Self::provider_phase(ProviderPhase::Shutdown, kind)
    }

    const fn provider_phase(phase: ProviderPhase, kind: MessagingErrorKind) -> Self {
        Self {
            detail: ErrorDetail::Provider {
                stage: "provider",
                phase,
                kind,
            },
        }
    }

    #[cfg(any(feature = "consumer", feature = "producer"))]
    pub(crate) const fn at_stage(self, stage: &'static str) -> Self {
        match self.detail {
            ErrorDetail::Provider { phase, kind, .. } => Self {
                detail: ErrorDetail::Provider { stage, phase, kind },
            },
            _ => self,
        }
    }

    /// Return the stable scenario stage at which conformance failed.
    #[must_use]
    pub const fn stage(self) -> &'static str {
        match self.detail {
            ErrorDetail::Mismatch { stage, .. }
            | ErrorDetail::Count { stage, .. }
            | ErrorDetail::Provider { stage, .. } => stage,
        }
    }

    /// Whether this failure is an aggregate count mismatch.
    #[must_use]
    pub const fn is_count(self) -> bool {
        matches!(self.detail, ErrorDetail::Count { .. })
    }

    /// Return the closed provider phase, when the driver failed inside an operation.
    #[must_use]
    pub const fn provider_phase_label(self) -> Option<&'static str> {
        match self.detail {
            ErrorDetail::Provider { phase, .. } => Some(phase.as_label()),
            _ => None,
        }
    }
}

impl ProviderPhase {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Connect => "connect",
            Self::Publish => "publish",
            Self::Delivery => "delivery",
            Self::Settlement => "settlement",
            Self::Shutdown => "shutdown",
        }
    }
}

impl std::fmt::Display for ConformanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.detail {
            ErrorDetail::Mismatch {
                stage,
                expected,
                actual,
            } => write!(formatter, "{stage}: expected {expected}, got {actual}"),
            ErrorDetail::Count {
                stage,
                expected,
                actual,
            } => write!(
                formatter,
                "{stage}: expected count {expected}, got {actual}"
            ),
            ErrorDetail::Provider { stage, phase, kind } => write!(
                formatter,
                "{stage}/{}: expected provider-operation-success, got {}",
                phase.as_label(),
                kind.as_label()
            ),
        }
    }
}

impl std::error::Error for ConformanceError {}

fn suite_deadline(
    timer: &impl ExecutionTimer,
    budget: ExecutionBudget,
) -> Result<AbsoluteDeadline, ConformanceError> {
    AbsoluteDeadline::from_timeout(timer, budget.total()).map_err(|_| {
        ConformanceError::mismatch(
            "conformance.budget",
            "representable-positive-budget",
            "deadline-overflow",
        )
    })
}

async fn within_budget<T, F>(
    timer: &impl ExecutionTimer,
    deadline: AbsoluteDeadline,
    stage: &'static str,
    future: F,
) -> Result<T, ConformanceError>
where
    F: Future<Output = T>,
{
    if deadline.remaining(timer).is_zero() {
        return Err(ConformanceError::mismatch(
            stage,
            "completed-within-budget",
            "deadline_elapsed",
        ));
    }
    let delay = timer.sleep_until(deadline);
    let mut delay = std::pin::pin!(delay);
    let mut operation = std::pin::pin!(future);
    std::future::poll_fn(|context| {
        if Future::poll(delay.as_mut(), context).is_ready() {
            return Poll::Ready(Err(ConformanceError::mismatch(
                stage,
                "completed-within-budget",
                "deadline_elapsed",
            )));
        }
        Future::poll(operation.as_mut(), context).map(Ok)
    })
    .await
}
