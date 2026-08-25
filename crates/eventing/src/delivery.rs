//! Closed delivery outcomes and provider-neutral delivery budgets.

use std::time::Duration;

/// Closed reason for terminal rejection through the dead-letter path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectKind {
    /// The delivery cannot be decoded or handled permanently.
    Permanent,
    /// The delivery contradicts a trusted envelope or transaction invariant.
    Invariant,
}

impl RejectKind {
    /// Stable low-cardinality observability label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Permanent => "permanent",
            Self::Invariant => "invariant",
        }
    }
}

/// Result of one transactional fresh-delivery attempt.
#[must_use = "consumer transaction outcomes must be settled explicitly"]
pub enum ConsumerTxOutcome<C> {
    /// Durable commit succeeded and carries provider-owned evidence.
    Committed(C),
    /// The handler failed without committing and may use the local retry policy.
    HandlerTransient,
    /// Infrastructure failed without a confirmed commit; broker redelivery is required.
    InfrastructureTransient,
    /// The delivery is terminal and must use the dead-letter transaction path.
    Rejected(RejectKind),
    /// Commit may have succeeded; replaying the handler locally is unsafe.
    CommitUnknown,
    /// Rollback was not acknowledged; replaying the handler locally is unsafe.
    RollbackFailed,
    /// The claimed inbox lease is no longer authoritative.
    Fenced,
}

impl<C> ConsumerTxOutcome<C> {
    /// Stable low-cardinality observability label.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Committed(_) => "committed",
            Self::HandlerTransient => "handler_transient",
            Self::InfrastructureTransient => "infrastructure_transient",
            Self::Rejected(RejectKind::Permanent) => "rejected_permanent",
            Self::Rejected(RejectKind::Invariant) => "rejected_invariant",
            Self::CommitUnknown => "commit_unknown",
            Self::RollbackFailed => "rollback_failed",
            Self::Fenced => "fenced",
        }
    }
}

/// Provider-neutral publication failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishErrorKind {
    /// The provider definitively did not accept the event and retry may succeed.
    Transient,
    /// Retry cannot succeed without changing the authored event or configuration.
    Permanent,
    /// The provider may have accepted the event; retry must preserve the event identity.
    Ambiguous,
}

impl PublishErrorKind {
    /// Whether retry is permitted with the same event identity.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient | Self::Ambiguous)
    }

    /// Whether the provider outcome is ambiguous.
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(self, Self::Ambiguous)
    }

    /// Whether retry is permanently disallowed.
    #[must_use]
    pub const fn is_permanent(self) -> bool {
        matches!(self, Self::Permanent)
    }
}

/// Maximum supported duration for any individual delivery budget component.
pub const DELIVERY_BUDGET_MAX: Duration = Duration::from_millis(86_400_000);

/// Failure while constructing a [`DeliveryBudget`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeliveryBudgetError {
    /// A required component is zero.
    #[error("delivery budget {field} must be non-zero")]
    Zero { field: &'static str },
    /// Operational boundaries require exact millisecond resolution.
    #[error("delivery budget {field} must use integral milliseconds")]
    NonIntegralMilliseconds { field: &'static str },
    /// A component exceeds [`DELIVERY_BUDGET_MAX`].
    #[error("delivery budget {field} exceeds operational maximum {max:?}")]
    OperationalRangeExceeded { field: &'static str, max: Duration },
    /// The required budget cannot be represented by [`Duration`].
    #[error("delivery required budget overflows Duration")]
    RequiredBudgetOverflow,
    /// Publish, settlement and safety must fit strictly inside the lease.
    #[error("delivery required budget {required:?} must be strictly below lease {lease:?}")]
    RequiredBudgetNotBelowLease { lease: Duration, required: Duration },
}

/// Validated I/O and lease budget for one delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryBudget {
    lease_ttl: Duration,
    publish_timeout: Duration,
    settle_timeout: Duration,
    safety_margin: Duration,
}

impl DeliveryBudget {
    /// Constructs a complete validated delivery budget.
    pub fn new(
        lease_ttl: Duration,
        publish_timeout: Duration,
        settle_timeout: Duration,
        safety_margin: Duration,
    ) -> Result<Self, DeliveryBudgetError> {
        let required = publish_timeout
            .checked_add(settle_timeout)
            .and_then(|value| value.checked_add(safety_margin))
            .ok_or(DeliveryBudgetError::RequiredBudgetOverflow)?;
        for (field, duration) in [
            ("lease_ttl", lease_ttl),
            ("publish_timeout", publish_timeout),
            ("settle_timeout", settle_timeout),
            ("safety_margin", safety_margin),
        ] {
            validate_duration(field, duration)?;
        }
        if required >= lease_ttl {
            return Err(DeliveryBudgetError::RequiredBudgetNotBelowLease {
                lease: lease_ttl,
                required,
            });
        }
        Ok(Self {
            lease_ttl,
            publish_timeout,
            settle_timeout,
            safety_margin,
        })
    }

    #[must_use]
    /// Returns the durable claim lease bound.
    pub const fn lease_ttl(&self) -> Duration {
        self.lease_ttl
    }

    #[must_use]
    /// Returns the publisher I/O bound.
    pub const fn publish_timeout(&self) -> Duration {
        self.publish_timeout
    }

    #[must_use]
    /// Returns the settlement I/O bound.
    pub const fn settle_timeout(&self) -> Duration {
        self.settle_timeout
    }

    #[must_use]
    /// Returns the reserve kept between I/O completion and lease expiry.
    pub const fn safety_margin(&self) -> Duration {
        self.safety_margin
    }

    #[must_use]
    /// Returns `publish_timeout + settle_timeout + safety_margin`.
    pub fn required_budget(&self) -> Duration {
        self.publish_timeout
            .saturating_add(self.settle_timeout)
            .saturating_add(self.safety_margin)
    }

    /// Whether the remaining lease is strictly greater than one complete provider attempt.
    ///
    /// Equality fails closed so provider I/O cannot consume the settlement and safety reserve.
    #[must_use]
    pub fn can_start_attempt(&self, remaining: Duration) -> bool {
        remaining > self.required_budget()
    }

    #[must_use]
    /// Returns the publisher watchdog bound including the safety reserve.
    pub fn publisher_watchdog_timeout(&self) -> Duration {
        self.publish_timeout.saturating_add(self.safety_margin)
    }
}

fn validate_duration(field: &'static str, duration: Duration) -> Result<(), DeliveryBudgetError> {
    if duration.is_zero() {
        return Err(DeliveryBudgetError::Zero { field });
    }
    if !duration.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(DeliveryBudgetError::NonIntegralMilliseconds { field });
    }
    if duration > DELIVERY_BUDGET_MAX {
        return Err(DeliveryBudgetError::OperationalRangeExceeded {
            field,
            max: DELIVERY_BUDGET_MAX,
        });
    }
    Ok(())
}
