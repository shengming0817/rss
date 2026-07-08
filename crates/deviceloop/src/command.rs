//! Device command L4 state machine.
//!
//! The model stays provider-agnostic: it returns dispatch intent with a stable key, and composition
//! roots decide how to bridge that intent into contract-backed command transport.
//! ref: kube-rs kube-runtime/src/controller/mod.rs@main
//! ref: mdeloof/statig statig/src/lib.rs@main

use std::time::{Duration, SystemTime};

use ids::DeviceId;
use vocab::TenantId;

/// Device command state-machine error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceCommandError {
    /// Opaque command/ack id is empty, blank, or contains control characters.
    #[error("device command id is not canonical")]
    InvalidId,
    /// Transition was requested from a state that does not allow it.
    #[error("device command state does not allow the transition")]
    InvalidState,
    /// Transition input belongs to another command.
    #[error("device command id does not match")]
    CommandMismatch,
    /// Transition input belongs to another tenant/device scope.
    #[error("device command scope does not match")]
    ScopeMismatch,
    /// Ack timeout must be non-zero.
    #[error("device command ack timeout must be non-zero")]
    InvalidTimeout,
    /// Deadline overflowed `SystemTime`.
    #[error("device command deadline overflowed")]
    DeadlineOverflow,
    /// Command timestamps are not monotonic.
    #[error("device command timestamps are not monotonic")]
    InvalidTimestampOrder,
}

/// Stable device command id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceCommandId(String);

impl DeviceCommandId {
    /// Parse a stable command id through the single public funnel.
    pub fn parse(raw: &str) -> Result<Self, DeviceCommandError> {
        parse_opaque_id(raw).map(Self)
    }

    /// Borrow the canonical command id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable device ack id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceAckId(String);

impl DeviceAckId {
    /// Parse a stable ack id through the single public funnel.
    pub fn parse(raw: &str) -> Result<Self, DeviceCommandError> {
        parse_opaque_id(raw).map(Self)
    }

    /// Borrow the canonical ack id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_opaque_id(raw: &str) -> Result<String, DeviceCommandError> {
    if raw.is_empty() || raw.trim().is_empty() || raw.chars().any(char::is_control) {
        return Err(DeviceCommandError::InvalidId);
    }
    Ok(raw.to_string())
}

/// Device connectivity observed by the L4 loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DevicePresence {
    /// Device is currently reachable.
    Online,
    /// Device is currently unreachable; command dispatch must wait.
    Offline,
}

/// Terminal convergence result label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceConvergenceResult {
    /// Command was acknowledged by the device.
    Acked,
    /// Command exceeded its ack deadline.
    TimedOut,
}

impl DeviceConvergenceResult {
    /// Stable low-cardinality label.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Acked => "acked",
            Self::TimedOut => "timed_out",
        }
    }
}

/// Tenant/device scope for a command lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceCommandScope {
    tenant: TenantId,
    device: DeviceId,
}

impl DeviceCommandScope {
    /// Build a command scope from already-validated tenant and device ids.
    pub fn new(tenant: TenantId, device: DeviceId) -> Self {
        Self { tenant, device }
    }

    /// Tenant that owns the command.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Device that owns the command.
    pub fn device(&self) -> DeviceId {
        self.device
    }
}

/// Provider-agnostic command dispatch intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDispatchIntent {
    scope: DeviceCommandScope,
    command_id: DeviceCommandId,
    stable_dispatch_key: String,
}

impl DeviceDispatchIntent {
    fn new(scope: DeviceCommandScope, command_id: DeviceCommandId) -> Self {
        let tenant = scope.tenant().to_string();
        let device = scope.device().as_uuid().hyphenated().to_string();
        let command = command_id.as_str();
        let stable_dispatch_key = format!(
            "devicecmd:v1:t{}:{tenant}:d{}:{device}:c{}:{command}",
            tenant.len(),
            device.len(),
            command.len()
        );
        Self {
            scope,
            command_id,
            stable_dispatch_key,
        }
    }

    /// Target tenant/device scope.
    pub fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    /// Target device id.
    pub fn device_id(&self) -> DeviceId {
        self.scope.device()
    }

    /// Target command id.
    pub fn command_id(&self) -> &DeviceCommandId {
        &self.command_id
    }

    /// Stable idempotency key for lower command outbox layers.
    pub fn stable_dispatch_key(&self) -> &str {
        &self.stable_dispatch_key
    }
}

/// Device ack observed by the L4 loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAck {
    scope: DeviceCommandScope,
    command_id: DeviceCommandId,
    ack_id: DeviceAckId,
    observed_at: SystemTime,
}

impl DeviceAck {
    /// Build an ack from already-validated scope and ids.
    pub fn new(
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        ack_id: DeviceAckId,
        observed_at: SystemTime,
    ) -> Self {
        Self {
            scope,
            command_id,
            ack_id,
            observed_at,
        }
    }

    /// Tenant/device scope this ack belongs to.
    pub fn scope(&self) -> DeviceCommandScope {
        self.scope
    }

    /// Command id this ack belongs to.
    pub fn command_id(&self) -> &DeviceCommandId {
        &self.command_id
    }

    /// Ack id.
    pub fn ack_id(&self) -> &DeviceAckId {
        &self.ack_id
    }

    /// Observation time supplied by the caller's injected clock boundary.
    pub fn observed_at(&self) -> SystemTime {
        self.observed_at
    }
}

/// Device command lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCommandState {
    inner: DeviceCommandStateKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceCommandStateKind {
    Pending {
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        queued_at: SystemTime,
    },
    Sent {
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        dispatch_key: String,
        queued_at: SystemTime,
        sent_at: SystemTime,
        ack_deadline: SystemTime,
    },
    Acked {
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        ack_id: DeviceAckId,
        queued_at: SystemTime,
        sent_at: SystemTime,
        acked_at: SystemTime,
        convergence_lag: Duration,
    },
    TimedOut {
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        queued_at: SystemTime,
        sent_at: SystemTime,
        timed_out_at: SystemTime,
        convergence_lag: Duration,
    },
}

/// Read-only command state view for callers that need to branch by lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceCommandSnapshot<'a> {
    /// Command exists but has not been dispatched to the device.
    Pending {
        scope: DeviceCommandScope,
        command_id: &'a DeviceCommandId,
        queued_at: SystemTime,
    },
    /// Command was dispatched and is awaiting an ack.
    Sent {
        scope: DeviceCommandScope,
        command_id: &'a DeviceCommandId,
        dispatch_key: &'a str,
        queued_at: SystemTime,
        sent_at: SystemTime,
        ack_deadline: SystemTime,
    },
    /// Command reached terminal acked state.
    Acked {
        scope: DeviceCommandScope,
        command_id: &'a DeviceCommandId,
        ack_id: &'a DeviceAckId,
        queued_at: SystemTime,
        sent_at: SystemTime,
        acked_at: SystemTime,
        convergence_lag: Duration,
    },
    /// Command reached terminal timed-out state.
    TimedOut {
        scope: DeviceCommandScope,
        command_id: &'a DeviceCommandId,
        queued_at: SystemTime,
        sent_at: SystemTime,
        timed_out_at: SystemTime,
        convergence_lag: Duration,
    },
}

impl DeviceCommandSnapshot<'_> {
    /// Terminal convergence lag when this snapshot represents a terminal state.
    pub fn convergence_lag(self) -> Option<Duration> {
        match self {
            Self::Acked {
                convergence_lag, ..
            }
            | Self::TimedOut {
                convergence_lag, ..
            } => Some(convergence_lag),
            Self::Pending { .. } | Self::Sent { .. } => None,
        }
    }
}

impl DeviceCommandState {
    /// Construct a pending command from a scope, validated id, and queue timestamp.
    pub fn pending(
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        queued_at: SystemTime,
    ) -> Self {
        Self {
            inner: DeviceCommandStateKind::Pending {
                scope,
                command_id,
                queued_at,
            },
        }
    }

    /// Current tenant/device scope.
    pub fn scope(&self) -> DeviceCommandScope {
        match &self.inner {
            DeviceCommandStateKind::Pending { scope, .. }
            | DeviceCommandStateKind::Sent { scope, .. }
            | DeviceCommandStateKind::Acked { scope, .. }
            | DeviceCommandStateKind::TimedOut { scope, .. } => *scope,
        }
    }

    /// Current command id.
    pub fn command_id(&self) -> &DeviceCommandId {
        match &self.inner {
            DeviceCommandStateKind::Pending { command_id, .. }
            | DeviceCommandStateKind::Sent { command_id, .. }
            | DeviceCommandStateKind::Acked { command_id, .. }
            | DeviceCommandStateKind::TimedOut { command_id, .. } => command_id,
        }
    }

    /// Read-only snapshot of the lifecycle state.
    pub fn snapshot(&self) -> DeviceCommandSnapshot<'_> {
        match &self.inner {
            DeviceCommandStateKind::Pending {
                scope,
                command_id,
                queued_at,
            } => DeviceCommandSnapshot::Pending {
                scope: *scope,
                command_id,
                queued_at: *queued_at,
            },
            DeviceCommandStateKind::Sent {
                scope,
                command_id,
                dispatch_key,
                queued_at,
                sent_at,
                ack_deadline,
            } => DeviceCommandSnapshot::Sent {
                scope: *scope,
                command_id,
                dispatch_key,
                queued_at: *queued_at,
                sent_at: *sent_at,
                ack_deadline: *ack_deadline,
            },
            DeviceCommandStateKind::Acked {
                scope,
                command_id,
                ack_id,
                queued_at,
                sent_at,
                acked_at,
                convergence_lag,
            } => DeviceCommandSnapshot::Acked {
                scope: *scope,
                command_id,
                ack_id,
                queued_at: *queued_at,
                sent_at: *sent_at,
                acked_at: *acked_at,
                convergence_lag: *convergence_lag,
            },
            DeviceCommandStateKind::TimedOut {
                scope,
                command_id,
                queued_at,
                sent_at,
                timed_out_at,
                convergence_lag,
            } => DeviceCommandSnapshot::TimedOut {
                scope: *scope,
                command_id,
                queued_at: *queued_at,
                sent_at: *sent_at,
                timed_out_at: *timed_out_at,
                convergence_lag: *convergence_lag,
            },
        }
    }

    /// Terminal convergence lag when available.
    pub fn convergence_lag(&self) -> Option<Duration> {
        match &self.inner {
            DeviceCommandStateKind::Acked {
                convergence_lag, ..
            }
            | DeviceCommandStateKind::TimedOut {
                convergence_lag, ..
            } => Some(*convergence_lag),
            DeviceCommandStateKind::Pending { .. } | DeviceCommandStateKind::Sent { .. } => None,
        }
    }

    /// Reconcile the current state against device presence and current time.
    pub fn reconcile(
        &self,
        presence: DevicePresence,
        now: SystemTime,
    ) -> DeviceReconcileTransition {
        match &self.inner {
            DeviceCommandStateKind::Acked { .. } | DeviceCommandStateKind::TimedOut { .. } => {
                DeviceReconcileTransition::new(self.clone(), DeviceCommandDecision::Noop)
            }
            DeviceCommandStateKind::Pending { .. } if presence == DevicePresence::Offline => {
                DeviceReconcileTransition::new(self.clone(), DeviceCommandDecision::AwaitOnline)
            }
            DeviceCommandStateKind::Pending {
                scope, command_id, ..
            } => {
                let intent = DeviceDispatchIntent::new(*scope, command_id.clone());
                DeviceReconcileTransition::new(
                    self.clone(),
                    DeviceCommandDecision::Dispatch(intent),
                )
            }
            DeviceCommandStateKind::Sent {
                scope,
                command_id,
                queued_at,
                sent_at,
                ack_deadline,
                ..
            } if now >= *ack_deadline => match terminal_lag(now, *queued_at, *sent_at) {
                Ok(lag) => {
                    let state = timed_out_state(*scope, command_id, *queued_at, *sent_at, now, lag);
                    DeviceReconcileTransition::new(state, DeviceCommandDecision::TimedOut { lag })
                }
                Err(DeviceCommandError::InvalidTimestampOrder) => DeviceReconcileTransition::new(
                    self.clone(),
                    DeviceCommandDecision::InvalidTimeOrder,
                ),
                Err(error) => unreachable!("terminal lag cannot fail with {error:?}"),
            },
            DeviceCommandStateKind::Sent { .. } if presence == DevicePresence::Offline => {
                DeviceReconcileTransition::new(self.clone(), DeviceCommandDecision::AwaitOnline)
            }
            DeviceCommandStateKind::Sent { .. } => {
                DeviceReconcileTransition::new(self.clone(), DeviceCommandDecision::AwaitAck)
            }
        }
    }

    /// Mark a pending command as dispatched with a computed ack deadline.
    pub fn mark_dispatched(
        &self,
        intent: &DeviceDispatchIntent,
        sent_at: SystemTime,
        ack_timeout: Duration,
    ) -> Result<Self, DeviceCommandError> {
        if ack_timeout.is_zero() {
            return Err(DeviceCommandError::InvalidTimeout);
        }
        let DeviceCommandStateKind::Pending {
            scope,
            command_id,
            queued_at,
        } = &self.inner
        else {
            return Err(DeviceCommandError::InvalidState);
        };
        ensure_not_before(sent_at, *queued_at)?;
        if *scope != intent.scope() {
            return Err(DeviceCommandError::ScopeMismatch);
        }
        if command_id != intent.command_id() {
            return Err(DeviceCommandError::CommandMismatch);
        }
        let ack_deadline = sent_at
            .checked_add(ack_timeout)
            .ok_or(DeviceCommandError::DeadlineOverflow)?;
        Ok(Self {
            inner: DeviceCommandStateKind::Sent {
                scope: *scope,
                command_id: command_id.clone(),
                dispatch_key: intent.stable_dispatch_key().to_string(),
                queued_at: *queued_at,
                sent_at,
                ack_deadline,
            },
        })
    }

    /// Apply an ack event.
    pub fn observe_ack(
        &self,
        ack: DeviceAck,
    ) -> Result<DeviceReconcileTransition, DeviceCommandError> {
        if self.scope() != ack.scope() {
            return Err(DeviceCommandError::ScopeMismatch);
        }
        if self.command_id() != ack.command_id() {
            return Err(DeviceCommandError::CommandMismatch);
        }
        match &self.inner {
            DeviceCommandStateKind::Sent {
                scope,
                command_id,
                queued_at,
                sent_at,
                ack_deadline,
                ..
            } if ack.observed_at() >= *ack_deadline => {
                let lag = terminal_lag(ack.observed_at(), *queued_at, *sent_at)?;
                let state = timed_out_state(
                    *scope,
                    command_id,
                    *queued_at,
                    *sent_at,
                    ack.observed_at(),
                    lag,
                );
                Ok(DeviceReconcileTransition::new(
                    state,
                    DeviceCommandDecision::TimedOut { lag },
                ))
            }
            DeviceCommandStateKind::Sent {
                scope,
                command_id,
                queued_at,
                sent_at,
                ..
            } => {
                let lag = terminal_lag(ack.observed_at(), *queued_at, *sent_at)?;
                let state = Self {
                    inner: DeviceCommandStateKind::Acked {
                        scope: *scope,
                        command_id: command_id.clone(),
                        queued_at: *queued_at,
                        sent_at: *sent_at,
                        ack_id: ack.ack_id().clone(),
                        acked_at: ack.observed_at(),
                        convergence_lag: lag,
                    },
                };
                Ok(DeviceReconcileTransition::new(
                    state,
                    DeviceCommandDecision::Acked { lag },
                ))
            }
            DeviceCommandStateKind::Acked {
                queued_at,
                sent_at,
                acked_at,
                ..
            } => {
                let _ = terminal_lag(*acked_at, *queued_at, *sent_at)?;
                ensure_not_before(ack.observed_at(), *sent_at)?;
                Ok(DeviceReconcileTransition::new(
                    self.clone(),
                    DeviceCommandDecision::DuplicateAck,
                ))
            }
            DeviceCommandStateKind::TimedOut {
                queued_at,
                sent_at,
                timed_out_at,
                ..
            } => {
                let _ = terminal_lag(*timed_out_at, *queued_at, *sent_at)?;
                ensure_not_before(ack.observed_at(), *sent_at)?;
                Ok(DeviceReconcileTransition::new(
                    self.clone(),
                    DeviceCommandDecision::LateAck,
                ))
            }
            DeviceCommandStateKind::Pending { .. } => Err(DeviceCommandError::InvalidState),
        }
    }
}

/// Reconcile decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceCommandDecision {
    /// Dispatch should be enqueued by the composition root.
    Dispatch(DeviceDispatchIntent),
    /// Command is waiting for device ack.
    AwaitAck,
    /// Device is offline; retry when the device is online.
    AwaitOnline,
    /// Ack completed the command.
    Acked { lag: Duration },
    /// Command timed out before an ack was observed.
    TimedOut { lag: Duration },
    /// Ack arrived after the command had already timed out; state is unchanged.
    LateAck,
    /// Ack was already applied; state is unchanged.
    DuplicateAck,
    /// Timestamps violated the command lifecycle ordering; state is unchanged.
    InvalidTimeOrder,
    /// Terminal state needs no further action.
    Noop,
}

/// Reconcile transition result.
#[must_use = "inspect the transition decision or consume it with finalize/into_dispatch_intent"]
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceReconcileTransition {
    state: DeviceCommandState,
    decision: DeviceCommandDecision,
}

impl DeviceReconcileTransition {
    fn new(state: DeviceCommandState, decision: DeviceCommandDecision) -> Self {
        Self { state, decision }
    }

    /// Read-only view of the resulting state.
    pub fn state(&self) -> DeviceCommandSnapshot<'_> {
        self.state.snapshot()
    }

    /// Decision for the caller.
    pub fn decision(&self) -> &DeviceCommandDecision {
        &self.decision
    }

    /// Consume and return the dispatch intent if this transition decided to dispatch.
    pub fn into_dispatch_intent(self) -> Option<DeviceDispatchIntent> {
        match self.decision {
            DeviceCommandDecision::Dispatch(intent) => Some(intent),
            DeviceCommandDecision::AwaitAck
            | DeviceCommandDecision::AwaitOnline
            | DeviceCommandDecision::Acked { .. }
            | DeviceCommandDecision::TimedOut { .. }
            | DeviceCommandDecision::LateAck
            | DeviceCommandDecision::DuplicateAck
            | DeviceCommandDecision::InvalidTimeOrder
            | DeviceCommandDecision::Noop => None,
        }
    }

    /// Consume the transition, record terminal convergence lag once, and return the resulting state.
    pub fn finalize(self) -> DeviceCommandState {
        match self.decision {
            DeviceCommandDecision::Acked { lag } => {
                record_device_command_convergence_lag(DeviceConvergenceResult::Acked, lag);
            }
            DeviceCommandDecision::TimedOut { lag } => {
                record_device_command_convergence_lag(DeviceConvergenceResult::TimedOut, lag);
            }
            DeviceCommandDecision::Dispatch(_)
            | DeviceCommandDecision::AwaitAck
            | DeviceCommandDecision::AwaitOnline
            | DeviceCommandDecision::LateAck
            | DeviceCommandDecision::DuplicateAck
            | DeviceCommandDecision::InvalidTimeOrder
            | DeviceCommandDecision::Noop => {}
        }
        self.state
    }
}

/// Emit device command convergence lag. Labels are closed and low-cardinality.
fn record_device_command_convergence_lag(result: DeviceConvergenceResult, lag: Duration) {
    metrics::histogram!(
        "device_command_convergence_lag_seconds",
        "result" => result.as_label()
    )
    .record(lag.as_secs_f64());
}

fn terminal_lag(
    terminal_at: SystemTime,
    queued_at: SystemTime,
    sent_at: SystemTime,
) -> Result<Duration, DeviceCommandError> {
    ensure_not_before(sent_at, queued_at)?;
    ensure_not_before(terminal_at, sent_at)?;
    duration_since_checked(terminal_at, queued_at)
}

fn ensure_not_before(later: SystemTime, earlier: SystemTime) -> Result<(), DeviceCommandError> {
    duration_since_checked(later, earlier).map(|_| ())
}

fn duration_since_checked(
    later: SystemTime,
    earlier: SystemTime,
) -> Result<Duration, DeviceCommandError> {
    later
        .duration_since(earlier)
        .map_err(|_| DeviceCommandError::InvalidTimestampOrder)
}

fn timed_out_state(
    scope: DeviceCommandScope,
    command_id: &DeviceCommandId,
    queued_at: SystemTime,
    sent_at: SystemTime,
    timed_out_at: SystemTime,
    convergence_lag: Duration,
) -> DeviceCommandState {
    DeviceCommandState {
        inner: DeviceCommandStateKind::TimedOut {
            scope,
            command_id: command_id.clone(),
            queued_at,
            sent_at,
            timed_out_at,
            convergence_lag,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ids::DeviceId;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use vocab::TenantId;

    use super::{
        DeviceAck, DeviceAckId, DeviceCommandDecision, DeviceCommandError, DeviceCommandId,
        DeviceCommandScope, DeviceCommandSnapshot, DeviceCommandState, DeviceDispatchIntent,
        DevicePresence, DeviceReconcileTransition,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_TENANT: &str = "9b6f0c8d-0de4-4d1b-bfa9-297f77fb9a90";
    const DEVICE: &str = "550e8400-e29b-41d4-a716-446655440000";
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[allow(clippy::expect_used)]
    fn tenant_id(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant id")
    }

    #[allow(clippy::expect_used)]
    fn device_id() -> DeviceId {
        DeviceId::parse(DEVICE).expect("canonical device id")
    }

    fn scope() -> DeviceCommandScope {
        DeviceCommandScope::new(tenant_id(TENANT), device_id())
    }

    fn other_scope() -> DeviceCommandScope {
        DeviceCommandScope::new(tenant_id(OTHER_TENANT), device_id())
    }

    #[allow(clippy::expect_used)]
    fn command_id(raw: &str) -> DeviceCommandId {
        DeviceCommandId::parse(raw).expect("valid command id")
    }

    #[allow(clippy::expect_used)]
    fn ack_id(raw: &str) -> DeviceAckId {
        DeviceAckId::parse(raw).expect("valid ack id")
    }

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn require_dispatch(
        transition: &DeviceReconcileTransition,
    ) -> TestResult<DeviceDispatchIntent> {
        match transition.decision() {
            DeviceCommandDecision::Dispatch(intent) => Ok(intent.clone()),
            other => Err(std::io::Error::other(format!("expected dispatch, got {other:?}")).into()),
        }
    }

    #[test]
    fn command_and_ack_ids_reject_empty_blank_and_control_chars() {
        assert!(DeviceCommandId::parse("").is_err());
        assert!(DeviceCommandId::parse("   ").is_err());
        assert!(DeviceCommandId::parse("cmd\n1").is_err());
        assert_eq!(command_id("cmd-1").as_str(), "cmd-1");

        assert!(DeviceAckId::parse("").is_err());
        assert!(DeviceAckId::parse("   ").is_err());
        assert!(DeviceAckId::parse("ack\r1").is_err());
        assert_eq!(ack_id("ack-1").as_str(), "ack-1");
    }

    #[test]
    fn pending_online_dispatches_stable_intent() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));

        let transition = state.reconcile(DevicePresence::Online, t(11));

        let intent = require_dispatch(&transition)?;
        assert_eq!(intent.scope(), scope());
        assert_eq!(intent.command_id().as_str(), "cmd-1");
        assert_eq!(
            intent.stable_dispatch_key(),
            "devicecmd:v1:t36:f47ac10b-58cc-4372-a567-0e02b2c3d479:d36:550e8400-e29b-41d4-a716-446655440000:c5:cmd-1"
        );
        assert_eq!(transition.state(), state.snapshot());
        Ok(())
    }

    #[test]
    fn sent_before_deadline_awaits_ack() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;

        let transition = sent.reconcile(DevicePresence::Online, t(40));

        assert_eq!(transition.decision(), &DeviceCommandDecision::AwaitAck);
        assert_eq!(transition.state(), sent.snapshot());
        Ok(())
    }

    #[test]
    fn sent_after_deadline_times_out() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;

        let transition = sent.reconcile(DevicePresence::Online, t(42));

        assert_eq!(
            transition.decision(),
            &DeviceCommandDecision::TimedOut {
                lag: Duration::from_secs(32)
            }
        );
        assert!(matches!(
            transition.state(),
            DeviceCommandSnapshot::TimedOut { .. }
        ));
        assert_eq!(
            transition.state().convergence_lag(),
            Some(Duration::from_secs(32))
        );
        Ok(())
    }

    #[test]
    fn sent_offline_after_deadline_times_out() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;

        let transition = sent.reconcile(DevicePresence::Offline, t(42));

        assert_eq!(
            transition.decision(),
            &DeviceCommandDecision::TimedOut {
                lag: Duration::from_secs(32)
            }
        );
        assert!(matches!(
            transition.state(),
            DeviceCommandSnapshot::TimedOut { .. }
        ));
        Ok(())
    }

    #[test]
    fn ack_success_and_duplicate_ack_are_idempotent() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;
        let ack = DeviceAck::new(scope(), command_id("cmd-1"), ack_id("ack-1"), t(17));

        let first = sent.observe_ack(ack.clone())?;
        assert_eq!(
            first.decision(),
            &DeviceCommandDecision::Acked {
                lag: Duration::from_secs(7)
            }
        );
        assert!(matches!(first.state(), DeviceCommandSnapshot::Acked { .. }));

        let first_state = first.finalize();
        let duplicate = first_state.observe_ack(ack)?;
        assert_eq!(duplicate.decision(), &DeviceCommandDecision::DuplicateAck);
        assert_eq!(duplicate.state(), first_state.snapshot());
        Ok(())
    }

    #[test]
    fn ack_with_same_command_id_but_different_scope_is_rejected() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;

        let observed = sent.observe_ack(DeviceAck::new(
            other_scope(),
            command_id("cmd-1"),
            ack_id("ack-wrong-scope"),
            t(17),
        ));

        let Err(error) = observed else {
            return Err(std::io::Error::other(
                "same command id in another scope must not complete this command",
            )
            .into());
        };
        assert_eq!(error, DeviceCommandError::ScopeMismatch);
        Ok(())
    }

    #[test]
    fn late_ack_after_deadline_times_out_instead_of_ack() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;

        let late = sent.observe_ack(DeviceAck::new(
            scope(),
            command_id("cmd-1"),
            ack_id("ack-1"),
            t(42),
        ))?;

        assert_eq!(
            late.decision(),
            &DeviceCommandDecision::TimedOut {
                lag: Duration::from_secs(32)
            }
        );
        assert!(matches!(
            late.state(),
            DeviceCommandSnapshot::TimedOut { .. }
        ));
        Ok(())
    }

    #[test]
    fn persisted_timeout_late_ack_is_explicit_and_state_preserving() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;
        let timed_out = sent.reconcile(DevicePresence::Online, t(42)).finalize();

        let late = timed_out.observe_ack(DeviceAck::new(
            scope(),
            command_id("cmd-1"),
            ack_id("late-ack"),
            t(50),
        ));

        let late = late?;
        assert_eq!(late.decision(), &DeviceCommandDecision::LateAck);
        assert_eq!(late.state(), timed_out.snapshot());
        Ok(())
    }

    #[test]
    fn ack_before_queued_time_is_rejected_instead_of_zero_lag() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;

        let observed = sent.observe_ack(DeviceAck::new(
            scope(),
            command_id("cmd-1"),
            ack_id("ack-before-queue"),
            t(9),
        ));

        let Err(error) = observed else {
            return Err(std::io::Error::other(
                "ack before queued_at must not be recorded as zero lag",
            )
            .into());
        };
        assert_eq!(error, DeviceCommandError::InvalidTimestampOrder);
        Ok(())
    }

    #[test]
    fn invalid_sent_time_order_does_not_emit_zero_lag_timeout() {
        let invalid_sent = DeviceCommandState {
            inner: super::DeviceCommandStateKind::Sent {
                scope: scope(),
                command_id: command_id("cmd-1"),
                dispatch_key: "dispatch".to_string(),
                queued_at: t(20),
                sent_at: t(1),
                ack_deadline: t(5),
            },
        };

        let transition = invalid_sent.reconcile(DevicePresence::Online, t(6));

        assert_eq!(
            transition.decision(),
            &DeviceCommandDecision::InvalidTimeOrder
        );
        assert_eq!(transition.state(), invalid_sent.snapshot());
    }

    #[test]
    fn terminal_states_ignore_presence() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;
        let acked = sent
            .observe_ack(DeviceAck::new(
                scope(),
                command_id("cmd-1"),
                ack_id("ack-1"),
                t(17),
            ))?
            .finalize();

        assert_eq!(
            acked.reconcile(DevicePresence::Offline, t(18)).decision(),
            &DeviceCommandDecision::Noop
        );

        let timed_out = sent.reconcile(DevicePresence::Online, t(42)).finalize();
        assert_eq!(
            timed_out
                .reconcile(DevicePresence::Offline, t(43))
                .decision(),
            &DeviceCommandDecision::Noop
        );
        Ok(())
    }

    #[test]
    fn offline_reconcile_waits_and_online_reuses_stable_key() -> TestResult {
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));

        let offline = state.reconcile(DevicePresence::Offline, t(12));
        assert_eq!(offline.decision(), &DeviceCommandDecision::AwaitOnline);
        assert_eq!(offline.state(), state.snapshot());

        let offline_state = offline.finalize();
        let online = offline_state.reconcile(DevicePresence::Online, t(20));
        let intent = require_dispatch(&online)?;

        assert_eq!(
            intent.stable_dispatch_key(),
            "devicecmd:v1:t36:f47ac10b-58cc-4372-a567-0e02b2c3d479:d36:550e8400-e29b-41d4-a716-446655440000:c5:cmd-1"
        );
        Ok(())
    }

    #[test]
    fn convergence_lag_metric_uses_result_label_only() -> TestResult {
        let recorder = PrometheusBuilder::new().build_recorder();
        let state = DeviceCommandState::pending(scope(), command_id("cmd-1"), t(10));
        let transition = state.reconcile(DevicePresence::Online, t(11));
        let intent = require_dispatch(&transition)?;
        let sent = state.mark_dispatched(&intent, t(11), Duration::from_secs(30))?;
        let timeout = sent.reconcile(DevicePresence::Online, t(42));

        metrics::with_local_recorder(&recorder, || {
            let _state = timeout.finalize();
        });

        let rendered = recorder.handle().render();
        assert!(
            rendered.contains("device_command_convergence_lag_seconds"),
            "{rendered}"
        );
        assert!(rendered.contains("result=\"timed_out\""), "{rendered}");
        assert!(!rendered.contains(DEVICE), "{rendered}");
        assert!(!rendered.contains("cmd-1"), "{rendered}");
        Ok(())
    }
}
