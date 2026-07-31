//! Provider-neutral device-command state machine.
//!
//! The state machine consumes authority evidence minted by [`crate::generation`]. Transport,
//! persistence, retries, and metrics stay outside this domain model.
//! ref: kube-rs@b60b81c88d37ab1f1f0d1ff7d42ab0ca268b4221
//! ref: statig@3780eecdbcf4326051c38676d592c6c2b4a3bab5

use std::time::SystemTime;

use ids::DeviceId;
use vocab::TenantId;

use crate::generation::{CurrentFence, FenceCoordinate, MatchingReportedState, NewerGeneration};

const MAX_COMMAND_ID_BYTES: usize = 256;

/// Device-command validation or transition error.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceCommandError {
    /// The command id is blank, too long, or contains a control character.
    #[error("device command id is not canonical")]
    InvalidId,
    /// A timestamp violates the state's monotonic ordering.
    #[error("device command timestamps are not monotonic")]
    InvalidTimestampOrder,
    /// The deadline is not later than the queue time.
    #[error("device command deadline must be later than queue time")]
    InvalidDeadline,
    /// Timeout was requested before the command deadline.
    #[error("device command deadline has not elapsed")]
    DeadlineNotElapsed,
    /// Authority evidence belongs to another generation or fence.
    #[error("device command authority does not match")]
    AuthorityMismatch,
    /// The persisted command version is outside the positive database range.
    #[error("device command version is outside 1..=i64::MAX")]
    InvalidVersion,
    /// The persisted state's fields do not satisfy that state's invariants.
    #[error("device command snapshot is invalid")]
    InvalidSnapshot,
    /// The command version cannot advance further.
    #[error("device command version overflowed")]
    VersionOverflow,
}

/// Bounded, provider-neutral command identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceCommandId(String);

impl DeviceCommandId {
    /// Validate an opaque command identifier.
    pub fn parse(raw: &str) -> Result<Self, DeviceCommandError> {
        if raw.is_empty()
            || raw.trim().is_empty()
            || raw.len() > MAX_COMMAND_ID_BYTES
            || raw.chars().any(char::is_control)
        {
            return Err(DeviceCommandError::InvalidId);
        }
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the validated identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable semantic identity of the desired command intent.
///
/// The digest algorithm is owned by the command authoring boundary. This type only makes the
/// exact persisted representation mandatory and prevents the digest from leaking through logs.
///
/// ```compile_fail
/// use deviceloop::CommandIntentDigest;
/// let _ = CommandIntentDigest([0_u8; 32]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandIntentDigest([u8; 32]);

impl CommandIntentDigest {
    /// Construct an already computed SHA-256 digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exact bytes used by persistence providers.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for CommandIntentDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CommandIntentDigest(<sha256>)")
    }
}

/// Tenant/device scope for one command lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceCommandScope {
    tenant: TenantId,
    device: DeviceId,
}

impl DeviceCommandScope {
    /// Build a scope from validated identifiers.
    pub fn new(tenant: TenantId, device: DeviceId) -> Self {
        Self { tenant, device }
    }

    /// Owning tenant.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Target device.
    pub fn device(&self) -> DeviceId {
        self.device
    }
}

/// Positive optimistic version of a command snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommandVersion(i64);

impl CommandVersion {
    /// First persisted version.
    pub const FIRST: Self = Self(1);

    /// Restore a checked positive version.
    pub fn restore(raw: i64) -> Result<Self, DeviceCommandError> {
        if raw < 1 {
            return Err(DeviceCommandError::InvalidVersion);
        }
        Ok(Self(raw))
    }

    /// Database representation.
    pub fn get(self) -> i64 {
        self.0
    }

    fn next(self) -> Result<Self, DeviceCommandError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(DeviceCommandError::VersionOverflow)
    }
}

/// Closed command-state vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceCommandStatus {
    /// Accepted for dispatch.
    Queued,
    /// Published to a transport.
    Published,
    /// Receipt acknowledged by the device.
    Received,
    /// Matching reported state was observed.
    Applied,
    /// The device rejected the command.
    Rejected,
    /// The deadline elapsed.
    TimedOut,
    /// A newer desired generation replaced the command.
    Superseded,
    /// The command was cancelled by its owner.
    Cancelled,
}

impl DeviceCommandStatus {
    /// Exhaustive state set.
    pub const ALL: [Self; 8] = [
        Self::Queued,
        Self::Published,
        Self::Received,
        Self::Applied,
        Self::Rejected,
        Self::TimedOut,
        Self::Superseded,
        Self::Cancelled,
    ];

    /// Stable low-cardinality label.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Published => "published",
            Self::Received => "received",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::TimedOut => "timed_out",
            Self::Superseded => "superseded",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether this state absorbs every later event.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Applied | Self::Rejected | Self::TimedOut | Self::Superseded | Self::Cancelled
        )
    }
}

/// Classification of a transition attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandTransitionOutcome {
    /// The state and version advanced.
    Advanced,
    /// The same event was already reflected by the state.
    Duplicate,
    /// A terminal state absorbed the event.
    Late,
    /// The event requires an earlier protocol step.
    OutOfOrder,
}

/// Result that always returns ownership of the command state.
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceCommandTransition {
    state: DeviceCommandState,
    outcome: CommandTransitionOutcome,
}

impl DeviceCommandTransition {
    /// Transition classification.
    pub fn outcome(&self) -> CommandTransitionOutcome {
        self.outcome
    }

    /// Consume the result and recover the state.
    pub fn into_state(self) -> DeviceCommandState {
        self.state
    }
}

/// A rejected transition attempt that returns ownership of the unchanged state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{error}")]
pub struct DeviceCommandTransitionError {
    state: Box<DeviceCommandState>,
    #[source]
    error: DeviceCommandError,
}

impl DeviceCommandTransitionError {
    /// Validation error that rejected the transition.
    pub fn error(&self) -> &DeviceCommandError {
        &self.error
    }

    /// Recover the unchanged command state.
    pub fn into_state(self) -> DeviceCommandState {
        *self.state
    }
}

/// Runtime command state with no nullable cross-state payload.
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceCommandState {
    inner: CommandState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandState {
    Queued(Base),
    Published(Published),
    Received(Received),
    Applied(Terminal),
    Rejected(Terminal),
    TimedOut(Terminal),
    Superseded(Terminal),
    Cancelled(Terminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Base {
    scope: DeviceCommandScope,
    command_id: DeviceCommandId,
    intent_digest: CommandIntentDigest,
    coordinate: FenceCoordinate,
    deadline: SystemTime,
    version: CommandVersion,
    queued_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Published {
    base: Base,
    published_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Received {
    published: Published,
    received_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Terminal {
    base: Base,
    progress: CommandProgress,
    terminal_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandProgress {
    Queued,
    Published {
        published_at: SystemTime,
    },
    Received {
        published_at: SystemTime,
        received_at: SystemTime,
    },
}

impl DeviceCommandState {
    /// Queue a command under the tracker's current generation and fence.
    ///
    /// The pre-durability signature without an intent digest no longer exists:
    ///
    /// ```compile_fail
    /// use deviceloop::{CurrentFence, DeviceCommandId, DeviceCommandState};
    /// use std::time::SystemTime;
    /// fn old_queue(command_id: DeviceCommandId, authority: CurrentFence) {
    ///     let _ = DeviceCommandState::queue(
    ///         command_id,
    ///         authority,
    ///         SystemTime::UNIX_EPOCH,
    ///         SystemTime::UNIX_EPOCH,
    ///     );
    /// }
    /// ```
    pub fn queue(
        command_id: DeviceCommandId,
        intent_digest: CommandIntentDigest,
        authority: CurrentFence,
        queued_at: SystemTime,
        deadline: SystemTime,
    ) -> Result<Self, DeviceCommandError> {
        if deadline <= queued_at {
            return Err(DeviceCommandError::InvalidDeadline);
        }
        Ok(Self {
            inner: CommandState::Queued(Base {
                scope: authority.scope(),
                command_id,
                intent_digest,
                coordinate: authority.coordinate(),
                deadline,
                version: CommandVersion::FIRST,
                queued_at,
            }),
        })
    }

    /// Current closed state.
    pub fn status(&self) -> DeviceCommandStatus {
        match self.inner {
            CommandState::Queued(_) => DeviceCommandStatus::Queued,
            CommandState::Published(_) => DeviceCommandStatus::Published,
            CommandState::Received(_) => DeviceCommandStatus::Received,
            CommandState::Applied(_) => DeviceCommandStatus::Applied,
            CommandState::Rejected(_) => DeviceCommandStatus::Rejected,
            CommandState::TimedOut(_) => DeviceCommandStatus::TimedOut,
            CommandState::Superseded(_) => DeviceCommandStatus::Superseded,
            CommandState::Cancelled(_) => DeviceCommandStatus::Cancelled,
        }
    }

    /// Current optimistic version.
    pub fn version(&self) -> CommandVersion {
        self.base().version
    }

    /// Tenant/device scope.
    pub fn scope(&self) -> DeviceCommandScope {
        self.base().scope
    }

    /// Command identifier.
    pub fn command_id(&self) -> &DeviceCommandId {
        &self.base().command_id
    }

    /// Stable semantic digest used for canonical-active uniqueness.
    pub fn intent_digest(&self) -> CommandIntentDigest {
        self.base().intent_digest
    }

    /// Generation/fence coordinate bound to the command.
    pub fn coordinate(&self) -> FenceCoordinate {
        self.base().coordinate
    }

    /// Publish a queued command. Publication never implies device receipt or application.
    pub fn publish(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.publish_checked(authority, at))
    }

    fn publish_checked(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        self.require_current(&authority)?;
        match self.inner {
            CommandState::Queued(mut base) => {
                require_at_or_after(at, base.queued_at)?;
                base.version = base.version.next()?;
                Ok(advanced(CommandState::Published(Published {
                    base,
                    published_at: at,
                })))
            }
            CommandState::Published(state) => Ok(noop(
                CommandState::Published(state),
                CommandTransitionOutcome::Duplicate,
            )),
            terminal if is_terminal(&terminal) => {
                Ok(noop(terminal, CommandTransitionOutcome::Late))
            }
            other => Ok(noop(other, CommandTransitionOutcome::OutOfOrder)),
        }
    }

    /// Record transport/device receipt. An ACK only reaches `Received`.
    pub fn ack_received(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.ack_received_checked(authority, at))
    }

    fn ack_received_checked(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        self.require_current(&authority)?;
        match self.inner {
            CommandState::Published(mut published) => {
                require_at_or_after(at, published.published_at)?;
                published.base.version = published.base.version.next()?;
                Ok(advanced(CommandState::Received(Received {
                    published,
                    received_at: at,
                })))
            }
            CommandState::Received(state) => Ok(noop(
                CommandState::Received(state),
                CommandTransitionOutcome::Duplicate,
            )),
            CommandState::Queued(state) => Ok(noop(
                CommandState::Queued(state),
                CommandTransitionOutcome::OutOfOrder,
            )),
            terminal => Ok(noop(terminal, CommandTransitionOutcome::Late)),
        }
    }

    /// Record rejection after publication.
    pub fn reject(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.reject_checked(authority, at))
    }

    fn reject_checked(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        self.require_current(&authority)?;
        match self.inner {
            CommandState::Published(mut published) => {
                require_at_or_after(at, published.published_at)?;
                published.base.version = published.base.version.next()?;
                Ok(advanced(CommandState::Rejected(Terminal {
                    base: published.base,
                    progress: CommandProgress::Published {
                        published_at: published.published_at,
                    },
                    terminal_at: at,
                })))
            }
            CommandState::Rejected(state) => Ok(noop(
                CommandState::Rejected(state),
                CommandTransitionOutcome::Duplicate,
            )),
            CommandState::Queued(state) => Ok(noop(
                CommandState::Queued(state),
                CommandTransitionOutcome::OutOfOrder,
            )),
            other => Ok(noop(other, CommandTransitionOutcome::Late)),
        }
    }

    /// Apply only after receipt and exact matching reported state.
    ///
    /// An ACK fence is deliberately not application evidence:
    ///
    /// ```compile_fail
    /// use std::time::SystemTime;
    /// use deviceloop::{CurrentFence, DeviceCommandState};
    ///
    /// fn ack_cannot_apply(state: DeviceCommandState, ack: CurrentFence) {
    ///     let _ = state.apply(ack, SystemTime::UNIX_EPOCH);
    /// }
    /// ```
    pub fn apply(
        self,
        evidence: MatchingReportedState,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.apply_checked(evidence, at))
    }

    fn apply_checked(
        self,
        evidence: MatchingReportedState,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        if self.scope() != evidence.scope() || self.coordinate() != evidence.coordinate() {
            return Err(DeviceCommandError::AuthorityMismatch);
        }
        match self.inner {
            CommandState::Received(mut received) => {
                require_at_or_after(at, received.received_at)?;
                received.published.base.version = received.published.base.version.next()?;
                Ok(advanced(CommandState::Applied(Terminal {
                    base: received.published.base,
                    progress: CommandProgress::Received {
                        published_at: received.published.published_at,
                        received_at: received.received_at,
                    },
                    terminal_at: at,
                })))
            }
            CommandState::Applied(state) => Ok(noop(
                CommandState::Applied(state),
                CommandTransitionOutcome::Duplicate,
            )),
            CommandState::Queued(state) => Ok(noop(
                CommandState::Queued(state),
                CommandTransitionOutcome::OutOfOrder,
            )),
            CommandState::Published(state) => Ok(noop(
                CommandState::Published(state),
                CommandTransitionOutcome::OutOfOrder,
            )),
            other => Ok(noop(other, CommandTransitionOutcome::Late)),
        }
    }

    /// Time out a nonterminal command after its deadline.
    pub fn timeout(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.timeout_checked(authority, at))
    }

    fn timeout_checked(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        self.require_current(&authority)?;
        if self.status().is_terminal() {
            return Ok(if self.status() == DeviceCommandStatus::TimedOut {
                noop(self.inner, CommandTransitionOutcome::Duplicate)
            } else {
                noop(self.inner, CommandTransitionOutcome::Late)
            });
        }
        if at < self.base().deadline {
            return Err(DeviceCommandError::DeadlineNotElapsed);
        }
        let terminal = terminal_from(self.inner, at, true)?;
        Ok(advanced(CommandState::TimedOut(terminal)))
    }

    /// Cancel a nonterminal command under its current fence.
    pub fn cancel(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.cancel_checked(authority, at))
    }

    fn cancel_checked(
        self,
        authority: CurrentFence,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        self.require_current(&authority)?;
        if self.status().is_terminal() {
            return Ok(if self.status() == DeviceCommandStatus::Cancelled {
                noop(self.inner, CommandTransitionOutcome::Duplicate)
            } else {
                noop(self.inner, CommandTransitionOutcome::Late)
            });
        }
        let terminal = terminal_from(self.inner, at, false)?;
        Ok(advanced(CommandState::Cancelled(terminal)))
    }

    /// Supersede a nonterminal command only with evidence of a newer generation.
    pub fn supersede(
        self,
        evidence: NewerGeneration,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        self.attempt(|state| state.supersede_checked(evidence, at))
    }

    fn supersede_checked(
        self,
        evidence: NewerGeneration,
        at: SystemTime,
    ) -> Result<DeviceCommandTransition, DeviceCommandError> {
        if self.scope() != evidence.scope()
            || self.coordinate() != evidence.previous_coordinate()
            || evidence.coordinate().generation() <= self.coordinate().generation()
        {
            return Err(DeviceCommandError::AuthorityMismatch);
        }
        if self.status().is_terminal() {
            return Ok(if self.status() == DeviceCommandStatus::Superseded {
                noop(self.inner, CommandTransitionOutcome::Duplicate)
            } else {
                noop(self.inner, CommandTransitionOutcome::Late)
            });
        }
        let terminal = terminal_from(self.inner, at, false)?;
        Ok(advanced(CommandState::Superseded(terminal)))
    }

    /// Produce an owned, state-specific persistence snapshot.
    pub fn snapshot(&self) -> DeviceCommandSnapshot {
        DeviceCommandSnapshot {
            inner: match &self.inner {
                CommandState::Queued(v) => CommandSnapshot::Queued(v.clone()),
                CommandState::Published(v) => CommandSnapshot::Published(v.clone()),
                CommandState::Received(v) => CommandSnapshot::Received(v.clone()),
                CommandState::Applied(v) => CommandSnapshot::Applied(v.clone()),
                CommandState::Rejected(v) => CommandSnapshot::Rejected(v.clone()),
                CommandState::TimedOut(v) => CommandSnapshot::TimedOut(v.clone()),
                CommandState::Superseded(v) => CommandSnapshot::Superseded(v.clone()),
                CommandState::Cancelled(v) => CommandSnapshot::Cancelled(v.clone()),
            },
        }
    }

    /// Restore without replaying entry actions, reading a clock, or emitting side effects.
    pub fn restore(input: DeviceCommandRestore) -> Result<Self, DeviceCommandError> {
        let inner = match input.inner {
            CommandSnapshot::Queued(v) => CommandState::Queued(v),
            CommandSnapshot::Published(v) => CommandState::Published(v),
            CommandSnapshot::Received(v) => CommandState::Received(v),
            CommandSnapshot::Applied(v) => CommandState::Applied(v),
            CommandSnapshot::Rejected(v) => CommandState::Rejected(v),
            CommandSnapshot::TimedOut(v) => CommandState::TimedOut(v),
            CommandSnapshot::Superseded(v) => CommandState::Superseded(v),
            CommandSnapshot::Cancelled(v) => CommandState::Cancelled(v),
        };
        validate_state(&inner)?;
        Ok(Self { inner })
    }

    fn base(&self) -> &Base {
        base_of(&self.inner)
    }

    fn require_current(&self, authority: &CurrentFence) -> Result<(), DeviceCommandError> {
        if self.scope() == authority.scope() && self.coordinate() == authority.coordinate() {
            Ok(())
        } else {
            Err(DeviceCommandError::AuthorityMismatch)
        }
    }

    fn attempt(
        self,
        operation: impl FnOnce(Self) -> Result<DeviceCommandTransition, DeviceCommandError>,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        let retained = Self {
            inner: self.inner.clone(),
        };
        operation(self).map_err(|error| DeviceCommandTransitionError {
            state: Box::new(retained),
            error,
        })
    }
}

/// Opaque owned persistence snapshot whose payload is state-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCommandSnapshot {
    inner: CommandSnapshot,
}

impl DeviceCommandSnapshot {
    /// Borrow an exhaustive state-specific projection for persistence.
    pub fn view(&self) -> DeviceCommandSnapshotView<'_> {
        match &self.inner {
            CommandSnapshot::Queued(base) => DeviceCommandSnapshotView::Queued {
                common: CommandSnapshotCommon(base),
            },
            CommandSnapshot::Published(value) => DeviceCommandSnapshotView::Published {
                common: CommandSnapshotCommon(&value.base),
                published_at: value.published_at,
            },
            CommandSnapshot::Received(value) => DeviceCommandSnapshotView::Received {
                common: CommandSnapshotCommon(&value.published.base),
                published_at: value.published.published_at,
                received_at: value.received_at,
            },
            CommandSnapshot::Applied(value) => {
                let CommandProgress::Received {
                    published_at,
                    received_at,
                } = value.progress
                else {
                    unreachable!("validated Applied snapshots have Received progress")
                };
                DeviceCommandSnapshotView::Applied {
                    common: CommandSnapshotCommon(&value.base),
                    published_at,
                    received_at,
                    applied_at: value.terminal_at,
                }
            }
            CommandSnapshot::Rejected(value) => {
                let CommandProgress::Published { published_at } = value.progress else {
                    unreachable!("validated Rejected snapshots have Published progress")
                };
                DeviceCommandSnapshotView::Rejected {
                    common: CommandSnapshotCommon(&value.base),
                    published_at,
                    rejected_at: value.terminal_at,
                }
            }
            CommandSnapshot::TimedOut(value) => DeviceCommandSnapshotView::TimedOut {
                common: CommandSnapshotCommon(&value.base),
                progress: CommandProgressSnapshot::from(&value.progress),
                timed_out_at: value.terminal_at,
            },
            CommandSnapshot::Superseded(value) => DeviceCommandSnapshotView::Superseded {
                common: CommandSnapshotCommon(&value.base),
                progress: CommandProgressSnapshot::from(&value.progress),
                superseded_at: value.terminal_at,
            },
            CommandSnapshot::Cancelled(value) => DeviceCommandSnapshotView::Cancelled {
                common: CommandSnapshotCommon(&value.base),
                progress: CommandProgressSnapshot::from(&value.progress),
                cancelled_at: value.terminal_at,
            },
        }
    }
}

/// Common checked fields shared by every state-specific snapshot projection.
#[derive(Debug, Clone, Copy)]
pub struct CommandSnapshotCommon<'a>(&'a Base);

impl<'a> CommandSnapshotCommon<'a> {
    /// Tenant/device scope.
    pub fn scope(self) -> DeviceCommandScope {
        self.0.scope
    }

    /// Command identifier.
    pub fn command_id(self) -> &'a DeviceCommandId {
        &self.0.command_id
    }

    /// Stable semantic digest used for canonical-active uniqueness.
    pub fn intent_digest(self) -> CommandIntentDigest {
        self.0.intent_digest
    }

    /// Generation/fence coordinate.
    pub fn coordinate(self) -> FenceCoordinate {
        self.0.coordinate
    }

    /// Command deadline.
    pub fn deadline(self) -> SystemTime {
        self.0.deadline
    }

    /// Checked optimistic version.
    pub fn version(self) -> CommandVersion {
        self.0.version
    }

    /// Server queue timestamp.
    pub fn queued_at(self) -> SystemTime {
        self.0.queued_at
    }
}

/// Progress reached before a terminal event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandProgressSnapshot {
    /// Terminal transition originated in `Queued`.
    Queued,
    /// Terminal transition originated in `Published`.
    Published {
        /// Server publication time.
        published_at: SystemTime,
    },
    /// Terminal transition originated in `Received`.
    Received {
        /// Server publication time.
        published_at: SystemTime,
        /// Server receipt time.
        received_at: SystemTime,
    },
}

impl From<&CommandProgress> for CommandProgressSnapshot {
    fn from(value: &CommandProgress) -> Self {
        match *value {
            CommandProgress::Queued => Self::Queued,
            CommandProgress::Published { published_at } => Self::Published { published_at },
            CommandProgress::Received {
                published_at,
                received_at,
            } => Self::Received {
                published_at,
                received_at,
            },
        }
    }
}

/// Exhaustive borrowed persistence projection with no nullable cross-state fields.
#[derive(Debug, Clone, Copy)]
pub enum DeviceCommandSnapshotView<'a> {
    /// Queued snapshot fields.
    Queued {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
    },
    /// Published snapshot fields.
    Published {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Server publication time.
        published_at: SystemTime,
    },
    /// Received snapshot fields.
    Received {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Server publication time.
        published_at: SystemTime,
        /// Server receipt time.
        received_at: SystemTime,
    },
    /// Applied snapshot fields.
    Applied {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Server publication time.
        published_at: SystemTime,
        /// Server receipt time.
        received_at: SystemTime,
        /// Server application-observation time.
        applied_at: SystemTime,
    },
    /// Rejected snapshot fields.
    Rejected {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Server publication time.
        published_at: SystemTime,
        /// Server rejection time.
        rejected_at: SystemTime,
    },
    /// Timed-out snapshot fields.
    TimedOut {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Progress reached before timeout.
        progress: CommandProgressSnapshot,
        /// Server timeout time.
        timed_out_at: SystemTime,
    },
    /// Superseded snapshot fields.
    Superseded {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Progress reached before supersession.
        progress: CommandProgressSnapshot,
        /// Server supersession time.
        superseded_at: SystemTime,
    },
    /// Cancelled snapshot fields.
    Cancelled {
        /// Fields shared by every state.
        common: CommandSnapshotCommon<'a>,
        /// Progress reached before cancellation.
        progress: CommandProgressSnapshot,
        /// Server cancellation time.
        cancelled_at: SystemTime,
    },
}

/// Checked common input accepted by state-specific restore constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRestoreCommon {
    base: Base,
}

impl CommandRestoreCommon {
    /// Assemble common persisted fields; cross-field validation happens in `restore`.
    pub fn new(
        scope: DeviceCommandScope,
        command_id: DeviceCommandId,
        intent_digest: CommandIntentDigest,
        coordinate: FenceCoordinate,
        deadline: SystemTime,
        version: CommandVersion,
        queued_at: SystemTime,
    ) -> Self {
        Self {
            base: Base {
                scope,
                command_id,
                intent_digest,
                coordinate,
                deadline,
                version,
                queued_at,
            },
        }
    }
}

/// State-specific progress input for terminal restore carriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandProgressRestore {
    progress: CommandProgress,
}

impl CommandProgressRestore {
    /// Restore terminal progress originating from `Queued`.
    pub fn queued() -> Self {
        Self {
            progress: CommandProgress::Queued,
        }
    }

    /// Restore terminal progress originating from `Published`.
    pub fn published(published_at: SystemTime) -> Self {
        Self {
            progress: CommandProgress::Published { published_at },
        }
    }

    /// Restore terminal progress originating from `Received`.
    pub fn received(published_at: SystemTime, received_at: SystemTime) -> Self {
        Self {
            progress: CommandProgress::Received {
                published_at,
                received_at,
            },
        }
    }
}

/// Untrusted, state-specific persistence input consumed by the restore funnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCommandRestore {
    inner: CommandSnapshot,
}

impl DeviceCommandRestore {
    /// Build raw queued-state restore input.
    pub fn queued(common: CommandRestoreCommon) -> Self {
        Self {
            inner: CommandSnapshot::Queued(common.base),
        }
    }

    /// Build raw published-state restore input.
    pub fn published(common: CommandRestoreCommon, published_at: SystemTime) -> Self {
        Self {
            inner: CommandSnapshot::Published(Published {
                base: common.base,
                published_at,
            }),
        }
    }

    /// Build raw received-state restore input.
    pub fn received(
        common: CommandRestoreCommon,
        published_at: SystemTime,
        received_at: SystemTime,
    ) -> Self {
        Self {
            inner: CommandSnapshot::Received(Received {
                published: Published {
                    base: common.base,
                    published_at,
                },
                received_at,
            }),
        }
    }

    /// Build raw applied-state restore input.
    pub fn applied(
        common: CommandRestoreCommon,
        published_at: SystemTime,
        received_at: SystemTime,
        applied_at: SystemTime,
    ) -> Self {
        Self {
            inner: CommandSnapshot::Applied(Terminal {
                base: common.base,
                progress: CommandProgress::Received {
                    published_at,
                    received_at,
                },
                terminal_at: applied_at,
            }),
        }
    }

    /// Build raw rejected-state restore input.
    pub fn rejected(
        common: CommandRestoreCommon,
        published_at: SystemTime,
        rejected_at: SystemTime,
    ) -> Self {
        Self {
            inner: CommandSnapshot::Rejected(Terminal {
                base: common.base,
                progress: CommandProgress::Published { published_at },
                terminal_at: rejected_at,
            }),
        }
    }

    /// Build raw timed-out-state restore input.
    pub fn timed_out(
        common: CommandRestoreCommon,
        progress: CommandProgressRestore,
        timed_out_at: SystemTime,
    ) -> Self {
        terminal_restore(common, progress, timed_out_at, CommandSnapshot::TimedOut)
    }

    /// Build raw superseded-state restore input.
    pub fn superseded(
        common: CommandRestoreCommon,
        progress: CommandProgressRestore,
        superseded_at: SystemTime,
    ) -> Self {
        terminal_restore(common, progress, superseded_at, CommandSnapshot::Superseded)
    }

    /// Build raw cancelled-state restore input.
    pub fn cancelled(
        common: CommandRestoreCommon,
        progress: CommandProgressRestore,
        cancelled_at: SystemTime,
    ) -> Self {
        terminal_restore(common, progress, cancelled_at, CommandSnapshot::Cancelled)
    }
}

impl From<DeviceCommandSnapshot> for DeviceCommandRestore {
    fn from(snapshot: DeviceCommandSnapshot) -> Self {
        Self {
            inner: snapshot.inner,
        }
    }
}

fn terminal_restore(
    common: CommandRestoreCommon,
    progress: CommandProgressRestore,
    terminal_at: SystemTime,
    wrap: fn(Terminal) -> CommandSnapshot,
) -> DeviceCommandRestore {
    DeviceCommandRestore {
        inner: wrap(Terminal {
            base: common.base,
            progress: progress.progress,
            terminal_at,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandSnapshot {
    Queued(Base),
    Published(Published),
    Received(Received),
    Applied(Terminal),
    Rejected(Terminal),
    TimedOut(Terminal),
    Superseded(Terminal),
    Cancelled(Terminal),
}

fn advanced(inner: CommandState) -> DeviceCommandTransition {
    DeviceCommandTransition {
        state: DeviceCommandState { inner },
        outcome: CommandTransitionOutcome::Advanced,
    }
}

fn noop(inner: CommandState, outcome: CommandTransitionOutcome) -> DeviceCommandTransition {
    DeviceCommandTransition {
        state: DeviceCommandState { inner },
        outcome,
    }
}

fn base_of(state: &CommandState) -> &Base {
    match state {
        CommandState::Queued(v) => v,
        CommandState::Published(v) => &v.base,
        CommandState::Received(v) => &v.published.base,
        CommandState::Applied(v)
        | CommandState::Rejected(v)
        | CommandState::TimedOut(v)
        | CommandState::Superseded(v)
        | CommandState::Cancelled(v) => &v.base,
    }
}

fn is_terminal(state: &CommandState) -> bool {
    matches!(
        state,
        CommandState::Applied(_)
            | CommandState::Rejected(_)
            | CommandState::TimedOut(_)
            | CommandState::Superseded(_)
            | CommandState::Cancelled(_)
    )
}

fn terminal_from(
    state: CommandState,
    at: SystemTime,
    deadline_checked: bool,
) -> Result<Terminal, DeviceCommandError> {
    let (mut base, progress, lower_bound) = match state {
        CommandState::Queued(base) => {
            let queued_at = base.queued_at;
            (base, CommandProgress::Queued, queued_at)
        }
        CommandState::Published(published) => {
            let lower = published.published_at;
            (
                published.base,
                CommandProgress::Published {
                    published_at: lower,
                },
                lower,
            )
        }
        CommandState::Received(received) => {
            let lower = received.received_at;
            (
                received.published.base,
                CommandProgress::Received {
                    published_at: received.published.published_at,
                    received_at: lower,
                },
                lower,
            )
        }
        _ => return Err(DeviceCommandError::InvalidSnapshot),
    };
    require_at_or_after(at, lower_bound)?;
    if deadline_checked && at < base.deadline {
        return Err(DeviceCommandError::DeadlineNotElapsed);
    }
    base.version = base.version.next()?;
    Ok(Terminal {
        base,
        progress,
        terminal_at: at,
    })
}

fn validate_state(state: &CommandState) -> Result<(), DeviceCommandError> {
    let base = base_of(state);
    CommandVersion::restore(base.version.get())?;
    let expected_version = match state {
        CommandState::Queued(_) => 1,
        CommandState::Published(_) => 2,
        CommandState::Received(_) | CommandState::Rejected(_) => 3,
        CommandState::Applied(_) => 4,
        CommandState::TimedOut(value)
        | CommandState::Superseded(value)
        | CommandState::Cancelled(value) => match value.progress {
            CommandProgress::Queued => 2,
            CommandProgress::Published { .. } => 3,
            CommandProgress::Received { .. } => 4,
        },
    };
    if base.version.get() != expected_version {
        return Err(DeviceCommandError::InvalidSnapshot);
    }
    if base.deadline <= base.queued_at {
        return Err(DeviceCommandError::InvalidSnapshot);
    }
    match state {
        CommandState::Queued(_) => Ok(()),
        CommandState::Published(v) => require_at_or_after(v.published_at, v.base.queued_at),
        CommandState::Received(v) => {
            require_at_or_after(v.published.published_at, v.published.base.queued_at)?;
            require_at_or_after(v.received_at, v.published.published_at)
        }
        CommandState::Applied(v) => {
            validate_terminal(v, Some(DeviceCommandStatus::Received), false)
        }
        CommandState::Rejected(v) => {
            validate_terminal(v, Some(DeviceCommandStatus::Published), false)
        }
        CommandState::TimedOut(v) => validate_terminal(v, None, true),
        CommandState::Superseded(v) | CommandState::Cancelled(v) => {
            validate_terminal(v, None, false)
        }
    }
    .map_err(|_| DeviceCommandError::InvalidSnapshot)
}

fn validate_terminal(
    value: &Terminal,
    required_progress: Option<DeviceCommandStatus>,
    deadline_required: bool,
) -> Result<(), DeviceCommandError> {
    let (actual_progress, lower) = match value.progress {
        CommandProgress::Queued => (DeviceCommandStatus::Queued, value.base.queued_at),
        CommandProgress::Published { published_at } => {
            require_at_or_after(published_at, value.base.queued_at)?;
            (DeviceCommandStatus::Published, published_at)
        }
        CommandProgress::Received {
            published_at,
            received_at,
        } => {
            require_at_or_after(published_at, value.base.queued_at)?;
            require_at_or_after(received_at, published_at)?;
            (DeviceCommandStatus::Received, received_at)
        }
    };
    if required_progress.is_some_and(|required| required != actual_progress) {
        return Err(DeviceCommandError::InvalidSnapshot);
    }
    require_at_or_after(value.terminal_at, lower)?;
    if deadline_required && value.terminal_at < value.base.deadline {
        return Err(DeviceCommandError::InvalidSnapshot);
    }
    Ok(())
}

fn require_at_or_after(at: SystemTime, lower: SystemTime) -> Result<(), DeviceCommandError> {
    if at < lower {
        Err(DeviceCommandError::InvalidTimestampOrder)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::generation::{DesiredGeneration, FenceEpoch, GenerationTracker};

    fn time(second: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(second)
    }

    fn scope() -> DeviceCommandScope {
        DeviceCommandScope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            DeviceId::parse("550e8400-e29b-41d4-a716-446655440000").expect("device"),
        )
    }

    fn other_scope() -> DeviceCommandScope {
        DeviceCommandScope::new(
            TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant"),
            DeviceId::parse("7e4b30e8-58f3-4b7f-a1ef-d5cc60dd18d4").expect("device"),
        )
    }

    fn tracker() -> GenerationTracker<&'static str> {
        GenerationTracker::new(
            scope(),
            DesiredGeneration::try_new(1).expect("generation"),
            "on",
            FenceEpoch::try_new(1).expect("epoch"),
        )
    }

    fn intent_digest() -> CommandIntentDigest {
        CommandIntentDigest::from_bytes([0x42; 32])
    }

    fn queued(tracker: &GenerationTracker<&'static str>) -> DeviceCommandState {
        DeviceCommandState::queue(
            DeviceCommandId::parse("rotate-cert").expect("id"),
            intent_digest(),
            tracker.current_fence(),
            time(10),
            time(20),
        )
        .expect("queue")
    }

    fn published(tracker: &GenerationTracker<&'static str>) -> DeviceCommandState {
        queued(tracker)
            .publish(tracker.current_fence(), time(11))
            .expect("publish")
            .into_state()
    }

    fn received(tracker: &GenerationTracker<&'static str>) -> DeviceCommandState {
        published(tracker)
            .ack_received(tracker.current_fence(), time(12))
            .expect("receive")
            .into_state()
    }

    fn assert_advanced(transition: DeviceCommandTransition, expected: DeviceCommandStatus) {
        assert_eq!(transition.outcome(), CommandTransitionOutcome::Advanced);
        assert_eq!(transition.into_state().status(), expected);
    }

    #[derive(Clone, Copy)]
    enum TestEvent {
        Publish,
        Ack,
        Reject,
        Apply,
        Timeout,
        Supersede,
        Cancel,
    }

    const EVENTS: [TestEvent; 7] = [
        TestEvent::Publish,
        TestEvent::Ack,
        TestEvent::Reject,
        TestEvent::Apply,
        TestEvent::Timeout,
        TestEvent::Supersede,
        TestEvent::Cancel,
    ];

    fn snapshot_common(snapshot: &DeviceCommandSnapshot) -> CommandSnapshotCommon<'_> {
        match snapshot.view() {
            DeviceCommandSnapshotView::Queued { common }
            | DeviceCommandSnapshotView::Published { common, .. }
            | DeviceCommandSnapshotView::Received { common, .. }
            | DeviceCommandSnapshotView::Applied { common, .. }
            | DeviceCommandSnapshotView::Rejected { common, .. }
            | DeviceCommandSnapshotView::TimedOut { common, .. }
            | DeviceCommandSnapshotView::Superseded { common, .. }
            | DeviceCommandSnapshotView::Cancelled { common, .. } => common,
        }
    }

    fn attempt_event(
        snapshot: &DeviceCommandSnapshot,
        event: TestEvent,
        authority_scope: DeviceCommandScope,
    ) -> Result<DeviceCommandTransition, DeviceCommandTransitionError> {
        let common = snapshot_common(snapshot);
        let mut authority = GenerationTracker::new(
            authority_scope,
            common.coordinate().generation(),
            "on",
            common.coordinate().epoch(),
        );
        let state = DeviceCommandState::restore(snapshot.clone().into()).expect("restore fixture");
        match event {
            TestEvent::Publish => state.publish(authority.current_fence(), time(30)),
            TestEvent::Ack => state.ack_received(authority.current_fence(), time(30)),
            TestEvent::Reject => state.reject(authority.current_fence(), time(30)),
            TestEvent::Apply => {
                let evidence = authority
                    .report(
                        crate::generation::ObservedGeneration::try_new(
                            common.coordinate().generation().get(),
                        )
                        .expect("observed"),
                        common.coordinate().epoch(),
                        "on",
                    )
                    .into_matching()
                    .expect("matching");
                state.apply(evidence, time(30))
            }
            TestEvent::Timeout => state.timeout(authority.current_fence(), time(30)),
            TestEvent::Supersede => {
                let evidence = authority
                    .advance_desired(
                        DesiredGeneration::try_new(common.coordinate().generation().get() + 1)
                            .expect("new generation"),
                        "off",
                        FenceEpoch::try_new(common.coordinate().epoch().get() + 1)
                            .expect("new epoch"),
                    )
                    .expect("advance");
                state.supersede(evidence, time(30))
            }
            TestEvent::Cancel => state.cancel(authority.current_fence(), time(30)),
        }
    }

    fn all_state_snapshots() -> Vec<(DeviceCommandStatus, DeviceCommandSnapshot)> {
        let authority = tracker();
        let queued_state = queued(&authority);
        let published_state = published(&authority);
        let received_state = received(&authority);
        let rejected_state = published(&authority)
            .reject(authority.current_fence(), time(12))
            .expect("reject")
            .into_state();
        let timed_out_state = queued(&authority)
            .timeout(authority.current_fence(), time(20))
            .expect("timeout")
            .into_state();
        let cancelled_state = received(&authority)
            .cancel(authority.current_fence(), time(13))
            .expect("cancel")
            .into_state();

        let mut matching_authority = tracker();
        let matching = matching_authority
            .report(
                crate::generation::ObservedGeneration::try_new(1).expect("observed"),
                FenceEpoch::try_new(1).expect("epoch"),
                "on",
            )
            .into_matching()
            .expect("matching");
        let applied_state = received(&matching_authority)
            .apply(matching, time(13))
            .expect("apply")
            .into_state();

        let mut newer = tracker();
        let supersede_candidate = published(&newer);
        let evidence = newer
            .advance_desired(
                DesiredGeneration::try_new(2).expect("generation"),
                "off",
                FenceEpoch::try_new(2).expect("epoch"),
            )
            .expect("advance");
        let superseded_state = supersede_candidate
            .supersede(evidence, time(12))
            .expect("supersede")
            .into_state();

        [
            queued_state,
            published_state,
            received_state,
            applied_state,
            rejected_state,
            timed_out_state,
            superseded_state,
            cancelled_state,
        ]
        .into_iter()
        .map(|state| (state.status(), state.snapshot()))
        .collect()
    }

    fn restore_common(version: i64) -> CommandRestoreCommon {
        let authority = tracker();
        CommandRestoreCommon::new(
            scope(),
            DeviceCommandId::parse("restore-test").expect("id"),
            intent_digest(),
            authority.fence_coordinate(),
            time(20),
            CommandVersion::restore(version).expect("version"),
            time(10),
        )
    }

    fn restore_common_with_deadline(version: i64, deadline: SystemTime) -> CommandRestoreCommon {
        let authority = tracker();
        CommandRestoreCommon::new(
            scope(),
            DeviceCommandId::parse("restore-test").expect("id"),
            intent_digest(),
            authority.fence_coordinate(),
            deadline,
            CommandVersion::restore(version).expect("version"),
            time(10),
        )
    }

    #[test]
    fn status_vocabulary_is_exact_and_closed() {
        assert_eq!(DeviceCommandStatus::ALL.len(), 8);
        assert_eq!(DeviceCommandStatus::Applied.as_label(), "applied");
        assert!(!DeviceCommandStatus::Received.is_terminal());
        assert!(DeviceCommandStatus::Rejected.is_terminal());
    }

    #[test]
    fn ids_are_bounded_and_canonical() {
        assert!(DeviceCommandId::parse("").is_err());
        assert!(DeviceCommandId::parse("  ").is_err());
        assert!(DeviceCommandId::parse("bad\n").is_err());
        assert!(DeviceCommandId::parse(&"x".repeat(257)).is_err());
        assert!(DeviceCommandId::parse(&"x".repeat(256)).is_ok());
        assert_eq!(
            CommandVersion::restore(0),
            Err(DeviceCommandError::InvalidVersion)
        );
        assert_eq!(
            CommandVersion::restore(-1),
            Err(DeviceCommandError::InvalidVersion)
        );
        assert_eq!(
            CommandVersion::restore(i64::MAX).expect("checked").get(),
            i64::MAX
        );
    }

    #[test]
    fn ack_and_matching_report_are_separate_steps() {
        let mut authority = tracker();
        let queued = queued(&authority);
        let published = queued
            .publish(authority.current_fence(), time(11))
            .expect("publish")
            .into_state();
        let received = published
            .ack_received(authority.current_fence(), time(12))
            .expect("ack")
            .into_state();
        assert_eq!(received.status(), DeviceCommandStatus::Received);
        let matching = authority
            .report(
                crate::generation::ObservedGeneration::try_new(1).expect("observed"),
                FenceEpoch::try_new(1).expect("epoch"),
                "on",
            )
            .into_matching()
            .expect("matching report");
        let applied = received
            .apply(matching, time(13))
            .expect("apply")
            .into_state();
        assert_eq!(applied.status(), DeviceCommandStatus::Applied);
    }

    #[test]
    fn report_before_ack_is_an_exact_noop() {
        let mut authority = tracker();
        let matching = authority
            .report(
                crate::generation::ObservedGeneration::try_new(1).expect("observed"),
                FenceEpoch::try_new(1).expect("epoch"),
                "on",
            )
            .into_matching()
            .expect("matching report");
        let queued = queued(&authority);
        let before = queued.snapshot();
        let transition = queued.apply(matching, time(11)).expect("no-op");
        assert_eq!(transition.outcome(), CommandTransitionOutcome::OutOfOrder);
        assert_eq!(transition.into_state().snapshot(), before);
    }

    #[test]
    fn duplicate_late_and_timeout_preserve_or_advance_version_exactly() {
        let authority = tracker();
        let queued = queued(&authority);
        let published = queued
            .publish(authority.current_fence(), time(11))
            .expect("publish")
            .into_state();
        assert_eq!(published.version().get(), 2);
        let before = published.snapshot();
        let duplicate = published
            .publish(authority.current_fence(), time(19))
            .expect("duplicate");
        assert_eq!(duplicate.outcome(), CommandTransitionOutcome::Duplicate);
        assert_eq!(duplicate.into_state().snapshot(), before);

        let published = DeviceCommandState::restore(before.into()).expect("restore");
        let rejected_attempt = published
            .timeout(authority.current_fence(), time(19))
            .expect_err("deadline has not elapsed");
        assert_eq!(
            rejected_attempt.error(),
            &DeviceCommandError::DeadlineNotElapsed
        );
        let published = rejected_attempt.into_state();
        let timed_out = published
            .timeout(authority.current_fence(), time(20))
            .expect("timeout")
            .into_state();
        assert_eq!(timed_out.version().get(), 3);
        let terminal_snapshot = timed_out.snapshot();
        let late = timed_out
            .cancel(authority.current_fence(), time(21))
            .expect("late");
        assert_eq!(late.outcome(), CommandTransitionOutcome::Late);
        assert_eq!(late.into_state().snapshot(), terminal_snapshot);
    }

    #[test]
    fn snapshot_roundtrips_each_legal_state_and_restore_fails_closed() {
        let authority = tracker();
        let queued_state = queued(&authority);
        let published_state = published(&authority);
        let received_state = received(&authority);
        let rejected_state = published(&authority)
            .reject(authority.current_fence(), time(12))
            .expect("rejected")
            .into_state();
        let timed_out_state = received(&authority)
            .timeout(authority.current_fence(), time(20))
            .expect("timeout")
            .into_state();
        let cancelled_state = received(&authority)
            .cancel(authority.current_fence(), time(13))
            .expect("cancel")
            .into_state();

        let mut matching_authority = tracker();
        let matching = matching_authority
            .report(
                crate::generation::ObservedGeneration::try_new(1).expect("observed"),
                FenceEpoch::try_new(1).expect("epoch"),
                "on",
            )
            .into_matching()
            .expect("matching");
        let applied_state = received(&matching_authority)
            .apply(matching, time(13))
            .expect("apply")
            .into_state();

        let mut newer = tracker();
        let supersede_candidate = queued(&newer);
        let newer_evidence = newer
            .advance_desired(
                DesiredGeneration::try_new(2).expect("generation"),
                "off",
                FenceEpoch::try_new(2).expect("epoch"),
            )
            .expect("advance");
        let superseded_state = supersede_candidate
            .supersede(newer_evidence, time(11))
            .expect("supersede")
            .into_state();

        for state in [
            &queued_state,
            &published_state,
            &received_state,
            &applied_state,
            &rejected_state,
            &timed_out_state,
            &superseded_state,
            &cancelled_state,
        ] {
            let snapshot = state.snapshot();
            let restored = DeviceCommandState::restore(snapshot.clone().into()).expect("restore");
            assert_eq!(restored.snapshot(), snapshot);
        }

        let mut invalid = DeviceCommandState::restore(cancelled_state.snapshot().into())
            .expect("restore")
            .snapshot();
        if let CommandSnapshot::Cancelled(value) = &mut invalid.inner {
            value.terminal_at = time(1);
        }
        assert_eq!(
            DeviceCommandState::restore(invalid.into()),
            Err(DeviceCommandError::InvalidSnapshot)
        );
    }

    #[test]
    fn raw_restore_rejects_unreachable_versions_and_invalid_time_relations() {
        let invalid = [
            DeviceCommandRestore::queued(restore_common_with_deadline(1, time(10))),
            DeviceCommandRestore::queued(restore_common(2)),
            DeviceCommandRestore::published(restore_common(1), time(11)),
            DeviceCommandRestore::received(restore_common(3), time(12), time(11)),
            DeviceCommandRestore::applied(restore_common(4), time(11), time(13), time(12)),
            DeviceCommandRestore::rejected(restore_common(3), time(12), time(11)),
            DeviceCommandRestore::timed_out(
                restore_common(2),
                CommandProgressRestore::queued(),
                time(19),
            ),
            DeviceCommandRestore::timed_out(
                restore_common(3),
                CommandProgressRestore::received(time(11), time(12)),
                time(20),
            ),
            DeviceCommandRestore::superseded(
                restore_common(3),
                CommandProgressRestore::received(time(11), time(12)),
                time(13),
            ),
            DeviceCommandRestore::cancelled(
                restore_common(3),
                CommandProgressRestore::published(time(12)),
                time(11),
            ),
            DeviceCommandRestore::cancelled(
                restore_common(2),
                CommandProgressRestore::published(time(11)),
                time(12),
            ),
        ];
        for input in invalid {
            assert_eq!(
                DeviceCommandState::restore(input),
                Err(DeviceCommandError::InvalidSnapshot)
            );
        }
    }

    #[test]
    fn newer_generation_is_required_for_supersede() {
        let mut authority = tracker();
        let queued = queued(&authority);
        let evidence = authority
            .advance_desired(
                DesiredGeneration::try_new(2).expect("generation"),
                "off",
                FenceEpoch::try_new(2).expect("epoch"),
            )
            .expect("advance");
        let superseded = queued
            .supersede(evidence, time(11))
            .expect("supersede")
            .into_state();
        assert_eq!(superseded.status(), DeviceCommandStatus::Superseded);
    }

    #[test]
    fn every_declared_nonterminal_edge_advances() {
        let authority = tracker();
        assert_advanced(
            queued(&authority)
                .timeout(authority.current_fence(), time(20))
                .expect("queued timeout"),
            DeviceCommandStatus::TimedOut,
        );
        assert_advanced(
            queued(&authority)
                .cancel(authority.current_fence(), time(11))
                .expect("queued cancel"),
            DeviceCommandStatus::Cancelled,
        );
        assert_advanced(
            published(&authority)
                .reject(authority.current_fence(), time(12))
                .expect("published reject"),
            DeviceCommandStatus::Rejected,
        );
        assert_advanced(
            published(&authority)
                .timeout(authority.current_fence(), time(20))
                .expect("published timeout"),
            DeviceCommandStatus::TimedOut,
        );
        assert_advanced(
            published(&authority)
                .cancel(authority.current_fence(), time(12))
                .expect("published cancel"),
            DeviceCommandStatus::Cancelled,
        );
        assert_advanced(
            received(&authority)
                .timeout(authority.current_fence(), time(20))
                .expect("received timeout"),
            DeviceCommandStatus::TimedOut,
        );
        assert_advanced(
            received(&authority)
                .cancel(authority.current_fence(), time(13))
                .expect("received cancel"),
            DeviceCommandStatus::Cancelled,
        );

        for source in [
            DeviceCommandStatus::Queued,
            DeviceCommandStatus::Published,
            DeviceCommandStatus::Received,
        ] {
            let mut authority = tracker();
            let state = match source {
                DeviceCommandStatus::Queued => queued(&authority),
                DeviceCommandStatus::Published => published(&authority),
                DeviceCommandStatus::Received => received(&authority),
                _ => unreachable!("test source is nonterminal"),
            };
            let evidence = authority
                .advance_desired(
                    DesiredGeneration::try_new(2).expect("generation"),
                    "off",
                    FenceEpoch::try_new(2).expect("epoch"),
                )
                .expect("advance");
            assert_advanced(
                state.supersede(evidence, time(13)).expect("supersede"),
                DeviceCommandStatus::Superseded,
            );
        }
    }

    #[test]
    fn every_terminal_state_absorbs_late_events_without_version_change() {
        let mut matching_authority = tracker();
        let matching = matching_authority
            .report(
                crate::generation::ObservedGeneration::try_new(1).expect("observed"),
                FenceEpoch::try_new(1).expect("epoch"),
                "on",
            )
            .into_matching()
            .expect("matching");
        let applied = received(&matching_authority)
            .apply(matching, time(13))
            .expect("apply")
            .into_state();

        let authority = tracker();
        let rejected = published(&authority)
            .reject(authority.current_fence(), time(12))
            .expect("reject")
            .into_state();
        let timed_out = queued(&authority)
            .timeout(authority.current_fence(), time(20))
            .expect("timeout")
            .into_state();
        let cancelled = queued(&authority)
            .cancel(authority.current_fence(), time(11))
            .expect("cancel")
            .into_state();
        let mut newer = tracker();
        let superseded = queued(&newer)
            .supersede(
                newer
                    .advance_desired(
                        DesiredGeneration::try_new(2).expect("generation"),
                        "off",
                        FenceEpoch::try_new(2).expect("epoch"),
                    )
                    .expect("advance"),
                time(11),
            )
            .expect("supersede")
            .into_state();

        for terminal in [applied, rejected, timed_out, superseded, cancelled] {
            let expected = terminal.snapshot();
            let late = terminal
                .publish(authority.current_fence(), time(30))
                .expect("terminal absorbs");
            assert_eq!(late.outcome(), CommandTransitionOutcome::Late);
            assert_eq!(late.into_state().snapshot(), expected);
        }
    }

    #[test]
    fn state_event_matrix_is_exhaustive_and_versioned() {
        use CommandTransitionOutcome::{Advanced, Duplicate, Late, OutOfOrder};

        let expected = [
            [
                Advanced, OutOfOrder, OutOfOrder, OutOfOrder, Advanced, Advanced, Advanced,
            ],
            [
                Duplicate, Advanced, Advanced, OutOfOrder, Advanced, Advanced, Advanced,
            ],
            [
                OutOfOrder, Duplicate, Late, Advanced, Advanced, Advanced, Advanced,
            ],
            [Late, Late, Late, Duplicate, Late, Late, Late],
            [Late, Late, Duplicate, Late, Late, Late, Late],
            [Late, Late, Late, Late, Duplicate, Late, Late],
            [Late, Late, Late, Late, Late, Duplicate, Late],
            [Late, Late, Late, Late, Late, Late, Duplicate],
        ];
        let target_status = [
            DeviceCommandStatus::Published,
            DeviceCommandStatus::Received,
            DeviceCommandStatus::Rejected,
            DeviceCommandStatus::Applied,
            DeviceCommandStatus::TimedOut,
            DeviceCommandStatus::Superseded,
            DeviceCommandStatus::Cancelled,
        ];

        let states = all_state_snapshots();
        assert_eq!(
            states.iter().map(|(status, _)| *status).collect::<Vec<_>>(),
            DeviceCommandStatus::ALL
        );
        for (state_index, (source_status, snapshot)) in states.iter().enumerate() {
            let before_version = snapshot_common(snapshot).version().get();
            for (event_index, event) in EVENTS.into_iter().enumerate() {
                let transition =
                    attempt_event(snapshot, event, scope()).expect("matching authority");
                assert_eq!(
                    transition.outcome(),
                    expected[state_index][event_index],
                    "state={source_status:?} event={event_index}"
                );
                let result = transition.into_state();
                if expected[state_index][event_index] == Advanced {
                    assert_eq!(result.status(), target_status[event_index]);
                    assert_eq!(result.version().get(), before_version + 1);
                } else {
                    assert_eq!(result.snapshot(), snapshot.clone());
                }
            }
        }
    }

    #[test]
    fn every_state_event_rejects_cross_scope_authority_without_mutation() {
        for (status, snapshot) in all_state_snapshots() {
            for (event_index, event) in EVENTS.into_iter().enumerate() {
                let failure = attempt_event(&snapshot, event, other_scope())
                    .expect_err("cross-scope evidence must fail");
                assert_eq!(
                    failure.error(),
                    &DeviceCommandError::AuthorityMismatch,
                    "state={status:?} event={event_index}"
                );
                assert_eq!(failure.into_state().snapshot(), snapshot);
            }
        }
    }

    #[test]
    fn mismatched_authority_cannot_mutate_command() {
        let authority = tracker();
        let command = queued(&authority);
        let before = command.snapshot();
        let other = GenerationTracker::new(
            scope(),
            DesiredGeneration::try_new(1).expect("generation"),
            "on",
            FenceEpoch::try_new(2).expect("epoch"),
        );
        let rejected = command
            .publish(other.current_fence(), time(11))
            .expect_err("mismatched fence");
        assert_eq!(rejected.error(), &DeviceCommandError::AuthorityMismatch);
        assert_eq!(rejected.into_state().snapshot(), before);
    }
}
