//! Identity and authority are distinct from product authentication.
use rss_request_context::TenantId;

/// Closed validation and lifecycle failures; no runtime identifiers enter messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Malformed bounded identity or coordinate.
    #[error("invalid command value")]
    InvalidValue,
    /// Persisted shape or timestamp ordering is inconsistent.
    #[error("invalid command snapshot")]
    InvalidSnapshot,
    /// A deadline must be later than queue time.
    #[error("command deadline elapsed")]
    DeadlineElapsed,
    /// The supplied scope, command or current authority does not match.
    #[error("command authority lost")]
    Fenced,
    /// Same identity denotes different immutable facts.
    #[error("command fact conflict")]
    Conflict,
    /// The positive persisted version cannot advance.
    #[error("command version overflow")]
    VersionOverflow,
}

/// Device identity owned by this capability; parsing is not authentication.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(uuid::Uuid);
impl DeviceId {
    /// Parse a non-nil UUID without generating an identity.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let id = uuid::Uuid::parse_str(raw).map_err(|_| Error::InvalidValue)?;
        if id.is_nil() {
            return Err(Error::InvalidValue);
        }
        Ok(Self(id))
    }
    /// Canonical storage representation.
    pub fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}
impl std::fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceId(<redacted>)")
    }
}
/// Tenant-local command identity: 1–255 ASCII letters, digits or `_.:-`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommandId(String);
impl CommandId {
    /// Validate the exact identity without normalization.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        if raw.is_empty()
            || raw.len() > 255
            || !raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(Error::InvalidValue);
        }
        Ok(Self(raw.to_owned()))
    }
    /// Storage representation; callers must redact it in diagnostics.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for CommandId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommandId(<redacted>)")
    }
}
/// Exact authority scope, supplied by a trusted product boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope {
    tenant: TenantId,
    device: DeviceId,
}
impl Scope {
    /// Bind already validated identities; this does not authenticate either identity.
    pub const fn new(tenant: TenantId, device: DeviceId) -> Self {
        Self { tenant, device }
    }
    /// Owning tenant.
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
    /// Target device.
    pub const fn device(self) -> DeviceId {
        self.device
    }
}
/// Independently persisted generation and authority epoch. Neither is a command version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coordinate {
    generation: i64,
    epoch: i64,
}
impl Coordinate {
    /// Both values must be positive PostgreSQL bigints.
    pub fn new(generation: i64, epoch: i64) -> Result<Self, Error> {
        if generation < 1 || epoch < 1 {
            return Err(Error::InvalidValue);
        }
        Ok(Self { generation, epoch })
    }
    /// Desired version.
    pub const fn generation(self) -> i64 {
        self.generation
    }
    /// Authority version.
    pub const fn epoch(self) -> i64 {
        self.epoch
    }
    /// A takeover may retain generation; every authority change strictly increases epoch.
    pub const fn supersedes(self, old: Self) -> bool {
        self.generation >= old.generation && self.epoch > old.epoch
    }
}
/// Product-defined semantic digest of the expected or actually observed state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StateDigest([u8; 32]);
impl StateDigest {
    /// Supply a digest after product-owned normalization and authentication.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Exact persisted representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for StateDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateDigest(<redacted>)")
    }
}
/// Immutable command facts. Deadline and all stored times are Unix epoch microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    scope: Scope,
    id: CommandId,
    coordinate: Coordinate,
    expected: StateDigest,
    deadline: i64,
}
impl CommandSpec {
    /// Bind command facts; queue admission checks the deadline against provider time.
    pub const fn new(
        scope: Scope,
        id: CommandId,
        coordinate: Coordinate,
        expected: StateDigest,
        deadline: i64,
    ) -> Self {
        Self {
            scope,
            id,
            coordinate,
            expected,
            deadline,
        }
    }
    /// Exact target scope.
    pub const fn scope(&self) -> Scope {
        self.scope
    }
    /// Tenant-local identity.
    pub fn id(&self) -> &CommandId {
        &self.id
    }
    /// Immutable authority coordinate.
    pub const fn coordinate(&self) -> Coordinate {
        self.coordinate
    }
    /// Desired semantic state for this command alone.
    pub const fn expected(&self) -> StateDigest {
        self.expected
    }
    /// Absolute command deadline, independent from an operation's time budget.
    pub const fn deadline(&self) -> i64 {
        self.deadline
    }
}
/// Device-originated input cannot claim publication, timeout, cancellation or supersession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceEvent {
    /// Device receipt only.
    Received,
    /// Device declined execution, including after acknowledging receipt.
    Rejected,
    /// Actual observed state, not an ACK claiming success.
    Reported(StateDigest),
}
/// An authenticated product must correlate every input to exactly one command.
#[derive(Debug, Clone)]
pub struct DeviceReport {
    /// Expected target; the provider additionally binds its transaction tenant.
    pub scope: Scope,
    /// Exact command identity.
    pub command_id: CommandId,
    /// Coordinate reported by the device, never replaced with the current one.
    pub coordinate: Coordinate,
    /// Device observation.
    pub event: DeviceEvent,
}
