//! Tenant-scoped L2 disaster-recovery plan model.
//!
//! The model deliberately carries only recovery-point evidence and stable event identities. Fact
//! material and delivery deadlines remain provider-owned, so an operator cannot author a new fact
//! or extend the bounded same-ID delivery window through this API.
//!
//! ref: watermill message/router.go@master (stable message identity across redelivery); RSS adds a
//! tenant-scoped, durably audited plan digest and keeps publication behind the normal outbox relay.

use consistency::IdemKey;
use sha2::{Digest as _, Sha256};

const PLAN_DIGEST_DOMAIN: &[u8] = b"rss.l2-dr-recovery-plan.v1";
/// Single source for the closed same-ID delivery policy revision (digest + receipt checks).
const DELIVERY_POLICY_REVISION: &str = "same-id-delivery-v1";
const MAX_CHANGE_TICKET_BYTES: usize = 128;
const MAX_OPERATOR_SUBJECT_BYTES: usize = 128;

/// Operator authorization witness for L2 DR recovery mutation.
///
/// Authentication and exact tenant/action authorization must succeed before this zero-sized token
/// is issued. Construction of [`AuthorizedL2DrRecoveryPlan`] consumes it so apply cannot be
/// expressed without a capability-bearing authorized plan. Production issuing callsites are locked
/// by `rss_operator_authorization_callsite` to the reviewed runtime wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorL2DrRecoveryCapability {
    _seal: (),
}

impl OperatorL2DrRecoveryCapability {
    /// Issue after service-principal authentication and exact tenant/action authorization.
    pub fn issue_for_authorized_operator() -> Self {
        Self { _seal: () }
    }
}

/// Positive UTC timestamp represented as microseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcEpochMicros(i64);

impl UtcEpochMicros {
    /// Build a checked restore point. Non-positive timestamps are not valid durable evidence.
    pub const fn new(value: i64) -> Result<Self, L2DrRecoveryError> {
        if value <= 0 {
            return Err(L2DrRecoveryError::InvalidRestorePoint);
        }
        Ok(Self(value))
    }

    /// Return the canonical signed microsecond value used by durable providers.
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Which durable system is ahead after comparing the two exact restore points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryDirection {
    /// PostgreSQL contains a committed outbox fact that the restored broker does not contain.
    DatabaseAheadBrokerEarlier,
    /// The broker contains a delivery whose committed PostgreSQL effects were restored away.
    BrokerAheadDatabaseEarlier,
}

impl RecoveryDirection {
    /// Derive the only valid direction from both restore points; equal points are not divergent.
    pub fn derive(
        database_restore_point: UtcEpochMicros,
        broker_restore_point: UtcEpochMicros,
    ) -> Result<Self, L2DrRecoveryError> {
        if database_restore_point > broker_restore_point {
            Ok(Self::DatabaseAheadBrokerEarlier)
        } else if database_restore_point < broker_restore_point {
            Ok(Self::BrokerAheadDatabaseEarlier)
        } else {
            Err(L2DrRecoveryError::EqualRestorePoints)
        }
    }

    /// Stable storage and audit label.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DatabaseAheadBrokerEarlier => "database_ahead_broker_earlier",
            Self::BrokerAheadDatabaseEarlier => "broker_ahead_database_earlier",
        }
    }

    /// Parse the closed durable storage label.
    pub fn parse_label(value: &str) -> Result<Self, L2DrRecoveryError> {
        match value {
            "database_ahead_broker_earlier" => Ok(Self::DatabaseAheadBrokerEarlier),
            "broker_ahead_database_earlier" => Ok(Self::BrokerAheadDatabaseEarlier),
            _ => Err(L2DrRecoveryError::StoreInvariant),
        }
    }
}

/// Stable identity of one recovery epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryEpochId(uuid::Uuid);

impl RecoveryEpochId {
    /// Build an epoch identity from a non-nil UUID.
    pub fn new(value: uuid::Uuid) -> Result<Self, L2DrRecoveryError> {
        if value.is_nil() {
            return Err(L2DrRecoveryError::InvalidRecoveryEpochId);
        }
        Ok(Self(value))
    }

    /// Parse the single canonical lowercase-hyphenated UUID representation.
    pub fn parse(raw: &str) -> Result<Self, L2DrRecoveryError> {
        let value =
            uuid::Uuid::try_parse(raw).map_err(|_| L2DrRecoveryError::InvalidRecoveryEpochId)?;
        if value.hyphenated().to_string() != raw {
            return Err(L2DrRecoveryError::InvalidRecoveryEpochId);
        }
        Self::new(value)
    }

    /// Return the durable UUID representation.
    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}

/// Canonical, duplicate-free recovery event set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEventSet(Vec<IdemKey>);

impl RecoveryEventSet {
    /// Maximum facts authorized by one recovery epoch.
    pub const MAX_EVENTS: usize = 500;

    /// Validate cardinality and sort exact UTF-8 identity bytes into canonical order.
    pub fn new(mut events: Vec<IdemKey>) -> Result<Self, L2DrRecoveryError> {
        if events.is_empty() {
            return Err(L2DrRecoveryError::EmptyEventSet);
        }
        if events.len() > Self::MAX_EVENTS {
            return Err(L2DrRecoveryError::TooManyEvents);
        }
        events.sort_unstable_by(|left, right| {
            left.as_str().as_bytes().cmp(right.as_str().as_bytes())
        });
        if events
            .windows(2)
            .any(|pair| pair[0].as_str().as_bytes() == pair[1].as_str().as_bytes())
        {
            return Err(L2DrRecoveryError::DuplicateEventId);
        }
        Ok(Self(events))
    }

    /// Number of stable facts in the plan.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The event set is non-empty by construction.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterate in canonical byte order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &IdemKey> {
        self.0.iter()
    }

    /// Borrow the canonically ordered stable identities.
    pub fn as_slice(&self) -> &[IdemKey] {
        &self.0
    }
}

/// Audited change ticket bound into a recovery plan.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RecoveryChangeTicket(String);

impl std::fmt::Debug for RecoveryChangeTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecoveryChangeTicket(<redacted>)")
    }
}

impl RecoveryChangeTicket {
    /// Parse a canonical non-empty ticket of at most 128 bytes.
    pub fn parse(raw: impl Into<String>) -> Result<Self, L2DrRecoveryError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > MAX_CHANGE_TICKET_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(L2DrRecoveryError::InvalidChangeTicket);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical audit value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque SHA-256 identity derived from the complete canonical recovery plan.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct L2DrRecoveryPlanDigest([u8; 32]);

impl std::fmt::Debug for L2DrRecoveryPlanDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("L2DrRecoveryPlanDigest(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl L2DrRecoveryPlanDigest {
    /// Borrow the fixed-width storage representation.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return canonical lowercase hexadecimal text for audit correlation.
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }

    /// Parse the exact fixed-width digest returned by a durable provider.
    pub fn from_store_bytes(value: &[u8]) -> Result<Self, L2DrRecoveryError> {
        let bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| L2DrRecoveryError::StoreInvariant)?;
        Ok(Self(bytes))
    }
}

/// Immutable tenant-scoped plan for one pair of divergent durable restore points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2DrRecoveryPlan {
    epoch_id: RecoveryEpochId,
    tenant: vocab::TenantId,
    database_restore_point: UtcEpochMicros,
    broker_restore_point: UtcEpochMicros,
    direction: RecoveryDirection,
    events: RecoveryEventSet,
    change_ticket: RecoveryChangeTicket,
    digest: L2DrRecoveryPlanDigest,
}

impl L2DrRecoveryPlan {
    /// Build a plan and derive its direction and digest from complete canonical input.
    pub fn new(
        epoch_id: RecoveryEpochId,
        tenant: vocab::TenantId,
        database_restore_point: UtcEpochMicros,
        broker_restore_point: UtcEpochMicros,
        events: RecoveryEventSet,
        change_ticket: RecoveryChangeTicket,
    ) -> Result<Self, L2DrRecoveryError> {
        let direction = RecoveryDirection::derive(database_restore_point, broker_restore_point)?;
        let digest = derive_plan_digest(
            epoch_id,
            tenant,
            database_restore_point,
            broker_restore_point,
            direction,
            &events,
            &change_ticket,
        )?;
        Ok(Self {
            epoch_id,
            tenant,
            database_restore_point,
            broker_restore_point,
            direction,
            events,
            change_ticket,
            digest,
        })
    }

    /// Return the durable recovery epoch identity.
    pub const fn epoch_id(&self) -> RecoveryEpochId {
        self.epoch_id
    }

    /// Return the tenant scope bound into this plan.
    pub const fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// Return the PostgreSQL restore-point evidence.
    pub const fn database_restore_point(&self) -> UtcEpochMicros {
        self.database_restore_point
    }

    /// Return the broker restore-point evidence.
    pub const fn broker_restore_point(&self) -> UtcEpochMicros {
        self.broker_restore_point
    }

    /// Return the derived recovery direction.
    pub const fn direction(&self) -> RecoveryDirection {
        self.direction
    }

    /// Borrow the canonical recovery event set.
    pub const fn events(&self) -> &RecoveryEventSet {
        &self.events
    }

    /// Borrow the audited change ticket.
    pub const fn change_ticket(&self) -> &RecoveryChangeTicket {
        &self.change_ticket
    }

    /// Borrow the complete canonical plan digest.
    pub const fn digest(&self) -> &L2DrRecoveryPlanDigest {
        &self.digest
    }
}

fn derive_plan_digest(
    epoch_id: RecoveryEpochId,
    tenant: vocab::TenantId,
    database_restore_point: UtcEpochMicros,
    broker_restore_point: UtcEpochMicros,
    direction: RecoveryDirection,
    events: &RecoveryEventSet,
    change_ticket: &RecoveryChangeTicket,
) -> Result<L2DrRecoveryPlanDigest, L2DrRecoveryError> {
    let epoch_uuid = epoch_id.as_uuid();
    let tenant_uuid = tenant.as_uuid();
    let database_micros = database_restore_point.get().to_be_bytes();
    let broker_micros = broker_restore_point.get().to_be_bytes();
    let event_count = u64::try_from(events.len())
        .map_err(|_| L2DrRecoveryError::CanonicalFieldTooLong)?
        .to_be_bytes();
    let mut digest = Sha256::new();
    for value in [
        PLAN_DIGEST_DOMAIN,
        DELIVERY_POLICY_REVISION.as_bytes(),
        epoch_uuid.as_bytes(),
        tenant_uuid.as_bytes(),
        direction.as_label().as_bytes(),
        &database_micros,
        &broker_micros,
        &event_count,
    ] {
        append_length_prefixed(&mut digest, value)?;
    }
    for event in events.iter() {
        append_length_prefixed(&mut digest, event.as_str().as_bytes())?;
    }
    append_length_prefixed(&mut digest, change_ticket.as_str().as_bytes())?;
    Ok(L2DrRecoveryPlanDigest(digest.finalize().into()))
}

fn append_length_prefixed(digest: &mut Sha256, value: &[u8]) -> Result<(), L2DrRecoveryError> {
    let length =
        u64::try_from(value.len()).map_err(|_| L2DrRecoveryError::CanonicalFieldTooLong)?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
}

/// Canonical audit identity of the authenticated maintenance service operator.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct L2DrRecoveryOperatorSubject(String);

impl std::fmt::Debug for L2DrRecoveryOperatorSubject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("L2DrRecoveryOperatorSubject(<redacted>)")
    }
}

impl L2DrRecoveryOperatorSubject {
    /// Parse the exact verified principal audit subject without normalization.
    pub fn parse(raw: impl Into<String>) -> Result<Self, L2DrRecoveryError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > MAX_OPERATOR_SUBJECT_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(L2DrRecoveryError::InvalidOperatorSubject);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical audit and durable receipt value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Move-only proof that the audit lane durably persisted the exact authenticated start decision.
#[derive(Debug, PartialEq, Eq)]
pub struct L2DrRecoveryDurableStartProof {
    caller: vocab::ServiceCallerDomain,
    operator_subject: L2DrRecoveryOperatorSubject,
    tenant: vocab::TenantId,
    epoch_id: RecoveryEpochId,
    plan_digest: L2DrRecoveryPlanDigest,
    start_audit_id: uuid::Uuid,
}

impl L2DrRecoveryDurableStartProof {
    /// Mint proof only after the provider has committed the exact start audit row.
    pub fn from_store(
        caller: vocab::ServiceCallerDomain,
        operator_subject: L2DrRecoveryOperatorSubject,
        tenant: vocab::TenantId,
        epoch_id: RecoveryEpochId,
        plan_digest: L2DrRecoveryPlanDigest,
        start_audit_id: uuid::Uuid,
    ) -> Result<Self, L2DrRecoveryError> {
        if caller != vocab::ServiceCallerDomain::MaintenanceOperator {
            return Err(L2DrRecoveryError::InvalidOperatorCaller);
        }
        if start_audit_id.is_nil() {
            return Err(L2DrRecoveryError::InvalidStartAuditId);
        }
        Ok(Self {
            caller,
            operator_subject,
            tenant,
            epoch_id,
            plan_digest,
            start_audit_id,
        })
    }
}

/// Authenticated and authorized recovery plan accepted by the executor provider port.
///
/// This type is intentionally move-only. Construction consumes both a provider-issued durable-start
/// proof whose tenant, epoch and complete plan digest must match the plan exactly, and the
/// operator capability issued only after authentication and exact tenant/action authorization.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedL2DrRecoveryPlan {
    plan: L2DrRecoveryPlan,
    caller: vocab::ServiceCallerDomain,
    operator_subject: L2DrRecoveryOperatorSubject,
    start_audit_id: uuid::Uuid,
    capability: OperatorL2DrRecoveryCapability,
}

impl AuthorizedL2DrRecoveryPlan {
    /// Consume the exact durable-start proof and authorization capability.
    pub fn from_authenticated_and_authorized(
        plan: L2DrRecoveryPlan,
        proof: L2DrRecoveryDurableStartProof,
        capability: OperatorL2DrRecoveryCapability,
    ) -> Result<Self, L2DrRecoveryError> {
        if proof.tenant != plan.tenant()
            || proof.epoch_id != plan.epoch_id()
            || proof.plan_digest != *plan.digest()
        {
            return Err(L2DrRecoveryError::StartAuditMismatch);
        }
        Ok(Self {
            plan,
            caller: proof.caller,
            operator_subject: proof.operator_subject,
            start_audit_id: proof.start_audit_id,
            capability,
        })
    }

    /// Borrow the authorized recovery plan.
    pub const fn plan(&self) -> &L2DrRecoveryPlan {
        &self.plan
    }

    /// Return the authenticated maintenance caller domain.
    pub const fn caller(&self) -> vocab::ServiceCallerDomain {
        self.caller
    }

    /// Return the exact authenticated service principal bound at the authorization boundary.
    pub const fn operator_subject(&self) -> &L2DrRecoveryOperatorSubject {
        &self.operator_subject
    }

    /// Return the durable start-audit identity bound at authorization.
    pub const fn start_audit_id(&self) -> uuid::Uuid {
        self.start_audit_id
    }

    /// Return the authorization capability consumed at construction.
    pub const fn capability(&self) -> OperatorL2DrRecoveryCapability {
        self.capability
    }
}

/// Closed durable application result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2DrRecoveryOutcome {
    /// The provider atomically recorded and applied this recovery epoch.
    Applied,
    /// The same epoch and plan digest had already been applied.
    AlreadyApplied,
}

impl L2DrRecoveryOutcome {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadyApplied => "already_applied",
        }
    }

    /// Parse the closed provider result label.
    pub fn parse_label(value: &str) -> Result<Self, L2DrRecoveryError> {
        match value {
            "applied" => Ok(Self::Applied),
            "already_applied" => Ok(Self::AlreadyApplied),
            _ => Err(L2DrRecoveryError::StoreInvariant),
        }
    }
}

/// Complete durable row decoded by a provider before it can become a trusted receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct L2DrRecoveryDurableReceipt {
    epoch_id: RecoveryEpochId,
    tenant: vocab::TenantId,
    database_restore_point: UtcEpochMicros,
    broker_restore_point: UtcEpochMicros,
    plan_digest: L2DrRecoveryPlanDigest,
    direction: RecoveryDirection,
    events: RecoveryEventSet,
    policy_revision: String,
    operator_subject: L2DrRecoveryOperatorSubject,
    start_audit_id: uuid::Uuid,
    applied_at: UtcEpochMicros,
    outcome: L2DrRecoveryOutcome,
}

impl L2DrRecoveryDurableReceipt {
    /// Decode the complete receipt row returned by the durable provider.
    #[allow(clippy::too_many_arguments)]
    // reason: this constructor mirrors the fixed SQL receipt projection; grouping would permit omitted evidence.
    pub fn from_store(
        epoch_id: RecoveryEpochId,
        tenant: vocab::TenantId,
        database_restore_point: UtcEpochMicros,
        broker_restore_point: UtcEpochMicros,
        plan_digest: L2DrRecoveryPlanDigest,
        direction: RecoveryDirection,
        events: RecoveryEventSet,
        policy_revision: String,
        operator_subject: L2DrRecoveryOperatorSubject,
        start_audit_id: uuid::Uuid,
        applied_at: UtcEpochMicros,
        outcome: L2DrRecoveryOutcome,
    ) -> Result<Self, L2DrRecoveryError> {
        if start_audit_id.is_nil() {
            return Err(L2DrRecoveryError::InvalidStartAuditId);
        }
        if policy_revision != DELIVERY_POLICY_REVISION {
            return Err(L2DrRecoveryError::StoreInvariant);
        }
        Ok(Self {
            epoch_id,
            tenant,
            database_restore_point,
            broker_restore_point,
            plan_digest,
            direction,
            events,
            policy_revision,
            operator_subject,
            start_audit_id,
            applied_at,
            outcome,
        })
    }

    pub const fn outcome(&self) -> L2DrRecoveryOutcome {
        self.outcome
    }
}

/// Provider-issued receipt validated against every field of the authorized plan.
#[derive(Debug, PartialEq, Eq)]
pub struct L2DrRecoveryReceipt(L2DrRecoveryDurableReceipt);

impl L2DrRecoveryReceipt {
    /// Validate a complete durable row before exposing it as recovery evidence.
    pub fn from_store(
        authorized: &AuthorizedL2DrRecoveryPlan,
        durable: L2DrRecoveryDurableReceipt,
    ) -> Result<Self, L2DrRecoveryError> {
        let plan = authorized.plan();
        if durable.epoch_id != plan.epoch_id()
            || durable.tenant != plan.tenant()
            || durable.database_restore_point != plan.database_restore_point()
            || durable.broker_restore_point != plan.broker_restore_point()
            || durable.plan_digest != *plan.digest()
            || durable.direction != plan.direction()
            || durable.events != *plan.events()
            || durable.policy_revision != DELIVERY_POLICY_REVISION
            || (durable.outcome == L2DrRecoveryOutcome::Applied
                && (&durable.operator_subject != authorized.operator_subject()
                    || durable.start_audit_id != authorized.start_audit_id()))
        {
            return Err(L2DrRecoveryError::StoreInvariant);
        }
        Ok(Self(durable))
    }

    /// Return the durable recovery epoch identity recorded on the receipt.
    pub const fn epoch_id(&self) -> RecoveryEpochId {
        self.0.epoch_id
    }

    /// Return the tenant scope recorded on the receipt.
    pub const fn tenant(&self) -> vocab::TenantId {
        self.0.tenant
    }

    /// Return the PostgreSQL restore-point evidence recorded on the receipt.
    pub const fn database_restore_point(&self) -> UtcEpochMicros {
        self.0.database_restore_point
    }

    /// Return the broker restore-point evidence recorded on the receipt.
    pub const fn broker_restore_point(&self) -> UtcEpochMicros {
        self.0.broker_restore_point
    }

    /// Return the complete plan digest recorded on the receipt.
    pub const fn plan_digest(&self) -> L2DrRecoveryPlanDigest {
        self.0.plan_digest
    }

    /// Return the recovery direction recorded on the receipt.
    pub const fn direction(&self) -> RecoveryDirection {
        self.0.direction
    }

    /// Borrow the canonical event set recorded on the receipt.
    pub const fn events(&self) -> &RecoveryEventSet {
        &self.0.events
    }

    /// Return the number of stable facts recorded on the receipt.
    pub fn event_count(&self) -> usize {
        self.0.events.len()
    }

    /// Borrow the closed same-ID delivery policy revision.
    pub fn policy_revision(&self) -> &str {
        &self.0.policy_revision
    }

    /// Return the operator subject durably recorded by the first successful epoch application.
    pub const fn operator_subject(&self) -> &L2DrRecoveryOperatorSubject {
        &self.0.operator_subject
    }

    /// Return the first start-audit identity retained for the epoch.
    pub const fn start_audit_id(&self) -> uuid::Uuid {
        self.0.start_audit_id
    }

    /// Return when the provider recorded the durable application.
    pub const fn applied_at(&self) -> UtcEpochMicros {
        self.0.applied_at
    }

    /// Return whether this epoch was newly applied or already applied.
    pub const fn outcome(&self) -> L2DrRecoveryOutcome {
        self.0.outcome
    }
}

/// Closed validation and durable recovery failure set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum L2DrRecoveryError {
    #[error("restore point must be positive UTC epoch microseconds")]
    InvalidRestorePoint,
    #[error("database and broker restore points are equal")]
    EqualRestorePoints,
    #[error("recovery epoch id must be a canonical non-nil UUID")]
    InvalidRecoveryEpochId,
    #[error("recovery event set must not be empty")]
    EmptyEventSet,
    #[error("recovery event set exceeds 500 events")]
    TooManyEvents,
    #[error("recovery event set contains a duplicate stable event id")]
    DuplicateEventId,
    #[error("recovery change ticket is invalid")]
    InvalidChangeTicket,
    #[error("a canonical recovery field exceeds the digest length encoding")]
    CanonicalFieldTooLong,
    #[error("recovery operator caller is invalid")]
    InvalidOperatorCaller,
    #[error("recovery operator subject is invalid")]
    InvalidOperatorSubject,
    #[error("recovery start audit id must be non-nil")]
    InvalidStartAuditId,
    #[error("durable recovery start audit does not match the complete plan")]
    StartAuditMismatch,
    #[error("recovery tenant scope does not match the executor transaction")]
    TenantScopeMismatch,
    #[error("the durable provider rejected the recovery plan")]
    InvalidDurablePlan,
    #[error("recovery epoch conflicts with its existing durable plan")]
    EpochConflict,
    #[error("the durable same-id delivery policy does not match")]
    DeliveryPolicyMismatch,
    #[error("a recovery fact was not found")]
    FactNotFound,
    #[error("a recovery fact is not in the required published state")]
    FactNotPublished,
    #[error("a recovery fact does not match its durable identity")]
    FactConflict,
    #[error("the original same-id recovery deadline has expired")]
    DeadlineExpired,
    #[error("the recovery executor lost a selected row lock")]
    ApplyLostLock,
    #[error("the L2 DR recovery store is unavailable")]
    StoreUnavailable,
    #[error("the L2 DR recovery store violated a durable invariant")]
    StoreInvariant,
}

impl L2DrRecoveryError {
    /// Stable bounded observability label.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::InvalidRestorePoint => "invalid_restore_point",
            Self::EqualRestorePoints => "equal_restore_points",
            Self::InvalidRecoveryEpochId => "invalid_recovery_epoch_id",
            Self::EmptyEventSet => "empty_event_set",
            Self::TooManyEvents => "too_many_events",
            Self::DuplicateEventId => "duplicate_event_id",
            Self::InvalidChangeTicket => "invalid_change_ticket",
            Self::CanonicalFieldTooLong => "canonical_field_too_long",
            Self::InvalidOperatorCaller => "invalid_operator_caller",
            Self::InvalidOperatorSubject => "invalid_operator_subject",
            Self::InvalidStartAuditId => "invalid_start_audit_id",
            Self::StartAuditMismatch => "start_audit_mismatch",
            Self::TenantScopeMismatch => "tenant_scope_mismatch",
            Self::InvalidDurablePlan => "invalid_durable_plan",
            Self::EpochConflict => "epoch_conflict",
            Self::DeliveryPolicyMismatch => "delivery_policy_mismatch",
            Self::FactNotFound => "fact_not_found",
            Self::FactNotPublished => "fact_not_published",
            Self::FactConflict => "fact_conflict",
            Self::DeadlineExpired => "deadline_expired",
            Self::ApplyLostLock => "apply_lost_lock",
            Self::StoreUnavailable => "store_unavailable",
            Self::StoreInvariant => "store_invariant",
        }
    }

    /// Single stable audit reason used by every runtime and provider failure path.
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::InvalidOperatorCaller | Self::InvalidOperatorSubject => "operator_authorization",
            Self::InvalidStartAuditId | Self::StartAuditMismatch => "audit",
            Self::TenantScopeMismatch => "tenant_scope",
            Self::EpochConflict => "epoch_conflict",
            Self::FactNotFound => "event_missing",
            Self::FactNotPublished | Self::FactConflict => "event_state",
            Self::DeadlineExpired => "deadline",
            Self::DeliveryPolicyMismatch | Self::StoreInvariant => "policy",
            Self::StoreUnavailable | Self::ApplyLostLock => "execution",
            Self::InvalidRestorePoint
            | Self::EqualRestorePoints
            | Self::InvalidRecoveryEpochId
            | Self::EmptyEventSet
            | Self::TooManyEvents
            | Self::DuplicateEventId
            | Self::InvalidChangeTicket
            | Self::CanonicalFieldTooLong
            | Self::InvalidDurablePlan => "plan_invalid",
        }
    }
}

/// Provider-agnostic, tenant-scoped L2 DR recovery port.
#[allow(async_fn_in_trait)]
// reason: service-internal native AFIT port; adapters implement it directly and callers use static dispatch.
pub trait L2DrRecoveryStore: Send + Sync {
    /// Atomically persist and apply one authenticated, authorized, start-audited recovery plan.
    async fn apply_l2_dr_recovery(
        &self,
        plan: AuthorizedL2DrRecoveryPlan,
    ) -> Result<L2DrRecoveryReceipt, L2DrRecoveryError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use consistency::IdemKey;
    use sha2::Sha256;

    const TENANT: &str = "15d35f5c-2e08-4eef-bdb1-a1164235d738";
    const EPOCH: &str = "885ee0b2-0f20-4b4a-a003-662a06bc50e8";
    const START_AUDIT: &str = "ed24c18e-5337-49c8-9de5-14df5ec81f66";
    const OTHER_TENANT: &str = "25d35f5c-2e08-4eef-bdb1-a1164235d739";
    const OTHER_EPOCH: &str = "985ee0b2-0f20-4b4a-a003-662a06bc50e9";

    #[allow(clippy::expect_used)]
    // reason: fixed literal fixtures must panic loudly on invariant failure in unit tests.
    fn point(value: i64) -> UtcEpochMicros {
        UtcEpochMicros::new(value).expect("valid restore point")
    }

    #[allow(clippy::expect_used)]
    // reason: fixed literal fixtures must panic loudly on invariant failure in unit tests.
    fn event(value: &str) -> IdemKey {
        IdemKey::parse(value).expect("valid event id")
    }

    #[allow(clippy::expect_used)]
    // reason: fixed literal fixtures must panic loudly on invariant failure in unit tests.
    fn events(values: &[&str]) -> RecoveryEventSet {
        RecoveryEventSet::new(values.iter().map(|value| event(value)).collect())
            .expect("valid recovery event set")
    }

    #[allow(clippy::expect_used)]
    // reason: fixed literal fixtures must panic loudly on invariant failure in unit tests.
    fn plan(values: &[&str]) -> L2DrRecoveryPlan {
        L2DrRecoveryPlan::new(
            RecoveryEpochId::parse(EPOCH).expect("valid epoch id"),
            vocab::TenantId::parse(TENANT).expect("valid tenant"),
            point(1_700_000_000_000_200),
            point(1_700_000_000_000_100),
            events(values),
            RecoveryChangeTicket::parse("CHG-1837").expect("valid ticket"),
        )
        .expect("valid recovery plan")
    }

    #[allow(clippy::expect_used)]
    // reason: fixed literal fixtures must panic loudly on invariant failure in unit tests.
    fn durable_start(plan: &L2DrRecoveryPlan) -> L2DrRecoveryDurableStartProof {
        L2DrRecoveryDurableStartProof::from_store(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            L2DrRecoveryOperatorSubject::parse("service:l2-dr-primary").expect("valid subject"),
            plan.tenant(),
            plan.epoch_id(),
            *plan.digest(),
            uuid::Uuid::parse_str(START_AUDIT).expect("start audit uuid"),
        )
        .expect("durable start proof")
    }

    fn authorized_capability() -> OperatorL2DrRecoveryCapability {
        OperatorL2DrRecoveryCapability::issue_for_authorized_operator()
    }

    #[test]
    fn dr_recovery_restore_point_is_positive_checked_utc_epoch_micros() {
        assert_eq!(
            UtcEpochMicros::new(0),
            Err(L2DrRecoveryError::InvalidRestorePoint)
        );
        assert_eq!(
            UtcEpochMicros::new(-1),
            Err(L2DrRecoveryError::InvalidRestorePoint)
        );
        assert_eq!(point(1).get(), 1);
        assert_eq!(point(i64::MAX).get(), i64::MAX);
    }

    #[test]
    fn dr_recovery_direction_is_derived_from_both_restore_points() {
        assert_eq!(
            RecoveryDirection::derive(point(20), point(10)),
            Ok(RecoveryDirection::DatabaseAheadBrokerEarlier)
        );
        assert_eq!(
            RecoveryDirection::derive(point(10), point(20)),
            Ok(RecoveryDirection::BrokerAheadDatabaseEarlier)
        );
        assert_eq!(
            RecoveryDirection::derive(point(10), point(10)),
            Err(L2DrRecoveryError::EqualRestorePoints)
        );
    }

    #[test]
    fn dr_recovery_epoch_id_rejects_nil_and_noncanonical_text() {
        assert_eq!(
            RecoveryEpochId::new(uuid::Uuid::nil()),
            Err(L2DrRecoveryError::InvalidRecoveryEpochId)
        );
        assert_eq!(
            RecoveryEpochId::parse("885EE0B2-0F20-4B4A-A003-662A06BC50E8"),
            Err(L2DrRecoveryError::InvalidRecoveryEpochId)
        );
        assert_eq!(
            RecoveryEpochId::parse(EPOCH)
                .expect("canonical epoch")
                .as_uuid()
                .to_string(),
            EPOCH
        );
    }

    #[test]
    fn dr_recovery_event_set_enforces_size_and_duplicate_bounds() {
        assert_eq!(
            RecoveryEventSet::new(Vec::new()),
            Err(L2DrRecoveryError::EmptyEventSet)
        );
        assert_eq!(
            RecoveryEventSet::new(vec![event("same"), event("same")]),
            Err(L2DrRecoveryError::DuplicateEventId)
        );
        assert_eq!(events(&["one"]).len(), 1);

        let maximum = (0..RecoveryEventSet::MAX_EVENTS)
            .map(|index| event(&format!("event-{index:03}")))
            .collect();
        assert_eq!(
            RecoveryEventSet::new(maximum)
                .expect("maximum-sized event set")
                .len(),
            RecoveryEventSet::MAX_EVENTS
        );

        let oversized = (0..=RecoveryEventSet::MAX_EVENTS)
            .map(|index| event(&format!("event-{index:03}")))
            .collect();
        assert_eq!(
            RecoveryEventSet::new(oversized),
            Err(L2DrRecoveryError::TooManyEvents)
        );
    }

    #[test]
    fn dr_recovery_event_set_uses_canonical_byte_order() {
        let set = events(&["event-2", "z", "event-10", "a"]);
        let ordered: Vec<_> = set.iter().map(IdemKey::as_str).collect();
        assert_eq!(ordered, ["a", "event-10", "event-2", "z"]);
    }

    #[test]
    fn dr_recovery_change_ticket_is_canonical_and_bounded() {
        assert_eq!(
            RecoveryChangeTicket::parse(""),
            Err(L2DrRecoveryError::InvalidChangeTicket)
        );
        assert_eq!(
            RecoveryChangeTicket::parse(" CHG-1837"),
            Err(L2DrRecoveryError::InvalidChangeTicket)
        );
        assert_eq!(
            RecoveryChangeTicket::parse("CHG-1837\n"),
            Err(L2DrRecoveryError::InvalidChangeTicket)
        );
        assert_eq!(
            RecoveryChangeTicket::parse("x".repeat(129)),
            Err(L2DrRecoveryError::InvalidChangeTicket)
        );
        assert_eq!(
            RecoveryChangeTicket::parse("x".repeat(128))
                .expect("maximum-sized ticket")
                .as_str()
                .len(),
            128
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: positive-path fixtures must panic loudly when the closed plan digest drifts.
    fn dr_recovery_plan_derives_a_length_prefixed_digest_in_event_order() {
        let plan = plan(&["event-b", "event-a"]);
        let mut reference = Sha256::new();
        for value in [
            b"rss.l2-dr-recovery-plan.v1".as_slice(),
            DELIVERY_POLICY_REVISION.as_bytes(),
            uuid::Uuid::parse_str(EPOCH).expect("epoch uuid").as_bytes(),
            uuid::Uuid::parse_str(TENANT)
                .expect("tenant uuid")
                .as_bytes(),
            RecoveryDirection::DatabaseAheadBrokerEarlier
                .as_label()
                .as_bytes(),
            &1_700_000_000_000_200_i64.to_be_bytes(),
            &1_700_000_000_000_100_i64.to_be_bytes(),
            &2_u64.to_be_bytes(),
            b"event-a".as_slice(),
            b"event-b".as_slice(),
            b"CHG-1837".as_slice(),
        ] {
            reference.update((value.len() as u64).to_be_bytes());
            reference.update(value);
        }

        assert_eq!(
            plan.digest().as_bytes(),
            &<[u8; 32]>::from(reference.finalize())
        );
        assert_eq!(
            plan.direction(),
            RecoveryDirection::DatabaseAheadBrokerEarlier
        );
        assert_eq!(plan.events().len(), 2);
        assert_eq!(plan.change_ticket().as_str(), "CHG-1837");
        assert_eq!(DELIVERY_POLICY_REVISION, "same-id-delivery-v1");
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: positive-path fixtures must panic loudly when digest stability regresses.
    fn dr_recovery_digest_is_stable_across_caller_event_order() {
        let left = plan(&["event-c", "event-a", "event-b"]);
        let right = plan(&["event-b", "event-c", "event-a"]);
        assert_eq!(left.digest(), right.digest());

        let changed = L2DrRecoveryPlan::new(
            left.epoch_id(),
            left.tenant(),
            left.database_restore_point(),
            left.broker_restore_point(),
            events(&["event-a", "event-b", "event-c"]),
            RecoveryChangeTicket::parse("CHG-1837-OTHER").expect("valid ticket"),
        )
        .expect("valid changed plan");
        assert_ne!(left.digest(), changed.digest());
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: positive-path fixtures must panic loudly when authorization binding regresses.
    fn dr_recovery_authorized_plan_binds_validated_operator_subject_and_start_audit() {
        let start_audit_id = uuid::Uuid::parse_str(START_AUDIT).expect("start audit uuid");
        let recovery_plan = plan(&["event-a"]);
        let capability = authorized_capability();
        let authorized = AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
            recovery_plan.clone(),
            durable_start(&recovery_plan),
            capability,
        )
        .expect("authorized plan");
        assert_eq!(authorized.caller().as_str(), "rss-maintenance-operator");
        assert_eq!(
            authorized.operator_subject().as_str(),
            "service:l2-dr-primary"
        );
        assert_eq!(authorized.start_audit_id(), start_audit_id);
        assert_eq!(authorized.capability(), capability);
        assert_eq!(authorized.plan().events().len(), 1);

        let first_start_audit_id = uuid::Uuid::new_v4();
        let durable = L2DrRecoveryDurableReceipt::from_store(
            recovery_plan.epoch_id(),
            recovery_plan.tenant(),
            recovery_plan.database_restore_point(),
            recovery_plan.broker_restore_point(),
            *recovery_plan.digest(),
            recovery_plan.direction(),
            recovery_plan.events().clone(),
            DELIVERY_POLICY_REVISION.to_owned(),
            L2DrRecoveryOperatorSubject::parse("service:l2-dr-first").expect("valid subject"),
            first_start_audit_id,
            point(1_700_000_000_000_300),
            L2DrRecoveryOutcome::AlreadyApplied,
        )
        .expect("decoded receipt");
        let receipt =
            L2DrRecoveryReceipt::from_store(&authorized, durable).expect("durable receipt");
        assert_eq!(receipt.operator_subject().as_str(), "service:l2-dr-first");
        assert_eq!(receipt.start_audit_id(), first_start_audit_id);
        assert_eq!(receipt.events(), recovery_plan.events());
        assert_eq!(receipt.policy_revision(), DELIVERY_POLICY_REVISION);

        let invalid_plan = plan(&["event-a"]);
        let invalid_proof = L2DrRecoveryDurableStartProof::from_store(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            L2DrRecoveryOperatorSubject::parse("service:l2-dr-primary").expect("valid subject"),
            invalid_plan.tenant(),
            invalid_plan.epoch_id(),
            *invalid_plan.digest(),
            uuid::Uuid::nil(),
        );
        assert_eq!(invalid_proof, Err(L2DrRecoveryError::InvalidStartAuditId));

        for invalid in [
            String::new(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "control\ncharacter".to_owned(),
            "x".repeat(129),
        ] {
            assert_eq!(
                L2DrRecoveryOperatorSubject::parse(invalid),
                Err(L2DrRecoveryError::InvalidOperatorSubject)
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: mismatch fixtures must panic loudly when seed plan construction fails.
    fn dr_recovery_start_audit_mismatch_rejects_tenant_epoch_or_digest_drift() {
        let recovery_plan = plan(&["event-a"]);
        let capability = authorized_capability();
        let cases = [
            (
                "tenant",
                L2DrRecoveryDurableStartProof::from_store(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    L2DrRecoveryOperatorSubject::parse("service:l2-dr-primary")
                        .expect("valid subject"),
                    vocab::TenantId::parse(OTHER_TENANT).expect("other tenant"),
                    recovery_plan.epoch_id(),
                    *recovery_plan.digest(),
                    uuid::Uuid::parse_str(START_AUDIT).expect("start audit uuid"),
                )
                .expect("mismatched tenant proof"),
            ),
            (
                "epoch",
                L2DrRecoveryDurableStartProof::from_store(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    L2DrRecoveryOperatorSubject::parse("service:l2-dr-primary")
                        .expect("valid subject"),
                    recovery_plan.tenant(),
                    RecoveryEpochId::parse(OTHER_EPOCH).expect("other epoch"),
                    *recovery_plan.digest(),
                    uuid::Uuid::parse_str(START_AUDIT).expect("start audit uuid"),
                )
                .expect("mismatched epoch proof"),
            ),
            (
                "digest",
                L2DrRecoveryDurableStartProof::from_store(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    L2DrRecoveryOperatorSubject::parse("service:l2-dr-primary")
                        .expect("valid subject"),
                    recovery_plan.tenant(),
                    recovery_plan.epoch_id(),
                    *plan(&["event-b"]).digest(),
                    uuid::Uuid::parse_str(START_AUDIT).expect("start audit uuid"),
                )
                .expect("mismatched digest proof"),
            ),
        ];
        for (label, proof) in cases {
            assert_eq!(
                AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
                    recovery_plan.clone(),
                    proof,
                    capability,
                ),
                Err(L2DrRecoveryError::StartAuditMismatch),
                "{label}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: positive-path fixtures must panic loudly when authorization binding regresses.
    fn dr_recovery_authorization_consumes_matching_durable_start_proof() {
        let plan = plan(&["event-a"]);
        let proof = L2DrRecoveryDurableStartProof::from_store(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            L2DrRecoveryOperatorSubject::parse("service:l2-dr-primary").expect("valid subject"),
            plan.tenant(),
            plan.epoch_id(),
            *plan.digest(),
            uuid::Uuid::parse_str(START_AUDIT).expect("start audit uuid"),
        )
        .expect("durable start proof");
        let authorized = AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
            plan,
            proof,
            authorized_capability(),
        )
        .expect("authorized plan");
        assert_eq!(authorized.start_audit_id().to_string(), START_AUDIT);
    }

    #[test]
    fn dr_recovery_errors_have_one_closed_audit_reason_source() {
        for (error, expected) in [
            (
                L2DrRecoveryError::InvalidOperatorCaller,
                "operator_authorization",
            ),
            (
                L2DrRecoveryError::InvalidOperatorSubject,
                "operator_authorization",
            ),
            (L2DrRecoveryError::InvalidStartAuditId, "audit"),
            (L2DrRecoveryError::StartAuditMismatch, "audit"),
            (L2DrRecoveryError::TenantScopeMismatch, "tenant_scope"),
            (L2DrRecoveryError::EpochConflict, "epoch_conflict"),
            (L2DrRecoveryError::FactNotFound, "event_missing"),
            (L2DrRecoveryError::FactNotPublished, "event_state"),
            (L2DrRecoveryError::FactConflict, "event_state"),
            (L2DrRecoveryError::DeadlineExpired, "deadline"),
            (L2DrRecoveryError::DeliveryPolicyMismatch, "policy"),
            (L2DrRecoveryError::StoreInvariant, "policy"),
            (L2DrRecoveryError::StoreUnavailable, "execution"),
            (L2DrRecoveryError::ApplyLostLock, "execution"),
            (L2DrRecoveryError::InvalidRestorePoint, "plan_invalid"),
            (L2DrRecoveryError::EqualRestorePoints, "plan_invalid"),
            (L2DrRecoveryError::InvalidRecoveryEpochId, "plan_invalid"),
            (L2DrRecoveryError::EmptyEventSet, "plan_invalid"),
            (L2DrRecoveryError::TooManyEvents, "plan_invalid"),
            (L2DrRecoveryError::DuplicateEventId, "plan_invalid"),
            (L2DrRecoveryError::InvalidChangeTicket, "plan_invalid"),
            (L2DrRecoveryError::CanonicalFieldTooLong, "plan_invalid"),
            (L2DrRecoveryError::InvalidDurablePlan, "plan_invalid"),
        ] {
            assert_eq!(error.audit_reason(), expected, "{}", error.as_label());
        }
    }
}
