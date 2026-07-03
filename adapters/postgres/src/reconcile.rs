//! Postgres durable reconcile schema adapter (#1629).
//!
//! This module intentionally exposes only a narrow target/lease/attempt/action store. It does not
//! wire a runtime worker or define a new engine/domain trait. All tenant-table access goes through
//! [`PgTenantPool`], so `SET LOCAL rss.tenant_id` remains the single RLS funnel.
//!
//! ref: kube-rs/kube kube-runtime/src/controller/mod.rs@ae49cce192b85db3d734d290a6031aa2d9ac60e0
//! ref: apalis-postgres migrations/20220530084123_jobs_workers.sql@5a930218b6b4128fc4c9e191cecc7cd0e1cbbbed

use std::time::Duration;

use diport::RedactedSource;

use crate::PgStore;
use crate::cotx::PgTenantPool;

/// Reconcile target identity under one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileTargetKey {
    reconciler_id: String,
    resource_kind: String,
    resource_id: String,
}

impl ReconcileTargetKey {
    /// Build a validated reconcile target key.
    pub fn parse(
        reconciler_id: impl Into<String>,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Result<Self, ReconcileKeyError> {
        let reconciler_id = validate_component(
            "reconciler_id",
            reconciler_id.into(),
            RECONCILE_ID_MAX_BYTES,
        )?;
        let resource_kind = validate_component(
            "resource_kind",
            resource_kind.into(),
            RECONCILE_ID_MAX_BYTES,
        )?;
        let resource_id =
            validate_component("resource_id", resource_id.into(), RESOURCE_ID_MAX_BYTES)?;
        Ok(Self {
            reconciler_id,
            resource_kind,
            resource_id,
        })
    }

    /// Reconciler namespace.
    pub fn reconciler_id(&self) -> &str {
        &self.reconciler_id
    }

    /// Resource kind within this reconciler.
    pub fn resource_kind(&self) -> &str {
        &self.resource_kind
    }

    /// Opaque resource id within this reconciler.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
}

/// Reconcile key parse error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReconcileKeyError {
    /// Component was empty.
    #[error("{component} is empty")]
    Empty { component: &'static str },
    /// Component was blank or contained control characters.
    #[error("{component} is blank or contains control characters")]
    NotCanonical { component: &'static str },
    /// Component exceeded the DB-bound byte limit.
    #[error("{component} exceeds max bytes")]
    TooLong { component: &'static str },
}

/// Durable target row created or found by [`PgReconcileStore::upsert_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileTarget {
    target_id: String,
}

impl ReconcileTarget {
    /// DB target id as canonical UUID text.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
}

/// Lease CAS result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileLeaseOutcome {
    /// Lease token and epoch still matched.
    Held,
    /// Lease token or epoch no longer matched.
    Lost,
}

/// Acquired reconcile lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileLease {
    target_id: String,
    lease_token: String,
    epoch: u64,
}

impl ReconcileLease {
    /// Target this lease protects.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Opaque lease token as UUID text.
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }

    /// Monotonic target-local epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Trigger reason for a reconcile attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileAttemptTrigger {
    /// Periodic resync pulse.
    Resync,
    /// Targeted event dispatch.
    Targeted,
    /// Requeue requested by prior outcome.
    Requeue,
    /// Stale lease was reclaimed.
    LeaseReclaim,
}

impl ReconcileAttemptTrigger {
    fn as_label(self) -> &'static str {
        match self {
            Self::Resync => "resync",
            Self::Targeted => "targeted",
            Self::Requeue => "requeue",
            Self::LeaseReclaim => "lease_reclaim",
        }
    }
}

/// Append-only attempt insert request.
#[derive(Debug, Clone)]
pub struct ReconcileAttemptInsert<'a> {
    /// Target id as UUID text.
    pub target_id: &'a str,
    /// Lease token as UUID text.
    pub lease_token: &'a str,
    /// Lease epoch.
    pub epoch: u64,
    /// Holder id.
    pub holder_id: &'a str,
    /// Trigger reason.
    pub trigger: ReconcileAttemptTrigger,
}

/// Append-only action insert request.
#[derive(Debug, Clone)]
pub struct ReconcileActionInsert<'a> {
    /// Attempt id as UUID text.
    pub attempt_id: &'a str,
    /// Target id as UUID text.
    pub target_id: &'a str,
    /// Pure converge action label.
    pub action: consistency::ConvergeAction,
    /// Reconcile result label.
    pub result: consistency::ReconcileResultLabel,
    /// Optional requeue delay.
    pub requeue_after: Option<Duration>,
    /// Optional error kind label.
    pub error_kind: Option<ReconcileActionErrorKind>,
}

/// Error kind recorded on an action result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileActionErrorKind {
    /// Transient error.
    Transient,
    /// Permanent error.
    Permanent,
    /// Invariant error.
    Invariant,
}

impl ReconcileActionErrorKind {
    fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Invariant => "invariant",
        }
    }
}

/// Append-only insert result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileLedgerId {
    id: String,
}

impl ReconcileLedgerId {
    /// UUID id as canonical text.
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Postgres reconcile target/lease/attempt/action store.
///
/// Private field is the tenant-scoped pool wrapper; callers cannot bypass RLS setup through this
/// store.
pub struct PgReconcileStore {
    pool: PgTenantPool,
}

impl PgStore {
    /// Construct the reconcile store from the shared pool.
    pub(crate) fn reconcile(&self) -> PgReconcileStore {
        PgReconcileStore {
            pool: PgTenantPool::new(self),
        }
    }
}

impl PgReconcileStore {
    /// Upsert a target and ensure its lease row exists.
    pub async fn upsert_target(
        &self,
        tenant: vocab::TenantId,
        key: &ReconcileTargetKey,
    ) -> Result<ReconcileTarget, ReconcileStoreError> {
        let fields = TargetFields::from_key(tenant, key);
        self.pool
            .write(
                tenant,
                move |tx| {
                    Box::pin(async move {
                        let (target_id,): (String,) = sqlx::query_as(
                            r#"
                            INSERT INTO reconcile_targets
                                (tenant_id, reconciler_id, resource_kind, resource_id)
                            VALUES ($1::uuid, $2, $3, $4)
                            ON CONFLICT (tenant_id, reconciler_id, resource_kind, resource_id)
                            DO UPDATE
                              SET status = 'active',
                                  updated_at = now()
                            RETURNING target_id::text
                            "#,
                        )
                        .bind(&fields.tenant_id)
                        .bind(&fields.reconciler_id)
                        .bind(&fields.resource_kind)
                        .bind(&fields.resource_id)
                        .fetch_one(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;

                        sqlx::query(
                            r#"
                            INSERT INTO reconcile_leases (tenant_id, target_id)
                            VALUES ($1::uuid, $2::uuid)
                            ON CONFLICT (tenant_id, target_id) DO NOTHING
                            "#,
                        )
                        .bind(&fields.tenant_id)
                        .bind(&target_id)
                        .execute(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;

                        Ok(ReconcileTarget { target_id })
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Acquire a free or expired lease. Returns `Ok(None)` when another holder still owns it.
    pub async fn acquire_lease(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Option<ReconcileLease>, ReconcileStoreError> {
        validate_runtime_component("target_id", target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("holder_id", holder_id, HOLDER_ID_MAX_BYTES)?;
        let ttl_secs = duration_secs(ttl)?;
        let tenant_id = tenant.to_string();
        let target_id = target_id.to_string();
        let holder_id = holder_id.to_string();

        self.pool
            .write(
                tenant,
                move |tx| {
                    let tenant_id = tenant_id.clone();
                    let target_id = target_id.clone();
                    let holder_id = holder_id.clone();
                    Box::pin(async move {
                        let row: Option<(String, String, i64)> = sqlx::query_as(
                            r#"
                            UPDATE reconcile_leases
                            SET state = 'held',
                                lease_token = gen_random_uuid(),
                                holder_id = $3,
                                epoch = epoch + 1,
                                acquired_at = now(),
                                expires_at = now() + make_interval(secs => $4),
                                heartbeat_at = now(),
                                updated_at = now()
                            WHERE tenant_id = $1::uuid
                              AND target_id = $2::uuid
                              AND (
                                    state = 'free'
                                 OR expires_at <= now()
                              )
                            RETURNING target_id::text, lease_token::text, epoch
                            "#,
                        )
                        .bind(&tenant_id)
                        .bind(&target_id)
                        .bind(&holder_id)
                        .bind(ttl_secs)
                        .fetch_optional(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;

                        row.map(lease_from_row).transpose()
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Extend a held lease by token and epoch CAS.
    pub async fn extend_lease(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        lease_token: &str,
        epoch: u64,
        ttl: Duration,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        let ttl_secs = duration_secs(ttl)?;
        let epoch = epoch_to_db(epoch)?;
        self.cas_lease(
            tenant,
            LeaseCasRequest {
                target_id,
                lease_token,
                epoch,
                operation: LeaseCasOperation::Extend { ttl_secs },
            },
        )
        .await
    }

    /// Release a held lease by token and epoch CAS.
    pub async fn release_lease(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
        lease_token: &str,
        epoch: u64,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        let epoch = epoch_to_db(epoch)?;
        self.cas_lease(
            tenant,
            LeaseCasRequest {
                target_id,
                lease_token,
                epoch,
                operation: LeaseCasOperation::Release,
            },
        )
        .await
    }

    /// Append one immutable attempt row.
    pub async fn append_attempt(
        &self,
        tenant: vocab::TenantId,
        attempt: ReconcileAttemptInsert<'_>,
    ) -> Result<ReconcileLedgerId, ReconcileStoreError> {
        validate_runtime_component("target_id", attempt.target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("lease_token", attempt.lease_token, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("holder_id", attempt.holder_id, HOLDER_ID_MAX_BYTES)?;
        let tenant_id = tenant.to_string();
        let target_id = attempt.target_id.to_string();
        let lease_token = attempt.lease_token.to_string();
        let epoch = epoch_to_db(attempt.epoch)?;
        let holder_id = attempt.holder_id.to_string();
        let trigger = attempt.trigger.as_label();

        self.pool
            .write(
                tenant,
                move |tx| {
                    Box::pin(async move {
                        let (id,): (String,) = sqlx::query_as(
                            r#"
                            INSERT INTO reconcile_attempts
                                (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind)
                            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
                            RETURNING attempt_id::text
                            "#,
                        )
                        .bind(&tenant_id)
                        .bind(&target_id)
                        .bind(&lease_token)
                        .bind(epoch)
                        .bind(&holder_id)
                        .bind(trigger)
                        .fetch_one(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;
                        Ok(ReconcileLedgerId { id })
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Append one immutable action row.
    pub async fn append_action(
        &self,
        tenant: vocab::TenantId,
        action: ReconcileActionInsert<'_>,
    ) -> Result<ReconcileLedgerId, ReconcileStoreError> {
        validate_runtime_component("attempt_id", action.attempt_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("target_id", action.target_id, UUID_TEXT_MAX_BYTES)?;
        let requeue_after_ms = action.requeue_after.map(duration_millis).transpose()?;
        let tenant_id = tenant.to_string();
        let attempt_id = action.attempt_id.to_string();
        let target_id = action.target_id.to_string();
        let action_kind = action.action.as_label();
        let result_label = action.result.as_label();
        let error_kind = action.error_kind.map(ReconcileActionErrorKind::as_label);

        self.pool
            .write(
                tenant,
                move |tx| {
                    Box::pin(async move {
                        let (id,): (String,) = sqlx::query_as(
                            r#"
                            INSERT INTO reconcile_actions
                                (tenant_id, attempt_id, target_id, action_kind, result_label,
                                 requeue_after_ms, error_kind)
                            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)
                            RETURNING action_id::text
                            "#,
                        )
                        .bind(&tenant_id)
                        .bind(&attempt_id)
                        .bind(&target_id)
                        .bind(action_kind)
                        .bind(result_label)
                        .bind(requeue_after_ms)
                        .bind(error_kind)
                        .fetch_one(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;
                        Ok(ReconcileLedgerId { id })
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    async fn cas_lease(
        &self,
        tenant: vocab::TenantId,
        request: LeaseCasRequest<'_>,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        validate_runtime_component("target_id", request.target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("lease_token", request.lease_token, UUID_TEXT_MAX_BYTES)?;
        let tenant_id = tenant.to_string();
        let target_id = request.target_id.to_string();
        let lease_token = request.lease_token.to_string();
        self.pool
            .write(
                tenant,
                move |tx| {
                    Box::pin(async move {
                        let result = match request.operation {
                            LeaseCasOperation::Extend { ttl_secs } => {
                                sqlx::query(
                                    r#"
                                    UPDATE reconcile_leases
                                    SET expires_at = now() + make_interval(secs => $5),
                                        heartbeat_at = now(),
                                        updated_at = now()
                                    WHERE tenant_id = $1::uuid
                                      AND target_id = $2::uuid
                                      AND lease_token = $3::uuid
                                      AND epoch = $4
                                      AND state = 'held'
                                      AND expires_at > now()
                                    "#,
                                )
                                .bind(&tenant_id)
                                .bind(&target_id)
                                .bind(&lease_token)
                                .bind(request.epoch)
                                .bind(ttl_secs)
                                .execute(tx.conn())
                                .await
                            }
                            LeaseCasOperation::Release => {
                                sqlx::query(
                                    r#"
                                    UPDATE reconcile_leases
                                    SET state = 'free',
                                        lease_token = NULL,
                                        holder_id = NULL,
                                        acquired_at = NULL,
                                        expires_at = NULL,
                                        heartbeat_at = NULL,
                                        updated_at = now()
                                    WHERE tenant_id = $1::uuid
                                      AND target_id = $2::uuid
                                      AND lease_token = $3::uuid
                                      AND epoch = $4
                                      AND state = 'held'
                                    "#,
                                )
                                .bind(&tenant_id)
                                .bind(&target_id)
                                .bind(&lease_token)
                                .bind(request.epoch)
                                .execute(tx.conn())
                                .await
                            }
                        }
                        .map_err(ReconcileStoreError::new)?;

                        Ok(if result.rows_affected() == 1 {
                            ReconcileLeaseOutcome::Held
                        } else {
                            ReconcileLeaseOutcome::Lost
                        })
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }
}

/// Reconcile store error.
#[derive(Debug, thiserror::Error)]
#[error("reconcile store operation failed")]
pub struct ReconcileStoreError {
    #[source]
    source: RedactedSource,
}

impl ReconcileStoreError {
    fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

impl From<ReconcileKeyError> for ReconcileStoreError {
    fn from(source: ReconcileKeyError) -> Self {
        Self::new(source)
    }
}

struct TargetFields {
    tenant_id: String,
    reconciler_id: String,
    resource_kind: String,
    resource_id: String,
}

impl TargetFields {
    fn from_key(tenant: vocab::TenantId, key: &ReconcileTargetKey) -> Self {
        Self {
            tenant_id: tenant.to_string(),
            reconciler_id: key.reconciler_id().to_string(),
            resource_kind: key.resource_kind().to_string(),
            resource_id: key.resource_id().to_string(),
        }
    }
}

struct LeaseCasRequest<'a> {
    target_id: &'a str,
    lease_token: &'a str,
    epoch: i64,
    operation: LeaseCasOperation,
}

enum LeaseCasOperation {
    Extend { ttl_secs: i64 },
    Release,
}

const RECONCILE_ID_MAX_BYTES: usize = 128;
const RESOURCE_ID_MAX_BYTES: usize = 512;
const HOLDER_ID_MAX_BYTES: usize = 256;
const UUID_TEXT_MAX_BYTES: usize = 36;

fn validate_component(
    component: &'static str,
    value: String,
    max_bytes: usize,
) -> Result<String, ReconcileKeyError> {
    if value.is_empty() {
        return Err(ReconcileKeyError::Empty { component });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReconcileKeyError::NotCanonical { component });
    }
    if value.len() > max_bytes {
        return Err(ReconcileKeyError::TooLong { component });
    }
    Ok(value)
}

fn validate_runtime_component(
    component: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ReconcileStoreError> {
    validate_component(component, value.to_string(), max_bytes)
        .map(|_| ())
        .map_err(ReconcileStoreError::from)
}

fn epoch_to_db(epoch: u64) -> Result<i64, ReconcileStoreError> {
    i64::try_from(epoch).map_err(ReconcileStoreError::new)
}

fn epoch_from_db(epoch: i64) -> Result<u64, ReconcileStoreError> {
    u64::try_from(epoch).map_err(ReconcileStoreError::new)
}

fn duration_secs(duration: Duration) -> Result<i64, ReconcileStoreError> {
    let secs = i64::try_from(duration.as_secs()).map_err(ReconcileStoreError::new)?;
    if secs <= 0 {
        return Err(ReconcileStoreError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "lease ttl must be positive",
        )));
    }
    Ok(secs)
}

fn duration_millis(duration: Duration) -> Result<i64, ReconcileStoreError> {
    i64::try_from(duration.as_millis()).map_err(ReconcileStoreError::new)
}

fn lease_from_row(row: (String, String, i64)) -> Result<ReconcileLease, ReconcileStoreError> {
    Ok(ReconcileLease {
        target_id: row.0,
        lease_token: row.1,
        epoch: epoch_from_db(row.2)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIGRATION_0041: &str = include_str!("../migrations/0041_create_reconcile_schema.sql");

    #[test]
    fn migration_locks_reconcile_labels_and_append_only_grants() {
        for needle in [
            "CHECK (status IN ('active', 'disabled'))",
            "CHECK (state IN ('free', 'held'))",
            "CHECK (trigger_kind IN ('resync', 'targeted', 'requeue', 'lease_reclaim'))",
            "CHECK (action_kind IN ('noop', 'create', 'update', 'delete'))",
            "CHECK (result_label IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant'))",
            "GRANT SELECT, INSERT ON reconcile_attempts TO rss_app",
            "REVOKE UPDATE, DELETE ON reconcile_attempts FROM rss_app",
            "GRANT SELECT, INSERT ON reconcile_actions TO rss_app",
            "REVOKE UPDATE, DELETE ON reconcile_actions FROM rss_app",
        ] {
            assert!(
                MIGRATION_0041.contains(needle),
                "0041 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn migration_locks_reconcile_rls_and_cas_predicates() {
        for table in [
            "reconcile_targets",
            "reconcile_leases",
            "reconcile_attempts",
            "reconcile_actions",
        ] {
            assert!(
                MIGRATION_0041.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY")),
                "0041 migration must FORCE RLS on {table}"
            );
        }
        for needle in [
            "tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
            "CONSTRAINT reconcile_targets_tenant_resource_unique",
            "UNIQUE (tenant_id, reconciler_id, resource_kind, resource_id)",
            "CONSTRAINT reconcile_attempts_attempt_target_unique",
            "FOREIGN KEY (tenant_id, attempt_id, target_id)",
            "FOREIGN KEY (tenant_id, target_id)",
        ] {
            assert!(
                MIGRATION_0041.contains(needle),
                "0041 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn key_parse_rejects_non_canonical_components() {
        assert!(ReconcileTargetKey::parse("", "kind", "res").is_err());
        assert!(ReconcileTargetKey::parse("rec", " ", "res").is_err());
        assert!(ReconcileTargetKey::parse("rec", "kind", "res\nid").is_err());
        assert!(ReconcileTargetKey::parse("rec", "kind", "res").is_ok());
    }
}
