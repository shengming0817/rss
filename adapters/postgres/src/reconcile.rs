//! Postgres durable reconcile schema adapter (#1629).
//!
//! This module intentionally exposes only a narrow target/lease/attempt/action store. It does not
//! wire a runtime worker or define a new engine/domain trait. All tenant-table access goes through
//! [`PgTenantPool`], so `SET LOCAL rss.tenant_id` remains the single RLS funnel.
//!
//! ref: kube-rs/kube kube-runtime/src/controller/mod.rs@ae49cce192b85db3d734d290a6031aa2d9ac60e0
//! ref: apalis-postgres migrations/20220530084123_jobs_workers.sql@5a930218b6b4128fc4c9e191cecc7cd0e1cbbbed

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use diport::{Clock, RedactedSource};
use eventexec::reconcile::{
    AttemptErrorKind, AttemptResult, AttemptTrigger, ClaimedTarget, ReconcileAttempt,
    ReconcileScheduleError, ReconcileScheduleStore, ReviewedCommand, ScheduleAttemptOutcome,
    ScheduleLeaseOutcome,
};

use crate::PgStore;
use crate::cotx::{PgTenantPool, TxCapability, infra_tenant_scope};
use crate::outbox::{
    OutboxAppendOutcome, OutboxEnvelope, append_outbox, metadata_with_ambient, unix_secs,
};

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

/// Append-only attempt result insert request.
#[derive(Debug, Clone)]
pub struct ReconcileAttemptResultInsert<'a> {
    /// Attempt id as UUID text.
    pub attempt_id: &'a str,
    /// Target id as UUID text.
    pub target_id: &'a str,
    /// Reconcile result label.
    pub result: consistency::ReconcileResultLabel,
    /// Optional requeue delay.
    pub requeue_after: Option<Duration>,
    /// Optional error kind label.
    pub error_kind: Option<ReconcileActionErrorKind>,
    /// Delay before this target is due again.
    pub next_run_after: Duration,
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
    clock: Arc<dyn Clock>,
}

struct PgReconcileSystemClock;

impl Clock for PgReconcileSystemClock {
    fn now(&self) -> SystemTime {
        // reason: postgres reconcile outbox producer production clock; adapter-owned Clock impl is a sanctioned system-time boundary.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

impl PgStore {
    /// Construct the reconcile store from the shared pool.
    pub(crate) fn reconcile(&self) -> PgReconcileStore {
        PgReconcileStore {
            pool: PgTenantPool::new(self),
            clock: Arc::new(PgReconcileSystemClock),
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
                infra_tenant_scope(tenant),
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
                infra_tenant_scope(tenant),
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
    ) -> Result<Option<ReconcileLedgerId>, ReconcileStoreError> {
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
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        let held = lock_held_lease(tx, &tenant_id, &target_id, &lease_token, epoch)
                            .await
                            .map_err(ReconcileStoreError::new)?;
                        if !held {
                            return Ok(None);
                        }
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
                        Ok(Some(ReconcileLedgerId { id }))
                    })
                },
                ReconcileStoreError::new,
            )
            .await
    }

    /// Append one immutable attempt result row and schedule the next target run under lease CAS.
    pub async fn append_attempt_result(
        &self,
        tenant: vocab::TenantId,
        lease_token: &str,
        epoch: u64,
        result: ReconcileAttemptResultInsert<'_>,
    ) -> Result<ReconcileLeaseOutcome, ReconcileStoreError> {
        validate_runtime_component("attempt_id", result.attempt_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("target_id", result.target_id, UUID_TEXT_MAX_BYTES)?;
        validate_runtime_component("lease_token", lease_token, UUID_TEXT_MAX_BYTES)?;
        let requeue_after_ms = result.requeue_after.map(duration_millis).transpose()?;
        let next_run_after_ms = duration_millis(result.next_run_after)?;
        let tenant_id = tenant.to_string();
        let attempt_id = result.attempt_id.to_string();
        let target_id = result.target_id.to_string();
        let lease_token = lease_token.to_string();
        let epoch = epoch_to_db(epoch)?;
        let result_label = result.result.as_label();
        let error_kind = result.error_kind.map(ReconcileActionErrorKind::as_label);

        self.pool
            .write(
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        let held = lock_held_lease(tx, &tenant_id, &target_id, &lease_token, epoch)
                            .await
                            .map_err(ReconcileStoreError::new)?;
                        if !held {
                            return Ok(ReconcileLeaseOutcome::Lost);
                        }
                        sqlx::query(
                            r#"
                            INSERT INTO reconcile_attempt_results
                                (tenant_id, attempt_id, target_id, result_label, requeue_after_ms,
                                 error_kind)
                            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
                            "#,
                        )
                        .bind(&tenant_id)
                        .bind(&attempt_id)
                        .bind(&target_id)
                        .bind(result_label)
                        .bind(requeue_after_ms)
                        .bind(error_kind)
                        .execute(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;
                        sqlx::query(
                            r#"
                            UPDATE reconcile_targets
                            SET next_run_at = now() + ($3::bigint * interval '1 millisecond'),
                                updated_at = now()
                            WHERE tenant_id = $1::uuid
                              AND target_id = $2::uuid
                            "#,
                        )
                        .bind(&tenant_id)
                        .bind(&target_id)
                        .bind(next_run_after_ms)
                        .execute(tx.conn())
                        .await
                        .map_err(ReconcileStoreError::new)?;
                        Ok(ReconcileLeaseOutcome::Held)
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
                infra_tenant_scope(tenant),
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

    /// Pause a target: future due scans skip disabled rows.
    pub async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileStoreError> {
        update_target_status(&self.pool, tenant, target_id, "disabled", false).await
    }

    /// Resume a target and make it immediately due.
    pub async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileStoreError> {
        update_target_status(&self.pool, tenant, target_id, "active", true).await
    }
}

impl ReconcileScheduleStore for PgReconcileStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        limit: u32,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
        validate_runtime_component("reconciler_id", reconciler_id, RECONCILE_ID_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        validate_runtime_component("holder_id", holder_id, HOLDER_ID_MAX_BYTES)
            .map_err(ReconcileScheduleError::new)?;
        let ttl_secs = duration_secs(lease_ttl).map_err(ReconcileScheduleError::new)?;
        let tenant_id = tenant.to_string();
        let reconciler_id = reconciler_id.to_string();
        let holder_id = holder_id.to_string();
        let limit = i64::from(limit.max(1));
        self.pool
            .write(
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        let rows: Vec<(String, String, i64, String, String, String, String)> =
                            sqlx::query_as(
                                r#"
                                WITH due AS (
                                    SELECT t.tenant_id,
                                           t.target_id,
                                           t.reconciler_id,
                                           t.resource_kind,
                                           t.resource_id,
                                           l.state AS prior_state,
                                           l.expires_at AS prior_expires_at,
                                           r.result_label AS prior_result_label
                                    FROM reconcile_targets t
                                    JOIN reconcile_leases l
                                      ON l.tenant_id = t.tenant_id
                                     AND l.target_id = t.target_id
                                    LEFT JOIN LATERAL (
                                        SELECT result_label
                                        FROM reconcile_attempt_results
                                        WHERE tenant_id = t.tenant_id
                                          AND target_id = t.target_id
                                        ORDER BY completed_at DESC, attempt_id DESC
                                        LIMIT 1
                                    ) r ON true
                                    WHERE t.tenant_id = $1::uuid
                                      AND t.reconciler_id = $2
                                      AND t.status = 'active'
                                      AND t.next_run_at <= now()
                                      AND (l.state = 'free' OR l.expires_at <= now())
                                    ORDER BY t.next_run_at, t.target_id
                                    LIMIT $5
                                    FOR UPDATE OF l SKIP LOCKED
                                )
                                UPDATE reconcile_leases l
                                SET state = 'held',
                                    lease_token = gen_random_uuid(),
                                    holder_id = $3,
                                    epoch = l.epoch + 1,
                                    acquired_at = now(),
                                    expires_at = now() + make_interval(secs => $4),
                                    heartbeat_at = now(),
                                    updated_at = now()
                                FROM due d
                                WHERE l.tenant_id = d.tenant_id
                                  AND l.target_id = d.target_id
                                RETURNING l.target_id::text,
                                          l.lease_token::text,
                                          l.epoch,
                                          d.reconciler_id,
                                          d.resource_kind,
                                          d.resource_id,
                                          CASE
                                            WHEN d.prior_state = 'held'
                                             AND d.prior_expires_at <= now()
                                            THEN 'lease_reclaim'
                                            WHEN d.prior_result_label = 'requeue_after'
                                            THEN 'requeue'
                                            ELSE 'resync'
                                          END
                                "#,
                            )
                            .bind(&tenant_id)
                            .bind(&reconciler_id)
                            .bind(&holder_id)
                            .bind(ttl_secs)
                            .bind(limit)
                            .fetch_all(tx.conn())
                            .await
                            .map_err(ReconcileScheduleError::new)?;
                        rows.into_iter()
                            .map(|row| {
                                Ok(ClaimedTarget::new(
                                    tenant,
                                    row.0,
                                    row.1,
                                    epoch_from_db(row.2).map_err(ReconcileScheduleError::new)?,
                                    row.3,
                                    row.4,
                                    row.5,
                                    trigger_from_label(&row.6)
                                        .map_err(ReconcileScheduleError::new)?,
                                ))
                            })
                            .collect()
                    })
                },
                ReconcileScheduleError::new,
            )
            .await
    }

    async fn append_attempt(
        &self,
        target: &ClaimedTarget,
        holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
        let trigger = match target.trigger() {
            AttemptTrigger::Resync => ReconcileAttemptTrigger::Resync,
            AttemptTrigger::Targeted => ReconcileAttemptTrigger::Targeted,
            AttemptTrigger::Requeue => ReconcileAttemptTrigger::Requeue,
            AttemptTrigger::LeaseReclaim => ReconcileAttemptTrigger::LeaseReclaim,
        };
        let Some(id) = PgReconcileStore::append_attempt(
            self,
            target.tenant(),
            ReconcileAttemptInsert {
                target_id: target.target_id(),
                lease_token: target.lease_token(),
                epoch: target.epoch(),
                holder_id,
                trigger,
            },
        )
        .await
        .map_err(ReconcileScheduleError::new)?
        else {
            return Ok(ScheduleAttemptOutcome::Lost);
        };
        Ok(ScheduleAttemptOutcome::Started(ReconcileAttempt::new(
            id.id(),
            target.clone(),
        )))
    }

    async fn record_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        result: AttemptResult,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        let error_kind = result.error_kind().map(map_attempt_error_kind);
        let outcome = self
            .append_attempt_result(
                attempt.target().tenant(),
                attempt.target().lease_token(),
                attempt.target().epoch(),
                ReconcileAttemptResultInsert {
                    attempt_id: attempt.attempt_id(),
                    target_id: attempt.target().target_id(),
                    result: result.result(),
                    requeue_after: result.requeue_after(),
                    error_kind,
                    next_run_after: result.next_run_after(),
                },
            )
            .await
            .map_err(ReconcileScheduleError::new)?;
        Ok(map_lease_outcome(outcome))
    }

    async fn record_action_and_enqueue_command(
        &self,
        attempt: &ReconcileAttempt,
        action: consistency::ConvergeAction,
        command: ReviewedCommand,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        let (intent, envelope_parts) = command.into_parts();
        let (contract, command_tenant, subject_id, actor, partition_key, causation_id) =
            envelope_parts.into_parts();
        if command_tenant != attempt.target().tenant() {
            return Err(ReconcileScheduleError::new(ReconcileTenantMismatch));
        }
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), command_tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        let tenant = attempt.target().tenant();
        let tenant_id = tenant.to_string();
        let attempt_id = attempt.attempt_id().to_string();
        let target_id = attempt.target().target_id().to_string();
        let lease_token = attempt.target().lease_token().to_string();
        let epoch = epoch_to_db(attempt.target().epoch()).map_err(ReconcileScheduleError::new)?;
        let action_kind = action.as_label();
        self.pool
            .write(
                infra_tenant_scope(tenant),
                move |tx| {
                    Box::pin(async move {
                        let held = lock_held_lease(tx, &tenant_id, &target_id, &lease_token, epoch)
                            .await
                            .map_err(ReconcileScheduleError::new)?;
                        if !held {
                            return Ok(ScheduleLeaseOutcome::Lost);
                        }
                        let prepared = crate::command_journal::prepare_command(tx, tenant, intent)
                            .await
                            .map_err(ReconcileScheduleError::new)?;
                        sqlx::query(
                            r#"
                            INSERT INTO reconcile_actions
                                (tenant_id, attempt_id, target_id, action_kind, result_label,
                                 requeue_after_ms, error_kind)
                            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'recorded', NULL, NULL)
                            "#,
                        )
                        .bind(&tenant_id)
                        .bind(&attempt_id)
                        .bind(&target_id)
                        .bind(action_kind)
                        .execute(tx.conn())
                        .await
                        .map_err(ReconcileScheduleError::new)?;
                        match append_outbox(tx, &prepared.entry, &env)
                            .await
                            .map_err(ReconcileScheduleError::new)?
                        {
                            OutboxAppendOutcome::Inserted => {}
                            OutboxAppendOutcome::AlreadyExists => {
                                ensure_existing_outbox_matches(tx, &prepared.entry, &env)
                                    .await
                                    .map_err(ReconcileScheduleError::new)?;
                            }
                        }
                        Ok(ScheduleLeaseOutcome::Held)
                    })
                },
                ReconcileScheduleError::new,
            )
            .await
    }

    async fn extend_lease(
        &self,
        target: &ClaimedTarget,
        lease_ttl: Duration,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        let outcome = PgReconcileStore::extend_lease(
            self,
            target.tenant(),
            target.target_id(),
            target.lease_token(),
            target.epoch(),
            lease_ttl,
        )
        .await
        .map_err(ReconcileScheduleError::new)?;
        Ok(map_lease_outcome(outcome))
    }

    async fn release_lease(
        &self,
        target: &ClaimedTarget,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        let outcome = PgReconcileStore::release_lease(
            self,
            target.tenant(),
            target.target_id(),
            target.lease_token(),
            target.epoch(),
        )
        .await
        .map_err(ReconcileScheduleError::new)?;
        Ok(map_lease_outcome(outcome))
    }

    async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        PgReconcileStore::pause_target(self, tenant, target_id)
            .await
            .map_err(ReconcileScheduleError::new)
    }

    async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        PgReconcileStore::resume_target(self, tenant, target_id)
            .await
            .map_err(ReconcileScheduleError::new)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("reconcile command tenant does not match attempt tenant")]
struct ReconcileTenantMismatch;

#[derive(Debug, thiserror::Error)]
#[error("reconcile command outbox conflict")]
struct ReconcileOutboxConflict;

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

async fn lock_held_lease(
    tx: &mut TxCapability<'_>,
    tenant_id: &str,
    target_id: &str,
    lease_token: &str,
    epoch: i64,
) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT 1
        FROM reconcile_leases
        WHERE tenant_id = $1::uuid
          AND target_id = $2::uuid
          AND lease_token = $3::uuid
          AND epoch = $4
          AND state = 'held'
          AND expires_at > now()
        FOR UPDATE
        "#,
    )
    .bind(tenant_id)
    .bind(target_id)
    .bind(lease_token)
    .bind(epoch)
    .fetch_optional(tx.conn())
    .await?;
    Ok(row.is_some())
}

async fn ensure_existing_outbox_matches(
    tx: &mut TxCapability<'_>,
    entry: &consistency::StoredOutboxEntry,
    env: &OutboxEnvelope,
) -> Result<(), ReconcileOutboxConflict> {
    let row: Option<(bool,)> = sqlx::query_as(
        r#"
        SELECT tenant_id = $2::uuid
           AND topic = $3
           AND domain = $4
           AND contract_id = $5
           AND contract_version = $6
           AND schema_hash = $7
           AND payload = $8 AS matches
        FROM outbox
        WHERE event_id = $1
        "#,
    )
    .bind(entry.idem_key().as_str())
    .bind(env.tenant().to_string())
    .bind(entry.topic().as_str())
    .bind(env.domain())
    .bind(env.contract_id())
    .bind(env.contract_version())
    .bind(env.schema_hash())
    .bind(entry.payload())
    .fetch_optional(tx.conn())
    .await
    .map_err(|_| ReconcileOutboxConflict)?;

    match row {
        Some((true,)) => Ok(()),
        Some((false,)) | None => Err(ReconcileOutboxConflict),
    }
}

async fn update_target_status(
    pool: &PgTenantPool,
    tenant: vocab::TenantId,
    target_id: &str,
    status: &'static str,
    due_now: bool,
) -> Result<(), ReconcileStoreError> {
    validate_runtime_component("target_id", target_id, UUID_TEXT_MAX_BYTES)?;
    let tenant_id = tenant.to_string();
    let target_id = target_id.to_string();
    pool.write(
        infra_tenant_scope(tenant),
        move |tx| {
            Box::pin(async move {
                sqlx::query(
                    r#"
                    UPDATE reconcile_targets
                    SET status = $3,
                        next_run_at = CASE WHEN $4 THEN now() ELSE next_run_at END,
                        updated_at = now()
                    WHERE tenant_id = $1::uuid
                      AND target_id = $2::uuid
                    "#,
                )
                .bind(&tenant_id)
                .bind(&target_id)
                .bind(status)
                .bind(due_now)
                .execute(tx.conn())
                .await
                .map_err(ReconcileStoreError::new)
                .and_then(|result| {
                    if result.rows_affected() == 1 {
                        Ok(())
                    } else {
                        Err(ReconcileStoreError::new(ReconcileTargetNotFound))
                    }
                })?;
                Ok(())
            })
        },
        ReconcileStoreError::new,
    )
    .await
}

#[derive(Debug, thiserror::Error)]
#[error("reconcile target not found")]
struct ReconcileTargetNotFound;

fn trigger_from_label(label: &str) -> Result<AttemptTrigger, ReconcileStoreError> {
    match label {
        "resync" => Ok(AttemptTrigger::Resync),
        "targeted" => Ok(AttemptTrigger::Targeted),
        "requeue" => Ok(AttemptTrigger::Requeue),
        "lease_reclaim" => Ok(AttemptTrigger::LeaseReclaim),
        _ => Err(ReconcileStoreError::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown reconcile attempt trigger",
        ))),
    }
}

fn map_attempt_error_kind(kind: AttemptErrorKind) -> ReconcileActionErrorKind {
    match kind {
        AttemptErrorKind::Transient => ReconcileActionErrorKind::Transient,
        AttemptErrorKind::Permanent => ReconcileActionErrorKind::Permanent,
        AttemptErrorKind::Invariant => ReconcileActionErrorKind::Invariant,
    }
}

fn map_lease_outcome(outcome: ReconcileLeaseOutcome) -> ScheduleLeaseOutcome {
    match outcome {
        ReconcileLeaseOutcome::Held => ScheduleLeaseOutcome::Held,
        ReconcileLeaseOutcome::Lost => ScheduleLeaseOutcome::Lost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIGRATION_0041: &str = include_str!("../migrations/0041_create_reconcile_schema.sql");
    const MIGRATION_0044: &str =
        include_str!("../migrations/0044_create_reconcile_attempt_results.sql");
    const MIGRATION_0045: &str =
        include_str!("../migrations/0045_reconcile_actions_recorded_label.sql");

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
    fn attempt_results_migration_is_append_only_and_tenant_scoped() {
        for needle in [
            "CREATE TABLE reconcile_attempt_results",
            "FOREIGN KEY (tenant_id, attempt_id, target_id)",
            "CHECK (result_label IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant'))",
            "CHECK (error_kind IS NULL OR error_kind IN ('transient', 'permanent', 'invariant'))",
            "GRANT SELECT, INSERT ON reconcile_attempt_results TO rss_app",
            "REVOKE UPDATE, DELETE ON reconcile_attempt_results FROM rss_app",
            "ALTER TABLE reconcile_attempt_results FORCE ROW LEVEL SECURITY",
            "tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
        ] {
            assert!(
                MIGRATION_0044.contains(needle),
                "0044 migration missing `{needle}`"
            );
        }
    }

    #[test]
    fn actions_record_only_converge_action_not_terminal_result() {
        for needle in [
            "UPDATE reconcile_actions",
            "SET result_label = 'recorded'",
            "DROP CONSTRAINT reconcile_actions_result_label_valid",
            "CHECK (result_label = 'recorded')",
            "CHECK (requeue_after_ms IS NULL AND error_kind IS NULL)",
        ] {
            assert!(
                MIGRATION_0045.contains(needle),
                "0045 migration missing `{needle}`"
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
