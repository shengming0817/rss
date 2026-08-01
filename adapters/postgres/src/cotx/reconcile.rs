//! Typed reconcile SQL operations.
//!
//! Transaction-control SQL is intentionally confined to `reconcile_enqueue_command`; callers
//! cannot begin, roll back, release, or name a savepoint independently.

use consistency::OutboxAppendOutcome;
use eventexec::command::ReviewedCommandIntent;
use eventexec::reconcile::{
    DeviceCommandAuditProof, PersistableCommandDeadlineEpochSeconds, ReconcileScheduleError,
    ReconcileScheduleErrorKind, ScheduleResultOutcome,
};
use futures::future::BoxFuture;
use sqlx::PgConnection;

use super::{
    MaintenanceReadLane, MaintenanceWriteLane, ServingWriteLane, TenantDb, TenantLane,
    TenantScopeHandle, TenantTx,
};
use crate::device_certificate_scope::{
    DEVICE_CERTIFICATE_RECONCILER_ID, DEVICE_CERTIFICATE_RESOURCE_KIND,
};
use crate::outbox::{OutboxAppendError, OutboxEnvelope, append_outbox};
use crate::reconcile::CommittedActionOutcome;
#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
use crate::reconcile::TargetFields;

/// Non-interchangeable reconcile authority. It owns only reconcile operations and cannot invoke
/// identity, eventing, settings, or audit façades.
#[doc(hidden)]
pub struct ReconcileTx<'tx, L: TenantLane> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
    _lane: std::marker::PhantomData<fn() -> L>,
}

impl<'tx, L: TenantLane> ReconcileTx<'tx, L> {
    fn from_raw(tx: &'tx mut TenantTx<'_, L>) -> Self {
        Self {
            conn: &mut *tx.conn,
            tenant: tx.tenant,
            _lane: std::marker::PhantomData,
        }
    }
}

impl TenantDb<ServingWriteLane> {
    pub(crate) async fn reconcile_write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(ReconcileTx<'tx, ServingWriteLane>) -> BoxFuture<'tx, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(
            scope,
            move |tx| write(ReconcileTx::<ServingWriteLane>::from_raw(tx)),
            map_storage,
        )
        .await
    }
}

impl TenantDb<MaintenanceWriteLane> {
    pub(crate) async fn reconcile_write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(ReconcileTx<'tx, MaintenanceWriteLane>) -> BoxFuture<'tx, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(
            scope,
            move |tx| write(ReconcileTx::<MaintenanceWriteLane>::from_raw(tx)),
            map_storage,
        )
        .await
    }
}

impl TenantDb<MaintenanceReadLane> {
    pub(crate) async fn reconcile_read<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(
                ReconcileTx<'tx, MaintenanceReadLane>,
            ) -> BoxFuture<'tx, Result<T, sqlx::Error>>
            + Send,
        T: Send,
    {
        self.read(scope, move |tx| {
            read(ReconcileTx::<MaintenanceReadLane>::from_raw(tx))
        })
        .await
    }
}

#[cfg(any(
    all(test, feature = "integration"),
    feature = "fault-matrix-test-support"
))]
#[derive(sqlx::FromRow)]
pub(crate) struct ReconcileLeaseRow {
    pub(crate) target_id: String,
    pub(crate) lease_token: String,
    pub(crate) epoch: i64,
}

#[derive(sqlx::FromRow)]
pub(crate) struct ReconcileClaimedRow {
    pub(crate) target_id: String,
    pub(crate) lease_token: String,
    pub(crate) epoch: i64,
    pub(crate) reconciler_id: String,
    pub(crate) resource_kind: String,
    pub(crate) resource_id: String,
    pub(crate) failure_streak: i64,
    pub(crate) wake_version: i64,
    pub(crate) trigger_kind: String,
}

#[derive(sqlx::FromRow)]
pub(crate) struct ReconcileTargetRow {
    pub(crate) target_id: String,
    pub(crate) reconciler_id: String,
    pub(crate) resource_kind: String,
    pub(crate) status: String,
    pub(crate) disabled_reason: Option<String>,
}

pub(crate) struct ReconcileLeaseFence<'a> {
    pub(crate) target_id: &'a str,
    pub(crate) lease_token: &'a str,
    pub(crate) epoch: i64,
}

pub(crate) struct ReconcileAttemptDb<'a> {
    pub(crate) fence: ReconcileLeaseFence<'a>,
    pub(crate) holder_id: &'a str,
    pub(crate) trigger: &'static str,
    pub(crate) claimed_failure_streak: i64,
    pub(crate) claimed_wake_version: i64,
}

pub(crate) struct ReconcileAttemptResultDb<'a> {
    pub(crate) attempt_id: &'a str,
    pub(crate) fence: ReconcileLeaseFence<'a>,
    pub(crate) result_label: &'static str,
    pub(crate) requeue_after_ms: Option<i64>,
    pub(crate) error_kind: Option<&'static str>,
    pub(crate) transition: ReconcileResultTransition,
}

pub(crate) enum ReconcileResultTransition {
    ScheduleAfter { delay_ms: i64, transient: bool },
    Quarantine { reason: &'static str },
}

#[derive(sqlx::FromRow)]
struct ReconcileAttemptEvidenceRow {
    claimed_failure_streak: i64,
    claimed_wake_version: i64,
}

#[derive(sqlx::FromRow)]
struct ReconcileCommandTargetRow {
    reconciler_id: String,
    resource_kind: String,
    resource_id: String,
    wake_version: i64,
    claimed_wake_version: i64,
}

#[derive(sqlx::FromRow)]
pub(crate) struct DeviceCommandAuditRow {
    pub(crate) device_id: String,
    pub(crate) generation: i64,
    pub(crate) fence_epoch: i64,
    pub(crate) intent_digest: Vec<u8>,
    pub(crate) attempt_id: String,
}

pub(crate) enum ReconcileLeaseMutation {
    Extend { ttl_secs: i64 },
    Release,
}

pub(crate) struct ReconcileTargetTransition<'a> {
    pub(crate) target_id: &'a str,
    pub(crate) kind: ReconcileTargetTransitionKind,
}

#[derive(Clone, Copy)]
pub(crate) enum ReconcileTargetTransitionKind {
    ServingPause,
    ServingResume,
    MaintenanceFactConflictResume,
}

pub(crate) struct ReconcileEnqueue<'a> {
    pub(crate) attempt_id: &'a str,
    pub(crate) fence: ReconcileLeaseFence<'a>,
    pub(crate) action_kind: &'static str,
    pub(crate) intent: ReviewedCommandIntent,
    pub(crate) envelope: &'a OutboxEnvelope,
    pub(crate) audit: DeviceCommandAuditProof,
    pub(crate) deadline_epoch_seconds: PersistableCommandDeadlineEpochSeconds,
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fault: Option<crate::reconcile::ReconcileCommandWriteFault>,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Debug, thiserror::Error)]
#[error("injected reconcile command transaction fault")]
struct ReconcileCommandWriteInjectedFault;

#[cfg(all(test, feature = "integration"))]
fn inject_command_write_fault(
    selected: Option<crate::reconcile::ReconcileCommandWriteFault>,
    stage: crate::reconcile::ReconcileCommandWriteFault,
) -> Result<(), ReconcileScheduleError> {
    if selected == Some(stage) {
        return Err(ReconcileScheduleError::new(
            ReconcileCommandWriteInjectedFault,
        ));
    }
    Ok(())
}

enum ReconcileCommandInstallOutcome {
    Inserted,
    Duplicate,
    FactConflict,
}

impl ReconcileTx<'_, ServingWriteLane> {
    #[cfg(feature = "fault-matrix-test-support")]
    pub(crate) async fn reconcile_seed_device_desired_for_fault_matrix(
        &mut self,
        device_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO device_certificate_desired_states \
             (tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
              client_auth, server_auth, sans) \
             VALUES ($1::uuid, $2::uuid, 2, 3600, 600, true, false, ARRAY[]::text[]) \
             ON CONFLICT (tenant_id, device_id) DO NOTHING",
        )
        .bind(self.tenant.to_string())
        .bind(device_id)
        .execute(&mut *self.conn)
        .await
        .map(|_| ())
    }

    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    pub(crate) async fn reconcile_upsert_target(
        &mut self,
        fields: &TargetFields,
    ) -> Result<String, sqlx::Error> {
        let target_id: Option<String> = sqlx::query_scalar(
            r#"
            INSERT INTO reconcile_targets
                (tenant_id, reconciler_id, resource_kind, resource_id)
            VALUES ($1::uuid, $2, $3, $4)
            ON CONFLICT (tenant_id, reconciler_id, resource_kind, resource_id)
            DO NOTHING
            RETURNING target_id::text
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.reconciler_id)
        .bind(&fields.resource_kind)
        .bind(&fields.resource_id)
        .fetch_optional(&mut *self.conn)
        .await?;
        let target_id = match target_id {
            Some(target_id) => target_id,
            None => {
                sqlx::query_scalar(
                    r#"
                    SELECT target_id::text
                    FROM reconcile_targets
                    WHERE tenant_id = $1::uuid
                      AND reconciler_id = $2
                      AND resource_kind = $3
                      AND resource_id = $4
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(&fields.reconciler_id)
                .bind(&fields.resource_kind)
                .bind(&fields.resource_id)
                .fetch_one(&mut *self.conn)
                .await?
            }
        };
        sqlx::query(
            r#"
            INSERT INTO reconcile_leases (tenant_id, target_id)
            VALUES ($1::uuid, $2::uuid)
            ON CONFLICT (tenant_id, target_id) DO NOTHING
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&target_id)
        .execute(&mut *self.conn)
        .await?;
        Ok(target_id)
    }

    #[cfg(any(
        all(test, feature = "integration"),
        feature = "fault-matrix-test-support"
    ))]
    pub(crate) async fn reconcile_acquire_lease(
        &mut self,
        target_id: &str,
        holder_id: &str,
        ttl_secs: i64,
    ) -> Result<Option<ReconcileLeaseRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE reconcile_leases
            SET state = 'held', lease_token = gen_random_uuid(), holder_id = $3,
                epoch = epoch + 1, acquired_at = now(),
                expires_at = now() + make_interval(secs => $4),
                heartbeat_at = now(), updated_at = now()
            WHERE tenant_id = $1::uuid AND target_id = $2::uuid
              AND (state = 'free' OR expires_at <= now())
            RETURNING target_id::text, lease_token::text, epoch
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(target_id)
        .bind(holder_id)
        .bind(ttl_secs)
        .fetch_optional(&mut *self.conn)
        .await
    }

    async fn reconcile_lock_held_lease(
        &mut self,
        fence: &ReconcileLeaseFence<'_>,
    ) -> Result<bool, sqlx::Error> {
        let row: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM reconcile_leases
            WHERE tenant_id = $1::uuid AND target_id = $2::uuid
              AND lease_token = $3::uuid AND epoch = $4
              AND state = 'held' AND expires_at > now()
            FOR UPDATE
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(fence.target_id)
        .bind(fence.lease_token)
        .bind(fence.epoch)
        .fetch_optional(&mut *self.conn)
        .await?;
        Ok(row.is_some())
    }

    async fn reconcile_lock_attempt_evidence(
        &mut self,
        attempt_id: &str,
        fence: &ReconcileLeaseFence<'_>,
    ) -> Result<Option<ReconcileAttemptEvidenceRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT a.claimed_failure_streak, a.claimed_wake_version
            FROM reconcile_attempts a
            JOIN reconcile_leases l
              ON l.tenant_id = a.tenant_id AND l.target_id = a.target_id
            WHERE a.tenant_id = $1::uuid AND a.attempt_id = $2::uuid
              AND a.target_id = $3::uuid
              AND a.lease_token = $4::uuid AND a.epoch = $5
              AND l.lease_token = $4::uuid AND l.epoch = $5
              AND l.state = 'held' AND l.expires_at > now()
            FOR UPDATE OF l
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(attempt_id)
        .bind(fence.target_id)
        .bind(fence.lease_token)
        .bind(fence.epoch)
        .fetch_optional(&mut *self.conn)
        .await
    }

    async fn reconcile_lock_command_target(
        &mut self,
        attempt_id: &str,
        target_id: &str,
    ) -> Result<Option<ReconcileCommandTargetRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT t.reconciler_id, t.resource_kind, t.resource_id, t.wake_version,
                   a.claimed_wake_version
            FROM reconcile_targets t
            JOIN reconcile_attempts a
              ON a.tenant_id = t.tenant_id AND a.target_id = t.target_id
            WHERE t.tenant_id = $1::uuid AND t.target_id = $2::uuid
              AND a.attempt_id = $3::uuid
            FOR UPDATE OF t
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(target_id)
        .bind(attempt_id)
        .fetch_optional(&mut *self.conn)
        .await
    }

    async fn reconcile_lock_desired_generation(
        &mut self,
        device_id: uuid::Uuid,
    ) -> Result<Option<i64>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT generation
            FROM device_certificate_desired_states
            WHERE tenant_id = $1::uuid AND device_id = $2::uuid
            FOR UPDATE
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(device_id.hyphenated().to_string())
        .fetch_optional(&mut *self.conn)
        .await
    }

    async fn reconcile_install_fenced_command(
        &mut self,
        audit: &DeviceCommandAuditProof,
        command_id: &str,
        deadline_epoch_seconds: PersistableCommandDeadlineEpochSeconds,
    ) -> Result<ReconcileCommandInstallOutcome, ReconcileScheduleError> {
        let tenant = self.tenant.to_string();
        let device = audit.device_id().hyphenated().to_string();
        let outcome: String = sqlx::query_scalar(
            r#"
            SELECT public.rss_install_fenced_device_command(
                $1::uuid, $2::uuid, $3, $4, $5, $6, $7
            )
            "#,
        )
        .bind(&tenant)
        .bind(&device)
        .bind(command_id)
        .bind(audit.desired_generation().get())
        .bind(audit.fence_epoch().get())
        .bind(audit.intent_digest().as_slice())
        .bind(deadline_epoch_seconds.get())
        .fetch_one(&mut *self.conn)
        .await
        .map_err(ReconcileScheduleError::new)?;
        match outcome.as_str() {
            "inserted" => Ok(ReconcileCommandInstallOutcome::Inserted),
            "duplicate" => Ok(ReconcileCommandInstallOutcome::Duplicate),
            "fact_conflict" => Ok(ReconcileCommandInstallOutcome::FactConflict),
            _ => Err(ReconcileScheduleError::new(std::io::Error::other(
                "fenced command authority changed after canonical locks",
            ))),
        }
    }

    pub(crate) async fn reconcile_append_attempt(
        &mut self,
        attempt: ReconcileAttemptDb<'_>,
    ) -> Result<Option<String>, sqlx::Error> {
        if !self.reconcile_lock_held_lease(&attempt.fence).await? {
            return Ok(None);
        }
        sqlx::query_scalar(
            r#"
            INSERT INTO reconcile_attempts
                (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind,
                 claimed_failure_streak, claimed_wake_version)
            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8)
            RETURNING attempt_id::text
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(attempt.fence.target_id)
        .bind(attempt.fence.lease_token)
        .bind(attempt.fence.epoch)
        .bind(attempt.holder_id)
        .bind(attempt.trigger)
        .bind(attempt.claimed_failure_streak)
        .bind(attempt.claimed_wake_version)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn reconcile_record_attempt_result(
        &mut self,
        result: ReconcileAttemptResultDb<'_>,
    ) -> Result<ScheduleResultOutcome, sqlx::Error> {
        let Some(evidence) = self
            .reconcile_lock_attempt_evidence(result.attempt_id, &result.fence)
            .await?
        else {
            return Ok(ScheduleResultOutcome::Lost);
        };
        sqlx::query(
            r#"
            INSERT INTO reconcile_attempt_results
                (tenant_id, attempt_id, target_id, result_label, requeue_after_ms, error_kind)
            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(result.attempt_id)
        .bind(result.fence.target_id)
        .bind(result.result_label)
        .bind(result.requeue_after_ms)
        .bind(result.error_kind)
        .execute(&mut *self.conn)
        .await?;
        let updated = match result.transition {
            ReconcileResultTransition::ScheduleAfter {
                delay_ms,
                transient,
            } => {
                sqlx::query(
                    r#"
                    UPDATE reconcile_targets
                    SET failure_streak = $5,
                        last_result = $3,
                        next_run_at = now() + ($4::bigint * interval '1 millisecond'),
                        updated_at = now()
                    WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                      AND wake_version = $6
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(result.fence.target_id)
                .bind(result.result_label)
                .bind(delay_ms)
                .bind(if transient {
                    evidence
                        .claimed_failure_streak
                        .saturating_add(1)
                        .min(4_294_967_295)
                } else {
                    0
                })
                .bind(evidence.claimed_wake_version)
                .execute(&mut *self.conn)
                .await?
            }
            ReconcileResultTransition::Quarantine { reason } => {
                sqlx::query(
                    r#"
                    UPDATE reconcile_targets
                    SET status = 'disabled', disabled_reason = $4,
                        failure_streak = $5, last_result = $3, updated_at = now()
                    WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                      AND wake_version = $6
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(result.fence.target_id)
                .bind(result.result_label)
                .bind(reason)
                .bind(evidence.claimed_failure_streak)
                .bind(evidence.claimed_wake_version)
                .execute(&mut *self.conn)
                .await?
            }
        };
        let released = sqlx::query(
            r#"
            UPDATE reconcile_leases
            SET state = 'free', lease_token = NULL, holder_id = NULL,
                acquired_at = NULL, expires_at = NULL, heartbeat_at = NULL, updated_at = now()
            WHERE tenant_id = $1::uuid AND target_id = $2::uuid
              AND lease_token = $3::uuid AND epoch = $4 AND state = 'held'
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(result.fence.target_id)
        .bind(result.fence.lease_token)
        .bind(result.fence.epoch)
        .execute(&mut *self.conn)
        .await?;
        debug_assert_eq!(released.rows_affected(), 1);
        Ok(if updated.rows_affected() == 1 {
            ScheduleResultOutcome::Recorded
        } else {
            ScheduleResultOutcome::WakeSuperseded
        })
    }

    pub(crate) async fn reconcile_cas_lease(
        &mut self,
        fence: ReconcileLeaseFence<'_>,
        mutation: ReconcileLeaseMutation,
    ) -> Result<bool, sqlx::Error> {
        let result = match mutation {
            ReconcileLeaseMutation::Extend { ttl_secs } => {
                sqlx::query(
                    r#"
                UPDATE reconcile_leases
                SET expires_at = now() + make_interval(secs => $5),
                    heartbeat_at = now(), updated_at = now()
                WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                  AND lease_token = $3::uuid AND epoch = $4
                  AND state = 'held' AND expires_at > now()
                "#,
                )
                .bind(self.tenant.to_string())
                .bind(fence.target_id)
                .bind(fence.lease_token)
                .bind(fence.epoch)
                .bind(ttl_secs)
                .execute(&mut *self.conn)
                .await?
            }
            ReconcileLeaseMutation::Release => {
                sqlx::query(
                    r#"
                UPDATE reconcile_leases
                SET state = 'free', lease_token = NULL, holder_id = NULL,
                    acquired_at = NULL, expires_at = NULL, heartbeat_at = NULL, updated_at = now()
                WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                  AND lease_token = $3::uuid AND epoch = $4 AND state = 'held'
                "#,
                )
                .bind(self.tenant.to_string())
                .bind(fence.target_id)
                .bind(fence.lease_token)
                .bind(fence.epoch)
                .execute(&mut *self.conn)
                .await?
            }
        };
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn reconcile_claim_due_targets(
        &mut self,
        reconciler_id: &str,
        holder_id: &str,
        lease_ttl_secs: i64,
        limit: i64,
    ) -> Result<Vec<ReconcileClaimedRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            WITH due AS (
                SELECT t.tenant_id, t.target_id, t.reconciler_id, t.resource_kind,
                       t.resource_id, l.state AS prior_state,
                       l.expires_at AS prior_expires_at,
                       r.result_label AS prior_result_label,
                       a.claimed_wake_version AS latest_claimed_wake_version,
                       t.failure_streak, t.wake_version, t.next_run_at
                FROM reconcile_targets t
                JOIN reconcile_leases l
                  ON l.tenant_id = t.tenant_id AND l.target_id = t.target_id
                LEFT JOIN LATERAL (
                    SELECT result_label FROM reconcile_attempt_results
                    WHERE tenant_id = t.tenant_id AND target_id = t.target_id
                    ORDER BY completed_at DESC, attempt_id DESC LIMIT 1
                ) r ON true
                LEFT JOIN LATERAL (
                    SELECT claimed_wake_version FROM reconcile_attempts
                    WHERE tenant_id = t.tenant_id AND target_id = t.target_id
                    ORDER BY started_at DESC, attempt_id DESC LIMIT 1
                ) a ON true
                WHERE t.tenant_id = $1::uuid AND t.reconciler_id = $2
                  AND t.status = 'active' AND t.next_run_at <= now()
                  AND (l.state = 'free' OR l.expires_at <= now())
                ORDER BY t.next_run_at, t.target_id
                LIMIT $5
                FOR UPDATE OF l SKIP LOCKED
            ), claimed AS (
            UPDATE reconcile_leases l
            SET state = 'held', lease_token = gen_random_uuid(), holder_id = $3,
                epoch = l.epoch + 1, acquired_at = now(),
                expires_at = now() + make_interval(secs => $4),
                heartbeat_at = now(), updated_at = now()
            FROM due d
            WHERE l.tenant_id = d.tenant_id AND l.target_id = d.target_id
            RETURNING l.target_id::text, l.lease_token::text, l.epoch,
                      d.reconciler_id, d.resource_kind, d.resource_id,
                      d.failure_streak, d.wake_version, d.next_run_at,
                      CASE
                        WHEN d.wake_version > COALESCE(d.latest_claimed_wake_version, 0)
                        THEN 'targeted'
                        WHEN d.prior_state = 'held' AND d.prior_expires_at <= now()
                        THEN 'lease_reclaim'
                        WHEN d.prior_result_label = 'requeue_after' THEN 'requeue'
                        ELSE 'resync'
                      END AS trigger_kind
            )
            SELECT target_id, lease_token, epoch, reconciler_id, resource_kind,
                   resource_id, failure_streak, wake_version, trigger_kind
            FROM claimed
            ORDER BY next_run_at, target_id
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(reconciler_id)
        .bind(holder_id)
        .bind(lease_ttl_secs)
        .bind(limit)
        .fetch_all(&mut *self.conn)
        .await
    }

    pub(crate) async fn reconcile_claim_targeted(
        &mut self,
        reconciler_id: &str,
        target_id: &str,
        wake_version: i64,
        holder_id: &str,
        lease_ttl_secs: i64,
    ) -> Result<Option<ReconcileClaimedRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            WITH due AS (
                SELECT t.tenant_id, t.target_id, t.reconciler_id, t.resource_kind,
                       t.resource_id, t.failure_streak, t.wake_version
                FROM reconcile_targets t
                JOIN reconcile_leases l
                  ON l.tenant_id = t.tenant_id AND l.target_id = t.target_id
                WHERE t.tenant_id = $1::uuid
                  AND t.reconciler_id = $2
                  AND t.target_id = $3::uuid
                  AND t.wake_version = $4
                  AND t.status = 'active'
                  AND t.next_run_at <= now()
                  AND (l.state = 'free' OR l.expires_at <= now())
                FOR UPDATE OF l SKIP LOCKED
            )
            UPDATE reconcile_leases l
            SET state = 'held', lease_token = gen_random_uuid(), holder_id = $5,
                epoch = l.epoch + 1, acquired_at = now(),
                expires_at = now() + make_interval(secs => $6),
                heartbeat_at = now(), updated_at = now()
            FROM due d
            WHERE l.tenant_id = d.tenant_id AND l.target_id = d.target_id
            RETURNING l.target_id::text, l.lease_token::text, l.epoch,
                      d.reconciler_id, d.resource_kind, d.resource_id,
                      d.failure_streak, d.wake_version,
                      'targeted'::text AS trigger_kind
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(reconciler_id)
        .bind(target_id)
        .bind(wake_version)
        .bind(holder_id)
        .bind(lease_ttl_secs)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn reconcile_enqueue_command(
        &mut self,
        enqueue: ReconcileEnqueue<'_>,
    ) -> Result<CommittedActionOutcome, ReconcileScheduleError> {
        let Some(target) = self
            .reconcile_lock_command_target(enqueue.attempt_id, enqueue.fence.target_id)
            .await
            .map_err(ReconcileScheduleError::new)?
        else {
            return Ok(CommittedActionOutcome::Lost);
        };
        if target.reconciler_id != DEVICE_CERTIFICATE_RECONCILER_ID
            || target.resource_kind != DEVICE_CERTIFICATE_RESOURCE_KIND
            || target.resource_id != enqueue.audit.device_id().hyphenated().to_string()
            || target.wake_version != target.claimed_wake_version
        {
            return Ok(CommittedActionOutcome::Lost);
        }
        let Some(evidence) = self
            .reconcile_lock_attempt_evidence(enqueue.attempt_id, &enqueue.fence)
            .await
            .map_err(ReconcileScheduleError::new)?
        else {
            return Ok(CommittedActionOutcome::Lost);
        };
        if evidence.claimed_wake_version != target.claimed_wake_version
            || enqueue.audit.fence_epoch().get() != enqueue.fence.epoch
        {
            return Ok(CommittedActionOutcome::Lost);
        }
        let Some(desired_generation) = self
            .reconcile_lock_desired_generation(enqueue.audit.device_id())
            .await
            .map_err(ReconcileScheduleError::new)?
        else {
            return Ok(CommittedActionOutcome::Lost);
        };
        if desired_generation != enqueue.audit.desired_generation().get() {
            return Ok(CommittedActionOutcome::Lost);
        }

        sqlx::query("SAVEPOINT reconcile_command_write")
            .execute(&mut *self.conn)
            .await
            .map_err(ReconcileScheduleError::new)?;

        let write = async {
            let prepared = {
                let mut command =
                    super::eventing::CommandTx::from_parts(&mut *self.conn, self.tenant);
                crate::command_journal::prepare_command(&mut command, enqueue.intent)
                    .await
                    .map_err(ReconcileScheduleError::new)?
            };
            {
                let mut command =
                    super::eventing::CommandTx::from_parts(&mut *self.conn, self.tenant);
                if !crate::command_journal::insert_journal_claim(
                    &mut command,
                    &prepared,
                    enqueue.envelope,
                )
                .await
                .map_err(ReconcileScheduleError::new)?
                {
                    let duplicate = crate::command_journal::duplicate_outcome(
                        &mut command,
                        prepared.entry.idem_key().as_str(),
                        &prepared.fingerprint,
                    )
                    .await
                    .map_err(ReconcileScheduleError::new)?;
                    return match duplicate {
                        consistency::CommandJournalOutcome::Conflict => Err(
                            ReconcileScheduleError::fact_conflict(consistency::OutboxFactConflict),
                        ),
                        _ => Ok(CommittedActionOutcome::Duplicate),
                    };
                }
            }
            #[cfg(all(test, feature = "integration"))]
            inject_command_write_fault(
                enqueue.fault,
                crate::reconcile::ReconcileCommandWriteFault::Journal,
            )?;
            {
                match self
                    .reconcile_install_fenced_command(
                        &enqueue.audit,
                        prepared.entry.idem_key().as_str(),
                        enqueue.deadline_epoch_seconds,
                    )
                    .await?
                {
                    ReconcileCommandInstallOutcome::Inserted => {}
                    ReconcileCommandInstallOutcome::Duplicate
                    | ReconcileCommandInstallOutcome::FactConflict => {
                        return Err(ReconcileScheduleError::fact_conflict(
                            consistency::OutboxFactConflict,
                        ));
                    }
                }
            }
            #[cfg(all(test, feature = "integration"))]
            inject_command_write_fault(
                enqueue.fault,
                crate::reconcile::ReconcileCommandWriteFault::DeviceCommand,
            )?;
            sqlx::query(
                r#"
                INSERT INTO reconcile_actions
                    (tenant_id, attempt_id, target_id, action_kind, result_label,
                     requeue_after_ms, error_kind)
                VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'recorded', NULL, NULL)
                "#,
            )
            .bind(self.tenant.to_string())
            .bind(enqueue.attempt_id)
            .bind(enqueue.fence.target_id)
            .bind(enqueue.action_kind)
            .execute(&mut *self.conn)
            .await
            .map_err(ReconcileScheduleError::new)?;
            #[cfg(all(test, feature = "integration"))]
            inject_command_write_fault(
                enqueue.fault,
                crate::reconcile::ReconcileCommandWriteFault::Action,
            )?;
            let append = {
                let mut outbox =
                    super::eventing::OutboxTx::from_parts(&mut *self.conn, self.tenant);
                append_outbox(&mut outbox, &prepared.entry, enqueue.envelope).await
            };
            match append.map_err(|error| match error {
                OutboxAppendError::Conflict(conflict) => {
                    ReconcileScheduleError::fact_conflict(conflict)
                }
                other => ReconcileScheduleError::new(other),
            })? {
                OutboxAppendOutcome::Inserted | OutboxAppendOutcome::SameFact => {}
            }
            #[cfg(all(test, feature = "integration"))]
            inject_command_write_fault(
                enqueue.fault,
                crate::reconcile::ReconcileCommandWriteFault::Outbox,
            )?;
            Ok::<CommittedActionOutcome, ReconcileScheduleError>(CommittedActionOutcome::Enqueued)
        }
        .await;

        match write {
            Ok(outcome) => {
                sqlx::query("RELEASE SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn)
                    .await
                    .map_err(ReconcileScheduleError::new)?;
                Ok(outcome)
            }
            Err(error) => {
                sqlx::query("ROLLBACK TO SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn)
                    .await
                    .map_err(ReconcileScheduleError::new)?;
                sqlx::query("RELEASE SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn)
                    .await
                    .map_err(ReconcileScheduleError::new)?;
                if error.kind() != ReconcileScheduleErrorKind::FactConflict {
                    return Err(error);
                }
                let quarantined = sqlx::query(
                    r#"
                    UPDATE reconcile_targets
                    SET status = 'disabled', disabled_reason = 'fact_conflict', updated_at = now()
                    WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                      AND wake_version = $3
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(enqueue.fence.target_id)
                .bind(evidence.claimed_wake_version)
                .execute(&mut *self.conn)
                .await
                .map_err(ReconcileScheduleError::new)?;
                if quarantined.rows_affected() == 1 {
                    Ok(CommittedActionOutcome::FactConflictQuarantined)
                } else {
                    Ok(CommittedActionOutcome::Lost)
                }
            }
        }
    }
}

macro_rules! impl_reconcile_operator_write {
    ($lane:ty) => {
        impl ReconcileTx<'_, $lane> {
            pub(crate) async fn reconcile_transition_target(
                &mut self,
                transition: ReconcileTargetTransition<'_>,
            ) -> Result<bool, sqlx::Error> {
                let sql = match transition.kind {
                    ReconcileTargetTransitionKind::ServingPause => {
                        r#"
                        UPDATE reconcile_targets
                        SET status = 'disabled', updated_at = now()
                        WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                          AND status = 'active' AND disabled_reason IS NULL
                    "#
                    }
                    ReconcileTargetTransitionKind::ServingResume => {
                        r#"
                        UPDATE reconcile_targets
                        SET status = 'active', next_run_at = now(), updated_at = now()
                        WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                          AND status = 'disabled' AND disabled_reason IS NULL
                    "#
                    }
                    ReconcileTargetTransitionKind::MaintenanceFactConflictResume => {
                        r#"
                        UPDATE reconcile_targets
                        SET status = 'active', disabled_reason = NULL,
                            next_run_at = now(), updated_at = now()
                        WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                          AND status = 'disabled' AND disabled_reason = 'fact_conflict'
                    "#
                    }
                };
                let result = sqlx::query(sql)
                    .bind(self.tenant.to_string())
                    .bind(transition.target_id)
                    .execute(&mut *self.conn)
                    .await?;
                Ok(result.rows_affected() == 1)
            }
        }
    };
}

impl_reconcile_operator_write!(ServingWriteLane);
impl_reconcile_operator_write!(MaintenanceWriteLane);

impl ReconcileTx<'_, MaintenanceReadLane> {
    pub(crate) async fn reconcile_read_device_command_audit(
        &mut self,
        command_id: &str,
    ) -> Result<Option<DeviceCommandAuditRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT command.device_id::text AS device_id, command.generation, command.fence_epoch,
                   command.intent_digest, attempt.attempt_id::text
            FROM device_commands AS command
            JOIN outbox
              ON outbox.tenant_id = command.tenant_id
             AND outbox.event_id = command.command_id
            JOIN command_journal AS journal
              ON journal.tenant_id = command.tenant_id
             AND journal.command_id = command.command_id
             AND journal.outbox_event_id = outbox.event_id
            JOIN reconcile_attempts AS attempt
              ON attempt.tenant_id = command.tenant_id
             AND attempt.attempt_id::text = outbox.causation_id
             AND attempt.epoch = command.fence_epoch
            JOIN reconcile_actions AS action
              ON action.tenant_id = attempt.tenant_id
             AND action.attempt_id = attempt.attempt_id
             AND action.target_id = attempt.target_id
            JOIN reconcile_targets AS target
              ON target.tenant_id = attempt.tenant_id
             AND target.target_id = attempt.target_id
             AND target.reconciler_id = $3
             AND target.resource_kind = $4
             AND target.resource_id = command.device_id::text
            WHERE command.tenant_id = $1::uuid
              AND command.command_id = $2
              AND outbox.metadata->>'subjectId' = command.device_id::text
              AND outbox.metadata#>>'{actor,kind}' = 'service'
              AND outbox.metadata#>>'{actor,id}' = 'rss.reconcile.device-certificate.v1'
              AND outbox.metadata#>>'{actor,scope}' = 'all'
              AND action.result_label = 'recorded'
            ORDER BY action.created_at, action.action_id
            LIMIT 1
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(command_id)
        .bind(DEVICE_CERTIFICATE_RECONCILER_ID)
        .bind(DEVICE_CERTIFICATE_RESOURCE_KIND)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn reconcile_inspect_target(
        &mut self,
        target_id: &str,
    ) -> Result<Option<ReconcileTargetRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT target_id::text, reconciler_id, resource_kind, status, disabled_reason
            FROM reconcile_targets
            WHERE tenant_id = $1::uuid AND target_id = $2::uuid
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(target_id)
        .fetch_optional(&mut *self.conn)
        .await
    }
}
