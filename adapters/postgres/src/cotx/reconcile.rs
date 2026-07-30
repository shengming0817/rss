//! Typed reconcile SQL operations.
//!
//! Transaction-control SQL is intentionally confined to `reconcile_enqueue_command`; callers
//! cannot begin, roll back, release, or name a savepoint independently.

use consistency::OutboxAppendOutcome;
use eventexec::command::ReviewedCommandIntent;
use eventexec::reconcile::{ReconcileScheduleError, ReconcileScheduleErrorKind};
use futures::future::BoxFuture;
use sqlx::PgConnection;

use super::{
    MaintenanceReadLane, MaintenanceWriteLane, ServingWriteLane, TenantDb, TenantLane,
    TenantScopeHandle, TenantTx,
};
use crate::outbox::{OutboxAppendError, OutboxEnvelope, append_outbox};
use crate::reconcile::{CommittedActionOutcome, TargetFields};

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
}

pub(crate) struct ReconcileAttemptResultDb<'a> {
    pub(crate) attempt_id: &'a str,
    pub(crate) fence: ReconcileLeaseFence<'a>,
    pub(crate) result_label: &'static str,
    pub(crate) requeue_after_ms: Option<i64>,
    pub(crate) error_kind: Option<&'static str>,
    pub(crate) next_run_after_ms: i64,
}

pub(crate) enum ReconcileLeaseMutation {
    Extend { ttl_secs: i64 },
    Release,
}

pub(crate) struct ReconcileTargetTransition<'a> {
    pub(crate) target_id: &'a str,
    pub(crate) status: &'static str,
    pub(crate) disabled_reason: Option<&'static str>,
    pub(crate) due_now: bool,
}

pub(crate) struct ReconcileEnqueue<'a> {
    pub(crate) attempt_id: &'a str,
    pub(crate) fence: ReconcileLeaseFence<'a>,
    pub(crate) action_kind: &'static str,
    pub(crate) intent: ReviewedCommandIntent,
    pub(crate) envelope: &'a OutboxEnvelope,
}

impl ReconcileTx<'_, ServingWriteLane> {
    pub(crate) async fn reconcile_upsert_target(
        &mut self,
        fields: &TargetFields,
    ) -> Result<String, sqlx::Error> {
        let target_id: String = sqlx::query_scalar(
            r#"
            INSERT INTO reconcile_targets
                (tenant_id, reconciler_id, resource_kind, resource_id)
            VALUES ($1::uuid, $2, $3, $4)
            ON CONFLICT (tenant_id, reconciler_id, resource_kind, resource_id)
            DO UPDATE SET status = 'active', updated_at = now()
            RETURNING target_id::text
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(&fields.reconciler_id)
        .bind(&fields.resource_kind)
        .bind(&fields.resource_id)
        .fetch_one(&mut *self.conn)
        .await?;
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
                (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind)
            VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
            RETURNING attempt_id::text
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(attempt.fence.target_id)
        .bind(attempt.fence.lease_token)
        .bind(attempt.fence.epoch)
        .bind(attempt.holder_id)
        .bind(attempt.trigger)
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn reconcile_record_attempt_result(
        &mut self,
        result: ReconcileAttemptResultDb<'_>,
    ) -> Result<bool, sqlx::Error> {
        if !self.reconcile_lock_held_lease(&result.fence).await? {
            return Ok(false);
        }
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
        sqlx::query(
            r#"
            UPDATE reconcile_targets
            SET next_run_at = now() + ($3::bigint * interval '1 millisecond'), updated_at = now()
            WHERE tenant_id = $1::uuid AND target_id = $2::uuid
            "#,
        )
        .bind(self.tenant.to_string())
        .bind(result.fence.target_id)
        .bind(result.next_run_after_ms)
        .execute(&mut *self.conn)
        .await?;
        Ok(true)
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
                       r.result_label AS prior_result_label
                FROM reconcile_targets t
                JOIN reconcile_leases l
                  ON l.tenant_id = t.tenant_id AND l.target_id = t.target_id
                LEFT JOIN LATERAL (
                    SELECT result_label FROM reconcile_attempt_results
                    WHERE tenant_id = t.tenant_id AND target_id = t.target_id
                    ORDER BY completed_at DESC, attempt_id DESC LIMIT 1
                ) r ON true
                WHERE t.tenant_id = $1::uuid AND t.reconciler_id = $2
                  AND t.status = 'active' AND t.next_run_at <= now()
                  AND (l.state = 'free' OR l.expires_at <= now())
                ORDER BY t.next_run_at, t.target_id
                LIMIT $5
                FOR UPDATE OF l SKIP LOCKED
            )
            UPDATE reconcile_leases l
            SET state = 'held', lease_token = gen_random_uuid(), holder_id = $3,
                epoch = l.epoch + 1, acquired_at = now(),
                expires_at = now() + make_interval(secs => $4),
                heartbeat_at = now(), updated_at = now()
            FROM due d
            WHERE l.tenant_id = d.tenant_id AND l.target_id = d.target_id
            RETURNING l.target_id::text, l.lease_token::text, l.epoch,
                      d.reconciler_id, d.resource_kind, d.resource_id,
                      CASE
                        WHEN d.prior_state = 'held' AND d.prior_expires_at <= now()
                        THEN 'lease_reclaim'
                        WHEN d.prior_result_label = 'requeue_after' THEN 'requeue'
                        ELSE 'resync'
                      END AS trigger_kind
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

    pub(crate) async fn reconcile_enqueue_command(
        &mut self,
        enqueue: ReconcileEnqueue<'_>,
    ) -> Result<CommittedActionOutcome, ReconcileScheduleError> {
        if !self
            .reconcile_lock_held_lease(&enqueue.fence)
            .await
            .map_err(ReconcileScheduleError::new)?
        {
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
            Ok::<(), ReconcileScheduleError>(())
        }
        .await;

        match write {
            Ok(()) => {
                sqlx::query("RELEASE SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn)
                    .await
                    .map_err(ReconcileScheduleError::new)?;
                Ok(CommittedActionOutcome::Enqueued)
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
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(enqueue.fence.target_id)
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
                let result = sqlx::query(
                    r#"
                    UPDATE reconcile_targets
                    SET status = $3, disabled_reason = $4,
                        next_run_at = CASE WHEN $5 THEN now() ELSE next_run_at END,
                        updated_at = now()
                    WHERE tenant_id = $1::uuid AND target_id = $2::uuid
                    "#,
                )
                .bind(self.tenant.to_string())
                .bind(transition.target_id)
                .bind(transition.status)
                .bind(transition.disabled_reason)
                .bind(transition.due_now)
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
