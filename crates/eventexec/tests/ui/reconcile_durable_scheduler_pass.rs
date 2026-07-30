//! compile-pass：durable scheduler API + AttemptScope command seam 可由 provider fake 实现。

use std::sync::Arc;
use std::time::Duration;

use consistency::{Context, ConvergeAction, EngineErrorKind, Outcome, ReconcileError};
use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor};
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use eventexec::reconcile::{
    AttemptResult, AttemptScope, AttemptTrigger, ClaimedTarget, DurableReconciler,
    ReconcileAttempt, ReconcileScheduleError, ReconcileScheduleStore, ReconcileSchedulerBuilder,
    ReviewedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleLeaseOutcome, Tenancy,
    Trigger,
};

#[derive(Clone)]
struct NoopStore;

impl ReconcileScheduleStore for NoopStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        _holder_id: &str,
        _limit: u32,
        _lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
        Ok(vec![ClaimedTarget::new(
            tenant,
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            1,
            reconciler_id,
            "device",
            "device-1",
            AttemptTrigger::Resync,
        )])
    }

    async fn append_attempt(
        &self,
        target: &ClaimedTarget,
        _holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
        Ok(ScheduleAttemptOutcome::Started(ReconcileAttempt::new(
            "44444444-4444-4444-4444-444444444444",
            target.clone(),
        )))
    }

    async fn record_attempt_result(
        &self,
        _attempt: &ReconcileAttempt,
        _result: AttemptResult,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        Ok(ScheduleLeaseOutcome::Held)
    }

    async fn record_action_and_enqueue_command(
        &self,
        _attempt: &ReconcileAttempt,
        _action: ConvergeAction,
        _command: ReviewedCommand,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
        Ok(ScheduleActionOutcome::Enqueued)
    }

    async fn extend_lease(
        &self,
        _target: &ClaimedTarget,
        _lease_ttl: Duration,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        Ok(ScheduleLeaseOutcome::Held)
    }

    async fn release_lease(
        &self,
        _target: &ClaimedTarget,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        Ok(ScheduleLeaseOutcome::Held)
    }

    async fn pause_target(
        &self,
        _tenant: vocab::TenantId,
        _target_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        Ok(())
    }

    async fn resume_target(
        &self,
        _tenant: vocab::TenantId,
        _target_id: &str,
    ) -> Result<(), ReconcileScheduleError> {
        Ok(())
    }
}

struct NoopDurableReconciler;

impl DurableReconciler<NoopStore> for NoopDurableReconciler {
    async fn reconcile(
        &self,
        _ctx: &Context,
        target: &ClaimedTarget,
        attempt: &AttemptScope<'_, NoopStore>,
    ) -> Result<Outcome, ReconcileError> {
        let request = serde_json::from_value::<
            generated::command::identity_v1::IdentityApplyDeviceCertificateRequest,
        >(serde_json::json!({
            "deviceId": "b497a9ce-6ac5-4d44-a0a3-869af114db5f",
            "desiredGeneration": 2,
            "fenceEpoch": 3,
            "intentId": "certificate-intent-1",
            "policyHash": format!("sha256:{}", "1".repeat(64)),
            "artifactId": "certificate-artifact-1",
            "artifactDigest": format!("sha256:{}", "2".repeat(64)),
            "deadlineEpochSeconds": 42
        }))
        .expect("generated certificate command request");
        let command = generated::command::identity_v1::reconcile_command(
            request,
            target.tenant(),
            EnvelopeSubjectId::from_opaque("device-1").expect("subject"),
            OutboxActor::service(OpaqueActorId::from_opaque("reconcile-test").expect("actor")),
            "device-1-create".to_string(),
        );
        match attempt
            .record_action_and_enqueue_command(ConvergeAction::Create, command)
            .await
            .expect("record action and command")
        {
            ScheduleActionOutcome::Enqueued => {}
            ScheduleActionOutcome::Lost => {
                return Err(ReconcileError::new(EngineErrorKind::Transient));
            }
        }
        Ok(Outcome::settled())
    }
}

fn main() {
    let tenant = vocab::TenantId::parse("11111111-1111-1111-1111-111111111111").expect("tenant");
    let trigger = Trigger::interval(Duration::from_secs(30)).expect("non-zero trigger");
    let worker = ReconcileSchedulerBuilder::new(
        NoopStore,
        NoopDurableReconciler,
        Arc::new(
            CommandIdempotencyKeyring::new(
                CommandAliasKey::new("current", vec![0x42; 32]).expect("key"),
                Vec::new(),
            )
            .expect("keyring"),
        ),
        tenant,
        "test-reconciler",
        "holder-a",
        Tenancy::tenant_scoped(),
        trigger,
    )
    .with_batch_size(1)
    .expect("positive batch size")
    .with_lease_ttl(Duration::from_secs(5))
    .expect("whole-second lease ttl")
    .build();
    let _control = worker.control();
    let _health = worker.health();
}
