//! compile-pass：durable scheduler API + AttemptScope command seam 可由 provider fake 实现。

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use consistency::{Context, ConvergeAction, EngineErrorKind, ReconcileError};
use eventexec::command::{CommandAliasKey, CommandIdempotencyKeyring};
use eventexec::reconcile::{
    AttemptResult, AttemptScope, AttemptTrigger, ClaimedTarget, ClaimedTargetRestore,
    DeviceCertificateCommandTtl, DeviceCertificateSystemProducer, DurableReconcileOutcome,
    DurableReconciler, FailureStreak, ReconcileAttempt, ReconcileMaxInFlight,
    ReconcileScheduleError, ReconcileScheduleStore, ReconcileSchedulerBuilder, ReconcileWake,
    ReviewedFencedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome,
    ScheduleCompletionOutcome, ScheduleLeaseOutcome, ScheduleResultOutcome, Tenancy, Trigger,
    WakeVersion,
};

#[derive(Clone)]
struct NoopStore;

impl ReconcileScheduleStore for NoopStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        _holder_id: &str,
        _limit: ReconcileMaxInFlight,
        _lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
        Ok(vec![ClaimedTarget::restore(ClaimedTargetRestore {
            tenant,
            target_id: "22222222-2222-2222-2222-222222222222".to_owned(),
            reconciler_id: reconciler_id.to_owned(),
            resource_kind: "device-certificate".to_owned(),
            resource_id: "b497a9ce-6ac5-4d44-a0a3-869af114db5f".to_owned(),
            lease_token: "33333333-3333-3333-3333-333333333333".to_owned(),
            epoch: 1,
            failure_streak: FailureStreak::restore(0),
            wake_version: WakeVersion::try_new(1).expect("wake version"),
            trigger: AttemptTrigger::Resync,
        })])
    }

    async fn claim_targeted(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        _holder_id: &str,
        wake: &ReconcileWake,
        _lease_ttl: Duration,
    ) -> Result<Option<ClaimedTarget>, ReconcileScheduleError> {
        Ok(Some(ClaimedTarget::restore(ClaimedTargetRestore {
            tenant,
            target_id: wake.target_id().to_owned(),
            reconciler_id: reconciler_id.to_owned(),
            resource_kind: "device-certificate".to_owned(),
            resource_id: "b497a9ce-6ac5-4d44-a0a3-869af114db5f".to_owned(),
            lease_token: "33333333-3333-3333-3333-333333333333".to_owned(),
            epoch: 1,
            failure_streak: FailureStreak::restore(0),
            wake_version: wake.version(),
            trigger: AttemptTrigger::Targeted,
        })))
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
    ) -> Result<ScheduleResultOutcome, ReconcileScheduleError> {
        Ok(ScheduleResultOutcome::Recorded)
    }

    async fn record_fenced_command(
        &self,
        _attempt: &ReconcileAttempt,
        _action: ConvergeAction,
        _command: ReviewedFencedCommand,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
        Ok(ScheduleActionOutcome::Enqueued)
    }

    async fn complete_device_certificate_deletion(
        &self,
        _attempt: &ReconcileAttempt,
    ) -> Result<ScheduleCompletionOutcome, ReconcileScheduleError> {
        Ok(ScheduleCompletionOutcome::Lost)
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
        _target: &ClaimedTarget,
        attempt: &AttemptScope<'_, NoopStore>,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        let reviewed = attempt
            .review_device_certificate_command(
                2,
                "certificate-artifact-1",
                [0x22; 32],
                [0x11; 32],
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(41)).expect("ttl"),
            )
            .expect("attempt-reviewed command");
        match attempt
            .record_device_certificate_command(ConvergeAction::Create, reviewed)
            .await
            .expect("record action and command")
        {
            ScheduleActionOutcome::Enqueued => {}
            ScheduleActionOutcome::Duplicate => {}
            ScheduleActionOutcome::Lost => {
                return Err(ReconcileError::new(EngineErrorKind::Transient));
            }
        }
        Ok(DurableReconcileOutcome::settled())
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
        DeviceCertificateSystemProducer::install(),
        tenant,
        "identity.device-certificate",
        "holder-a",
        Tenancy::tenant_scoped(),
        trigger,
    )
    .with_max_in_flight(ReconcileMaxInFlight::try_new(1).expect("valid concurrency"))
    .with_lease_ttl(Duration::from_secs(5))
    .expect("whole-second lease ttl")
    .build();
    let _control = worker.control();
    let _health = worker.health();
}
