//! Test-graph driver for the real `AttemptScope` fenced-command entry point.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use consistency::{Context, ConvergeAction, EngineErrorKind, ReconcileError};
use eventexec::command::CommandIdempotencyKeyring;
use eventexec::reconcile::{
    ApplyDeviceCertificateReconcileCommand, AttemptResult, AttemptScope, ClaimedTarget,
    DeviceCertificateCommandTtl, DeviceCertificateSystemProducer, DurableReconcileOutcome,
    DurableReconciler, ReconcileAttempt, ReconcileMaxInFlight, ReconcileScheduleError,
    ReconcileScheduleStore, ReconcileSchedulerBuilder, ReconcileWake, ReviewedFencedCommand,
    ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleCompletionOutcome, ScheduleLeaseOutcome,
    ScheduleResultOutcome, Tenancy, Trigger,
};
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
const FENCED_INTENT_DIGEST_DOMAIN: &str = "rss-fenced-intent-v1";

#[cfg(test)]
pub(crate) fn canonical_device_command(
    mut value: serde_json::Value,
) -> Result<ApplyDeviceCertificateReconcileCommand, ReconcileScheduleError> {
    let object = value.as_object_mut().ok_or_else(|| {
        ReconcileScheduleError::new(std::io::Error::other("command fixture must be an object"))
    })?;
    object.insert(
        "intentDigest".to_owned(),
        serde_json::Value::String(format!("sha256:{}", "0".repeat(64))),
    );
    let mut semantic = value.clone();
    let semantic_object = semantic.as_object_mut().ok_or_else(|| {
        ReconcileScheduleError::new(std::io::Error::other("command fixture must be an object"))
    })?;
    for coordinate in [
        "deviceId",
        "desiredGeneration",
        "fenceEpoch",
        "intentDigest",
        "deadlineEpochSeconds",
    ] {
        semantic_object.remove(coordinate).ok_or_else(|| {
            ReconcileScheduleError::new(std::io::Error::other("command coordinate missing"))
        })?;
    }
    let canonical =
        serde_json_canonicalizer::to_vec(&semantic).map_err(ReconcileScheduleError::new)?;
    let binding = generated::command::identity_v1::CONTRACT;
    let mut hasher = Sha256::new();
    for component in [
        FENCED_INTENT_DIGEST_DOMAIN.as_bytes(),
        binding.domain().as_bytes(),
        binding.contract_id().as_bytes(),
        binding.version().as_bytes(),
        binding.schema_hash().as_bytes(),
        canonical.as_slice(),
    ] {
        hasher.update(component.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(component);
        hasher.update(b"\0");
    }
    value
        .as_object_mut()
        .ok_or_else(|| {
            ReconcileScheduleError::new(std::io::Error::other("command fixture must be an object"))
        })?
        .insert(
            "intentDigest".to_owned(),
            serde_json::Value::String(format!("sha256:{:x}", hasher.finalize())),
        );
    let request = serde_json::from_value(value).map_err(ReconcileScheduleError::new)?;
    Ok(generated::command::identity_v1::fenced_reconcile_command(
        request,
    ))
}

#[derive(Clone)]
struct CaptureStore {
    target: ClaimedTarget,
    attempt_id: Arc<str>,
    claimed: Arc<AtomicBool>,
    captured: Arc<Mutex<Option<ReviewedFencedCommand>>>,
    cancellation: CancellationToken,
}

impl ReconcileScheduleStore for CaptureStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        _holder_id: &str,
        _limit: ReconcileMaxInFlight,
        _lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
        if tenant != self.target.tenant()
            || reconciler_id != self.target.reconciler_id()
            || self.claimed.swap(true, Ordering::AcqRel)
        {
            return Ok(Vec::new());
        }
        Ok(vec![self.target.clone()])
    }

    async fn claim_targeted(
        &self,
        _tenant: vocab::TenantId,
        _reconciler_id: &str,
        _holder_id: &str,
        _wake: &ReconcileWake,
        _lease_ttl: Duration,
    ) -> Result<Option<ClaimedTarget>, ReconcileScheduleError> {
        Ok(None)
    }

    async fn append_attempt(
        &self,
        target: &ClaimedTarget,
        _holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
        Ok(ScheduleAttemptOutcome::Started(ReconcileAttempt::new(
            self.attempt_id.as_ref(),
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
        command: ReviewedFencedCommand,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
        *self.captured.lock().map_err(|_| {
            ReconcileScheduleError::new(std::io::Error::other("capture poisoned"))
        })? = Some(command);
        self.cancellation.cancel();
        Ok(ScheduleActionOutcome::Enqueued)
    }

    async fn complete_device_certificate_deletion(
        &self,
        _attempt: &ReconcileAttempt,
    ) -> Result<ScheduleCompletionOutcome, ReconcileScheduleError> {
        Ok(ScheduleCompletionOutcome::EvidencePending)
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

struct CaptureReconciler {
    command: Mutex<Option<ApplyDeviceCertificateReconcileCommand>>,
}

struct TestCertificateAuthorization {
    device_id: uuid::Uuid,
    generation: u64,
    artifact_id: String,
    artifact_digest: [u8; 32],
    policy_hash: [u8; 32],
    deadline_epoch_seconds: u64,
}

fn parse_sha256_label(value: &str) -> Result<[u8; 32], ReconcileScheduleError> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        ReconcileScheduleError::new(std::io::Error::other("digest fixture is not sha256"))
    })?;
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(ReconcileScheduleError::new(std::io::Error::other(
            "digest fixture length is invalid",
        )));
    }
    let bytes = (0..32)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReconcileScheduleError::new)?;
    bytes.try_into().map_err(|_| {
        ReconcileScheduleError::new(std::io::Error::other("digest fixture length is invalid"))
    })
}

fn semantic_device_command(
    command: &ApplyDeviceCertificateReconcileCommand,
) -> Result<TestCertificateAuthorization, ReconcileScheduleError> {
    use generated::command::FencedCommandSpec as _;
    let request = command.request();
    Ok(TestCertificateAuthorization {
        device_id: request.device_id,
        generation: request.desired_generation.get(),
        artifact_id: request.artifact_id.as_str().to_owned(),
        artifact_digest: parse_sha256_label(request.artifact_digest.as_str())?,
        policy_hash: parse_sha256_label(request.policy_hash.as_str())?,
        deadline_epoch_seconds: request.deadline_epoch_seconds.get(),
    })
}

impl DurableReconciler<CaptureStore> for CaptureReconciler {
    async fn reconcile(
        &self,
        _ctx: &Context,
        target: &ClaimedTarget,
        attempt: &AttemptScope<'_, CaptureStore>,
    ) -> Result<DurableReconcileOutcome, ReconcileError> {
        let command = self
            .command
            .lock()
            .map_err(|_| ReconcileError::new(EngineErrorKind::Permanent))?
            .take()
            .ok_or_else(|| ReconcileError::new(EngineErrorKind::Permanent))?;
        let command = semantic_device_command(&command)
            .map_err(|_| ReconcileError::new(EngineErrorKind::Permanent))?;
        if uuid::Uuid::parse_str(target.resource_id()).ok() != Some(command.device_id) {
            return Err(ReconcileError::new(EngineErrorKind::Permanent));
        }
        let reviewed = attempt
            .review_device_certificate_command(
                command.generation,
                &command.artifact_id,
                command.artifact_digest,
                command.policy_hash,
                SystemTime::UNIX_EPOCH,
                DeviceCertificateCommandTtl::try_new(Duration::from_secs(
                    command.deadline_epoch_seconds,
                ))
                .map_err(|_| ReconcileError::new(EngineErrorKind::Permanent))?,
            )
            .map_err(|_| ReconcileError::new(EngineErrorKind::Permanent))?;
        match attempt
            .record_device_certificate_command(ConvergeAction::Update, reviewed)
            .await
            .map_err(|_| ReconcileError::new(EngineErrorKind::Permanent))?
        {
            ScheduleActionOutcome::Enqueued => {}
            ScheduleActionOutcome::Duplicate | ScheduleActionOutcome::Lost => {
                return Err(ReconcileError::new(EngineErrorKind::Permanent));
            }
        }
        Ok(DurableReconcileOutcome::settled())
    }
}

pub(crate) async fn drive_reviewed_device_command(
    attempt: &ReconcileAttempt,
    command: ApplyDeviceCertificateReconcileCommand,
    keyring: Arc<CommandIdempotencyKeyring>,
) -> Result<ReviewedFencedCommand, ReconcileScheduleError> {
    let cancellation = CancellationToken::new();
    let captured = Arc::new(Mutex::new(None));
    let store = CaptureStore {
        target: attempt.target().clone(),
        attempt_id: Arc::from(attempt.attempt_id()),
        claimed: Arc::new(AtomicBool::new(false)),
        captured: Arc::clone(&captured),
        cancellation: cancellation.clone(),
    };
    let trigger =
        Trigger::interval(Duration::from_secs(3600)).map_err(ReconcileScheduleError::new)?;
    let worker = ReconcileSchedulerBuilder::new(
        store,
        CaptureReconciler {
            command: Mutex::new(Some(command)),
        },
        keyring,
        DeviceCertificateSystemProducer::install(),
        attempt.target().tenant(),
        attempt.target().reconciler_id(),
        "postgres-fenced-command-test-driver",
        Tenancy::tenant_scoped(),
        trigger,
    )
    .with_max_in_flight(ReconcileMaxInFlight::try_new(1).map_err(ReconcileScheduleError::new)?)
    .with_lease_ttl(Duration::from_secs(5))
    .map_err(ReconcileScheduleError::new)?
    .build();
    tokio::time::timeout(Duration::from_secs(5), worker.run(cancellation))
        .await
        .map_err(|_| ReconcileScheduleError::new(std::io::Error::other("test driver timeout")))?;
    captured
        .lock()
        .map_err(|_| ReconcileScheduleError::new(std::io::Error::other("capture poisoned")))?
        .take()
        .ok_or_else(|| ReconcileScheduleError::new(std::io::Error::other("command not captured")))
}
