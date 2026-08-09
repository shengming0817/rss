//! Device-certificate persistence and reconcile-join seams.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use consistency::ConvergeAction;
use diport::ManagedResource as _;
use diport::{CertNotAfter, CertScope, CertSerial};
use eventexec::command::CommandIdempotencyKeyring;
use eventexec::reconcile::DeviceCertificateCommandEvidence;
use eventexec::reconcile::{
    AttemptResult, DeviceCertificateCommandTtl, DeviceCertificateSystemProducer,
    ReconcileScheduleStore, ReconcileSchedulerBuilder, ReviewedFencedCommand,
    ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleCompletionOutcome, ScheduleLeaseOutcome,
    ScheduleResultOutcome, Tenancy, Trigger,
};
use identity::ports::device_certificate::{
    ArtifactAppendAuthorization, ArtifactAppendOutcome, ArtifactDigest,
    AuthorizedCertificateArtifact, CertificateArtifactAcquisition, CertificateArtifactError,
    CertificateArtifactId, CertificateArtifactRequest, CertificateArtifactSource,
    CertificateAttemptAuthority, CertificateAttemptFence, CertificateConditionMutation,
    CertificatePublicKeyDigest, CertificateReconcileRepository,
    CertificateReconcileRepositoryError, CertificateReconcileView, CurrentCommandExpiryOutcome,
    DeletionRequestOutcome, DeviceCertificateReconciler, DeviceIngressContract,
    DeviceIngressDelivery, DeviceIngressPreparation, DeviceIngressRepository,
    FencedMutationOutcome, PersistedCertificateArtifactSnapshot, ProductionEligibility,
    ProviderCertificateCandidate, ReportedStateHash, RotationOutcome,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::support::*;
use crate::PgStore;
use crate::cotx::test_proof::DeviceCertificateJoinObservation;
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::device_certificate::PgDeviceCertificateRepository;
use crate::reconcile::PgReconcileStore;

struct ExpiryRejectedAck {
    tenant: vocab::TenantId,
    device: ids::DeviceId,
    event_id: String,
    payload: Vec<u8>,
}

impl DeviceIngressDelivery for ExpiryRejectedAck {
    fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    fn device(&self) -> ids::DeviceId {
        self.device
    }

    fn credential_generation(&self) -> u64 {
        1
    }

    fn contract(&self) -> DeviceIngressContract {
        DeviceIngressContract::CommandAcked
    }

    fn correlation_data(&self) -> Option<&[u8]> {
        Some(self.event_id.as_bytes())
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

async fn commit_expiry_rejected_ack(
    repository: &PgDeviceCertificateRepository<ProductionEligibility>,
    fence: &CertificateAttemptFence,
    command_id: &str,
    event_id: &str,
) -> TestResult {
    let delivery = ExpiryRejectedAck {
        tenant: fence.scope().tenant(),
        device: fence.scope().device(),
        event_id: event_id.to_owned(),
        payload: serde_json::to_vec(&serde_json::json!({
            "deviceId": fence.scope().device().as_uuid(),
            "commandId": command_id,
            "desiredGeneration": fence.expected_generation().get(),
            "fenceEpoch": fence.epoch().get(),
            "deviceSequence": 1,
            "result": "rejected",
            "reason": "DeviceFailure",
            "observedAt": 1_700_000_000_000_000_i64
        }))?,
    };
    let prepared = match identity::ports::device_certificate::prepare_device_ingress(&delivery) {
        DeviceIngressPreparation::Accepted(prepared)
        | DeviceIngressPreparation::Rejected(prepared) => prepared,
        DeviceIngressPreparation::UnaddressablePoison(_) => {
            return Err("expiry ACK fixture was unaddressable".into());
        }
    };
    let (write, pending) = prepared.into_parts();
    let committed = DeviceIngressRepository::commit(repository, write).await?;
    let (receipt, _proof) = committed.into_parts();
    pending.verify_receipt(receipt)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_latent_operator_audit_is_fixed_identifier_free_and_business_zero_write()
-> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let params = fixture.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let operator = crate::PgDeviceLatentOperatorDeps::connect(&config).await?;
    let operator_subject = "service:device-latent-inspection-test";
    let tenant_bait = uuid::Uuid::new_v4().hyphenated().to_string();
    let device_bait = uuid::Uuid::new_v4().hyphenated().to_string();
    let command_bait = format!("command:v2:{}", uuid::Uuid::new_v4());

    let before_business: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM device_certificate_desired_states), \
           (SELECT count(*) FROM device_certificate_reported_states), \
           (SELECT count(*) FROM device_commands), \
           (SELECT count(*) FROM outbox)",
    )
    .fetch_one(&owner.pool)
    .await?;

    operator.record_start_audit().await?;
    operator
        .record_finish_audit(
            operator_subject,
            crate::DeviceLatentInspectionAuditOutcome::NotFound,
        )
        .await?;

    let rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT principal_id,principal_kind,resource_kind,resource_id,action,outcome, \
                failure_reason,tenant_context::text,request_id,correlation_id \
         FROM auth_audit_events \
         WHERE resource_kind='device-certificate.status.inspection' \
         ORDER BY id",
    )
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        rows,
        vec![
            (
                crate::UNVERIFIED_DEVICE_LATENT_OPERATOR.to_owned(),
                "service".to_owned(),
                "device-certificate.status.inspection".to_owned(),
                "device-certificate-status".to_owned(),
                "device.latent.inspect.start".to_owned(),
                "success".to_owned(),
                None,
                None,
                None,
                None,
            ),
            (
                operator_subject.to_owned(),
                "service".to_owned(),
                "device-certificate.status.inspection".to_owned(),
                "device-certificate-status".to_owned(),
                "device.latent.inspect.finish".to_owned(),
                "failure".to_owned(),
                Some("not_found".to_owned()),
                None,
                None,
                None,
            ),
        ],
        "DeviceLatent start/finish audits must keep their complete fixed, identifier-free shape",
    );
    for row in &rows {
        let rendered = format!("{row:?}");
        for bait in [&tenant_bait, &device_bait, &command_bait] {
            assert!(
                !rendered.contains(bait),
                "DeviceLatent audit must not persist target identifier bait"
            );
        }
    }

    let after_business: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM device_certificate_desired_states), \
           (SELECT count(*) FROM device_certificate_reported_states), \
           (SELECT count(*) FROM device_commands), \
           (SELECT count(*) FROM outbox)",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        after_business, before_business,
        "the DeviceLatent operator owner may append audit only, never business state"
    );

    operator.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_receipt_concurrent_transactions_close_same_and_conflicting_values()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (same_scope, same_fence, same_policy_hash, _same_attempt) =
        artifact_append_fixture(&store, "receipt-concurrent-same").await?;
    let (same_left_authorization, _same_snapshot) = authorized_artifact(
        same_scope,
        1,
        &same_policy_hash,
        "artifact-concurrent-same",
        vec![0x19, 0x21],
    )?;
    let (same_right_authorization, _) = authorized_artifact(
        same_scope,
        1,
        &same_policy_hash,
        "artifact-concurrent-same",
        vec![0x19, 0x21],
    )?;
    let same_left =
        crate::device_certificate::PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store);
    let same_right = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let same_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let left_barrier = std::sync::Arc::clone(&same_barrier);
    let left_fence = same_fence.clone();
    let left = async move {
        left_barrier.wait().await;
        same_left
            .append_artifact_receipt(&left_fence, same_left_authorization)
            .await
    };
    let right_barrier = std::sync::Arc::clone(&same_barrier);
    let right_fence = same_fence.clone();
    let right = async move {
        right_barrier.wait().await;
        same_right
            .append_artifact_receipt(&right_fence, same_right_authorization)
            .await
    };
    let (left, right) = tokio::join!(left, right);
    let same_outcomes = [left?, right?];
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == ArtifactAppendOutcome::Appended)
            .count(),
        1
    );
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == ArtifactAppendOutcome::Replayed)
            .count(),
        1
    );
    let same_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=1",
    )
    .bind(same_scope.tenant().to_string())
    .bind(same_scope.device().as_uuid().to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(same_count, 1);

    let (conflict_scope, conflict_fence, conflict_policy_hash, _conflict_attempt) =
        artifact_append_fixture(&store, "receipt-concurrent-conflict").await?;
    let (conflict_a, _) = authorized_artifact(
        conflict_scope,
        1,
        &conflict_policy_hash,
        "artifact-concurrent-value-a",
        vec![0x19, 0x31],
    )?;
    let (conflict_b, _) = authorized_artifact(
        conflict_scope,
        1,
        &conflict_policy_hash,
        "artifact-concurrent-value-b",
        vec![0x19, 0x32],
    )?;
    let conflict_left = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let conflict_right = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let conflict_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let left_barrier = std::sync::Arc::clone(&conflict_barrier);
    let left_fence = conflict_fence.clone();
    let left = async move {
        left_barrier.wait().await;
        conflict_left
            .append_artifact_receipt(&left_fence, conflict_a)
            .await
    };
    let right_barrier = std::sync::Arc::clone(&conflict_barrier);
    let right_fence = conflict_fence.clone();
    let right = async move {
        right_barrier.wait().await;
        conflict_right
            .append_artifact_receipt(&right_fence, conflict_b)
            .await
    };
    let (left, right) = tokio::join!(left, right);
    let conflict_outcomes = [left?, right?];
    assert_eq!(
        conflict_outcomes
            .iter()
            .filter(|outcome| **outcome == ArtifactAppendOutcome::Appended)
            .count(),
        1
    );
    assert_eq!(
        conflict_outcomes
            .iter()
            .filter(|outcome| **outcome == ArtifactAppendOutcome::Conflict)
            .count(),
        1
    );
    let persisted: (i64, String) = sqlx::query_as(
        "SELECT count(*), min(artifact_id) FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=1",
    )
    .bind(conflict_scope.tenant().to_string())
    .bind(conflict_scope.device().as_uuid().to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(persisted.0, 1);
    assert!(matches!(
        persisted.1.as_str(),
        "artifact-concurrent-value-a" | "artifact-concurrent-value-b"
    ));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_command_requires_exact_persisted_artifact_before_any_write()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (scope, fence, policy_hash, attempt) =
        artifact_append_fixture(&store, "command-exact-artifact").await?;

    let missing = reviewed_bound_certificate_command(
        &attempt,
        1,
        &policy_hash,
        "artifact-command-missing",
        &[0x51; 32],
    )
    .await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &store.reconcile(),
            &attempt,
            ConvergeAction::Create,
            missing,
        )
        .await?,
        ScheduleActionOutcome::Lost
    );

    let (authorization, persisted) = authorized_artifact(
        scope,
        1,
        &policy_hash,
        "artifact-command-authorized",
        vec![0x19, 0x41],
    )?;
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    assert_eq!(
        repository
            .append_artifact_receipt(&fence, authorization)
            .await?,
        ArtifactAppendOutcome::Appended
    );
    let mismatch_cases = [
        (
            "artifact id",
            1,
            policy_hash.clone(),
            "artifact-command-mismatch",
            persisted.artifact_digest().as_bytes().to_vec(),
        ),
        (
            "artifact digest",
            1,
            policy_hash.clone(),
            persisted.artifact_id().as_str(),
            vec![0x52; 32],
        ),
        (
            "policy hash",
            1,
            vec![0x53; 32],
            persisted.artifact_id().as_str(),
            persisted.artifact_digest().as_bytes().to_vec(),
        ),
        (
            "generation",
            2,
            policy_hash.clone(),
            persisted.artifact_id().as_str(),
            persisted.artifact_digest().as_bytes().to_vec(),
        ),
    ];
    for (coordinate, generation, candidate_policy, artifact_id, artifact_digest) in mismatch_cases {
        let mismatched = reviewed_bound_certificate_command(
            &attempt,
            generation,
            &candidate_policy,
            artifact_id,
            &artifact_digest,
        )
        .await?;
        assert_eq!(
            ReconcileScheduleStore::record_fenced_command(
                &store.reconcile(),
                &attempt,
                ConvergeAction::Create,
                mismatched,
            )
            .await?,
            ScheduleActionOutcome::Lost,
            "mismatched {coordinate} must be rejected"
        );
    }

    let durable_writes: i64 = sqlx::query_scalar(
        "SELECT \
             (SELECT count(*) FROM command_journal WHERE tenant_id=$1::uuid) + \
             (SELECT count(*) FROM device_commands WHERE tenant_id=$1::uuid) + \
             (SELECT count(*) FROM reconcile_actions WHERE tenant_id=$1::uuid) + \
             (SELECT count(*) FROM outbox WHERE tenant_id=$1::uuid)",
    )
    .bind(scope.tenant().to_string())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        durable_writes, 0,
        "missing or mismatched immutable artifact evidence must reject before every command write"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn current_command_expiry_is_durable_closed_and_fenced_for_every_active_state() -> TestResult
{
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let mut fixtures = Vec::new();

    for state in ["queued", "published", "received"] {
        let device = uuid::Uuid::new_v4().to_string();
        insert_device_desired(&store, tenant, &device).await?;
        let policy_hash: Vec<u8> = sqlx::query_scalar(
            "SELECT policy_hash FROM device_certificate_desired_states \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
        let attempt =
            claim_device_certificate_attempt(&store, tenant, &device, &format!("expiry-{state}"))
                .await?;
        let scope = DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&device)?);
        let fence =
            CertificateAttemptFence::for_test(scope, &attempt, ExpectedGeneration::try_new(1)?)?;
        let repository =
            PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(
                &store,
            );
        let (authorization, receipt) = authorized_artifact(
            scope,
            1,
            &policy_hash,
            &format!("expiry-artifact-{state}"),
            vec![0x17, u8::try_from(state.len())?],
        )?;
        assert_eq!(
            repository
                .append_artifact_receipt(&fence, authorization)
                .await?,
            ArtifactAppendOutcome::Appended
        );
        let command = reviewed_bound_certificate_command_with_deadline(
            &attempt,
            1,
            &policy_hash,
            receipt.artifact_id().as_str(),
            receipt.artifact_digest().as_bytes(),
            u64::try_from(
                sqlx::query_scalar::<_, i64>(
                    "SELECT floor(extract(epoch FROM transaction_timestamp()))::bigint + 3",
                )
                .fetch_one(&store.pool)
                .await?,
            )?,
        )
        .await?;
        assert_eq!(
            ReconcileScheduleStore::record_fenced_command(
                &store.reconcile(),
                &attempt,
                ConvergeAction::Create,
                command,
            )
            .await?,
            ScheduleActionOutcome::Enqueued
        );
        let command_id: String = sqlx::query_scalar(
            "SELECT command_id FROM device_commands \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=1",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
        if matches!(state, "published" | "received") {
            sqlx::query(
                "UPDATE device_commands SET state='published',version=2, \
                 published_at=pg_catalog.transaction_timestamp() \
                 WHERE tenant_id=$1::uuid AND command_id=$2",
            )
            .bind(tenant.to_string())
            .bind(&command_id)
            .execute(&store.pool)
            .await?;
        }
        if state == "received" {
            sqlx::query(
                "UPDATE device_commands SET state='received',version=3, \
                 received_at=pg_catalog.transaction_timestamp() \
                 WHERE tenant_id=$1::uuid AND command_id=$2",
            )
            .bind(tenant.to_string())
            .bind(&command_id)
            .execute(&store.pool)
            .await?;
        }
        let repository =
            PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_stores_for_test(
                &app, &app,
            );
        let before: (String, i64) = sqlx::query_as(
            "SELECT state,version FROM device_commands \
             WHERE tenant_id=$1::uuid AND command_id=$2",
        )
        .bind(tenant.to_string())
        .bind(&command_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            repository.expire_due_current_command(&fence).await?,
            CurrentCommandExpiryOutcome::NotDue
        );
        let after: (String, i64) = sqlx::query_as(
            "SELECT state,version FROM device_commands \
             WHERE tenant_id=$1::uuid AND command_id=$2",
        )
        .bind(tenant.to_string())
        .bind(&command_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(after, before, "future deadline must be zero-write");
        fixtures.push((state, fence, command_id));
    }

    for (previous_state, fence, command_id) in fixtures {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let due: bool = sqlx::query_scalar(
                    "SELECT transaction_timestamp() >= deadline FROM device_commands \
                     WHERE tenant_id=$1::uuid AND command_id=$2",
                )
                .bind(tenant.to_string())
                .bind(&command_id)
                .fetch_one(&store.pool)
                .await?;
                if due {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let restarted =
            PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_stores_for_test(
                &app, &app,
            );
        let expiry = restarted.expire_due_current_command(&fence);
        let outcome = if previous_state == "published" {
            let ack =
                commit_expiry_rejected_ack(&restarted, &fence, &command_id, "expiry-rejected-ack");
            let (expiry_result, ack_result) = tokio::join!(expiry, ack);
            ack_result?;
            expiry_result?
        } else {
            expiry.await?
        };
        assert!(
            matches!(outcome, CurrentCommandExpiryOutcome::Expired)
                || (previous_state == "published"
                    && matches!(outcome, CurrentCommandExpiryOutcome::NoCurrent)),
            "{previous_state} command must have one expiry/rejection winner, got {outcome:?}"
        );
        let row: (String, i64, bool) = sqlx::query_as(
            "SELECT state,version,terminal_at >= deadline FROM device_commands \
             WHERE tenant_id=$1::uuid AND command_id=$2",
        )
        .bind(tenant.to_string())
        .bind(&command_id)
        .fetch_one(&store.pool)
        .await?;
        let expected_state = if outcome == CurrentCommandExpiryOutcome::Expired {
            "timed_out"
        } else {
            "rejected"
        };
        assert_eq!(row.0, expected_state);
        assert!(row.2);
        let replay = restarted.expire_due_current_command(&fence).await?;
        assert_eq!(
            replay,
            if expected_state == "timed_out" {
                CurrentCommandExpiryOutcome::AlreadyExpired
            } else {
                CurrentCommandExpiryOutcome::NoCurrent
            }
        );
        let replay_version: i64 = sqlx::query_scalar(
            "SELECT version FROM device_commands WHERE tenant_id=$1::uuid AND command_id=$2",
        )
        .bind(tenant.to_string())
        .bind(&command_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(replay_version, row.1, "repeated expiry must be zero-write");
    }

    let empty_device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &empty_device).await?;
    let empty_attempt =
        claim_device_certificate_attempt(&store, tenant, &empty_device, "expiry-empty").await?;
    let empty_scope =
        DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&empty_device)?);
    let empty_fence = CertificateAttemptFence::for_test(
        empty_scope,
        &empty_attempt,
        ExpectedGeneration::try_new(1)?,
    )?;
    let repository =
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_stores_for_test(
            &app, &app,
        );
    assert_eq!(
        repository.expire_due_current_command(&empty_fence).await?,
        CurrentCommandExpiryOutcome::NoCurrent
    );
    let stale_fence = CertificateAttemptFence::for_test(
        empty_scope,
        &empty_attempt,
        ExpectedGeneration::try_new(2)?,
    )?;
    assert_eq!(
        repository.expire_due_current_command(&stale_fence).await?,
        CurrentCommandExpiryOutcome::StaleFence
    );
    let empty_writes: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM device_commands \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&empty_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(empty_writes, 0);

    let raw_update =
        sqlx::query("UPDATE device_commands SET state='timed_out' WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string())
            .execute(&app.pool)
            .await
            .expect_err("rss_app must not receive raw command UPDATE");
    assert_eq!(
        raw_update
            .as_database_error()
            .and_then(|database| database.code())
            .map(|code| code.into_owned()),
        Some("42501".to_owned())
    );
    let other_tenant = uuid::Uuid::new_v4().to_string();
    let mut cross_tenant = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *cross_tenant)
        .await?;
    let cross_tenant_error = sqlx::query_scalar::<_, String>(
        "SELECT outcome FROM public.rss_select_due_current_device_command_production( \
         $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7)",
    )
    .bind(other_tenant)
    .bind(empty_scope.device().as_uuid().to_string())
    .bind(empty_fence.attempt_id())
    .bind(empty_fence.lease_token())
    .bind(i64::try_from(empty_fence.epoch().get())?)
    .bind(i64::try_from(empty_fence.wake_version().get())?)
    .bind(i64::try_from(empty_fence.expected_generation().get())?)
    .fetch_one(&mut *cross_tenant)
    .await
    .expect_err("expiry wrapper must reject cross-tenant authority");
    assert_eq!(
        cross_tenant_error
            .as_database_error()
            .and_then(|database| database.code())
            .map(|code| code.into_owned()),
        Some("42501".to_owned())
    );
    cross_tenant.rollback().await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_certificate_condition_funnel_accepts_only_closed_active_vectors() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &device).await?;
    let attempt =
        claim_device_certificate_attempt(&store, tenant, &device, "condition-vector-holder")
            .await?;
    let scope = DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&device)?);
    let fence =
        CertificateAttemptFence::for_test(scope, &attempt, ExpectedGeneration::try_new(1)?)?;
    let active_desired: (bool, bool) = sqlx::query_as(
        "SELECT deletion_requested_at IS NULL,finalizer_present \
         FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(active_desired, (true, true));

    let issue = [
        ("Ready", "False", "AwaitingDevice"),
        ("Reconciling", "True", "CommandQueued"),
        ("PendingDevice", "True", "AwaitingDevice"),
        ("Degraded", "False", "ArtifactUnavailable"),
        ("Quarantined", "False", "ProtocolViolation"),
        ("Deleting", "False", "DeletionPending"),
    ];
    assert!(
        rss_app_write_device_certificate_condition_vector(
            &store, tenant, &device, &fence, issue, true,
        )
        .await?,
        "the closed Issue vector must remain writable through rss_app"
    );
    let issue_snapshot = device_certificate_condition_rows(&store, tenant, &device).await?;
    assert_eq!(
        issue_snapshot,
        vec![
            (
                "Degraded".to_owned(),
                "False".to_owned(),
                "ArtifactUnavailable".to_owned(),
                Some(1)
            ),
            (
                "Deleting".to_owned(),
                "False".to_owned(),
                "DeletionPending".to_owned(),
                Some(1)
            ),
            (
                "PendingDevice".to_owned(),
                "True".to_owned(),
                "AwaitingDevice".to_owned(),
                Some(1)
            ),
            (
                "Quarantined".to_owned(),
                "False".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(1)
            ),
            (
                "Ready".to_owned(),
                "False".to_owned(),
                "AwaitingDevice".to_owned(),
                Some(1)
            ),
            (
                "Reconciling".to_owned(),
                "True".to_owned(),
                "CommandQueued".to_owned(),
                Some(1)
            ),
        ]
    );

    let illegal_vectors = [
        (
            "active desired cannot forge terminal deletion",
            [
                ("Ready", "False", "StateDrift"),
                ("Reconciling", "False", "StateDrift"),
                ("PendingDevice", "False", "AwaitingDevice"),
                ("Degraded", "False", "ArtifactUnavailable"),
                ("Quarantined", "False", "ProtocolViolation"),
                ("Deleting", "True", "DeletionComplete"),
            ],
        ),
        (
            "Reconciling and Deleting cannot both be true",
            [
                ("Ready", "False", "AwaitingDevice"),
                ("Reconciling", "True", "CommandQueued"),
                ("PendingDevice", "False", "AwaitingDevice"),
                ("Degraded", "False", "ArtifactUnavailable"),
                ("Quarantined", "False", "ProtocolViolation"),
                ("Deleting", "True", "DeletionPending"),
            ],
        ),
        (
            "Degraded and Quarantined cannot both be true",
            [
                ("Ready", "False", "ProtocolViolation"),
                ("Reconciling", "False", "StateDrift"),
                ("PendingDevice", "False", "AwaitingDevice"),
                ("Degraded", "True", "ArtifactUnavailable"),
                ("Quarantined", "True", "ProtocolViolation"),
                ("Deleting", "False", "DeletionPending"),
            ],
        ),
    ];
    for (case, vector) in illegal_vectors {
        let error = rss_app_write_device_certificate_condition_vector(
            &store, tenant, &device, &fence, vector, false,
        )
        .await
        .expect_err(case);
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database| database.code())
                .map(|code| code.into_owned()),
            Some("42501".to_owned()),
            "{case} must fail as an authorization violation"
        );
        assert_eq!(
            device_certificate_condition_rows(&store, tenant, &device).await?,
            issue_snapshot,
            "{case} must leave all six durable rows untouched"
        );
    }

    let degraded = [
        ("Ready", "False", "ArtifactUnavailable"),
        ("Reconciling", "False", "StateDrift"),
        ("PendingDevice", "False", "AwaitingDevice"),
        ("Degraded", "True", "ArtifactUnavailable"),
        ("Quarantined", "False", "ProtocolViolation"),
        ("Deleting", "False", "DeletionPending"),
    ];
    assert!(
        rss_app_write_device_certificate_condition_vector(
            &store, tenant, &device, &fence, degraded, true,
        )
        .await?,
        "the closed Degraded vector must remain writable through rss_app"
    );
    assert_eq!(
        device_certificate_condition_rows(&store, tenant, &device).await?,
        vec![
            (
                "Degraded".to_owned(),
                "True".to_owned(),
                "ArtifactUnavailable".to_owned(),
                Some(1)
            ),
            (
                "Deleting".to_owned(),
                "False".to_owned(),
                "DeletionPending".to_owned(),
                Some(1)
            ),
            (
                "PendingDevice".to_owned(),
                "False".to_owned(),
                "AwaitingDevice".to_owned(),
                Some(1)
            ),
            (
                "Quarantined".to_owned(),
                "False".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(1)
            ),
            (
                "Ready".to_owned(),
                "False".to_owned(),
                "ArtifactUnavailable".to_owned(),
                Some(1)
            ),
            (
                "Reconciling".to_owned(),
                "False".to_owned(),
                "StateDrift".to_owned(),
                Some(1)
            ),
        ]
    );

    let quarantined = [
        ("Ready", "False", "ProtocolViolation"),
        ("Reconciling", "False", "StateDrift"),
        ("PendingDevice", "False", "AwaitingDevice"),
        ("Degraded", "False", "ProtocolViolation"),
        ("Quarantined", "True", "ProtocolViolation"),
        ("Deleting", "False", "DeletionPending"),
    ];
    assert!(
        rss_app_write_device_certificate_condition_vector(
            &store,
            tenant,
            &device,
            &fence,
            quarantined,
            true,
        )
        .await?,
        "the closed Quarantined vector must remain writable through rss_app"
    );
    assert_eq!(
        device_certificate_condition_rows(&store, tenant, &device).await?,
        vec![
            (
                "Degraded".to_owned(),
                "False".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(1)
            ),
            (
                "Deleting".to_owned(),
                "False".to_owned(),
                "DeletionPending".to_owned(),
                Some(1)
            ),
            (
                "PendingDevice".to_owned(),
                "False".to_owned(),
                "AwaitingDevice".to_owned(),
                Some(1)
            ),
            (
                "Quarantined".to_owned(),
                "True".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(1)
            ),
            (
                "Ready".to_owned(),
                "False".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(1)
            ),
            (
                "Reconciling".to_owned(),
                "False".to_owned(),
                "StateDrift".to_owned(),
                Some(1)
            ),
        ]
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_receipt_is_append_once_and_all_fence_coordinates_are_hard() -> TestResult
{
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &device).await?;
    let policy_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT policy_hash FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    let attempt =
        claim_device_certificate_attempt(&store, tenant, &device, "receipt-holder").await?;
    let scope = DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&device)?);
    let fence =
        CertificateAttemptFence::for_test(scope, &attempt, ExpectedGeneration::try_new(1)?)?;
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let (append_authorization, receipt) = authorized_artifact(
        scope,
        1,
        &policy_hash,
        "artifact-append-once",
        vec![0x19, 0x11],
    )?;
    assert_eq!(
        repository
            .append_artifact_receipt(&fence, append_authorization)
            .await?,
        ArtifactAppendOutcome::Appended
    );
    let (replay_authorization, _) = authorized_artifact(
        scope,
        1,
        &policy_hash,
        "artifact-append-once",
        vec![0x19, 0x11],
    )?;
    assert_eq!(
        repository
            .append_artifact_receipt(&fence, replay_authorization)
            .await?,
        ArtifactAppendOutcome::Replayed
    );
    let original: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, i64) = sqlx::query_as(
        "SELECT policy_hash,public_key_digest,expected_state_hash,artifact_digest, \
                    artifact_id,serial,extract(epoch FROM not_after)::bigint \
             FROM device_certificate_authorized_artifacts \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=1",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    let (conflict, _) = authorized_artifact(
        scope,
        1,
        &policy_hash,
        "artifact-conflicting-value",
        vec![0x19, 0x12],
    )?;
    assert_eq!(
        repository.append_artifact_receipt(&fence, conflict).await?,
        ArtifactAppendOutcome::Conflict
    );
    let after_conflict: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, i64) =
        sqlx::query_as(
            "SELECT policy_hash,public_key_digest,expected_state_hash,artifact_digest, \
                    artifact_id,serial,extract(epoch FROM not_after)::bigint \
             FROM device_certificate_authorized_artifacts \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=1",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        after_conflict, original,
        "conflict must preserve the original row"
    );

    let command = reviewed_bound_certificate_command(
        &attempt,
        1,
        &policy_hash,
        receipt.artifact_id().as_str(),
        receipt.artifact_digest().as_bytes(),
    )
    .await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &store.reconcile(),
            &attempt,
            ConvergeAction::Create,
            command,
        )
        .await?,
        ScheduleActionOutcome::Enqueued
    );
    let command_id: String = sqlx::query_scalar(
        "SELECT command_id FROM device_commands \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=1",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='published',version=2, \
         published_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='received',version=3, \
         received_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO device_certificate_reported_states ( \
          tenant_id,device_id,observed_generation,fence_epoch,state_hash,artifact_digest, \
          report_envelope_id,device_sequence) \
         VALUES ($1::uuid,$2::uuid,1,$3,$4,$5,'ready-report',1)",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(i64::try_from(attempt.target().epoch())?)
    .bind(receipt.expected_reported_state_hash().as_bytes().as_slice())
    .bind(receipt.artifact_digest().as_bytes().as_slice())
    .execute(&store.pool)
    .await?;
    let active_row: (i64, i64, String) = sqlx::query_as(
        "SELECT generation,fence_epoch,state FROM device_commands \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid \
           AND state IN ('queued','published','received')",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(active_row.0, 1);
    assert_eq!(active_row.2, "received");
    let status_store = crate::device_certificate::PgDeviceCertificateStatusStore::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let status = status_store
        .inspect(device_certificate_status_query(scope)?)
        .await?
        .ok_or("ready fixture desired state was missing")?;
    let status_wire = serde_json::to_value(status.to_wire_response()?)?;
    assert_eq!(status_wire["data"]["desiredGeneration"], 1);
    assert_eq!(status_wire["data"]["observedGeneration"], 1);
    assert_eq!(status_wire["data"]["activeCommand"]["generation"], 1);
    assert_eq!(status_wire["data"]["activeCommand"]["state"], "received");
    assert!(status.observation().is_ok());
    assert!(!serde_json::to_string(&status_wire)?.contains(&command_id));
    let proof_authority = CertificateAttemptAuthority::for_test(scope, &attempt)?;
    let proof_view = repository
        .load_current_view(&proof_authority)
        .await?
        .ok_or("ready fixture current view was missing")?;
    let state = proof_view.state();
    let report = state
        .reported()
        .ok_or("ready fixture reported state was missing")?;
    let command = <crate::device_certificate::PgDeviceCertificateRepository<
        ProductionEligibility,
    > as
        identity::ports::device_certificate::CertificateReconcileRepository<
            ProductionEligibility,
        >>::load_current_command_evidence(&repository, &fence)
    .await?
    .ok_or("ready fixture command evidence was missing")?;
    let generation = Some(deviceloop::ObservedGeneration::try_new(1)?);
    let outage_conditions =
        CertificateConditionMutation::States(ConditionStateBatch::for_test(vec![
            deviceloop::DeviceConditionState::ready(
                deviceloop::NotReadyStatus::False,
                deviceloop::ReadyReason::ArtifactUnavailable,
                generation,
            ),
            deviceloop::DeviceConditionState::reconciling(
                deviceloop::ConditionStatus::False,
                deviceloop::ReconcilingReason::StateDrift,
                generation,
            ),
            deviceloop::DeviceConditionState::pending_device(
                deviceloop::ConditionStatus::False,
                deviceloop::PendingDeviceReason::AwaitingDevice,
                generation,
            ),
            deviceloop::DeviceConditionState::degraded(
                deviceloop::ConditionStatus::True,
                deviceloop::DegradedReason::ArtifactUnavailable,
                generation,
            ),
            deviceloop::DeviceConditionState::quarantined(
                deviceloop::ConditionStatus::False,
                deviceloop::QuarantinedReason::ProtocolViolation,
                generation,
            ),
            deviceloop::DeviceConditionState::deleting(
                deviceloop::ConditionStatus::False,
                deviceloop::DeletingReason::DeletionPending,
                generation,
            ),
        ])?);
    assert_eq!(
        repository
            .write_conditions(&fence, outage_conditions)
            .await?,
        FencedMutationOutcome::Applied
    );
    let outage_snapshot: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        outage_snapshot.len(),
        6,
        "outage writes the complete condition set"
    );
    let payload_mismatch_proof = CertificateReadyProof::restore_current(
        scope,
        state.desired(),
        &receipt,
        report,
        &command,
        std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000),
        CertificateRevocationObservation::Unrevoked,
    )?;
    let original_payload: Vec<u8> =
        sqlx::query_scalar("SELECT payload FROM outbox WHERE tenant_id=$1::uuid AND event_id=$2")
            .bind(tenant.to_string())
            .bind(&command_id)
            .fetch_one(&store.pool)
            .await?;
    let mut mismatched_payload: serde_json::Value = serde_json::from_slice(&original_payload)?;
    mismatched_payload["artifactId"] =
        serde_json::Value::String("artifact-payload-mismatch".to_owned());
    sqlx::query("UPDATE outbox SET payload=$3 WHERE tenant_id=$1::uuid AND event_id=$2")
        .bind(tenant.to_string())
        .bind(&command_id)
        .bind(serde_json::to_vec(&mismatched_payload)?)
        .execute(&store.pool)
        .await?;
    assert_eq!(
        repository
            .write_conditions(
                &fence,
                CertificateConditionMutation::Ready(Box::new(payload_mismatch_proof)),
            )
            .await?,
        FencedMutationOutcome::StaleFence,
        "durable outbox payload drift must reject an earlier valid proof"
    );
    let after_rejected_proof: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        after_rejected_proof, outage_snapshot,
        "rejected recovery proof must leave the complete outage condition set untouched"
    );
    sqlx::query("UPDATE outbox SET payload=$3 WHERE tenant_id=$1::uuid AND event_id=$2")
        .bind(tenant.to_string())
        .bind(&command_id)
        .bind(&original_payload)
        .execute(&store.pool)
        .await?;
    let proof = CertificateReadyProof::restore_current(
        scope,
        state.desired(),
        &receipt,
        report,
        &command,
        std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000),
        CertificateRevocationObservation::Unrevoked,
    )?;
    let report_received_at_micros = i64::try_from(
        proof
            .report_received_at()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    let mut forged_time_tx = store.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *forged_time_tx)
        .await?;
    let forged_renew_at_accepted: bool = sqlx::query_scalar(
        "SELECT public.rss_mark_device_certificate_ready( \
         $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14, \
         $15,$16,$17,$18,$19,$20)",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(fence.attempt_id())
    .bind(fence.lease_token())
    .bind(i64::try_from(fence.epoch().get())?)
    .bind(i64::try_from(fence.wake_version().get())?)
    .bind(i64::try_from(proof.generation().get())?)
    .bind(i64::try_from(proof.fence_epoch().get())?)
    .bind(proof.intent_digest().as_bytes().as_slice())
    .bind(proof.artifact_id().as_str())
    .bind(proof.artifact_digest().as_bytes().as_slice())
    .bind(proof.policy_hash().as_bytes().as_slice())
    .bind(proof.state_hash().as_bytes().as_slice())
    .bind(proof.report_envelope_id().as_str())
    .bind(i64::try_from(proof.device_sequence().get())?)
    .bind(report_received_at_micros)
    .bind(proof.serial().as_bytes())
    .bind(proof.not_after().unix_seconds())
    .bind(proof.not_after().unix_seconds() - 1)
    .bind(proof.not_after().unix_seconds() + 3_600)
    .fetch_one(&mut *forged_time_tx)
    .await?;
    forged_time_tx.rollback().await?;
    assert!(
        !forged_renew_at_accepted,
        "funnel must recompute renew-at from durable policy instead of trusting proof input"
    );
    sqlx::query(
        "CREATE FUNCTION public._test_fail_certificate_ready_recovery() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF NEW.condition_type='Ready' AND NEW.status='True' THEN \
             RAISE EXCEPTION 'injected Ready recovery failure'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER _test_fail_certificate_ready_recovery \
         BEFORE INSERT OR UPDATE ON public.device_certificate_conditions \
         FOR EACH ROW EXECUTE FUNCTION public._test_fail_certificate_ready_recovery()",
    )
    .execute(&store.pool)
    .await?;
    let injected_failure_proof = CertificateReadyProof::restore_current(
        scope,
        state.desired(),
        &receipt,
        report,
        &command,
        std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000),
        CertificateRevocationObservation::Unrevoked,
    )?;
    assert!(
        repository
            .write_conditions(
                &fence,
                CertificateConditionMutation::Ready(Box::new(injected_failure_proof)),
            )
            .await
            .is_err(),
        "a failure inside the Ready funnel must abort the entire recovery transaction"
    );
    sqlx::query(
        "DROP TRIGGER _test_fail_certificate_ready_recovery \
         ON public.device_certificate_conditions",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query("DROP FUNCTION public._test_fail_certificate_ready_recovery()")
        .execute(&store.pool)
        .await?;
    let after_injected_failure: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        after_injected_failure, outage_snapshot,
        "failed recovery must not partially clear outage conditions"
    );
    assert_eq!(
        repository
            .write_conditions(&fence, CertificateConditionMutation::Ready(Box::new(proof)))
            .await?,
        FencedMutationOutcome::Applied
    );
    let recovered_conditions: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        recovered_conditions,
        vec![
            (
                "Degraded".to_owned(),
                "False".to_owned(),
                "ArtifactUnavailable".to_owned(),
                Some(1)
            ),
            (
                "Deleting".to_owned(),
                "False".to_owned(),
                "DeletionPending".to_owned(),
                Some(1)
            ),
            (
                "PendingDevice".to_owned(),
                "False".to_owned(),
                "AwaitingDevice".to_owned(),
                Some(1)
            ),
            (
                "Quarantined".to_owned(),
                "False".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(1)
            ),
            (
                "Ready".to_owned(),
                "True".to_owned(),
                "StateMatches".to_owned(),
                Some(1)
            ),
            (
                "Reconciling".to_owned(),
                "False".to_owned(),
                "DeviceReported".to_owned(),
                Some(1)
            ),
        ],
        "Issue to Ready recovery must converge the complete condition set without conflicting true states"
    );
    let inspected_ready = status_store
        .inspect(device_certificate_status_query(scope)?)
        .await?
        .ok_or("fresh Ready inspection lost desired state")?;
    let ready_wire = serde_json::to_value(inspected_ready.to_wire_response()?)?;
    assert_eq!(ready_wire["data"]["activeCommand"]["state"], "received");
    assert!(
        ready_wire["data"]["conditions"]
            .as_array()
            .is_some_and(|conditions| conditions.iter().any(|condition| {
                condition["type"] == "Ready" && condition["status"] == "True"
            }))
    );
    let ready_observation = inspected_ready
        .observation()
        .expect("ready observation must form");
    assert_eq!(ready_observation.generation_lag(), 0);
    assert_eq!(ready_observation.drift_age(), None);
    assert!(
        ready_observation.queue_age().is_some() && ready_observation.ack_latency().is_some(),
        "received active command must expose queue age and ack latency"
    );
    sqlx::query("UPDATE outbox SET payload=$3 WHERE tenant_id=$1::uuid AND event_id=$2")
        .bind(tenant.to_string())
        .bind(&command_id)
        .bind(serde_json::to_vec(&mismatched_payload)?)
        .execute(&store.pool)
        .await?;
    assert!(matches!(
        status_store
            .inspect(device_certificate_status_query(scope)?)
            .await,
        Err(
            identity::ports::device_certificate::DeviceCertificateStatusStoreError::CorruptState(_)
        )
    ));
    sqlx::query("UPDATE outbox SET payload=$3 WHERE tenant_id=$1::uuid AND event_id=$2")
        .bind(tenant.to_string())
        .bind(&command_id)
        .bind(&original_payload)
        .execute(&store.pool)
        .await?;
    let authority = CertificateAttemptAuthority::for_test(scope, &attempt)?;
    let ready_view = repository
        .load_current_view(&authority)
        .await?
        .ok_or("ready fixture current view was missing")?;
    assert!(ready_view.state().conditions().iter().any(|condition| {
        condition.kind() == deviceloop::DeviceConditionKind::Ready
            && condition.status_label() == "True"
    }));
    let concurrent_proof = CertificateReadyProof::restore_current(
        scope,
        ready_view.state().desired(),
        &receipt,
        ready_view
            .state()
            .reported()
            .ok_or("ready view lost its report")?,
        &command,
        std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_001),
        CertificateRevocationObservation::Unrevoked,
    )?;
    let ready_again = repository.write_conditions(
        &fence,
        CertificateConditionMutation::Ready(Box::new(concurrent_proof)),
    );
    let revoke_concurrently = async {
        let mut revocation_tx = store.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *revocation_tx)
            .await?;
        sqlx::query(
            "INSERT INTO certificate_revocations (tenant_id,device_id,serial,not_after) \
             VALUES ($1::uuid,$2::uuid,$3,pg_catalog.to_timestamp($4))",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .bind(receipt.serial().as_bytes())
        .bind(receipt.not_after().unix_seconds())
        .execute(&mut *revocation_tx)
        .await?;
        revocation_tx.commit().await?;
        Ok::<(), TestError>(())
    };
    let (ready_race, revocation_race) = tokio::join!(ready_again, revoke_concurrently);
    assert!(matches!(
        ready_race?,
        FencedMutationOutcome::Applied | FencedMutationOutcome::StaleFence
    ));
    revocation_race?;
    let invalidated_ready: (String, String) = sqlx::query_as(
        "SELECT status,reason FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND condition_type='Ready'",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        invalidated_ready,
        ("False".to_owned(), "StateDrift".to_owned()),
        "same-generation revocation must atomically invalidate prior Ready evidence"
    );
    let invalidated_view = repository
        .load_current_view(&authority)
        .await?
        .ok_or("invalidated current view was missing")?;
    assert!(
        invalidated_view
            .state()
            .conditions()
            .iter()
            .any(|condition| {
                condition.kind() == deviceloop::DeviceConditionKind::Ready
                    && condition.status_label() == "False"
            })
    );

    let condition = CertificateConditionMutation::States(ConditionStateBatch::for_test(vec![
        deviceloop::DeviceConditionState::ready(
            deviceloop::NotReadyStatus::False,
            deviceloop::ReadyReason::StateDrift,
            Some(deviceloop::ObservedGeneration::try_new(1)?),
        ),
    ])?);
    let before_stale_condition_write: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE reconcile_attempts SET epoch=epoch+1 \
         WHERE tenant_id=$1::uuid AND attempt_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        repository.write_conditions(&fence, condition).await?,
        FencedMutationOutcome::StaleFence,
        "attempt epoch drift must be zero-write"
    );
    let after_stale_condition_write: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(after_stale_condition_write, before_stale_condition_write);
    sqlx::query(
        "UPDATE reconcile_attempts SET epoch=epoch-1 \
         WHERE tenant_id=$1::uuid AND attempt_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.attempt_id())
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "UPDATE reconcile_leases SET lease_token=gen_random_uuid() \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        repository.rotate_generation(&fence).await?,
        RotationOutcome::StaleFence,
        "lease token takeover must be zero-write"
    );
    let after_token: (i64, i64) = sqlx::query_as(
        "SELECT desired.generation,target.wake_version \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(after_token, (1, 0));
    sqlx::query(
        "UPDATE reconcile_leases SET lease_token=$3::uuid \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .bind(attempt.target().lease_token())
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "UPDATE reconcile_leases SET epoch=epoch+1 \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        repository.rotate_generation(&fence).await?,
        RotationOutcome::StaleFence,
        "lease epoch takeover must be zero-write"
    );
    sqlx::query(
        "UPDATE reconcile_leases SET epoch=epoch-1 \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "UPDATE reconcile_leases \
         SET acquired_at=pg_catalog.clock_timestamp()-interval '1 hour', \
             expires_at=pg_catalog.clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        repository.request_deletion(&fence).await?,
        DeletionRequestOutcome::StaleFence,
        "expired authoritative lease time must be zero-write"
    );
    sqlx::query(
        "UPDATE reconcile_leases SET expires_at=pg_catalog.clock_timestamp()+interval '30 seconds' \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "UPDATE reconcile_targets SET wake_version=wake_version+1 \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(attempt.target().target_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        repository.request_deletion(&fence).await?,
        DeletionRequestOutcome::StaleFence,
        "wake-version drift must be zero-write"
    );
    let deletion_requested: bool = sqlx::query_scalar(
        "SELECT deletion_requested_at IS NOT NULL \
         FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert!(!deletion_requested);

    sqlx::query(
        "UPDATE device_certificate_desired_states SET generation=2 \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .execute(&store.pool)
    .await?;
    let (stale_authorization, _) = authorized_artifact(
        scope,
        1,
        &policy_hash,
        "artifact-append-once",
        vec![0x19, 0x11],
    )?;
    assert_eq!(
        repository
            .append_artifact_receipt(&fence, stale_authorization)
            .await?,
        ArtifactAppendOutcome::StaleFence,
        "desired generation advance must be zero-write"
    );
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(receipt_count, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_rotation_and_deletion_request_commit_exact_atomic_state() -> TestResult
{
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);

    let rotation_device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &rotation_device).await?;
    let rotation_attempt =
        claim_device_certificate_attempt(&store, tenant, &rotation_device, "rotation-holder")
            .await?;
    let rotation_scope =
        DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&rotation_device)?);
    let rotation_fence = CertificateAttemptFence::for_test(
        rotation_scope,
        &rotation_attempt,
        ExpectedGeneration::try_new(1)?,
    )?;
    let before_rotation: (Vec<u8>, i32, i32, bool, bool, Vec<String>, i64) = sqlx::query_as(
        "SELECT desired.policy_hash,desired.validity_seconds, \
                    desired.renew_before_seconds,desired.client_auth,desired.server_auth, \
                    desired.sans,target.wake_version \
             FROM device_certificate_desired_states desired \
             JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
              AND target.resource_id=desired.device_id::text \
             WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&rotation_device)
    .fetch_one(&store.pool)
    .await?;
    let rotated = <crate::device_certificate::PgDeviceCertificateRepository<
        ProductionEligibility,
    > as
        identity::ports::device_certificate::CertificateReconcileRepository<
            ProductionEligibility,
        >>::rotate_generation(&repository, &rotation_fence)
    .await?;
    let RotationOutcome::Rotated { generation, wake } = rotated else {
        return Err("fresh rotation did not commit".into());
    };
    assert_eq!(generation.get(), 2);
    assert_eq!(wake.version().get(), u64::try_from(before_rotation.6 + 1)?);
    let after_rotation: (
        i64,
        Vec<u8>,
        i32,
        i32,
        bool,
        bool,
        Vec<String>,
        String,
        String,
        Option<i64>,
        i64,
    ) = sqlx::query_as(
        "SELECT desired.generation,desired.policy_hash,desired.validity_seconds, \
                desired.renew_before_seconds,desired.client_auth,desired.server_auth,desired.sans, \
                condition.status,condition.reason,condition.observed_generation,target.wake_version \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN device_certificate_conditions condition ON condition.tenant_id=desired.tenant_id \
          AND condition.device_id=desired.device_id AND condition.condition_type='Ready' \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&rotation_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(after_rotation.0, 2);
    assert_eq!(
        (
            &after_rotation.1,
            after_rotation.2,
            after_rotation.3,
            after_rotation.4,
            after_rotation.5,
            &after_rotation.6,
        ),
        (
            &before_rotation.0,
            before_rotation.1,
            before_rotation.2,
            before_rotation.3,
            before_rotation.4,
            &before_rotation.5,
        ),
        "rotation must copy the exact policy"
    );
    assert_eq!(
        (&after_rotation.7, &after_rotation.8, after_rotation.9),
        (&"False".to_owned(), &"AwaitingDevice".to_owned(), Some(2))
    );
    assert_eq!(after_rotation.10, before_rotation.6 + 1);
    assert_eq!(
        repository.rotate_generation(&rotation_fence).await?,
        RotationOutcome::StaleFence
    );
    let replay_rotation: (
        i64,
        Vec<u8>,
        i32,
        i32,
        bool,
        bool,
        Vec<String>,
        String,
        String,
        Option<i64>,
        i64,
    ) = sqlx::query_as(
        "SELECT desired.generation,desired.policy_hash,desired.validity_seconds, \
                desired.renew_before_seconds,desired.client_auth,desired.server_auth,desired.sans, \
                condition.status,condition.reason,condition.observed_generation,target.wake_version \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN device_certificate_conditions condition ON condition.tenant_id=desired.tenant_id \
          AND condition.device_id=desired.device_id AND condition.condition_type='Ready' \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&rotation_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        replay_rotation, after_rotation,
        "stale rotation must be zero-write"
    );

    let deletion_device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &deletion_device).await?;
    let deletion_attempt =
        claim_device_certificate_attempt(&store, tenant, &deletion_device, "deletion-holder")
            .await?;
    let deletion_scope =
        DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&deletion_device)?);
    let deletion_fence = CertificateAttemptFence::for_test(
        deletion_scope,
        &deletion_attempt,
        ExpectedGeneration::try_new(1)?,
    )?;
    let before_wake = i64::try_from(deletion_attempt.target().wake_version().get())?;
    let DeletionRequestOutcome::Requested(requested_wake) =
        repository.request_deletion(&deletion_fence).await?
    else {
        return Err("fresh deletion request did not commit".into());
    };
    assert_eq!(
        requested_wake.version().get(),
        u64::try_from(before_wake + 1)?
    );
    let requested: (bool, bool, i64) = sqlx::query_as(
        "SELECT deletion_requested_at IS NOT NULL,finalizer_present,target.wake_version \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&deletion_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(requested, (true, true, before_wake + 1));
    assert_eq!(
        ReconcileScheduleStore::release_lease(&store.reconcile(), deletion_attempt.target())
            .await?,
        eventexec::reconcile::ScheduleLeaseOutcome::Held
    );
    let replay_attempt =
        claim_device_certificate_attempt(&store, tenant, &deletion_device, "deletion-replay")
            .await?;
    let replay_fence = CertificateAttemptFence::for_test(
        deletion_scope,
        &replay_attempt,
        ExpectedGeneration::try_new(1)?,
    )?;
    let replay_before: (Option<String>, bool, i64, i64) = sqlx::query_as(
        "SELECT deletion_requested_at::text,finalizer_present, \
                target.wake_version,count(condition.*)::bigint \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         LEFT JOIN device_certificate_conditions condition ON condition.tenant_id=desired.tenant_id \
          AND condition.device_id=desired.device_id \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid \
         GROUP BY desired.deletion_requested_at,desired.finalizer_present,target.wake_version",
    )
    .bind(tenant.to_string())
    .bind(&deletion_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        repository.request_deletion(&replay_fence).await?,
        DeletionRequestOutcome::Replayed
    );
    let replay_after: (Option<String>, bool, i64, i64) = sqlx::query_as(
        "SELECT deletion_requested_at::text,finalizer_present, \
                target.wake_version,count(condition.*)::bigint \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         LEFT JOIN device_certificate_conditions condition ON condition.tenant_id=desired.tenant_id \
          AND condition.device_id=desired.device_id \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid \
         GROUP BY desired.deletion_requested_at,desired.finalizer_present,target.wake_version",
    )
    .bind(tenant.to_string())
    .bind(&deletion_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        replay_after, replay_before,
        "replayed request must be zero-write"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_finalize_requires_terminal_evidence_and_commits_atomically() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &device).await?;
    // Migration-owner setup creates the already-deleting fixture. Runtime rss_app reaches this
    // state only through rss_request_device_certificate_deletion and has no raw desired-row DML.
    sqlx::query(
        "UPDATE device_certificate_desired_states \
         SET deletion_requested_at=pg_catalog.clock_timestamp() \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .execute(&store.pool)
    .await?;
    let serial = vec![0x19_u8, 0x01];
    let short_artifact_id = sqlx::query(
        "INSERT INTO device_certificate_authorized_artifacts \
         (tenant_id,device_id,generation,policy_hash,public_key_digest,expected_state_hash, \
          artifact_digest,artifact_id,serial,not_after,artifact_eligibility) \
         SELECT tenant_id,device_id,generation,policy_hash,$3::bytea,$4::bytea,$5::bytea, \
                'short',$6::bytea,pg_catalog.clock_timestamp()+interval '1 hour','production' \
         FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(vec![0x22_u8; 32])
    .bind(vec![0x33_u8; 32])
    .bind(vec![0x44_u8; 32])
    .bind(&serial)
    .execute(&store.pool)
    .await;
    assert!(
        short_artifact_id.is_err(),
        "artifact ids shorter than the generated command minimum fail closed"
    );
    sqlx::query(
        "INSERT INTO device_certificate_authorized_artifacts \
         (tenant_id,device_id,generation,policy_hash,public_key_digest,expected_state_hash, \
          artifact_digest,artifact_id,serial,not_after,artifact_eligibility) \
         SELECT tenant_id,device_id,generation,policy_hash,$3::bytea,$4::bytea,$5::bytea, \
                'artifact-delete-test',$6::bytea,pg_catalog.clock_timestamp()+interval '1 hour', \
                'production' \
         FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(vec![0x22_u8; 32])
    .bind(vec![0x33_u8; 32])
    .bind(vec![0x44_u8; 32])
    .bind(&serial)
    .execute(&store.pool)
    .await?;
    for (generation, artifact_id, serial, not_after) in [
        (
            20_i64,
            "artifact-expired-history",
            vec![0x19_u8, 0x02],
            "pg_catalog.clock_timestamp()-interval '1 microsecond'",
        ),
        (
            30_i64,
            "artifact-expiry-equality",
            vec![0x19_u8, 0x03],
            "pg_catalog.clock_timestamp()",
        ),
    ] {
        let statement = format!(
            "INSERT INTO device_certificate_authorized_artifacts \
             (tenant_id,device_id,generation,policy_hash,public_key_digest,expected_state_hash, \
              artifact_digest,artifact_id,serial,not_after,authorized_at,artifact_eligibility) \
             SELECT tenant_id,device_id,$3,policy_hash,$4::bytea,$5::bytea,$6::bytea, \
                    $7,$8::bytea,{not_after},pg_catalog.clock_timestamp()-interval '1 day', \
                    'production' \
             FROM device_certificate_desired_states \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid"
        );
        sqlx::query(&statement)
            .bind(tenant.to_string())
            .bind(&device)
            .bind(generation)
            .bind(vec![0x22_u8; 32])
            .bind(vec![generation as u8; 32])
            .bind(vec![0x44_u8; 32])
            .bind(artifact_id)
            .bind(serial)
            .execute(&store.pool)
            .await?;
    }

    let reconcile = store.reconcile();
    let key =
        ReconcileTargetKey::parse("identity.device-certificate", "device-certificate", &device)?;
    reconcile.upsert_target(tenant, &key).await?;
    let claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "delete-holder",
        reconcile_limit(1),
        Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or("delete target was not claimable")?;
    let attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &claim, "delete-holder").await? {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("delete attempt lost fresh lease".into()),
        };
    assert_eq!(
        ReconcileScheduleStore::complete_device_certificate_deletion(&reconcile, &attempt).await?,
        eventexec::reconcile::ScheduleCompletionOutcome::EvidencePending
    );
    let pending: (bool, String, String) = sqlx::query_as(
        "SELECT desired.finalizer_present,target.status,lease.state \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN reconcile_leases lease ON lease.tenant_id=target.tenant_id \
          AND lease.target_id=target.target_id \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(pending, (true, "active".to_owned(), "held".to_owned()));

    sqlx::query(
        "INSERT INTO certificate_revocations (tenant_id,device_id,serial,not_after) \
         VALUES ($1::uuid,$2::uuid,$3,pg_catalog.clock_timestamp()+interval '2 hours')",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(&serial)
    .execute(&store.pool)
    .await?;
    assert_eq!(
        ReconcileScheduleStore::complete_device_certificate_deletion(&reconcile, &attempt).await?,
        eventexec::reconcile::ScheduleCompletionOutcome::EvidencePending,
        "same serial with a different expiry is not terminal evidence"
    );
    sqlx::query(
        "DELETE FROM certificate_revocations \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND serial=$3",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(&serial)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO certificate_revocations (tenant_id,device_id,serial,not_after) \
         SELECT tenant_id,device_id,serial,not_after \
         FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND serial=$3",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(&serial)
    .execute(&store.pool)
    .await?;
    assert_eq!(
        ReconcileScheduleStore::complete_device_certificate_deletion(&reconcile, &attempt).await?,
        eventexec::reconcile::ScheduleCompletionOutcome::Completed
    );
    let history_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM device_certificate_authorized_artifacts \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        history_count, 3,
        "mixed revoked, expired, and expiry-equality history is retained"
    );
    let completed: (bool, String, String, String, String) = sqlx::query_as(
        "SELECT desired.finalizer_present,target.status,lease.state,condition.reason,result.result_label \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN reconcile_leases lease ON lease.tenant_id=target.tenant_id AND lease.target_id=target.target_id \
         JOIN device_certificate_conditions condition ON condition.tenant_id=desired.tenant_id \
          AND condition.device_id=desired.device_id AND condition.condition_type='Deleting' \
         JOIN reconcile_attempt_results result ON result.tenant_id=target.tenant_id \
          AND result.target_id=target.target_id \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        completed,
        (
            false,
            "disabled".to_owned(),
            "free".to_owned(),
            "DeletionComplete".to_owned(),
            "settled".to_owned()
        )
    );
    assert_eq!(
        ReconcileScheduleStore::complete_device_certificate_deletion(&reconcile, &attempt).await?,
        eventexec::reconcile::ScheduleCompletionOutcome::Lost
    );

    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_stores_for_test(&app, &app);
    let scope = DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&device)?);
    let failed_reaccept_snapshot: (i64, bool, bool, String, i64, String, String, i64) =
        sqlx::query_as(
            "SELECT desired.generation,desired.deletion_requested_at IS NOT NULL, \
                    desired.finalizer_present,target.status,target.wake_version, \
                    deleting.status,deleting.reason, \
                    (SELECT count(*)::bigint FROM device_certificate_policy_operations operation \
                     WHERE operation.tenant_id=desired.tenant_id \
                       AND operation.device_id=desired.device_id) \
             FROM device_certificate_desired_states desired \
             JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
              AND target.resource_id=desired.device_id::text \
             JOIN device_certificate_conditions deleting ON deleting.tenant_id=desired.tenant_id \
              AND deleting.device_id=desired.device_id AND deleting.condition_type='Deleting' \
             WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
    sqlx::query(
        "CREATE FUNCTION public._test_fail_certificate_reaccept() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           IF OLD.condition_type='Deleting' AND OLD.status='True' AND NEW.status='False' THEN \
             RAISE EXCEPTION 'injected certificate reaccept failure'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER _test_fail_certificate_reaccept \
         BEFORE UPDATE ON public.device_certificate_conditions \
         FOR EACH ROW EXECUTE FUNCTION public._test_fail_certificate_reaccept()",
    )
    .execute(&store.pool)
    .await?;
    let failed_policy = deviceloop::CertificatePolicy::restore(
        7_200,
        900,
        vec!["clientAuth".to_owned()],
        vec!["reactivated.example".to_owned()],
    )?;
    assert!(
        repository
            .accept_desired_policy(AcceptDesiredPolicy::for_test(
                scope,
                ExpectedGeneration::try_new(1)?,
                DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
                failed_policy,
            )?)
            .await
            .is_err(),
        "failure while clearing Deleting must roll back the entire reaccept transaction"
    );
    sqlx::query(
        "DROP TRIGGER _test_fail_certificate_reaccept \
         ON public.device_certificate_conditions",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query("DROP FUNCTION public._test_fail_certificate_reaccept()")
        .execute(&store.pool)
        .await?;
    let after_failed_reaccept: (i64, bool, bool, String, i64, String, String, i64) =
        sqlx::query_as(
            "SELECT desired.generation,desired.deletion_requested_at IS NOT NULL, \
                    desired.finalizer_present,target.status,target.wake_version, \
                    deleting.status,deleting.reason, \
                    (SELECT count(*)::bigint FROM device_certificate_policy_operations operation \
                     WHERE operation.tenant_id=desired.tenant_id \
                       AND operation.device_id=desired.device_id) \
             FROM device_certificate_desired_states desired \
             JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
              AND target.resource_id=desired.device_id::text \
             JOIN device_certificate_conditions deleting ON deleting.tenant_id=desired.tenant_id \
              AND deleting.device_id=desired.device_id AND deleting.condition_type='Deleting' \
             WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
        )
        .bind(tenant.to_string())
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        after_failed_reaccept, failed_reaccept_snapshot,
        "failed reaccept must preserve desired, finalizer, disabled target, wake, Deleting, and idempotency state"
    );
    let policy = deviceloop::CertificatePolicy::restore(
        7_200,
        900,
        vec!["clientAuth".to_owned()],
        vec!["reactivated.example".to_owned()],
    )?;
    assert!(matches!(
        repository
            .accept_desired_policy(AcceptDesiredPolicy::for_test(
                scope,
                ExpectedGeneration::try_new(1)?,
                DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
                policy,
            )?)
            .await?,
        DesiredPolicyAcceptOutcome::Accepted { .. }
    ));
    let reactivated: (
        i64,
        bool,
        bool,
        String,
        Option<String>,
        String,
        String,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT desired.generation, desired.deletion_requested_at IS NULL, \
                desired.finalizer_present, target.status, target.disabled_reason, \
                deleting.status,deleting.reason,deleting.observed_generation \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN device_certificate_conditions deleting ON deleting.tenant_id=desired.tenant_id \
          AND deleting.device_id=desired.device_id AND deleting.condition_type='Deleting' \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        reactivated,
        (
            2,
            true,
            true,
            "active".to_owned(),
            None,
            "False".to_owned(),
            "DeletionPending".to_owned(),
            Some(2),
        ),
        "reaccept must atomically reactivate the target and clear terminal Deleting"
    );

    let reconcile_repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let ready_attempt =
        claim_device_certificate_attempt(&store, tenant, &device, "reactivated-ready").await?;
    let ready_fence =
        CertificateAttemptFence::for_test(scope, &ready_attempt, ExpectedGeneration::try_new(2)?)?;
    let policy_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT policy_hash FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    let (append_authorization, receipt) = authorized_artifact(
        scope,
        2,
        &policy_hash,
        "artifact-reactivated-ready",
        vec![0x19, 0x22],
    )?;
    assert_eq!(
        reconcile_repository
            .append_artifact_receipt(&ready_fence, append_authorization)
            .await?,
        ArtifactAppendOutcome::Appended
    );
    let generation = Some(deviceloop::ObservedGeneration::try_new(2)?);
    assert_eq!(
        <crate::device_certificate::PgDeviceCertificateRepository<ProductionEligibility> as
            identity::ports::device_certificate::CertificateReconcileRepository<
                ProductionEligibility,
            >>::write_conditions(
                &reconcile_repository,
                &ready_fence,
                CertificateConditionMutation::States(ConditionStateBatch::for_test(vec![
                    deviceloop::DeviceConditionState::ready(
                        deviceloop::NotReadyStatus::False,
                        deviceloop::ReadyReason::AwaitingDevice,
                        generation,
                    ),
                    deviceloop::DeviceConditionState::reconciling(
                        deviceloop::ConditionStatus::True,
                        deviceloop::ReconcilingReason::CommandQueued,
                        generation,
                    ),
                    deviceloop::DeviceConditionState::pending_device(
                        deviceloop::ConditionStatus::True,
                        deviceloop::PendingDeviceReason::AwaitingDevice,
                        generation,
                    ),
                    deviceloop::DeviceConditionState::degraded(
                        deviceloop::ConditionStatus::False,
                        deviceloop::DegradedReason::ArtifactUnavailable,
                        generation,
                    ),
                    deviceloop::DeviceConditionState::quarantined(
                        deviceloop::ConditionStatus::False,
                        deviceloop::QuarantinedReason::ProtocolViolation,
                        generation,
                    ),
                    deviceloop::DeviceConditionState::deleting(
                        deviceloop::ConditionStatus::False,
                        deviceloop::DeletingReason::DeletionPending,
                        generation,
                    ),
                ])?),
            )
            .await?,
        FencedMutationOutcome::Applied
    );
    let command = reviewed_bound_certificate_command(
        &ready_attempt,
        2,
        &policy_hash,
        receipt.artifact_id().as_str(),
        receipt.artifact_digest().as_bytes(),
    )
    .await?;
    assert_eq!(
        ReconcileScheduleStore::record_fenced_command(
            &store.reconcile(),
            &ready_attempt,
            ConvergeAction::Update,
            command,
        )
        .await?,
        ScheduleActionOutcome::Enqueued
    );
    let command_id: String = sqlx::query_scalar(
        "SELECT command_id FROM device_commands \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=2",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='published',version=2, \
         published_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE device_commands SET state='received',version=3, \
         received_at=pg_catalog.transaction_timestamp() \
         WHERE tenant_id=$1::uuid AND command_id=$2",
    )
    .bind(tenant.to_string())
    .bind(&command_id)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO device_certificate_reported_states ( \
          tenant_id,device_id,observed_generation,fence_epoch,state_hash,artifact_digest, \
          report_envelope_id,device_sequence) \
         VALUES ($1::uuid,$2::uuid,2,$3,$4,$5,'reactivated-ready-report',2)",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .bind(i64::try_from(ready_attempt.target().epoch())?)
    .bind(receipt.expected_reported_state_hash().as_bytes().as_slice())
    .bind(receipt.artifact_digest().as_bytes().as_slice())
    .execute(&store.pool)
    .await?;
    let status_store = crate::device_certificate::PgDeviceCertificateStatusStore::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);
    let status = status_store
        .inspect(device_certificate_status_query(scope)?)
        .await?
        .ok_or("reactivated desired state was missing")?;
    let status_wire = serde_json::to_value(status.to_wire_response()?)?;
    assert_eq!(status_wire["data"]["desiredGeneration"], 2);
    assert_eq!(status_wire["data"]["observedGeneration"], 2);
    assert_eq!(status_wire["data"]["activeCommand"]["state"], "received");
    assert!(status.observation().is_ok());
    let ready_authority = CertificateAttemptAuthority::for_test(scope, &ready_attempt)?;
    let ready_view = reconcile_repository
        .load_current_view(&ready_authority)
        .await?
        .ok_or("reactivated command view was missing")?;
    let state = ready_view.state();
    let report = state
        .reported()
        .ok_or("reactivated reported state was missing")?;
    let evidence = reconcile_repository
        .load_current_command_evidence(&ready_fence)
        .await?
        .ok_or("reactivated command evidence was missing")?;
    let proof = CertificateReadyProof::restore_current(
        scope,
        state.desired(),
        &receipt,
        report,
        &evidence,
        std::time::UNIX_EPOCH + Duration::from_secs(2_000_000_000),
        CertificateRevocationObservation::Unrevoked,
    )?;
    assert_eq!(
        reconcile_repository
            .write_conditions(
                &ready_fence,
                CertificateConditionMutation::Ready(Box::new(proof)),
            )
            .await?,
        FencedMutationOutcome::Applied
    );
    let final_conditions: Vec<(String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        final_conditions,
        vec![
            (
                "Degraded".to_owned(),
                "False".to_owned(),
                "ArtifactUnavailable".to_owned(),
                Some(2)
            ),
            (
                "Deleting".to_owned(),
                "False".to_owned(),
                "DeletionPending".to_owned(),
                Some(2)
            ),
            (
                "PendingDevice".to_owned(),
                "False".to_owned(),
                "AwaitingDevice".to_owned(),
                Some(2)
            ),
            (
                "Quarantined".to_owned(),
                "False".to_owned(),
                "ProtocolViolation".to_owned(),
                Some(2)
            ),
            (
                "Ready".to_owned(),
                "True".to_owned(),
                "StateMatches".to_owned(),
                Some(2)
            ),
            (
                "Reconciling".to_owned(),
                "False".to_owned(),
                "DeviceReported".to_owned(),
                Some(2)
            ),
        ],
        "delete completion, reaccept, Issue, and Ready must converge one coherent condition set"
    );
    let final_view = reconcile_repository
        .load_current_view(&ready_authority)
        .await?
        .ok_or("reactivated Ready view was missing")?;
    assert!(final_view.state().conditions().iter().any(|condition| {
        condition.kind() == deviceloop::DeviceConditionKind::Ready
            && condition.status_label() == "True"
    }));
    assert!(final_view.state().conditions().iter().any(|condition| {
        condition.kind() == deviceloop::DeviceConditionKind::Deleting
            && condition.status_label() == "False"
    }));
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_finalize_loses_to_new_desired_and_lease_takeover() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let reconcile = store.reconcile();
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(&store);

    let new_desired_device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &new_desired_device).await?;
    // Administrative fixture setup; this is deliberately not executed through rss_app.
    sqlx::query(
        "UPDATE device_certificate_desired_states \
         SET deletion_requested_at=pg_catalog.clock_timestamp() \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&new_desired_device)
    .execute(&store.pool)
    .await?;
    let key = ReconcileTargetKey::parse(
        "identity.device-certificate",
        "device-certificate",
        &new_desired_device,
    )?;
    reconcile.upsert_target(tenant, &key).await?;
    let claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "new-desired-holder",
        reconcile_limit(1),
        Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or("new-desired target was not claimable")?;
    let stale_attempt =
        match ReconcileScheduleStore::append_attempt(&reconcile, &claim, "new-desired-holder")
            .await?
        {
            ScheduleAttemptOutcome::Started(attempt) => attempt,
            ScheduleAttemptOutcome::Lost => return Err("fresh new-desired lease was lost".into()),
        };
    let scope =
        DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&new_desired_device)?);
    let policy = deviceloop::CertificatePolicy::restore(
        7_200,
        900,
        vec!["clientAuth".to_owned()],
        vec!["new-desired.example".to_owned()],
    )?;
    assert!(matches!(
        repository
            .accept_desired_policy(AcceptDesiredPolicy::for_test(
                scope,
                ExpectedGeneration::try_new(1)?,
                DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
                policy,
            )?)
            .await?,
        DesiredPolicyAcceptOutcome::Accepted { .. }
    ));
    assert_eq!(
        ReconcileScheduleStore::complete_device_certificate_deletion(&reconcile, &stale_attempt,)
            .await?,
        eventexec::reconcile::ScheduleCompletionOutcome::Lost,
        "new desired generation and wake must fence the old completion"
    );
    let preserved: (
        i64,
        bool,
        bool,
        String,
        i64,
        i64,
        String,
        String,
        String,
        i64,
    ) = sqlx::query_as(
        "SELECT desired.generation, desired.deletion_requested_at IS NULL, \
                desired.finalizer_present, target.status, \
                (SELECT count(*)::bigint FROM reconcile_attempt_results result \
                 WHERE result.tenant_id=target.tenant_id AND result.target_id=target.target_id), \
                (SELECT count(*)::bigint FROM device_certificate_conditions condition \
                 WHERE condition.tenant_id=desired.tenant_id AND condition.device_id=desired.device_id \
                   AND condition.condition_type='Deleting'), \
                (SELECT condition.status FROM device_certificate_conditions condition \
                 WHERE condition.tenant_id=desired.tenant_id AND condition.device_id=desired.device_id \
                   AND condition.condition_type='Deleting'), \
                lease.state,lease.lease_token::text,lease.epoch \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN reconcile_leases lease ON lease.tenant_id=target.tenant_id \
          AND lease.target_id=target.target_id \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&new_desired_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        preserved,
        (
            2,
            true,
            true,
            "active".to_owned(),
            0,
            1,
            "False".to_owned(),
            "held".to_owned(),
            stale_attempt.target().lease_token().to_owned(),
            i64::try_from(stale_attempt.target().epoch())?,
        ),
        "new desired must make old completion zero-write across all five durable components"
    );

    let takeover_device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(&store, tenant, &takeover_device).await?;
    // Administrative fixture setup; production desired mutation remains funnel-only.
    sqlx::query(
        "UPDATE device_certificate_desired_states \
         SET deletion_requested_at=pg_catalog.clock_timestamp() \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&takeover_device)
    .execute(&store.pool)
    .await?;
    let key = ReconcileTargetKey::parse(
        "identity.device-certificate",
        "device-certificate",
        &takeover_device,
    )?;
    let target = reconcile.upsert_target(tenant, &key).await?;
    let claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        "takeover-holder",
        reconcile_limit(1),
        Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or("takeover target was not claimable")?;
    let takeover_attempt = match ReconcileScheduleStore::append_attempt(
        &reconcile,
        &claim,
        "takeover-holder",
    )
    .await?
    {
        ScheduleAttemptOutcome::Started(attempt) => attempt,
        ScheduleAttemptOutcome::Lost => return Err("fresh takeover lease was lost".into()),
    };
    sqlx::query(
        "UPDATE reconcile_leases SET lease_token=gen_random_uuid(), epoch=epoch+1 \
         WHERE tenant_id=$1::uuid AND target_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&store.pool)
    .await?;
    assert_eq!(
        ReconcileScheduleStore::complete_device_certificate_deletion(
            &reconcile,
            &takeover_attempt,
        )
        .await?,
        eventexec::reconcile::ScheduleCompletionOutcome::Lost,
        "lease takeover must make the old completion zero-write"
    );
    let takeover_preserved: (bool, bool, String, i64, i64, String, String, i64) = sqlx::query_as(
        "SELECT desired.deletion_requested_at IS NOT NULL,desired.finalizer_present,target.status, \
                (SELECT count(*)::bigint FROM reconcile_attempt_results result \
                 WHERE result.tenant_id=target.tenant_id AND result.target_id=target.target_id), \
                (SELECT count(*)::bigint FROM device_certificate_conditions condition \
                 WHERE condition.tenant_id=desired.tenant_id AND condition.device_id=desired.device_id \
                   AND condition.condition_type='Deleting'), \
                lease.state,lease.lease_token::text,lease.epoch \
         FROM device_certificate_desired_states desired \
         JOIN reconcile_targets target ON target.tenant_id=desired.tenant_id \
          AND target.resource_id=desired.device_id::text \
         JOIN reconcile_leases lease ON lease.tenant_id=target.tenant_id \
          AND lease.target_id=target.target_id \
         WHERE desired.tenant_id=$1::uuid AND desired.device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&takeover_device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        (
            takeover_preserved.0,
            takeover_preserved.1,
            &takeover_preserved.2,
            takeover_preserved.3,
            takeover_preserved.4,
            &takeover_preserved.5,
            takeover_preserved.7,
        ),
        (
            true,
            true,
            &"active".to_owned(),
            0,
            0,
            &"held".to_owned(),
            i64::try_from(takeover_attempt.target().epoch())? + 1
        ),
        "lease takeover must preserve desired, condition, target, result, and held lease state"
    );
    assert_ne!(
        takeover_preserved.6,
        takeover_attempt.target().lease_token(),
        "takeover fixture must actually replace the token"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_schema_rls_and_acl_are_closed() -> TestResult {
    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tables: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity \
         FROM pg_catalog.pg_class AS c \
         JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' \
           AND c.relname IN ( \
             'device_certificate_desired_states', \
             'device_certificate_reported_states', \
             'device_certificate_conditions', \
             'device_certificate_policy_operations', \
             'device_certificate_authorized_artifacts' \
           ) \
         ORDER BY c.relname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        tables,
        vec![
            (
                "device_certificate_authorized_artifacts".to_owned(),
                true,
                true,
            ),
            ("device_certificate_conditions".to_owned(), true, true),
            ("device_certificate_desired_states".to_owned(), true, true),
            (
                "device_certificate_policy_operations".to_owned(),
                true,
                true,
            ),
            ("device_certificate_reported_states".to_owned(), true, true),
        ],
        "all device-certificate state tables must exist with ENABLE+FORCE RLS"
    );

    let policies: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT tablename, qual, with_check \
         FROM pg_catalog.pg_policies \
         WHERE schemaname = 'public' \
           AND tablename IN ( \
             'device_certificate_desired_states', \
             'device_certificate_reported_states', \
             'device_certificate_conditions', \
             'device_certificate_policy_operations', \
             'device_certificate_authorized_artifacts' \
           ) \
           AND policyname = 'tenant_isolation' \
         ORDER BY tablename",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        policies.len(),
        5,
        "each tenant relation needs one canonical policy"
    );
    for (table, using, with_check) in policies {
        for clause in [using, with_check] {
            let clause = clause.ok_or_else(|| {
                std::io::Error::other(format!("{table} tenant policy is incomplete"))
            })?;
            assert!(
                clause.contains("NULLIF(current_setting('rss.tenant_id'::text, true), ''::text)"),
                "{table} must fail closed through the canonical tenant GUC: {clause}"
            );
        }
    }

    let desired_columns: Vec<String> = sqlx::query_scalar(
        "SELECT a.attname FROM pg_catalog.pg_attribute AS a \
         WHERE a.attrelid = 'public.device_certificate_desired_states'::regclass \
           AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        desired_columns,
        vec![
            "tenant_id",
            "device_id",
            "generation",
            "policy_hash",
            "validity_seconds",
            "renew_before_seconds",
            "client_auth",
            "server_auth",
            "sans",
            "created_at",
            "updated_at",
            "deletion_requested_at",
            "finalizer_present",
        ],
        "desired state must not persist a fence epoch or open-text key usages"
    );

    let privileges: Vec<(String, bool, bool, bool, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT table_name, \
                has_table_privilege('rss_app', format('public.%I', table_name), 'SELECT'), \
                has_table_privilege('rss_app', format('public.%I', table_name), 'INSERT'), \
                has_table_privilege('rss_app', format('public.%I', table_name), 'UPDATE'), \
                has_table_privilege('rss_app', format('public.%I', table_name), 'DELETE'), \
                has_table_privilege('rss_app_read', format('public.%I', table_name), 'SELECT'), \
                has_table_privilege('rss_app_read', format('public.%I', table_name), 'INSERT'), \
                has_table_privilege('rss_app_read', format('public.%I', table_name), 'UPDATE') \
         FROM unnest(ARRAY[ \
             'device_certificate_desired_states', \
             'device_certificate_reported_states', \
             'device_certificate_conditions', \
             'device_certificate_policy_operations', \
             'device_certificate_authorized_artifacts' \
         ]) AS table_name \
         ORDER BY table_name",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(privileges.len(), 5);
    for (
        table,
        writer_select,
        writer_insert,
        writer_update,
        writer_delete,
        reader_select,
        reader_insert,
        reader_update,
    ) in privileges
    {
        assert!(writer_select, "rss_app must read {table}");
        assert!(
            !writer_insert && !writer_update,
            "rss_app must have column-level mutations only on {table}"
        );
        assert!(!writer_delete, "rss_app must not DELETE {table}");
        assert!(reader_select, "rss_app_read must read {table}");
        assert!(
            !reader_insert && !reader_update,
            "rss_app_read must be read-only on {table}"
        );
    }

    let writer_columns: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname, a.attname, \
                has_column_privilege('rss_app', c.oid, a.attnum, 'INSERT'), \
                has_column_privilege('rss_app', c.oid, a.attnum, 'UPDATE') \
         FROM pg_catalog.pg_class AS c \
         JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
         JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid \
         WHERE n.nspname = 'public' \
           AND c.relname IN ('device_certificate_desired_states', \
                             'device_certificate_reported_states', \
                             'device_certificate_conditions', \
                             'device_certificate_policy_operations', \
                             'device_certificate_authorized_artifacts') \
           AND a.attnum > 0 AND NOT a.attisdropped \
         ORDER BY c.relname, a.attnum",
    )
    .fetch_all(&store.pool)
    .await?;
    for (table, column, can_insert, can_update) in writer_columns {
        let expected_insert = match table.as_str() {
            "device_certificate_desired_states" => false,
            "device_certificate_reported_states" => false,
            "device_certificate_conditions" => false,
            "device_certificate_policy_operations" => false,
            "device_certificate_authorized_artifacts" => false,
            _ => false,
        };
        let expected_update = match table.as_str() {
            "device_certificate_desired_states" => false,
            "device_certificate_reported_states" => false,
            "device_certificate_conditions" => false,
            "device_certificate_policy_operations" => false,
            "device_certificate_authorized_artifacts" => false,
            _ => false,
        };
        assert_eq!(
            can_insert, expected_insert,
            "unexpected INSERT ACL on {table}.{column}"
        );
        assert_eq!(
            can_update, expected_update,
            "unexpected UPDATE ACL on {table}.{column}"
        );
    }

    let closed_constraints: String = sqlx::query_scalar(
        "SELECT string_agg(pg_catalog.pg_get_constraintdef(oid), E'\\n' ORDER BY conname) \
         FROM pg_catalog.pg_constraint \
         WHERE conrelid IN ( \
             'device_certificate_desired_states'::regclass, \
             'device_certificate_reported_states'::regclass, \
             'device_certificate_conditions'::regclass, \
             'device_certificate_policy_operations'::regclass, \
             'device_certificate_authorized_artifacts'::regclass \
         )",
    )
    .fetch_one(&store.pool)
    .await?;
    for invariant in [
        "generation > 0",
        "observed_generation > 0",
        "renew_before_seconds < validity_seconds",
        "client_auth OR server_auth",
        "octet_length(policy_hash) = 32",
        "octet_length(state_hash) = 32",
        "octet_length(artifact_digest) = 32",
        "octet_length(request_digest) = 32",
        "accepted_condition = 'reconciling'",
        "condition_type",
        "Ready",
        "QuarantinedByOperator",
    ] {
        assert!(
            closed_constraints.contains(invariant),
            "missing device-certificate DB invariant `{invariant}` in:\n{closed_constraints}"
        );
    }

    let legacy_observed_condition_funnel: Option<String> = sqlx::query_scalar(
        "SELECT pg_catalog.to_regprocedure( \
         'public.rss_write_device_certificate_observed_condition(uuid,uuid,text,text,text,bigint)' \
         )::text",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        legacy_observed_condition_funnel, None,
        "hard cut must remove the legacy observed-condition authoring function from pg_proc"
    );

    let functions: Vec<(String, String, bool, bool, bool, Vec<String>, String)> = sqlx::query_as(
        "SELECT p.proname, owner.rolname, p.prosecdef, \
                has_function_privilege('rss_app', p.oid, 'EXECUTE'), \
                has_function_privilege('rss_app_read', p.oid, 'EXECUTE'), p.proconfig, \
                pg_catalog.pg_get_function_identity_arguments(p.oid) \
         FROM pg_catalog.pg_proc AS p \
         JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace \
         JOIN pg_catalog.pg_roles AS owner ON owner.oid=p.proowner \
         WHERE n.nspname = 'public' AND p.proname IN ( \
           'rss_append_device_certificate_artifact_core', \
           'rss_append_device_certificate_artifact_draft', \
           'rss_append_device_certificate_artifact_production', \
           'rss_enroll_device_certificate_reconcile_target', \
           'rss_lock_device_certificate_reconcile_view', \
           'rss_write_device_certificate_conditions', \
           'rss_accept_device_certificate_desired', \
           'rss_mark_device_certificate_ready', \
           'rss_rotate_device_certificate_generation', \
           'rss_request_device_certificate_deletion', \
           'rss_complete_device_certificate_deletion') \
         ORDER BY p.proname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(functions.len(), 11);
    for (function, owner, security_definer, writer_execute, reader_execute, config, arguments) in
        functions
    {
        assert_eq!(owner, "rss_device_certificate_funnel_owner");
        assert!(security_definer, "{function} must be SECURITY DEFINER");
        assert_eq!(config, vec!["search_path=pg_catalog, pg_temp"]);
        let writer_expected = !matches!(
            function.as_str(),
            "rss_append_device_certificate_artifact_core"
                | "rss_append_device_certificate_artifact_production"
        );
        assert_eq!(
            writer_execute, writer_expected,
            "{function} writer EXECUTE ACL"
        );
        assert!(!reader_execute, "{function} reader EXECUTE ACL");
        if function == "rss_write_device_certificate_conditions" {
            for array_argument in [
                "p_condition_types text[]",
                "p_statuses text[]",
                "p_reasons text[]",
                "p_observed_generations bigint[]",
            ] {
                assert!(
                    arguments.contains(array_argument),
                    "ordinary condition funnel must expose the sealed batch signature: {arguments}"
                );
            }
        }
    }

    let tenant = uuid::Uuid::new_v4().to_string();
    let other_tenant = uuid::Uuid::new_v4().to_string();
    let device = uuid::Uuid::new_v4().to_string();
    let other_device = uuid::Uuid::new_v4().to_string();
    let sans = vec![
        "device.example".to_owned(),
        "spiffe://rss/device".to_owned(),
    ];
    insert_device_certificate_desired(&store, &other_tenant, &other_device, true, true, &sans)
        .await?;
    insert_device_certificate_desired(&store, &tenant, &device, true, true, &sans).await?;
    store
        .reconcile()
        .upsert_target(
            vocab::TenantId::parse(&tenant)?,
            &ReconcileTargetKey::parse(
                "identity.device-certificate",
                "device-certificate",
                &device,
            )?,
        )
        .await?;

    let app = connect_pg_rss_app_role(&pg, &store).await?;
    let production_mint = sqlx::query_scalar::<_, String>(
        "SELECT public.rss_append_device_certificate_artifact_production( \
         NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid, \
         NULL::bigint,NULL::bigint,NULL::bigint,NULL::bytea, \
         NULL::bytea,NULL::bytea,NULL::bytea,NULL::text,NULL::bytea,NULL::bigint)",
    )
    .fetch_one(&app.pool)
    .await
    .expect_err("rss_app must not execute the production artifact mint wrapper");
    assert_eq!(
        production_mint
            .as_database_error()
            .and_then(|database| database.code())
            .map(|code| code.into_owned()),
        Some("42501".to_owned()),
        "production artifact mint must fail at the database privilege boundary"
    );
    let mut removed_api = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *removed_api)
        .await?;
    let legacy_call = sqlx::query_scalar::<_, bool>(
        "SELECT public.rss_write_device_certificate_observed_condition( \
         $1::uuid,$2::uuid,$3::text,$4::text,$5::text,$6::bigint)",
    )
    .bind(&tenant)
    .bind(&device)
    .bind("Ready")
    .bind("True")
    .bind("StateMatches")
    .bind(1_i64)
    .fetch_one(&mut *removed_api)
    .await
    .expect_err("rss_app must not resolve the removed observed-condition authoring API");
    assert_eq!(
        legacy_call
            .as_database_error()
            .and_then(|database| database.code())
            .map(|code| code.into_owned()),
        Some("42883".to_owned()),
        "the legacy API must be absent, not merely ACL-hidden"
    );
    removed_api.rollback().await?;
    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *tx)
        .await?;
    let row: (Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT policy_hash, \
             (extract(epoch FROM created_at) * 1000000)::bigint, \
             (extract(epoch FROM updated_at) * 1000000)::bigint \
         FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(
        row.0,
        device_certificate_policy_hash(3600, 600, true, true, &sans)
    );
    assert_eq!(row.1, row.2);
    let visible: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM device_certificate_desired_states")
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(visible, 1, "RLS must hide the other tenant");
    tx.commit().await?;

    let mut direct_artifact = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *direct_artifact)
        .await?;
    let denied_artifact = sqlx::query(
        "INSERT INTO device_certificate_authorized_artifacts ( \
           tenant_id,device_id,generation,policy_hash,public_key_digest,expected_state_hash, \
           artifact_digest,artifact_id,serial,not_after) \
         SELECT tenant_id,device_id,generation,policy_hash,$3,$4,$5, \
                'direct-artifact-denied',$6,pg_catalog.clock_timestamp()+interval '1 hour' \
         FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .bind(vec![0x11_u8; 32])
    .bind(vec![0x12_u8; 32])
    .bind(vec![0x13_u8; 32])
    .bind(vec![0x14_u8])
    .execute(&mut *direct_artifact)
    .await;
    assert!(
        denied_artifact.is_err(),
        "rss_app cannot bypass artifact funnel"
    );
    direct_artifact.rollback().await?;

    let mut direct_condition = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *direct_condition)
        .await?;
    let denied_condition = sqlx::query(
        "INSERT INTO device_certificate_conditions ( \
           tenant_id,device_id,condition_type,status,reason,observed_generation) \
         VALUES ($1::uuid,$2::uuid,'Ready','True','StateMatches',1)",
    )
    .bind(&tenant)
    .bind(&device)
    .execute(&mut *direct_condition)
    .await;
    assert!(
        denied_condition.is_err(),
        "rss_app cannot author Ready directly"
    );
    direct_condition.rollback().await?;

    let mut direct_deletion = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *direct_deletion)
        .await?;
    let denied_deletion = sqlx::query(
        "UPDATE device_certificate_desired_states \
         SET deletion_requested_at=pg_catalog.clock_timestamp() \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .execute(&mut *direct_deletion)
    .await;
    assert!(
        denied_deletion.is_err(),
        "rss_app cannot bypass deletion-request fence"
    );
    direct_deletion.rollback().await?;

    for (label, mutation) in [
        (
            "generation",
            "UPDATE device_certificate_desired_states SET generation=2 \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
        ),
        (
            "policy",
            "UPDATE device_certificate_desired_states SET validity_seconds=7200 \
             WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
        ),
    ] {
        let mut direct_desired = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant)
            .execute(&mut *direct_desired)
            .await?;
        let denied = sqlx::query(mutation)
            .bind(&tenant)
            .bind(&device)
            .execute(&mut *direct_desired)
            .await;
        assert!(denied.is_err(), "rss_app cannot author raw desired {label}");
        direct_desired.rollback().await?;
    }

    let mut denied = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *denied)
        .await?;
    let explicit_server_state = sqlx::query(
        "INSERT INTO device_certificate_desired_states ( \
             tenant_id, device_id, generation, policy_hash, validity_seconds, \
             renew_before_seconds, client_auth, server_auth, sans, created_at, updated_at \
         ) VALUES ($1::uuid, gen_random_uuid(), 1, $2, 3600, 600, true, true, $3, now(), now())",
    )
    .bind(&tenant)
    .bind(vec![0_u8; 32])
    .bind(&sans)
    .execute(&mut *denied)
    .await;
    assert!(
        explicit_server_state.is_err(),
        "rss_app must not write policy hash or timestamps"
    );
    denied.rollback().await?;

    let app_repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_stores_for_test(&app, &app);
    let app_scope = DeviceCertificateScope::for_test(
        vocab::TenantId::parse(&tenant)?,
        ids::DeviceId::parse(&device)?,
    );
    let accepted_policy = deviceloop::CertificatePolicy::restore(
        7_200,
        900,
        vec!["clientAuth".to_owned()],
        vec!["accepted-active.example".to_owned()],
    )?;
    assert!(matches!(
        app_repository
            .accept_desired_policy(AcceptDesiredPolicy::for_test(
                app_scope,
                ExpectedGeneration::try_new(1)?,
                DevicePolicyIdempotencyKey::new(uuid::Uuid::new_v4()),
                accepted_policy,
            )?)
            .await?,
        DesiredPolicyAcceptOutcome::Accepted { .. }
    ));
    let mut accepted_tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(&tenant)
        .execute(&mut *accepted_tx)
        .await?;
    let accepted_generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&mut *accepted_tx)
    .await?;
    assert_eq!(accepted_generation, 2);
    accepted_tx.commit().await?;

    let without_tenant: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM device_certificate_desired_states")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(without_tenant, 0, "missing tenant context must fail closed");

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_database_guards_reject_regression_and_open_conditions() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = uuid::Uuid::new_v4().to_string();
    let device = uuid::Uuid::new_v4().to_string();
    let sans = vec![
        "device.example".to_owned(),
        "spiffe://rss/device".to_owned(),
    ];

    insert_device_certificate_desired(&store, &tenant, &device, true, true, &sans).await?;
    let target_id: String = sqlx::query_scalar(
        "INSERT INTO reconcile_targets \
         (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'identity.device-certificate', 'device-certificate', $2) \
         RETURNING target_id::text",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO reconcile_leases (tenant_id, target_id, epoch) \
         VALUES ($1::uuid, $2::uuid, 7)",
    )
    .bind(&tenant)
    .bind(&target_id)
    .execute(&store.pool)
    .await?;
    let initial: (i64, Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT generation, policy_hash, \
                (extract(epoch FROM created_at) * 1000000)::bigint, \
                (extract(epoch FROM updated_at) * 1000000)::bigint \
         FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        initial.1,
        device_certificate_policy_hash(3600, 600, true, true, &sans)
    );
    assert_eq!(initial.2, initial.3);

    for (case, client_auth, server_auth, policy_sans) in [
        ("client auth", true, false, Vec::<String>::new()),
        (
            "server auth",
            false,
            true,
            vec!["server.example".to_owned()],
        ),
        (
            "both usages and sorted SANs",
            true,
            true,
            vec![
                "device.example".to_owned(),
                "spiffe://rss/device".to_owned(),
            ],
        ),
    ] {
        let policy_device = uuid::Uuid::new_v4().to_string();
        insert_device_certificate_desired(
            &store,
            &tenant,
            &policy_device,
            client_auth,
            server_auth,
            &policy_sans,
        )
        .await?;
        let stored_hash: Vec<u8> = sqlx::query_scalar(
            "SELECT policy_hash FROM device_certificate_desired_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&policy_device)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            stored_hash,
            device_certificate_policy_hash(3600, 600, client_auth, server_auth, &policy_sans,),
            "database and production domain canonical encoders diverged for {case}"
        );
    }

    let generation_gap = sqlx::query(
        "UPDATE device_certificate_desired_states SET generation = 3 \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .execute(&store.pool)
    .await;
    assert!(
        generation_gap.is_err(),
        "desired generation must advance exactly once"
    );
    let after_gap: (i64, Vec<u8>, i64) = sqlx::query_as(
        "SELECT generation, policy_hash, \
                (extract(epoch FROM updated_at) * 1000000)::bigint \
         FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(after_gap, (initial.0, initial.1.clone(), initial.3));

    let invalid_policies = vec![
        ("empty usages", false, false, Vec::<String>::new()),
        ("empty SAN", true, false, vec![String::new()]),
        ("untrimmed SAN", true, false, vec![" device".to_owned()]),
        (
            "unicode untrimmed SAN",
            true,
            false,
            vec!["device\u{00a0}".to_owned()],
        ),
        (
            "control SAN",
            true,
            false,
            vec!["device\u{0085}".to_owned()],
        ),
        (
            "SAN order",
            true,
            false,
            vec!["z.example".to_owned(), "a.example".to_owned()],
        ),
        (
            "duplicate SAN",
            true,
            false,
            vec!["a.example".to_owned(), "a.example".to_owned()],
        ),
        ("long SAN", true, false, vec!["a".repeat(254)]),
        (
            "too many SANs",
            true,
            false,
            (0..33).map(|index| format!("{index:02}.example")).collect(),
        ),
    ];
    for (case, client_auth, server_auth, invalid_sans) in invalid_policies {
        let invalid_device = uuid::Uuid::new_v4().to_string();
        let result = insert_device_certificate_desired(
            &store,
            &tenant,
            &invalid_device,
            client_auth,
            server_auth,
            &invalid_sans,
        )
        .await;
        assert!(result.is_err(), "{case} must fail closed");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM device_certificate_desired_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&invalid_device)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(count, 0, "rejected {case} must be zero-write");
    }

    let changed_sans = vec!["new.example".to_owned()];
    sqlx::query(
        "UPDATE device_certificate_desired_states \
         SET generation = 2, sans = $3 \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .bind(&changed_sans)
    .execute(&store.pool)
    .await?;
    let changed_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT policy_hash FROM device_certificate_desired_states \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        changed_hash,
        device_certificate_policy_hash(3600, 600, true, true, &changed_sans),
        "database trigger must be the unique canonical policy-hash writer"
    );

    sqlx::query(
        "INSERT INTO device_certificate_reported_states ( \
             tenant_id, device_id, observed_generation, fence_epoch, state_hash, \
             artifact_digest, report_envelope_id, device_sequence \
         ) VALUES ($1::uuid, $2::uuid, 2, 7, $3, $4, 'report-2', 2)",
    )
    .bind(&tenant)
    .bind(&device)
    .bind(vec![0x32_u8; 32])
    .bind(vec![0x42_u8; 32])
    .execute(&store.pool)
    .await?;
    let reported_before: (i64, i64, Vec<u8>, Vec<u8>, String, i64, i64) = sqlx::query_as(
        "SELECT observed_generation, fence_epoch, state_hash, artifact_digest, \
                    report_envelope_id, device_sequence, \
                    (extract(epoch from received_at) * 1000000)::bigint \
             FROM device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;

    let duplicate = sqlx::query(
        "UPDATE device_certificate_reported_states \
         SET observed_generation = 2, fence_epoch = 7, state_hash = $3, \
             artifact_digest = $4, report_envelope_id = 'report-2', device_sequence = 2 \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&device)
    .bind(vec![0x32_u8; 32])
    .bind(vec![0x42_u8; 32])
    .execute(&store.pool)
    .await?;
    assert_eq!(
        duplicate.rows_affected(),
        0,
        "exact duplicate reports must be no-op"
    );

    for (case, state_hash, artifact_digest, envelope) in [
        (
            "state hash conflict",
            vec![0x33_u8; 32],
            vec![0x42_u8; 32],
            "report-2",
        ),
        (
            "artifact digest conflict",
            vec![0x32_u8; 32],
            vec![0x43_u8; 32],
            "report-2",
        ),
        (
            "envelope conflict",
            vec![0x32_u8; 32],
            vec![0x42_u8; 32],
            "report-conflict",
        ),
    ] {
        let rejected = sqlx::query(
            "UPDATE device_certificate_reported_states \
             SET observed_generation = 2, state_hash = $3, artifact_digest = $4, \
                 report_envelope_id = $5, device_sequence = 2 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&device)
        .bind(state_hash)
        .bind(artifact_digest)
        .bind(envelope)
        .execute(&store.pool)
        .await;
        assert!(rejected.is_err(), "{case} must fail closed");
        let reported_after: (i64, i64, Vec<u8>, Vec<u8>, String, i64, i64) = sqlx::query_as(
            "SELECT observed_generation, fence_epoch, state_hash, artifact_digest, \
                    report_envelope_id, device_sequence, \
                    (extract(epoch from received_at) * 1000000)::bigint \
             FROM device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            reported_after, reported_before,
            "rejected {case} must preserve the complete reported row"
        );
    }

    for (case, observed, sequence, envelope) in [
        ("generation regression", 1_i64, 3_i64, "report-stale"),
        ("ahead of desired", 3_i64, 3_i64, "report-ahead"),
    ] {
        let rejected = sqlx::query(
            "UPDATE device_certificate_reported_states \
             SET observed_generation = $3, state_hash = $4, artifact_digest = $5, \
                 report_envelope_id = $6, device_sequence = $7 \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&device)
        .bind(observed)
        .bind(vec![0x33_u8; 32])
        .bind(vec![0x43_u8; 32])
        .bind(envelope)
        .bind(sequence)
        .execute(&store.pool)
        .await;
        assert!(rejected.is_err(), "{case} must fail closed");
        let reported_after: (i64, i64, Vec<u8>, Vec<u8>, String, i64, i64) = sqlx::query_as(
            "SELECT observed_generation, fence_epoch, state_hash, artifact_digest, \
                        report_envelope_id, device_sequence, \
                        (extract(epoch from received_at) * 1000000)::bigint \
                 FROM device_certificate_reported_states \
                 WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&device)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            reported_after, reported_before,
            "rejected {case} must be zero-write"
        );
    }

    for (case, epoch, envelope, sequence) in [
        ("non-positive epoch", 0_i64, "report-epoch", 3_i64),
        ("untrimmed envelope", 8_i64, " report", 3_i64),
        (
            "non-breaking-space envelope",
            8_i64,
            "report\u{00a0}",
            3_i64,
        ),
        ("unicode-space envelope", 8_i64, "\u{2000}report", 3_i64),
        ("C0 control envelope", 8_i64, "report\n", 3_i64),
        ("C1 control envelope", 8_i64, "report\u{0085}id", 3_i64),
        ("negative sequence", 8_i64, "report-sequence", -1_i64),
    ] {
        let invalid_device = uuid::Uuid::new_v4().to_string();
        insert_device_certificate_desired(&store, &tenant, &invalid_device, true, false, &[])
            .await?;
        let rejected = sqlx::query(
            "INSERT INTO device_certificate_reported_states ( \
                 tenant_id, device_id, observed_generation, fence_epoch, state_hash, \
                 artifact_digest, report_envelope_id, device_sequence \
             ) VALUES ($1::uuid, $2::uuid, 1, $3, $4, $5, $6, $7)",
        )
        .bind(&tenant)
        .bind(&invalid_device)
        .bind(epoch)
        .bind(vec![0x51_u8; 32])
        .bind(vec![0x61_u8; 32])
        .bind(envelope)
        .bind(sequence)
        .execute(&store.pool)
        .await;
        assert!(rejected.is_err(), "{case} must fail closed");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM device_certificate_reported_states \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
        )
        .bind(&tenant)
        .bind(&invalid_device)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(count, 0, "rejected {case} must be zero-write");
    }

    sqlx::query(
        "INSERT INTO device_certificate_conditions ( \
             tenant_id, device_id, condition_type, status, reason, observed_generation \
         ) VALUES ($1::uuid, $2::uuid, 'Reconciling', 'True', 'DeviceReported', 2)",
    )
    .bind(&tenant)
    .bind(&device)
    .execute(&store.pool)
    .await?;
    let transition_before: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM last_transition_at) * 1000000)::bigint \
         FROM device_certificate_conditions \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
           AND condition_type = 'Reconciling'",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    let duplicate_condition = sqlx::query(
        "UPDATE device_certificate_conditions \
         SET status = 'True', reason = 'DeviceReported', observed_generation = 2 \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
           AND condition_type = 'Reconciling'",
    )
    .bind(&tenant)
    .bind(&device)
    .execute(&store.pool)
    .await?;
    assert_eq!(duplicate_condition.rows_affected(), 0);
    let transition_after: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM last_transition_at) * 1000000)::bigint \
         FROM device_certificate_conditions \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
           AND condition_type = 'Reconciling'",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        transition_after, transition_before,
        "duplicate condition must preserve transition time"
    );

    for (condition_type, status, reason, observed_generation) in [
        ("Ready", "False", "QuarantinedByOperator", Some(2_i64)),
        ("Ready", "True", "AwaitingDevice", Some(2_i64)),
        ("Ready", "True", "StateMatches", None),
        ("Ready", "False", "StateMatches", Some(2_i64)),
        ("FutureCondition", "Unknown", "AwaitingDevice", Some(2_i64)),
    ] {
        let invalid = sqlx::query(
            "INSERT INTO device_certificate_conditions ( \
                 tenant_id, device_id, condition_type, status, reason, observed_generation \
             ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)",
        )
        .bind(&tenant)
        .bind(&device)
        .bind(condition_type)
        .bind(status)
        .bind(reason)
        .bind(observed_generation)
        .execute(&store.pool)
        .await;
        assert!(
            invalid.is_err(),
            "invalid condition tuple {condition_type}/{status}/{reason} must fail closed"
        );
    }

    let ahead = sqlx::query(
        "INSERT INTO device_certificate_conditions ( \
             tenant_id, device_id, condition_type, status, reason, observed_generation \
         ) VALUES ($1::uuid, $2::uuid, 'PendingDevice', 'True', 'AwaitingDevice', 3)",
    )
    .bind(&tenant)
    .bind(&device)
    .execute(&store.pool)
    .await;
    assert!(
        ahead.is_err(),
        "condition observation must not exceed desired generation"
    );
    let ahead_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM device_certificate_conditions \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
           AND condition_type = 'PendingDevice'",
    )
    .bind(&tenant)
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(ahead_count, 0, "rejected condition must be zero-write");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn device_certificate_revocation_schema_has_one_non_vacuous_authority() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let authorities: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_catalog.pg_class AS c \
         JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace \
         WHERE n.nspname='public' AND c.relkind IN ('r','p') \
           AND c.relname LIKE '%certificate%revocation%' \
         ORDER BY c.relname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        authorities,
        vec!["certificate_revocations"],
        "the schema inventory must identify exactly one durable revocation authority"
    );
    store.shutdown().await?;
    Ok(())
}

// Real PostgreSQL / reconcile-worker join hazards for device-certificate seams.
//
// These T2 proofs own cross-worker and crash-boundary joins that Hard lease/epoch/artifact
// fences cannot statically close. Helpers stay private to this module.
//
// ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main

const RECONCILER_ID: &str = "identity.device-certificate";
const RESOURCE_KIND: &str = "device-certificate";
const GATE_BUDGET: Duration = Duration::from_secs(10);
const WORKER_BUDGET: Duration = Duration::from_secs(15);
const POLL_BUDGET: Duration = Duration::from_secs(10);
/// Worker lease TTL must dwarf GATE/POLL/WORKER budgets so a natural renew tick
/// (`lease_ttl / 3`) cannot race the SQL expiry → new-holder claim window.
const WORKER_LEASE_TTL: Duration = Duration::from_secs(300);

/// Stateful one-shot pause gate with loss-proof release and entered/released anti-vacuity.
///
/// `released` means the releaser has already stored the release bit (not merely that a waiter
/// woke). Waiters always check state → subscribe → re-check before awaiting, so a release that
/// lands before `notified()` is registered still unblocks.
struct PauseGate {
    entered: AtomicBool,
    released: AtomicBool,
    entered_notify: Notify,
    release_notify: Notify,
}

impl PauseGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: AtomicBool::new(false),
            entered_notify: Notify::new(),
            release_notify: Notify::new(),
        })
    }

    fn entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    fn released(&self) -> bool {
        self.released.load(Ordering::SeqCst)
    }

    async fn wait_entered(&self) -> TestResult {
        loop {
            if self.entered() {
                return Ok(());
            }
            let notified = self.entered_notify.notified();
            if self.entered() {
                return Ok(());
            }
            tokio::time::timeout(GATE_BUDGET, notified)
                .await
                .map_err(|_| "pause gate did not enter within budget")?;
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release_notify.notify_waiters();
    }

    async fn pause_until_released(&self) {
        self.entered.store(true, Ordering::SeqCst);
        self.entered_notify.notify_waiters();
        loop {
            if self.released() {
                return;
            }
            let notified = self.release_notify.notified();
            if self.released() {
                return;
            }
            notified.await;
        }
    }
}

// reason: this join hazard does not exercise revocation; revocation coverage stays with existing owners.
struct AlwaysUnrevoked;

impl diport::RevocationStore for AlwaysUnrevoked {
    async fn revoke(
        &self,
        _serial: CertSerial,
        _scope: CertScope,
        _not_after: CertNotAfter,
    ) -> Result<(), diport::RevocationStoreError> {
        Ok(())
    }

    async fn is_revoked(
        &self,
        _serial: CertSerial,
        _scope: CertScope,
    ) -> Result<bool, diport::RevocationStoreError> {
        Ok(false)
    }

    async fn shutdown(&self) -> Result<(), diport::RevocationStoreError> {
        Ok(())
    }
}

/// Far-future clock so command deadlines remain after PostgreSQL `queued_at`.
struct JoinClock;

impl diport::Clock for JoinClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(3_900_000_000)
    }
}

fn join_clock() -> Arc<dyn diport::Clock> {
    Arc::new(JoinClock)
}

fn mint_authorized(
    request: &CertificateArtifactAcquisition,
    artifact_id: &str,
    serial_tail: u8,
) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError> {
    let material = format!("join-certificate-material:{artifact_id}").into_bytes();
    let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&material))
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let public_key = CertificatePublicKeyDigest::restore(&[0x21_u8; 32])
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let state_hash = ReportedStateHash::restore(&[0x41_u8; 32])
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let artifact_id = CertificateArtifactId::parse(artifact_id)?;
    let cert_scope = CertScope::new(request.scope().tenant(), request.scope().device());
    let serial = CertSerial::try_new([0x19, serial_tail])
        .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let not_after = CertNotAfter::try_from_system_time(
        std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )
    .map_err(|_| CertificateArtifactError::BindingMismatch)?;
    let expected = CertificateArtifactRequest::for_test(
        request.scope(),
        request.generation(),
        request.policy_hash().clone(),
        public_key.clone(),
        artifact_digest,
        state_hash.clone(),
        artifact_id.clone(),
        cert_scope,
        serial.clone(),
        not_after,
    )?;
    ProviderCertificateCandidate::new(
        material,
        request.scope(),
        request.generation(),
        request.policy_hash().clone(),
        public_key,
        state_hash,
        artifact_id,
        cert_scope,
        serial,
        not_after,
    )
    .authorize_production_for_test(&expected)
}

struct ImmediateArtifactSource {
    serial_tail: u8,
}

impl CertificateArtifactSource for ImmediateArtifactSource {
    type Eligibility = ProductionEligibility;

    async fn acquire(
        &self,
        request: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>
    {
        let artifact_id = format!(
            "join-artifact-immediate-{}",
            uuid::Uuid::new_v4().as_simple()
        );
        mint_authorized(&request, &artifact_id, self.serial_tail)
    }
}

struct GatedArtifactSource {
    gate: Arc<PauseGate>,
    serial_tail: u8,
}

impl CertificateArtifactSource for GatedArtifactSource {
    type Eligibility = ProductionEligibility;

    async fn acquire(
        &self,
        request: CertificateArtifactAcquisition,
    ) -> Result<AuthorizedCertificateArtifact<ProductionEligibility>, CertificateArtifactError>
    {
        let artifact_id = format!("join-artifact-gated-{}", uuid::Uuid::new_v4().as_simple());
        let authorized = mint_authorized(&request, &artifact_id, self.serial_tail)?;
        self.gate.pause_until_released().await;
        Ok(authorized)
    }
}

/// Counts stale-fence append outcomes so the lost path cannot pass vacuously.
struct ObservingRepository {
    inner: PgDeviceCertificateRepository<ProductionEligibility>,
    stale_fence: Arc<AtomicUsize>,
}

impl CertificateReconcileRepository<ProductionEligibility> for ObservingRepository {
    async fn load_current_view(
        &self,
        authority: &CertificateAttemptAuthority,
    ) -> Result<Option<CertificateReconcileView>, CertificateReconcileRepositoryError> {
        self.inner.load_current_view(authority).await
    }

    async fn load_artifact_receipts(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<
        Vec<PersistedCertificateArtifactSnapshot<ProductionEligibility>>,
        CertificateReconcileRepositoryError,
    > {
        self.inner.load_artifact_receipts(fence).await
    }

    async fn load_current_command_evidence(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<Option<DeviceCertificateCommandEvidence>, CertificateReconcileRepositoryError> {
        self.inner.load_current_command_evidence(fence).await
    }

    async fn expire_due_current_command(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<CurrentCommandExpiryOutcome, CertificateReconcileRepositoryError> {
        self.inner.expire_due_current_command(fence).await
    }

    async fn append_artifact_receipt(
        &self,
        fence: &CertificateAttemptFence,
        authorization: ArtifactAppendAuthorization<ProductionEligibility>,
    ) -> Result<ArtifactAppendOutcome, CertificateReconcileRepositoryError> {
        let outcome = self
            .inner
            .append_artifact_receipt(fence, authorization)
            .await?;
        if matches!(outcome, ArtifactAppendOutcome::StaleFence) {
            self.stale_fence.fetch_add(1, Ordering::SeqCst);
        }
        Ok(outcome)
    }

    async fn write_conditions(
        &self,
        fence: &CertificateAttemptFence,
        conditions: CertificateConditionMutation,
    ) -> Result<FencedMutationOutcome, CertificateReconcileRepositoryError> {
        self.inner.write_conditions(fence, conditions).await
    }

    async fn rotate_generation(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<RotationOutcome, CertificateReconcileRepositoryError> {
        self.inner.rotate_generation(fence).await
    }

    async fn request_deletion(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<DeletionRequestOutcome, CertificateReconcileRepositoryError> {
        self.inner.request_deletion(fence).await
    }
}

/// Test-only decorator: pauses only after the four command writes already committed.
struct PostCommitPauseStore {
    inner: PgReconcileStore,
    gate: Arc<PauseGate>,
}

impl ReconcileScheduleStore for PostCommitPauseStore {
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        limit: eventexec::ReconcileMaxInFlight,
        lease_ttl: Duration,
    ) -> Result<
        Vec<eventexec::reconcile::ClaimedTarget>,
        eventexec::reconcile::ReconcileScheduleError,
    > {
        ReconcileScheduleStore::claim_due_targets(
            &self.inner,
            tenant,
            reconciler_id,
            holder_id,
            limit,
            lease_ttl,
        )
        .await
    }

    async fn claim_targeted(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        wake: &eventexec::reconcile::ReconcileWake,
        lease_ttl: Duration,
    ) -> Result<
        Option<eventexec::reconcile::ClaimedTarget>,
        eventexec::reconcile::ReconcileScheduleError,
    > {
        ReconcileScheduleStore::claim_targeted(
            &self.inner,
            tenant,
            reconciler_id,
            holder_id,
            wake,
            lease_ttl,
        )
        .await
    }

    async fn append_attempt(
        &self,
        target: &eventexec::reconcile::ClaimedTarget,
        holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::append_attempt(&self.inner, target, holder_id).await
    }

    async fn record_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        result: AttemptResult,
    ) -> Result<ScheduleResultOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::record_attempt_result(&self.inner, attempt, result).await
    }

    async fn record_fenced_command(
        &self,
        attempt: &ReconcileAttempt,
        action: ConvergeAction,
        command: ReviewedFencedCommand,
    ) -> Result<ScheduleActionOutcome, eventexec::reconcile::ReconcileScheduleError> {
        let outcome =
            ReconcileScheduleStore::record_fenced_command(&self.inner, attempt, action, command)
                .await?;
        if matches!(outcome, ScheduleActionOutcome::Enqueued) {
            self.gate.pause_until_released().await;
        }
        Ok(outcome)
    }

    async fn complete_device_certificate_deletion(
        &self,
        attempt: &ReconcileAttempt,
    ) -> Result<ScheduleCompletionOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::complete_device_certificate_deletion(&self.inner, attempt).await
    }

    async fn extend_lease(
        &self,
        target: &eventexec::reconcile::ClaimedTarget,
        lease_ttl: Duration,
    ) -> Result<ScheduleLeaseOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::extend_lease(&self.inner, target, lease_ttl).await
    }

    async fn release_lease(
        &self,
        target: &eventexec::reconcile::ClaimedTarget,
    ) -> Result<ScheduleLeaseOutcome, eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::release_lease(&self.inner, target).await
    }

    async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::pause_target(&self.inner, tenant, target_id).await
    }

    async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), eventexec::reconcile::ReconcileScheduleError> {
        ReconcileScheduleStore::resume_target(&self.inner, tenant, target_id).await
    }
}

fn command_ttl() -> Result<DeviceCertificateCommandTtl, TestError> {
    Ok(DeviceCertificateCommandTtl::try_new(Duration::from_secs(
        300,
    ))?)
}

fn build_worker<S, R>(
    store: S,
    reconciler: R,
    keyring: Arc<CommandIdempotencyKeyring>,
    tenant: vocab::TenantId,
    holder_id: &str,
) -> Result<eventexec::reconcile::ReconcileWorker<S, R>, TestError>
where
    S: ReconcileScheduleStore + Send + Sync + 'static,
    R: eventexec::reconcile::DurableReconciler<S> + Send + Sync + 'static,
{
    let trigger = Trigger::interval(Duration::from_millis(50))?;
    Ok(ReconcileSchedulerBuilder::new(
        store,
        reconciler,
        keyring,
        DeviceCertificateSystemProducer::install(),
        tenant,
        RECONCILER_ID,
        holder_id,
        Tenancy::tenant_scoped(),
        trigger,
    )
    .with_max_in_flight(reconcile_limit(1))
    // Renew interval is lease_ttl/3 (= 100s); keep it far above GATE/POLL budgets.
    .with_lease_ttl(WORKER_LEASE_TTL)?
    .build())
}

async fn expire_lease(store: &PgStore, tenant: vocab::TenantId, target_id: &str) -> TestResult {
    TenantDb::<ServingWriteLane>::from_unverified_for_test(store)
        .test_expire_reconcile_lease(integration_tenant_scope(tenant), target_id.to_owned())
        .await?;
    Ok(())
}

async fn lease_epoch(
    store: &PgStore,
    tenant: vocab::TenantId,
    target_id: &str,
) -> Result<i64, TestError> {
    let target = target_id.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move { tx.reconcile_lease_epoch(&target).await })
        })
        .await?)
}

async fn coordinate_snapshot(
    store: &PgStore,
    tenant: vocab::TenantId,
    device: &str,
    target_id: &str,
    generation: i64,
    epoch: i64,
) -> Result<DeviceCertificateJoinObservation, TestError> {
    let device = device.to_owned();
    let target = target_id.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move {
                tx.device_certificate_join_observation(&device, &target, generation, epoch)
                    .await
            })
        })
        .await?)
}

async fn wait_command_at_epoch(
    store: &PgStore,
    tenant: vocab::TenantId,
    device: &str,
    generation: i64,
    epoch: i64,
) -> TestResult {
    testkit::await_try(POLL_BUDGET, async || {
        let device = device.to_owned();
        let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
        let count = reader
            .test_read(integration_tenant_scope(tenant), move |mut tx| {
                Box::pin(async move {
                    tx.device_command_count_at_epoch(&device, generation, epoch)
                        .await
                })
            })
            .await?;
        Ok::<Option<()>, TestError>((count >= 1).then_some(()))
    })
    .await
    .map_err(|error| format!("current holder did not enqueue command at epoch {epoch}: {error}"))?;
    Ok(())
}

async fn attempt_count_for_trigger(
    store: &PgStore,
    tenant: vocab::TenantId,
    target_id: &str,
    trigger_kind: &str,
    epoch: i64,
) -> Result<i64, TestError> {
    let target = target_id.to_owned();
    let trigger = trigger_kind.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move {
                tx.reconcile_attempt_count_for_trigger(&target, &trigger, epoch)
                    .await
            })
        })
        .await?)
}

async fn command_count_at_epoch(
    store: &PgStore,
    tenant: vocab::TenantId,
    device: &str,
    generation: i64,
    epoch: i64,
) -> Result<i64, TestError> {
    let device = device.to_owned();
    let reader = TenantDb::<ServingReadLane>::from_unverified_for_test(store);
    Ok(reader
        .test_read(integration_tenant_scope(tenant), move |mut tx| {
            Box::pin(async move {
                tx.device_command_count_at_epoch(&device, generation, epoch)
                    .await
            })
        })
        .await?)
}

async fn wait_lease_epoch_gt(
    store: &PgStore,
    tenant: vocab::TenantId,
    target_id: &str,
    previous: i64,
) -> Result<i64, TestError> {
    testkit::await_try(POLL_BUDGET, async || {
        let epoch = lease_epoch(store, tenant, target_id).await?;
        Ok::<Option<i64>, TestError>((epoch > previous).then_some(epoch))
    })
    .await
    .map_err(|error| format!("lease epoch did not advance past {previous}: {error}").into())
}

async fn stop_worker(cancel: CancellationToken, join: JoinHandle<()>) -> TestResult {
    cancel.cancel();
    tokio::time::timeout(WORKER_BUDGET, join)
        .await
        .map_err(|_| "worker did not stop within budget")?
        .map_err(|error| format!("worker join failed: {error}"))?;
    Ok(())
}

async fn prepare_target(store: &PgStore) -> Result<(vocab::TenantId, String, String), TestError> {
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(store, tenant, &device).await?;
    let key = ReconcileTargetKey::parse(RECONCILER_ID, RESOURCE_KIND, &device)?;
    let target = store.reconcile().upsert_target(tenant, &key).await?;
    Ok((tenant, device, target.target_id().to_owned()))
}

#[tokio::test(flavor = "multi_thread")]
async fn authorized_artifact_return_loses_to_lease_takeover_without_stale_command() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (tenant, device, target_id) = prepare_target(&store).await?;
    let keyring = command_keyring();
    let ttl = command_ttl()?;
    let clock = join_clock();

    let acquire_gate = PauseGate::new();
    let stale_fence = Arc::new(AtomicUsize::new(0));
    let old_reconciler = DeviceCertificateReconciler::new(
        ObservingRepository {
            inner: PgDeviceCertificateRepository::from_unverified_for_test(&store),
            stale_fence: Arc::clone(&stale_fence),
        },
        Arc::new(GatedArtifactSource {
            gate: Arc::clone(&acquire_gate),
            serial_tail: 1,
        }),
        AlwaysUnrevoked,
        Arc::clone(&clock),
        ttl,
    );
    let old_cancel = CancellationToken::new();
    let old_worker = build_worker(
        store.reconcile(),
        old_reconciler,
        Arc::clone(&keyring),
        tenant,
        "holder-old",
    )?;
    let old_join = tokio::spawn(old_worker.run(old_cancel.child_token()));

    acquire_gate.wait_entered().await?;
    assert!(
        acquire_gate.entered() && !acquire_gate.released(),
        "old acquire must pause before return"
    );
    let old_epoch = lease_epoch(&store, tenant, &target_id).await?;

    expire_lease(&store, tenant, &target_id).await?;

    let new_reconciler = DeviceCertificateReconciler::new(
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store),
        Arc::new(ImmediateArtifactSource { serial_tail: 2 }),
        AlwaysUnrevoked,
        clock,
        ttl,
    );
    let new_cancel = CancellationToken::new();
    let new_worker = build_worker(
        store.reconcile(),
        new_reconciler,
        keyring,
        tenant,
        "holder-new",
    )?;
    let new_join = tokio::spawn(new_worker.run(new_cancel.child_token()));

    let new_epoch = wait_lease_epoch_gt(&store, tenant, &target_id, old_epoch).await?;
    wait_command_at_epoch(&store, tenant, &device, 1, new_epoch).await?;

    let reclaim_attempts = attempt_count_for_trigger(
        &store,
        tenant,
        &target_id,
        AttemptTrigger::LeaseReclaim.as_label(),
        new_epoch,
    )
    .await?;
    assert_eq!(
        reclaim_attempts, 1,
        "new holder must reclaim via LeaseReclaim with a strict epoch advance"
    );

    // Bound the current holder before releasing the stale return so the snapshot cannot race
    // with the new worker's own attempt-result append.
    stop_worker(new_cancel, new_join).await?;

    let before = coordinate_snapshot(&store, tenant, &device, &target_id, 1, new_epoch).await?;
    assert_eq!(
        before.artifacts, 1,
        "current holder must persist one artifact"
    );
    assert_eq!(
        before.device_commands, 1,
        "current holder must emit one command"
    );
    assert_eq!(before.journal, 1);
    assert_eq!(before.actions, 1);
    assert_eq!(before.outbox, 1);

    acquire_gate.release();
    testkit::await_try(POLL_BUDGET, async || {
        Ok::<Option<()>, TestError>(
            (acquire_gate.released() && stale_fence.load(Ordering::SeqCst) >= 1).then_some(()),
        )
    })
    .await
    .map_err(|error| {
        format!("stale/lost artifact return path did not execute (anti-vacuity): {error}")
    })?;
    assert!(
        acquire_gate.released(),
        "old artifact return must leave the gate"
    );
    assert!(
        stale_fence.load(Ordering::SeqCst) >= 1,
        "old return must hit the real StaleFence path"
    );

    let after = coordinate_snapshot(&store, tenant, &device, &target_id, 1, new_epoch).await?;
    assert_eq!(
        after, before,
        "stale authorized artifact return must be zero-write against the current snapshot"
    );
    let old_epoch_commands = command_count_at_epoch(&store, tenant, &device, 1, old_epoch).await?;
    assert_eq!(
        old_epoch_commands, 0,
        "stale return must not append a command under the lost epoch"
    );

    stop_worker(old_cancel, old_join).await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn expire_reconcile_lease_rejects_missing_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let missing_target = uuid::Uuid::new_v4().to_string();

    let expire = TenantDb::<ServingWriteLane>::from_unverified_for_test(&store)
        .test_expire_reconcile_lease(integration_tenant_scope(tenant), missing_target)
        .await;
    match expire {
        Err(sqlx::Error::RowNotFound) => {}
        Ok(()) => return Err("missing reconcile lease must not report success".into()),
        Err(other) => {
            return Err(format!(
                "missing lease must surface sqlx::Error::RowNotFound, got {other:?}"
            )
            .into());
        }
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn postcommit_worker_crash_reclaim_keeps_command_singular_and_exposes_interrupted_attempt()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let (tenant, device, target_id) = prepare_target(&store).await?;
    let keyring = command_keyring();
    let ttl = command_ttl()?;
    let clock = join_clock();
    let postcommit_gate = PauseGate::new();

    let crash_reconciler = DeviceCertificateReconciler::new(
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store),
        Arc::new(ImmediateArtifactSource { serial_tail: 3 }),
        AlwaysUnrevoked,
        Arc::clone(&clock),
        ttl,
    );
    let pause_store = PostCommitPauseStore {
        inner: store.reconcile(),
        gate: Arc::clone(&postcommit_gate),
    };
    let crash_cancel = CancellationToken::new();
    let crash_worker = build_worker(
        pause_store,
        crash_reconciler,
        Arc::clone(&keyring),
        tenant,
        "holder-crash",
    )?;
    let crash_join = tokio::spawn(crash_worker.run(crash_cancel.child_token()));
    // Intentionally keep crash_cancel alive but unused: abort must not clean-cancel.
    let _keep_cancel = crash_cancel;

    postcommit_gate.wait_entered().await?;
    assert!(
        postcommit_gate.entered() && !postcommit_gate.released(),
        "post-commit pause must enter after the four writes commit"
    );

    let crash_epoch = lease_epoch(&store, tenant, &target_id).await?;
    let before_crash =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, crash_epoch).await?;
    assert_eq!(before_crash.artifacts, 1);
    assert_eq!(before_crash.journal, 1);
    assert_eq!(before_crash.device_commands, 1);
    assert_eq!(before_crash.actions, 1);
    assert_eq!(before_crash.outbox, 1);
    assert_eq!(before_crash.attempts_at_epoch, 1);
    assert_eq!(
        before_crash.results_at_epoch, 0,
        "interrupted attempt must exist without an attempt_result"
    );

    // Simulate process crash: abort the task; never cancel/release through the clean path.
    // ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main forceful shutdown.
    crash_join.abort();
    let aborted = crash_join.await;
    let Err(join_error) = aborted else {
        return Err("crash simulation must abort the worker task".into());
    };
    assert!(
        join_error.is_cancelled(),
        "abort must surface JoinError::cancelled, not a test-implementation panic: {join_error}"
    );
    assert!(
        !postcommit_gate.released(),
        "crash must not release the post-commit gate via clean shutdown"
    );

    let before_reclaim =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, crash_epoch).await?;
    assert_eq!(before_reclaim, before_crash);

    expire_lease(&store, tenant, &target_id).await?;

    let reclaim_reconciler = DeviceCertificateReconciler::new(
        PgDeviceCertificateRepository::<ProductionEligibility>::from_unverified_for_test(&store),
        Arc::new(ImmediateArtifactSource { serial_tail: 4 }),
        AlwaysUnrevoked,
        clock,
        ttl,
    );
    let reclaim_cancel = CancellationToken::new();
    let reclaim_worker = build_worker(
        store.reconcile(),
        reclaim_reconciler,
        keyring,
        tenant,
        "holder-reclaim",
    )?;
    let reclaim_join = tokio::spawn(reclaim_worker.run(reclaim_cancel.child_token()));

    let reclaim_epoch = wait_lease_epoch_gt(&store, tenant, &target_id, crash_epoch).await?;
    testkit::await_try(POLL_BUDGET, async || {
        let attempts = attempt_count_for_trigger(
            &store,
            tenant,
            &target_id,
            AttemptTrigger::LeaseReclaim.as_label(),
            reclaim_epoch,
        )
        .await?;
        let snap =
            coordinate_snapshot(&store, tenant, &device, &target_id, 1, reclaim_epoch).await?;
        Ok::<Option<()>, TestError>((attempts == 1 && snap.results_at_epoch == 1).then_some(()))
    })
    .await
    .map_err(|error| {
        format!(
            "reclaim worker did not finish one LeaseReclaim attempt with a terminal result: {error}"
        )
    })?;

    // Bound reclaim before asserting so a later requeue cannot race the snapshot.
    // ref: kube-rs/kube kube-runtime/src/controller/mod.rs@main graceful shutdown.
    stop_worker(reclaim_cancel, reclaim_join).await?;

    let after_crash_epoch =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, crash_epoch).await?;
    assert_eq!(
        after_crash_epoch, before_crash,
        "reclaim must not duplicate the committed crash-epoch write set"
    );
    assert_eq!(
        after_crash_epoch.results_at_epoch, 0,
        "interrupted crash-epoch attempt remains result-less after reclaim"
    );

    let reclaim_attempt_count = attempt_count_for_trigger(
        &store,
        tenant,
        &target_id,
        AttemptTrigger::LeaseReclaim.as_label(),
        reclaim_epoch,
    )
    .await?;
    assert_eq!(
        reclaim_attempt_count, 1,
        "reclaim epoch must expose exactly one LeaseReclaim attempt"
    );
    let reclaim_snap =
        coordinate_snapshot(&store, tenant, &device, &target_id, 1, reclaim_epoch).await?;
    assert_eq!(
        reclaim_snap.attempts_at_epoch, 1,
        "reclaim epoch must keep a singular attempt row"
    );
    assert_eq!(
        reclaim_snap.results_at_epoch, 1,
        "reclaim epoch must expose a terminal attempt result"
    );
    // New-epoch command and supersede behavior remains owned by #1900; this proof only requires
    // real-worker reclaim completion plus the unchanged crash-epoch write set above.

    store.shutdown().await?;
    Ok(())
}
