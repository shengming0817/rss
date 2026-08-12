//! Dedicated Settings projection replay journeys.

use super::support::*;

#[derive(Default)]
struct CheckpointStore {
    state: std::sync::Mutex<Option<(consistency::Lsn, diport::CheckpointVersion)>>,
}

impl CheckpointStore {
    fn offset(&self) -> Option<consistency::Lsn> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|(offset, _)| offset)
    }
}

impl diport::OwnerCheckpointStore for CheckpointStore {
    async fn get_checkpoint(
        &self,
        _owner: &diport::CheckpointOwner,
        _id: &diport::CheckpointId,
    ) -> Result<Option<diport::Checkpoint>, diport::CheckpointStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|(offset, version)| diport::Checkpoint { offset, version }))
    }

    async fn save_checkpoint(
        &self,
        _owner: &diport::CheckpointOwner,
        _id: &diport::CheckpointId,
        offset: consistency::Lsn,
        expected: diport::CheckpointVersion,
    ) -> Result<diport::SaveOutcome, diport::CheckpointStoreError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *state {
            None if expected == diport::CheckpointVersion::INITIAL => {
                *state = Some((offset, expected.next()));
                Ok(diport::SaveOutcome::Saved)
            }
            Some((_, version)) if version == expected => {
                *state = Some((offset, expected.next()));
                Ok(diport::SaveOutcome::Saved)
            }
            _ => Ok(diport::SaveOutcome::StaleVersion),
        }
    }

    async fn shutdown(&self) -> Result<(), diport::CheckpointStoreError> {
        Ok(())
    }
}

struct SettingsConformanceDeadLetters;

impl diport::DeadLetterStore for SettingsConformanceDeadLetters {
    async fn write_dead_letter(
        &self,
        _record: diport::DeadLetterRecord,
    ) -> Result<(), diport::DeadLetterStoreError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::DeadLetterStoreError> {
        Ok(())
    }
}

struct SettingsConformanceSerialSource;

impl consistency::PartitionSerialDelivery for SettingsConformanceSerialSource {}

fn target(
    store: std::sync::Arc<crate::PgSettingsProjectionApplyStore>,
) -> std::sync::Arc<dyn eventexec::ProjectionTarget> {
    std::sync::Arc::new(
        eventexec::ConformingProjectionTarget::new(
            eventexec::ProjectionTargetDefinition::new(
                generated::projection::settings_v3::CONTRACT,
                generated::event::PROJECTION_INPUT_GENERATION,
            )
            .expect("generated Settings target definition"),
            generated::event::PROJECTION_INPUTS
                .iter()
                .copied()
                .filter(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
                .collect(),
            store,
        )
        .expect("generated Settings target bindings"),
    )
}

struct SettingsTargetHarness {
    target: std::sync::Arc<dyn eventexec::ProjectionTarget>,
}

impl SettingsTargetHarness {
    fn new(store: std::sync::Arc<crate::PgSettingsProjectionApplyStore>) -> Self {
        Self {
            target: target(store),
        }
    }

    fn from_target(target: std::sync::Arc<dyn eventexec::ProjectionTarget>) -> Self {
        Self { target }
    }

    async fn apply(
        &self,
        scope: settings::ports::SettingsProjectionApplyScope,
        mutation: settings::ports::SettingsProjectionMutation,
    ) -> Result<eventexec::ProjectionTargetStoreOutcome, eventexec::ProjectionTargetStoreError>
    {
        use consistency::{ProjectionApplyErrorReason, ProjectionApplyOutcome};

        let binding = generated::event::PROJECTION_INPUTS
            .iter()
            .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
            .expect("generated Settings projection binding");
        let change_kind = match mutation.change_kind() {
            generated::event::settings_v1::SettingsConfigChangeKind::Published => "published",
            generated::event::settings_v1::SettingsConfigChangeKind::RolledBack => "rolledBack",
            generated::event::settings_v1::SettingsConfigChangeKind::Deleted => "deleted",
        };
        let tenant = mutation.tenant();
        let record = consistency::ProjectionEventRecord::with_metadata(
            mutation.source_lsn(),
            consistency::EventTopic::parse(binding.topic()).expect("generated Settings topic"),
            serde_json::to_vec(&serde_json::json!({
                "tenantId": tenant.to_string(),
                "key": mutation.key().as_str(),
                "version": mutation.config_version(),
                "changeKind": change_kind,
                "occurredAt": mutation.source_occurred_at_secs(),
            }))
            .expect("Settings test payload"),
            consistency::ProjectionEventMetadata::new(
                tenant,
                mutation.source_event_id(),
                binding.domain(),
                binding.contract_id(),
                binding.version(),
                binding.schema_hash(),
                serde_json::json!({
                    "tenantId": tenant.to_string(),
                    "testFactDigest": mutation.fact_digest(),
                }),
                None,
                None,
            ),
        );
        let selector = eventexec::ProjectionSelector::new(
            scope.tenant_scope().tenant(),
            scope.projection().clone(),
            scope.target_generation().clone(),
        );
        let execution = settings_operator_execution(tenant);
        let outcome =
            eventexec::ProjectionTarget::apply(self.target.as_ref(), &execution, &selector, record)
                .await
                .map_err(|error| {
                    eventexec::ProjectionTargetStoreError::new(error.reason(), error)
                })?;
        match outcome {
            ProjectionApplyOutcome::Applied => Ok(eventexec::ProjectionTargetStoreOutcome::Applied),
            ProjectionApplyOutcome::Duplicate => {
                Ok(eventexec::ProjectionTargetStoreOutcome::Duplicate)
            }
            ProjectionApplyOutcome::Filtered => Err(eventexec::ProjectionTargetStoreError::new(
                ProjectionApplyErrorReason::ProviderInvariant,
                std::io::Error::other("canonical Settings test record was filtered"),
            )),
        }
    }
}

fn settings_conformance_selector() -> eventexec::ProjectionSelector {
    eventexec::ProjectionSelector::new(
        vocab::TenantId::parse(COTX_TENANT_A).expect("canonical tenant"),
        eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID).expect("canonical projection"),
        eventexec::ProjectionVersion::parse("settings-conformance").expect("canonical generation"),
    )
}

fn settings_conformance_record(
    lsn: u64,
    event_id: &str,
    key: &str,
    version: i64,
    schema_hash: &str,
) -> consistency::ProjectionEventRecord {
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).expect("canonical tenant");
    let binding = generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
        .expect("generated Settings input binding");
    consistency::ProjectionEventRecord::with_metadata(
        consistency::Lsn::new(lsn),
        consistency::EventTopic::parse(binding.topic()).expect("generated topic"),
        serde_json::to_vec(&serde_json::json!({
            "tenantId": tenant.to_string(),
            "key": key,
            "version": version,
            "changeKind": "published",
            "occurredAt": TEST_OCCURRED_SECS,
        }))
        .expect("canonical payload"),
        consistency::ProjectionEventMetadata::new(
            tenant,
            event_id,
            binding.domain(),
            binding.contract_id(),
            binding.version(),
            schema_hash,
            serde_json::json!({ "tenantId": tenant.to_string() }),
            None,
            None,
        ),
    )
}

async fn attempt(
    target: std::sync::Arc<dyn eventexec::ProjectionTarget>,
    checkpoint: std::sync::Arc<CheckpointStore>,
    event: consistency::ProjectionEventRecord,
) -> testkit::projection_conformance::ProjectionAttemptObservation {
    use consistency::ProjectionApplyErrorReason;
    use eventexec::ProjectionStop;
    use testkit::projection_conformance::{
        ProjectionAttemptError, ProjectionAttemptObservation, ProjectionAttemptOutcome,
    };
    let before = checkpoint.offset();
    let selector = settings_conformance_selector();
    let execution = settings_operator_execution(selector.tenant());
    let harness = eventexec::ProjectionHarness::new(
        std::sync::Arc::new(
            eventexec::ProjectionProjector::with_execution(execution, selector.clone(), target)
                .expect("plan-issued execution matches Settings conformance selector"),
        ),
        std::sync::Arc::clone(&checkpoint),
        selector.shadow_checkpoint_owner(),
        selector.shadow_checkpoint_id(),
        std::sync::Arc::new(SettingsConformanceDeadLetters),
        consistency::SerialInOrder::from_source(&SettingsConformanceSerialSource),
    );
    let run = harness.run(&[event]).await;
    let advanced = checkpoint.offset() != before;
    if run.applied == 1 {
        ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Applied, advanced)
    } else if run.duplicates == 1 {
        ProjectionAttemptObservation::succeeded(ProjectionAttemptOutcome::Duplicate, advanced)
    } else {
        let error = match run.stop {
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::Conflict,
                ..
            } => ProjectionAttemptError::Conflict,
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::OutOfOrder,
                ..
            } => ProjectionAttemptError::OutOfOrder,
            ProjectionStop::ApplyFailed { reason, .. }
                if matches!(
                    reason,
                    ProjectionApplyErrorReason::TargetDefinitionDrift
                        | ProjectionApplyErrorReason::InputBindingDrift
                        | ProjectionApplyErrorReason::TenantDrift
                        | ProjectionApplyErrorReason::ProviderInvariant
                ) =>
            {
                ProjectionAttemptError::IdentityMismatch
            }
            ProjectionStop::ApplyFailed { reason, .. }
                if matches!(
                    reason,
                    ProjectionApplyErrorReason::PayloadMalformed
                        | ProjectionApplyErrorReason::PayloadValueInvalid
                        | ProjectionApplyErrorReason::VersionRegression
                        | ProjectionApplyErrorReason::ProviderPermanent
                ) =>
            {
                ProjectionAttemptError::Permanent
            }
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::CommitUnknown,
                ..
            } => ProjectionAttemptError::CommitUnknown,
            ProjectionStop::ApplyFailed {
                reason: ProjectionApplyErrorReason::RollbackFailed,
                ..
            } => ProjectionAttemptError::RollbackFailed,
            _ => ProjectionAttemptError::Permanent,
        };
        ProjectionAttemptObservation::failed(error, advanced)
    }
}

async fn observation(
    attempts: Vec<testkit::projection_conformance::ProjectionAttemptObservation>,
    store: &crate::PgSettingsProjectionApplyStore,
    owner: &PgStore,
) -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    // Operator lane is function-only (no relation SELECT). Conformance observation
    // therefore counts rows/receipts through the owner pool while calls stay on the
    // apply-store counter. Generation metadata remains outside this aggregate.
    let selector = settings_conformance_selector();
    let (effects, receipts) = crate::cotx::settings_projection_conformance_counts(
        &owner.pool,
        selector.tenant(),
        selector.version().as_str(),
    )
    .await
    .map_err(|err| {
        tracing::warn!(
            target: "postgres",
            operation = "settings_projection_conformance_counts",
            error = %secure::redact_error(&err),
            "settings projection conformance counts failed"
        );
        testkit::projection_conformance::ProjectionConformanceError::provider(
            "postgres-settings-counts",
            rss_conformance::ConformanceErrorCategory::Storage,
        )
    })?;
    Ok(testkit::projection_conformance::ProjectionObservation::new(
        attempts,
        store.apply_calls(),
        effects as u64,
        receipts as u64,
    ))
}

async fn rollback_observation(
    attempts: Vec<testkit::projection_conformance::ProjectionAttemptObservation>,
    store: &crate::PgSettingsProjectionApplyStore,
    owner: &PgStore,
) -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let observation = observation(attempts, store, owner).await?;
    if observation.business_effects() != 0 || observation.receipts() != 0 {
        return Err(
            testkit::projection_conformance::ProjectionConformanceError::Mismatch {
                case: "transaction-rollback",
                invariant: "durable-state-rolled-back",
                expected: "(0, 0)".to_owned(),
                actual: format!(
                    "({:?}, {:?})",
                    observation.business_effects(),
                    observation.receipts()
                ),
            },
        );
    }
    Ok(observation)
}

async fn settings_conformance_store() -> Result<
    (
        testkit::OwnedPgFixture,
        PgStore,
        std::sync::Arc<crate::PgSettingsProjectionApplyStore>,
    ),
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let provider = || {
        testkit::projection_conformance::ProjectionConformanceError::provider(
            "postgres-settings-target",
            rss_conformance::ConformanceErrorCategory::Other,
        )
    };
    let (fixture, owner) = connect_pg().await.map_err(|_| provider())?;
    provision_runtime_logins(&fixture)
        .await
        .map_err(|_| provider())?;
    owner.run_migrations().await.map_err(|_| provider())?;
    let verified = PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await
    .map_err(|_| provider())?;
    Ok((
        fixture,
        owner,
        std::sync::Arc::new(
            crate::PgSettingsProjectionApplyStore::new_projection_operator(&verified),
        ),
    ))
}

async fn pg_settings_atomic() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    let result = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "atomic",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    observation(vec![result], &store, &owner).await
}

async fn pg_settings_duplicate() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    let checkpoint = std::sync::Arc::new(CheckpointStore::default());
    let first = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::clone(&checkpoint),
        settings_conformance_record(
            1,
            "duplicate-a",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    let second = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::clone(&checkpoint),
        settings_conformance_record(
            2,
            "duplicate-b",
            "projection.b",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    let replay = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "duplicate-a",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    observation(vec![first, second, replay], &store, &owner).await
}

async fn pg_settings_conflict() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    let checkpoint = std::sync::Arc::new(CheckpointStore::default());
    let first = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::clone(&checkpoint),
        settings_conformance_record(
            1,
            "conflict",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    let conflict = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "conflict",
            "projection.a",
            2,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    observation(vec![first, conflict], &store, &owner).await
}

async fn pg_settings_order() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    let checkpoint = std::sync::Arc::new(CheckpointStore::default());
    let first = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::clone(&checkpoint),
        settings_conformance_record(
            2,
            "order-new",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    let old = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "order-old",
            "projection.b",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    observation(vec![first, old], &store, &owner).await
}

async fn pg_settings_identity() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    let result = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "identity",
            "projection.a",
            1,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    )
    .await;
    observation(vec![result], &store, &owner).await
}

async fn pg_settings_rollback() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    store.inject_test_fault(
        crate::settings_projection::SettingsProjectionTestFault::ConfirmedRollback,
    );
    let result = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "confirmed-rollback",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    rollback_observation(vec![result], &store, &owner).await
}

async fn pg_settings_commit_unknown() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    store.inject_test_fault(crate::settings_projection::SettingsProjectionTestFault::CommitUnknown);
    let checkpoint = std::sync::Arc::new(CheckpointStore::default());
    let first = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::clone(&checkpoint),
        settings_conformance_record(
            1,
            "commit-unknown",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    let replay = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "commit-unknown",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    observation(vec![first, replay], &store, &owner).await
}

async fn pg_settings_rollback_failed() -> Result<
    testkit::projection_conformance::ProjectionObservation,
    testkit::projection_conformance::ProjectionConformanceError,
> {
    let (_fixture, owner, store) = settings_conformance_store().await?;
    store
        .inject_test_fault(crate::settings_projection::SettingsProjectionTestFault::RollbackFailed);
    let result = attempt(
        target(std::sync::Arc::clone(&store)),
        std::sync::Arc::new(CheckpointStore::default()),
        settings_conformance_record(
            1,
            "rollback-failed",
            "projection.a",
            1,
            generated::event::settings_v1::CONTRACT.schema_hash(),
        ),
    )
    .await;
    rollback_observation(vec![result], &store, &owner).await
}

const SETTINGS_PROJECTION_DEFINITION_VERSION: &str = "v3";

const SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST: &str =
    "sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8";

const SETTINGS_PROJECTION_INPUT_GENERATION: &str = generated::event::PROJECTION_INPUT_GENERATION;

fn settings_projection_apply_scope(
    tenant: vocab::TenantId,
    generation: &str,
) -> Result<settings::ports::SettingsProjectionApplyScope, TestError> {
    Ok(settings::ports::SettingsProjectionApplyScope::for_test(
        settings_scope(tenant),
        eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)?,
        eventexec::ProjectionVersion::parse(generation)?,
        SETTINGS_PROJECTION_DEFINITION_VERSION,
        SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST,
        SETTINGS_PROJECTION_INPUT_GENERATION,
    )?)
}

fn settings_projection_read_scope(
    tenant: vocab::TenantId,
    generation: &str,
) -> Result<settings::ports::SettingsProjectionReadScope, TestError> {
    Ok(settings::ports::SettingsProjectionReadScope::for_test(
        settings_scope(tenant),
        eventexec::ProjectionVersion::parse(generation)?,
    ))
}

fn settings_projection_mutation(
    scope: &settings::ports::SettingsProjectionApplyScope,
    tenant: vocab::TenantId,
    key: &str,
    version: u64,
    change_kind: generated::event::settings_v1::SettingsConfigChangeKind,
    occurred_at_secs: u64,
    event_id: &str,
    lsn: u64,
    fact_digest: [u8; 32],
) -> Result<settings::ports::SettingsProjectionMutation, TestError> {
    let event = settings::ConfigVersionChangedEvent::for_test(
        tenant,
        settings::ports::SettingKey::parse(key)?,
        version,
        change_kind,
        occurred_at_secs,
    );
    Ok(settings::ports::SettingsProjectionMutation::for_test(
        scope,
        event,
        event_id,
        consistency::Lsn::new(lsn),
        fact_digest,
    )?)
}

async fn invoke_settings_funnel_for_tenant_precondition(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: vocab::TenantId,
    generation: String,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT public.rss_settings_projection_apply_operator(\
         $1::uuid, $2, $3, $4, $5, $6, 'projection.tenant-precondition', 1, 'published', \
         $7, 1, $8, $9)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(unique_event_id("settings-tenant-precondition"))
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x5a_u8; 32])
    .fetch_one(&mut **tx)
    .await
}

async fn assert_settings_funnel_requires_bound_tenant(
    pool: &sqlx::PgPool,
    tenant: vocab::TenantId,
    other_tenant: vocab::TenantId,
    role_label: &str,
) -> TestResult {
    let mut unset = pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', '', true)")
        .execute(&mut *unset)
        .await?;
    let unset_result = invoke_settings_funnel_for_tenant_precondition(
        &mut unset,
        tenant,
        format!(
            "settings-{role_label}-unset-{}",
            uuid::Uuid::new_v4().simple()
        ),
    )
    .await;
    assert!(
        matches!(unset_result, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1902")),
        "{role_label} must reject an unset tenant scope: {unset_result:?}"
    );
    unset.rollback().await?;

    let mut mismatch = pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(other_tenant.to_string())
        .execute(&mut *mismatch)
        .await?;
    let mismatch_result = invoke_settings_funnel_for_tenant_precondition(
        &mut mismatch,
        tenant,
        format!(
            "settings-{role_label}-mismatch-{}",
            uuid::Uuid::new_v4().simple()
        ),
    )
    .await;
    assert!(
        matches!(mismatch_result, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1902")),
        "{role_label} must reject a mismatched tenant scope: {mismatch_result:?}"
    );
    mismatch.rollback().await?;

    let mut matched = pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *matched)
        .await?;
    let matched_result = invoke_settings_funnel_for_tenant_precondition(
        &mut matched,
        tenant,
        format!(
            "settings-{role_label}-matched-{}",
            uuid::Uuid::new_v4().simple()
        ),
    )
    .await?;
    assert_eq!(
        matched_result, "applied",
        "{role_label} exact tenant must apply"
    );
    matched.rollback().await?;
    Ok(())
}

async fn settings_projection_runtime_parts(
    owner: &PgStore,
    fixture: &testkit::OwnedPgFixture,
) -> Result<
    (
        std::sync::Arc<PgStore>,
        Box<settings::ports::DynSettingsProjectionReadRepo<'static>>,
        SettingsTargetHarness,
    ),
    TestError,
> {
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let app = std::sync::Arc::new(connect_pg_rss_app_role(fixture, owner).await?);
    let domain = crate::PgRuntimeHandle::from_store_for_test(std::sync::Arc::clone(&app))
        .for_domain::<crate::caps::Settings>();
    let reader = domain.settings_projection_read_repo();
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
        .ok_or("Settings projection binding missing")?;
    let operator = PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let writer = SettingsTargetHarness::from_target(target(std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_operator(&operator),
    )));
    let _ = binding;
    Ok((app, reader, writer))
}

/// Barrier-gated Settings projection source for dual-worker fencing T2.
/// Both runners rendezvous inside `read_from` after sharing the same checkpoint baseline.
#[derive(Clone)]
struct SettingsDualWorkerBarrierSource {
    events: std::sync::Arc<Vec<consistency::ProjectionEventRecord>>,
    barrier: std::sync::Arc<tokio::sync::Barrier>,
}

impl consistency::PartitionSerialDelivery for SettingsDualWorkerBarrierSource {}

impl consistency::ProjectionEventSource for SettingsDualWorkerBarrierSource {
    async fn read_from(
        &self,
        after: Option<consistency::Lsn>,
        limit: consistency::ProjectionBatchLimit,
    ) -> Result<Vec<consistency::ProjectionEventRecord>, consistency::EngineError> {
        self.barrier.wait().await;
        Ok(self
            .events
            .iter()
            .filter(|event| after.is_none_or(|after| event.lsn() > after))
            .take(limit.get() as usize)
            .cloned()
            .collect())
    }
}

fn settings_dual_worker_runner_config() -> Result<eventexec::ProjectionRunnerConfig, TestError> {
    Ok(eventexec::ProjectionRunnerConfig::new(
        consistency::ProjectionBatchLimit::new(10)?,
        std::time::Duration::from_millis(100),
        eventexec::ProjectionPoisonPolicy::Isolate,
    )?)
}

fn assert_settings_dual_worker_stops(
    run_a: &eventexec::ProjectionRun,
    run_b: &eventexec::ProjectionRun,
) {
    let stops = [&run_a.stop, &run_b.stop];
    let completed = stops
        .iter()
        .filter(|stop| matches!(stop, eventexec::ProjectionStop::Completed))
        .count();
    let fenced = stops
        .iter()
        .filter(|stop| matches!(stop, eventexec::ProjectionStop::Fenced))
        .count();
    assert_eq!(
        (completed, fenced),
        (1, 1),
        "exactly one Completed winner and one Fenced stale writer, got {stops:?}"
    );
}

fn settings_dual_worker_harness(
    worker: &crate::projection_worker::VerifiedPgProjectionWorkerStore,
    target_scope: &crate::projection_worker::ProjectionWorkerTarget,
    tenant: vocab::TenantId,
    projection_target: std::sync::Arc<dyn eventexec::ProjectionTarget>,
    execution: eventexec::ProjectionExecutionContext,
    source: &SettingsDualWorkerBarrierSource,
) -> Result<
    eventexec::ProjectionHarness<
        eventexec::ProjectionProjector,
        crate::projection_worker::PgProjectionWorkerCheckpointStore,
        crate::projection_worker::PgProjectionWorkerDeadLetterStore,
    >,
    TestError,
> {
    let selector = target_scope.selector(tenant);
    let checkpoint = std::sync::Arc::new(crate::projection_worker::checkpoint_for_integration(
        worker,
        target_scope,
        tenant,
    ));
    let dead_letter = std::sync::Arc::new(crate::projection_worker::dead_letter_for_integration(
        worker,
        target_scope,
        tenant,
        test_dlx_payload_protector(),
    ));
    let projector = eventexec::ProjectionProjector::with_execution(
        execution,
        selector.clone(),
        projection_target,
    )?;
    Ok(eventexec::ProjectionHarness::new(
        std::sync::Arc::new(projector),
        checkpoint,
        selector.shadow_checkpoint_owner(),
        selector.shadow_checkpoint_id(),
        dead_letter,
        consistency::SerialInOrder::from_source(source),
    ))
}

async fn settings_projection_generation_state(
    owner: &PgStore,
    tenant: vocab::TenantId,
    generation: &str,
) -> Result<
    (
        Vec<(String, i64, String, String, i64, i64)>,
        Vec<(String, i64, Vec<u8>)>,
        Option<i64>,
    ),
    sqlx::Error,
> {
    let rows = sqlx::query_as(
        "SELECT config_key, config_version, change_kind, source_event_id, source_lsn, \
                source_occurred_at_secs \
         FROM public.settings_config_projection_rows \
         WHERE tenant_id = $1::uuid AND generation = $2 ORDER BY config_key",
    )
    .bind(tenant.to_string())
    .bind(generation)
    .fetch_all(&owner.pool)
    .await?;
    let receipts = sqlx::query_as(
        "SELECT source_event_id, source_lsn, fact_digest \
         FROM public.settings_projection_dedupe_receipts \
         WHERE tenant_id = $1::uuid AND generation = $2 ORDER BY source_lsn, source_event_id",
    )
    .bind(tenant.to_string())
    .bind(generation)
    .fetch_all(&owner.pool)
    .await?;
    let high_water = sqlx::query_scalar(
        "SELECT high_water_lsn FROM public.settings_projection_generations \
         WHERE tenant_id = $1::uuid AND generation = $2",
    )
    .bind(tenant.to_string())
    .bind(generation)
    .fetch_optional(&owner.pool)
    .await?;
    Ok((rows, receipts, high_water))
}

async fn settings_projection_checkpoint(
    owner: &PgStore,
    selector: &eventexec::ProjectionSelector,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT offset_lsn FROM public.checkpoint WHERE owner = $1 AND checkpoint_id = $2",
    )
    .bind(selector.shadow_checkpoint_owner().as_str())
    .bind(selector.shadow_checkpoint_id().as_str())
    .fetch_optional(&owner.pool)
    .await
}

async fn settings_projection_dlx_count(
    owner: &PgStore,
    selector: &eventexec::ProjectionSelector,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM public.dead_letter \
         WHERE tenant_id = $1::uuid AND source_kind = 'projection' AND consumer_group = $2",
    )
    .bind(selector.tenant().to_string())
    .bind(selector.shadow_checkpoint_id().as_str())
    .fetch_one(&owner.pool)
    .await
}

fn settings_projection_record_for_tenant(
    tenant: vocab::TenantId,
    lsn: u64,
    event_id: &str,
    key: &str,
) -> consistency::ProjectionEventRecord {
    let binding = generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
        .expect("generated Settings input binding");
    consistency::ProjectionEventRecord::with_metadata(
        consistency::Lsn::new(lsn),
        consistency::EventTopic::parse(binding.topic()).expect("generated topic"),
        serde_json::to_vec(&serde_json::json!({
            "tenantId": tenant.to_string(), "key": key, "version": 1,
            "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
        }))
        .expect("canonical Settings payload"),
        consistency::ProjectionEventMetadata::new(
            tenant,
            event_id,
            binding.domain(),
            binding.contract_id(),
            binding.version(),
            binding.schema_hash(),
            serde_json::json!({ "tenantId": tenant.to_string() }),
            None,
            None,
        ),
    )
}

#[derive(Clone, Copy)]
enum SettingsReplayFailureCase {
    CommitUnknown,
    RollbackFailed,
    TenantDrift,
    PersistentOrder,
    SchemaDrift,
}

async fn settings_projection_operator_replay_failure_case(
    case: SettingsReplayFailureCase,
) -> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&owner).await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let verified_operator = PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let deps = crate::PgProjectionOperatorDeps::connect(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
        fixed_clock_arc(),
    )
    .await?;
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
        .ok_or("Settings projection binding missing")?;
    let projection = eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)?;
    let definition = || {
        eventexec::ProjectionTargetDefinition::new(
            generated::projection::settings_v3::CONTRACT,
            generated::event::PROJECTION_INPUT_GENERATION,
        )
    };
    let runner_config = eventexec::ProjectionRunnerConfig::new(
        consistency::ProjectionBatchLimit::new(10)?,
        std::time::Duration::from_millis(100),
        eventexec::ProjectionPoisonPolicy::Isolate,
    )?;

    if matches!(case, SettingsReplayFailureCase::CommitUnknown) {
        let commit_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let commit_generation =
            format!("settings-commit-unknown-{}", uuid::Uuid::new_v4().simple());
        let commit_selector = eventexec::ProjectionSelector::new(
            commit_tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse(&commit_generation)?,
        );
        let commit_scope =
            eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
                &projection,
                commit_tenant,
            )
            .ok_or("Settings commit-unknown source scope missing")?;
        let commit_lsn = append_projection_source_event_with_payload_for_tenant(
            &app,
            binding,
            "operator-commit-unknown",
            commit_tenant,
            &serde_json::to_vec(&serde_json::json!({
                "tenantId": commit_tenant.to_string(), "key": "projection.commit-unknown",
                "version": 1, "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
            }))?,
        )
        .await?;
        let commit_replay = deps
            .authorize_projection_target(
                projection_maintenance_receipt(
                    authn::ProjectionMaintenanceAction::Replay,
                    commit_tenant,
                    SETTINGS_PROJECTION_ID,
                ),
                crate::ProjectionReplayAction,
                &commit_selector,
                commit_scope.clone(),
            )?
            .into_settings_replay_stores_with_test_fault(
                settings_operator_execution(commit_tenant),
                definition()?,
                vec![binding],
                test_dlx_payload_protector(),
                crate::settings_projection::SettingsProjectionTestFault::CommitUnknown,
            )?;
        let commit_unknown = commit_replay.run_once(runner_config).await;
        assert!(matches!(
            commit_unknown.stop,
            eventexec::ProjectionStop::ApplyFailed {
                reason: consistency::ProjectionApplyErrorReason::CommitUnknown,
                ..
            }
        ));
        assert_eq!(commit_unknown.dead_lettered, 0);
        let commit_checkpoint = settings_projection_checkpoint(&owner, &commit_selector).await?;
        assert_eq!(commit_checkpoint, None);
        let commit_dlx = settings_projection_dlx_count(&owner, &commit_selector).await?;
        assert_eq!(
            commit_dlx, 0,
            "uncertain commit must never be classified as poison"
        );
        drop(commit_replay);

        let commit_retry = deps
            .authorize_projection_target(
                projection_maintenance_receipt(
                    authn::ProjectionMaintenanceAction::Replay,
                    commit_tenant,
                    SETTINGS_PROJECTION_ID,
                ),
                crate::ProjectionReplayAction,
                &commit_selector,
                commit_scope,
            )?
            .into_settings_replay_stores(
                settings_operator_execution(commit_tenant),
                definition()?,
                vec![binding],
                test_dlx_payload_protector(),
            )?;
        let commit_converged = commit_retry.run_once(runner_config).await;
        assert_eq!(commit_converged.stop, eventexec::ProjectionStop::Completed);
        assert_eq!(
            (commit_converged.scanned, commit_converged.duplicates),
            (1, 1)
        );
        let commit_checkpoint = settings_projection_checkpoint(&owner, &commit_selector).await?;
        assert_eq!(commit_checkpoint, Some(commit_lsn));
        drop(commit_retry);
    }

    if matches!(case, SettingsReplayFailureCase::RollbackFailed) {
        let rollback_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let rollback_generation =
            format!("settings-rollback-failed-{}", uuid::Uuid::new_v4().simple());
        let rollback_selector = eventexec::ProjectionSelector::new(
            rollback_tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse(&rollback_generation)?,
        );
        let rollback_scope =
            eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
                &projection,
                rollback_tenant,
            )
            .ok_or("Settings rollback-failed source scope missing")?;
        append_projection_source_event_with_payload_for_tenant(
            &app,
            binding,
            "operator-rollback-failed",
            rollback_tenant,
            &serde_json::to_vec(&serde_json::json!({
                "tenantId": rollback_tenant.to_string(), "key": "projection.rollback-failed",
                "version": 1, "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
            }))?,
        )
        .await?;
        let rollback_replay = deps
            .authorize_projection_target(
                projection_maintenance_receipt(
                    authn::ProjectionMaintenanceAction::Replay,
                    rollback_tenant,
                    SETTINGS_PROJECTION_ID,
                ),
                crate::ProjectionReplayAction,
                &rollback_selector,
                rollback_scope,
            )?
            .into_settings_replay_stores_with_test_fault(
                settings_operator_execution(rollback_tenant),
                definition()?,
                vec![binding],
                test_dlx_payload_protector(),
                crate::settings_projection::SettingsProjectionTestFault::RollbackFailed,
            )?;
        let rollback_failed = rollback_replay.run_once(runner_config).await;
        assert!(matches!(
            rollback_failed.stop,
            eventexec::ProjectionStop::ApplyFailed {
                reason: consistency::ProjectionApplyErrorReason::RollbackFailed,
                ..
            }
        ));
        assert_eq!(rollback_failed.dead_lettered, 0);
        let rollback_checkpoint =
            settings_projection_checkpoint(&owner, &rollback_selector).await?;
        assert_eq!(rollback_checkpoint, None);
        let rollback_dlx = settings_projection_dlx_count(&owner, &rollback_selector).await?;
        assert_eq!(
            rollback_dlx, 0,
            "uncertain rollback must never be classified as poison"
        );
        assert_eq!(
            settings_projection_generation_state(&owner, rollback_tenant, &rollback_generation)
                .await?,
            (Vec::new(), Vec::new(), None),
            "rollback-failed must leave no target state"
        );
        drop(rollback_replay);
    }

    if matches!(case, SettingsReplayFailureCase::TenantDrift) {
        let drift_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let payload_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let drift_generation = format!("settings-tenant-drift-{}", uuid::Uuid::new_v4().simple());
        let drift_selector = eventexec::ProjectionSelector::new(
            drift_tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse(&drift_generation)?,
        );
        let drift_scope =
            eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
                &projection,
                drift_tenant,
            )
            .ok_or("Settings tenant-drift source scope missing")?;
        let drift_id = unique_event_id("settings-tenant-drift");
        append_projection_source_event_with_payload_for_tenant(
            &app,
            binding,
            &drift_id,
            drift_tenant,
            &serde_json::to_vec(&serde_json::json!({
                "tenantId": payload_tenant.to_string(), "key": "projection.tenant-drift",
                "version": 1, "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
            }))?,
        )
        .await?;
        let drift_replay = deps
            .authorize_projection_target(
                projection_maintenance_receipt(
                    authn::ProjectionMaintenanceAction::Replay,
                    drift_tenant,
                    SETTINGS_PROJECTION_ID,
                ),
                crate::ProjectionReplayAction,
                &drift_selector,
                drift_scope,
            )?
            .into_settings_replay_stores(
                settings_operator_execution(drift_tenant),
                definition()?,
                vec![binding],
                test_dlx_payload_protector(),
            )?;
        let drift_failed = drift_replay.run_once(runner_config).await;
        assert!(
            matches!(
                drift_failed.stop,
                eventexec::ProjectionStop::ApplyFailed {
                    reason: consistency::ProjectionApplyErrorReason::TenantDrift,
                    ..
                }
            ),
            "tenant drift run: {drift_failed:?}"
        );
        assert_eq!(drift_failed.dead_lettered, 1);
        let drift_checkpoint = settings_projection_checkpoint(&owner, &drift_selector).await?;
        assert_eq!(drift_checkpoint, None);
        let drift_dlx = settings_projection_dlx_count(&owner, &drift_selector).await?;
        assert_eq!(drift_dlx, 1);
        drop(drift_replay);
    }

    if matches!(case, SettingsReplayFailureCase::PersistentOrder) {
        let order_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let order_generation = format!("settings-order-{}", uuid::Uuid::new_v4().simple());
        let order_selector = eventexec::ProjectionSelector::new(
            order_tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse(&order_generation)?,
        );
        let order_scope =
            eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
                &projection,
                order_tenant,
            )
            .ok_or("Settings order source scope missing")?;
        let order_id = unique_event_id("settings-persistent-order");
        let order_lsn = append_projection_source_event_with_payload_for_tenant(
            &app,
            binding,
            &order_id,
            order_tenant,
            &serde_json::to_vec(&serde_json::json!({
                "tenantId": order_tenant.to_string(), "key": "projection.order-old",
                "version": 1, "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
            }))?,
        )
        .await?;
        let serving_order = target(std::sync::Arc::new(
            crate::PgSettingsProjectionApplyStore::new_projection_operator(&verified_operator),
        ));
        assert_eq!(
            eventexec::ProjectionTarget::apply(
                serving_order.as_ref(),
                &settings_operator_execution(order_tenant),
                &order_selector,
                settings_projection_record_for_tenant(
                    order_tenant,
                    u64::try_from(order_lsn)? + 1,
                    &unique_event_id("settings-order-high-water-seed"),
                    "projection.order-new",
                ),
            )
            .await?,
            consistency::ProjectionApplyOutcome::Applied
        );
        let order_replay = deps
            .authorize_projection_target(
                projection_maintenance_receipt(
                    authn::ProjectionMaintenanceAction::Replay,
                    order_tenant,
                    SETTINGS_PROJECTION_ID,
                ),
                crate::ProjectionReplayAction,
                &order_selector,
                order_scope,
            )?
            .into_settings_replay_stores(
                settings_operator_execution(order_tenant),
                definition()?,
                vec![binding],
                test_dlx_payload_protector(),
            )?;
        let order_failed = order_replay.run_once(runner_config).await;
        assert!(matches!(
            order_failed.stop,
            eventexec::ProjectionStop::ApplyFailed {
                reason: consistency::ProjectionApplyErrorReason::OutOfOrder,
                ..
            }
        ));
        assert_eq!(order_failed.dead_lettered, 1);
        let order_checkpoint = settings_projection_checkpoint(&owner, &order_selector).await?;
        assert_eq!(order_checkpoint, None);
        let order_dlx = settings_projection_dlx_count(&owner, &order_selector).await?;
        assert_eq!(order_dlx, 1);
        drop(order_replay);
    }

    if matches!(case, SettingsReplayFailureCase::SchemaDrift) {
        let schema_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let schema_generation = format!("settings-schema-drift-{}", uuid::Uuid::new_v4().simple());
        let schema_selector = eventexec::ProjectionSelector::new(
            schema_tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse(&schema_generation)?,
        );
        let schema_scope =
            eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
                &projection,
                schema_tenant,
            )
            .ok_or("Settings schema-drift source scope missing")?;
        let schema_id = unique_event_id("settings-schema-drift");
        let mut schema_tx = owner.pool.begin().await?;
        sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
            .bind(schema_tenant.to_string())
            .execute(&mut *schema_tx)
            .await?;
        sqlx::query(
        "INSERT INTO public.projection_events (event_id, domain, aggregate_id, event_type, payload, \
         contract_id, contract_version, schema_hash, metadata) \
         VALUES ($1, $2, $1, $3, $4, $5, $6, $7, $8::jsonb)",
    )
    .bind(&schema_id)
    .bind(binding.domain())
    .bind(binding.topic())
    .bind(binding.projection_id().as_bytes())
    .bind(binding.contract_id())
    .bind("v999")
    .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .bind(serde_json::json!({ "tenantId": schema_tenant.to_string() }).to_string())
    .execute(&mut *schema_tx)
    .await?;
        schema_tx.commit().await?;
        let schema_replay = deps
            .authorize_projection_target(
                projection_maintenance_receipt(
                    authn::ProjectionMaintenanceAction::Replay,
                    schema_tenant,
                    SETTINGS_PROJECTION_ID,
                ),
                crate::ProjectionReplayAction,
                &schema_selector,
                schema_scope,
            )?
            .into_settings_replay_stores(
                settings_operator_execution(schema_tenant),
                definition()?,
                vec![binding],
                test_dlx_payload_protector(),
            )?;
        let schema_failed = schema_replay.run_once(runner_config).await;
        assert!(
            matches!(
                schema_failed.stop,
                eventexec::ProjectionStop::ApplyFailed {
                    reason: consistency::ProjectionApplyErrorReason::InputBindingDrift,
                    ..
                }
            ),
            "schema drift run: {schema_failed:?}"
        );
        assert_eq!((schema_failed.scanned, schema_failed.dead_lettered), (1, 1));
        let schema_dlx = settings_projection_dlx_count(&owner, &schema_selector).await?;
        assert_eq!(
            schema_dlx, 1,
            "known binding version/schema drift must enter one controlled invariant DLQ row"
        );
        let schema_checkpoint = settings_projection_checkpoint(&owner, &schema_selector).await?;
        assert_eq!(
            schema_checkpoint, None,
            "checkpoint must stay before schema poison"
        );
        assert_eq!(
            settings_projection_generation_state(&owner, schema_tenant, &schema_generation).await?,
            (Vec::new(), Vec::new(), None),
            "metadata-only drift detection must reach the target without writing target state"
        );

        drop(schema_replay);
    }
    deps.shutdown().await?;
    verified_operator.store_arc().shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_active_generation_swap_requires_exact_precondition_and_supports_rollback()
-> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    owner.run_migrations().await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let operator = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let store = operator.store_arc();

    for relation in [
        "checkpoint",
        "distributed_cas",
        "auth_audit_events",
        "dead_letter",
    ] {
        assert!(
            sqlx::query(&format!("SELECT count(*) FROM public.{relation}"))
                .execute(&store.pool)
                .await
                .is_err(),
            "function-only operator must not receive direct {relation} table access"
        );
    }

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == generated::projection::settings_v3::CONTRACT_ID)
        .ok_or_else(|| std::io::Error::other("generated Settings Projection input is missing"))?;
    let projection = eventexec::ProjectionId::parse(binding.projection_id())?;
    let scope = eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
        &projection,
        tenant,
    )
    .ok_or_else(|| std::io::Error::other("generated registry did not mint source scope"))?;
    let v1 = eventexec::ProjectionSelector::new(
        tenant,
        projection.clone(),
        eventexec::ProjectionVersion::parse("v1")?,
    );
    let empty = eventexec::ProjectionSelector::new(
        tenant,
        projection.clone(),
        eventexec::ProjectionVersion::parse("empty-source")?,
    );
    let v2 = eventexec::ProjectionSelector::new(
        tenant,
        projection,
        eventexec::ProjectionVersion::parse("v2")?,
    );
    let operator_config = crate::PgProjectionOperatorConfig::new(runtime_pg_config(
        pg.owner_params(),
        TEST_PROJECTION_OPERATOR_ROLE,
        TEST_PROJECTION_OPERATOR_PASSWORD,
    ));
    let source_config = crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
        pg.owner_params(),
        TEST_PROJECTION_READER_ROLE,
        TEST_PROJECTION_READER_PASSWORD,
    ));
    let deps = crate::PgProjectionOperatorDeps::connect(
        &operator_config,
        &source_config,
        fixed_clock_arc(),
    )
    .await?;
    insert_settings_projection_generation(&owner, &empty, 10).await?;
    insert_projection_shadow_checkpoint(&owner, &empty, 10).await?;
    let empty_status = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Status,
                tenant,
                empty.projection().as_str(),
            ),
            crate::ProjectionStatusAction,
            &empty,
            scope.clone(),
        )?
        .status()
        .await?;
    assert_eq!(empty_status.source_high_water_lsn(), None);
    assert!(empty_status.active_generation().is_none());
    let empty_swap = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Swap,
                tenant,
                empty.projection().as_str(),
            ),
            crate::ProjectionSwapAction,
            &empty,
            scope.clone(),
        )?
        .swap_active(crate::ProjectionPointerPrecondition::ExpectUnset)
        .await;
    assert!(
        matches!(
            &empty_swap,
            Err(crate::ProjectionControlError::SwapRejected(
                crate::ProjectionSwapRejection::SourceMissing
            ))
        ),
        "unexpected empty-source swap outcome: {empty_swap:?}"
    );

    let source_event_id = unique_event_id("projection-promote-source");
    append_projection_source_event_for_tenant(&app, binding, &source_event_id, tenant).await?;
    let source_high_water = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Status,
                tenant,
                v1.projection().as_str(),
            ),
            crate::ProjectionStatusAction,
            &v1,
            scope.clone(),
        )?
        .status()
        .await?
        .source_high_water_lsn()
        .map(|lsn| lsn.get())
        .ok_or_else(|| std::io::Error::other("committed source event lacks high-water"))?;
    let v1_high_water = source_high_water;
    let v2_high_water = source_high_water;
    insert_settings_projection_generation(&owner, &v1, v1_high_water).await?;
    insert_settings_projection_generation(&owner, &v2, v2_high_water).await?;
    insert_projection_shadow_checkpoint(&owner, &v1, v1_high_water).await?;
    insert_projection_shadow_checkpoint(&owner, &v2, v2_high_water).await?;
    assert!(
        deps.authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Status,
                tenant,
                v1.projection().as_str(),
            ),
            crate::ProjectionStatusAction,
            &v1,
            scope.clone(),
        )?
        .status()
        .await?
        .active_generation()
        .is_none()
    );

    let first = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Swap,
                tenant,
                v1.projection().as_str(),
            ),
            crate::ProjectionSwapAction,
            &v1,
            scope.clone(),
        )?
        .swap_active(crate::ProjectionPointerPrecondition::ExpectUnset)
        .await?;
    assert!(first.previous_generation().is_none());
    assert_eq!(first.active_generation().as_str(), "v1");
    assert_eq!(
        first.promoted_high_water_lsn(),
        consistency::Lsn::new(v1_high_water)
    );

    let stale = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Swap,
                tenant,
                v2.projection().as_str(),
            ),
            crate::ProjectionSwapAction,
            &v2,
            scope.clone(),
        )?
        .swap_active(crate::ProjectionPointerPrecondition::ExpectUnset)
        .await;
    assert!(matches!(
        stale,
        Err(crate::ProjectionControlError::CasConflict)
    ));

    let second = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Swap,
                tenant,
                v2.projection().as_str(),
            ),
            crate::ProjectionSwapAction,
            &v2,
            scope.clone(),
        )?
        .swap_active(
            crate::ProjectionPointerPrecondition::ExpectedActiveGeneration(
                eventexec::ProjectionVersion::parse("v1")?,
            ),
        )
        .await?;
    assert_eq!(
        second
            .previous_generation()
            .map(eventexec::ProjectionVersion::as_str),
        Some("v1")
    );
    assert_eq!(second.active_generation().as_str(), "v2");
    assert_eq!(
        second.promoted_high_water_lsn(),
        consistency::Lsn::new(v2_high_water)
    );

    let rollback = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Swap,
                tenant,
                v1.projection().as_str(),
            ),
            crate::ProjectionSwapAction,
            &v1,
            scope.clone(),
        )?
        .swap_active(
            crate::ProjectionPointerPrecondition::ExpectedActiveGeneration(
                eventexec::ProjectionVersion::parse("v2")?,
            ),
        )
        .await?;
    assert_eq!(rollback.active_generation().as_str(), "v1");
    assert_eq!(
        deps.authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Status,
                tenant,
                v1.projection().as_str(),
            ),
            crate::ProjectionStatusAction,
            &v1,
            scope,
        )?
        .status()
        .await?
        .active_generation()
        .map(eventexec::ProjectionVersion::as_str),
        Some("v1")
    );

    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;
    let mut read_tx = reader.pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *read_tx)
        .await?;
    let resolved: (String, String, String, String, i64, i64) = sqlx::query_as(
        "SELECT generation, definition_version, definition_schema_digest, \
                input_generation, promoted_high_water_lsn, token \
         FROM public.rss_settings_projection_resolve_active()",
    )
    .fetch_one(&mut *read_tx)
    .await?;
    assert_eq!(resolved.0, "v1");
    assert_eq!(
        resolved.1,
        generated::projection::settings_v3::CONTRACT.version()
    );
    assert_eq!(
        resolved.2,
        generated::projection::settings_v3::CONTRACT.schema_hash()
    );
    assert_eq!(resolved.3, generated::event::PROJECTION_INPUT_GENERATION);
    assert_eq!(resolved.4, i64::try_from(v1_high_water)?);
    assert_eq!(resolved.5, 3);
    assert!(
        sqlx::query("SELECT * FROM public.settings_projection_active_pointer")
            .execute(&mut *read_tx)
            .await
            .is_err(),
        "tenant reader must resolve through the fixed function, never raw pointer rows"
    );
    read_tx.rollback().await?;

    deps.shutdown().await?;
    operator.store_arc().shutdown().await?;
    reader.shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_active_swap_rejections_preserve_pointer_and_candidate_state() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    owner.run_migrations().await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let operator = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let operator_pool = &operator.store_arc().pool;
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == generated::projection::settings_v3::CONTRACT_ID)
        .ok_or_else(|| std::io::Error::other("generated Settings projection input is missing"))?;
    let definition = generated::projection::settings_v3::CONTRACT;

    for fixture in SwapRejectionFixture::ALL {
        let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
        let projection = eventexec::ProjectionId::parse(definition.contract_id())?;
        let baseline = eventexec::ProjectionSelector::new(
            tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse("baseline")?,
        );
        let target = eventexec::ProjectionSelector::new(
            tenant,
            projection,
            eventexec::ProjectionVersion::parse("candidate")?,
        );
        insert_settings_projection_generation(&owner, &baseline, 0).await?;
        sqlx::query(
            "INSERT INTO public.settings_projection_active_pointer (\
                 tenant_id, projection_id, generation, promoted_high_water_lsn, token\
             ) VALUES ($1::uuid, 'settings.config-projection', 'baseline', 0, 41)",
        )
        .bind(tenant.to_string())
        .execute(&owner.pool)
        .await?;

        let source_high_water = if fixture == SwapRejectionFixture::SourceMissing {
            None
        } else {
            append_projection_source_event_for_tenant(
                &app,
                binding,
                &unique_event_id(&format!("swap-rejection-{}", fixture.reason())),
                tenant,
            )
            .await?;
            Some(
                sqlx::query_scalar::<_, i64>(
                    "SELECT max(id) FROM public.projection_events \
                     WHERE metadata ->> 'tenantId' = $1",
                )
                .bind(tenant.to_string())
                .fetch_one(&owner.pool)
                .await?,
            )
        };
        let checkpoint_high_water = match fixture {
            SwapRejectionFixture::CheckpointMissing => None,
            SwapRejectionFixture::SourceMissing => Some(10),
            SwapRejectionFixture::CheckpointStale => Some(
                source_high_water
                    .ok_or_else(|| std::io::Error::other("fixture source is missing"))?
                    - 1,
            ),
            SwapRejectionFixture::CheckpointAhead => Some(
                source_high_water
                    .ok_or_else(|| std::io::Error::other("fixture source is missing"))?
                    + 1,
            ),
            _ => source_high_water,
        };
        let generation_high_water = match fixture {
            SwapRejectionFixture::CheckpointMissing => source_high_water
                .ok_or_else(|| std::io::Error::other("fixture source is missing"))?,
            SwapRejectionFixture::GenerationHighWaterMismatch => {
                source_high_water
                    .ok_or_else(|| std::io::Error::other("fixture source is missing"))?
                    + 1
            }
            _ => checkpoint_high_water.unwrap_or(0),
        };

        if fixture != SwapRejectionFixture::GenerationMissing {
            let definition_digest = if fixture == SwapRejectionFixture::DefinitionMismatch {
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            } else {
                definition.schema_hash()
            };
            let input_generation = if fixture == SwapRejectionFixture::InputGenerationMismatch {
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            } else {
                generated::event::PROJECTION_INPUT_GENERATION
            };
            sqlx::query(
                "INSERT INTO public.settings_projection_generations (\
                     tenant_id, projection_id, generation, definition_version,\
                     definition_schema_digest, input_generation, high_water_lsn\
                 ) VALUES ($1::uuid, 'settings.config-projection', 'candidate',\
                           $2, $3, $4, $5)",
            )
            .bind(tenant.to_string())
            .bind(definition.version())
            .bind(definition_digest)
            .bind(input_generation)
            .bind(generation_high_water)
            .execute(&owner.pool)
            .await?;
            let candidate_event_id = unique_event_id("candidate-retained");
            sqlx::query(
                "INSERT INTO public.settings_config_projection_rows (\
                     tenant_id, projection_id, generation, config_key, config_version,\
                     change_kind, source_event_id, source_lsn, source_occurred_at_secs\
                 ) VALUES ($1::uuid, 'settings.config-projection', 'candidate',\
                           $2, 1, 'published', $3, $4, 1)",
            )
            .bind(tenant.to_string())
            .bind(format!("candidate-{}", fixture.reason()))
            .bind(&candidate_event_id)
            .bind(generation_high_water)
            .execute(&owner.pool)
            .await?;
            sqlx::query(
                "INSERT INTO public.settings_projection_dedupe_receipts (\
                     tenant_id, projection_id, generation, source_event_id, source_lsn,\
                     fact_digest, actor, purpose\
                 ) VALUES ($1::uuid, 'settings.config-projection', 'candidate', $2, $3,\
                           $4, 'rss-projection-worker', 'background-worker')",
            )
            .bind(tenant.to_string())
            .bind(candidate_event_id)
            .bind(generation_high_water)
            .bind(vec![0x52_u8; 32])
            .execute(&owner.pool)
            .await?;
        }
        if let Some(checkpoint_high_water) = checkpoint_high_water {
            insert_projection_shadow_checkpoint(
                &owner,
                &target,
                u64::try_from(checkpoint_high_water)?,
            )
            .await?;
        }
        if fixture == SwapRejectionFixture::TargetQuarantined {
            sqlx::query(
                "INSERT INTO public.projection_worker_tenant_quarantine (\
                     tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn\
                 ) VALUES ($1::uuid, 'settings.config-projection', 'candidate',\
                           'quarantined', 'provider_permanent', $2)",
            )
            .bind(tenant.to_string())
            .bind(generation_high_water)
            .execute(&owner.pool)
            .await?;
        }

        let rejected = projection_operator_swap_once(
            operator_pool,
            &tenant.to_string(),
            target.version().as_str(),
            Some(baseline.version().as_str()),
            Some(41),
        )
        .await?;
        assert_eq!(rejected.outcome, "rejected", "fixture {fixture:?}");
        assert_eq!(
            rejected.reason.as_deref(),
            Some(fixture.reason()),
            "fixture {fixture:?}"
        );
        assert_eq!(rejected.previous_generation, None, "fixture {fixture:?}");
        assert_eq!(rejected.active_generation, None, "fixture {fixture:?}");
        assert_eq!(rejected.result_token, None, "fixture {fixture:?}");
        assert_eq!(
            rejected.promoted_high_water_lsn, None,
            "fixture {fixture:?}"
        );

        let state: SwapRejectionStateRow = sqlx::query_as(
            "SELECT pointer.generation, pointer.promoted_high_water_lsn, pointer.token, \
                    (SELECT count(*) FROM public.settings_projection_generations \
                     WHERE tenant_id = $1::uuid AND generation = 'candidate') \
                        AS candidate_generations, \
                    (SELECT count(*) FROM public.settings_config_projection_rows \
                     WHERE tenant_id = $1::uuid AND generation = 'candidate') \
                        AS candidate_rows, \
                    (SELECT count(*) FROM public.settings_projection_dedupe_receipts \
                     WHERE tenant_id = $1::uuid AND generation = 'candidate') \
                        AS candidate_receipts, \
                    (SELECT count(*) FROM public.checkpoint \
                     WHERE owner = 'projection:' || $1 \
                       AND checkpoint_id = 'settings.config-projection@candidate:shadow') \
                        AS candidate_checkpoints, \
                    (SELECT count(*) FROM public.projection_worker_tenant_quarantine \
                     WHERE tenant_scope_id = $1::uuid \
                       AND projection_id = 'settings.config-projection' \
                       AND target_generation = 'candidate') AS candidate_quarantines, \
                    (SELECT count(*) FROM public.projection_events \
                     WHERE metadata ->> 'tenantId' = $1) AS source_events \
             FROM public.settings_projection_active_pointer AS pointer \
             WHERE pointer.tenant_id = $1::uuid",
        )
        .bind(tenant.to_string())
        .fetch_one(&owner.pool)
        .await?;
        let candidate_count = i64::from(fixture != SwapRejectionFixture::GenerationMissing);
        let checkpoint_count = i64::from(checkpoint_high_water.is_some());
        let quarantine_count = i64::from(fixture == SwapRejectionFixture::TargetQuarantined);
        let source_count = i64::from(source_high_water.is_some());
        assert_eq!(state.generation, "baseline", "fixture {fixture:?}");
        assert_eq!(state.promoted_high_water_lsn, 0, "fixture {fixture:?}");
        assert_eq!(state.token, 41, "fixture {fixture:?}");
        assert_eq!(
            state.candidate_generations, candidate_count,
            "fixture {fixture:?}"
        );
        assert_eq!(state.candidate_rows, candidate_count, "fixture {fixture:?}");
        assert_eq!(
            state.candidate_receipts, candidate_count,
            "fixture {fixture:?}"
        );
        assert_eq!(
            state.candidate_checkpoints, checkpoint_count,
            "fixture {fixture:?}"
        );
        assert_eq!(
            state.candidate_quarantines, quarantine_count,
            "fixture {fixture:?}"
        );
        assert_eq!(state.source_events, source_count, "fixture {fixture:?}");
    }

    operator.store_arc().shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_query_request_pins_one_active_generation_across_swaps() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    owner.run_migrations().await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let operator = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let reader_config = rss_app_read_config(&pg, &owner).await?;
    let reader = crate::PgStore::connect_verified_read(&reader_config).await?;
    let resolver_calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let query_service = settings::SettingsProjectionQueryService::new(
        settings::ports::DynActiveProjectionResolver::new_box(CountingPgActiveProjectionResolver {
            inner: crate::PgActiveProjectionResolver::new(&reader),
            calls: std::sync::Arc::clone(&resolver_calls),
        }),
        settings::ports::DynSettingsProjectionReadRepo::new_box(
            crate::PgSettingsProjectionReadRepo::new(&reader),
        ),
    );

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == generated::projection::settings_v3::CONTRACT_ID)
        .ok_or_else(|| std::io::Error::other("generated Settings projection input is missing"))?;
    append_projection_source_event_for_tenant(
        &app,
        binding,
        &unique_event_id("settings-query-pin-source"),
        tenant,
    )
    .await?;
    let high_water: i64 = sqlx::query_scalar(
        "SELECT max(id) FROM public.projection_events \
         WHERE metadata ->> 'tenantId' = $1",
    )
    .bind(tenant.to_string())
    .fetch_one(&owner.pool)
    .await?;
    let projection =
        eventexec::ProjectionId::parse(generated::projection::settings_v3::CONTRACT_ID)?;
    let blue = eventexec::ProjectionSelector::new(
        tenant,
        projection.clone(),
        eventexec::ProjectionVersion::parse("blue")?,
    );
    let green = eventexec::ProjectionSelector::new(
        tenant,
        projection,
        eventexec::ProjectionVersion::parse("green")?,
    );
    for selector in [&blue, &green] {
        insert_settings_projection_generation(&owner, selector, u64::try_from(high_water)?).await?;
        insert_projection_shadow_checkpoint(&owner, selector, u64::try_from(high_water)?).await?;
    }
    for (generation, config_version, event_id) in [
        ("blue", 11_i64, "settings-query-blue"),
        ("green", 22_i64, "settings-query-green"),
    ] {
        sqlx::query(
            "INSERT INTO public.settings_config_projection_rows (\
                 tenant_id, projection_id, generation, config_key, config_version, change_kind,\
                 source_event_id, source_lsn, source_occurred_at_secs\
             ) VALUES ($1::uuid, 'settings.config-projection', $2, 'projection.metadata', $3,\
                       'published', $4, $5, 1)",
        )
        .bind(tenant.to_string())
        .bind(generation)
        .bind(config_version)
        .bind(event_id)
        .bind(high_water)
        .execute(&owner.pool)
        .await?;
    }

    let initial = projection_operator_swap_once(
        operator.pool(),
        &tenant.to_string(),
        blue.version().as_str(),
        None,
        None,
    )
    .await?;
    assert_eq!(initial.outcome, "applied");
    assert_eq!(initial.active_generation.as_deref(), Some("blue"));
    assert_eq!(initial.result_token, Some(1));

    let tenant_scope = settings::ports::TenantRepoScope::for_test(tenant);
    let key = settings::ports::SettingKey::parse("projection.metadata")?;
    let request_a = query_service.begin(tenant_scope).await?;
    assert_eq!(request_a.snapshot().generation().as_str(), "blue");
    assert_eq!(resolver_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let promoted_green = projection_operator_swap_once(
        operator.pool(),
        &tenant.to_string(),
        green.version().as_str(),
        Some(blue.version().as_str()),
        Some(1),
    )
    .await?;
    assert_eq!(promoted_green.outcome, "applied");
    assert_eq!(promoted_green.active_generation.as_deref(), Some("green"));
    assert_eq!(promoted_green.result_token, Some(2));

    let row_a = request_a
        .find(&key)
        .await?
        .ok_or_else(|| std::io::Error::other("request A blue row is missing"))?;
    assert_eq!(row_a.generation().as_str(), "blue");
    assert_eq!(row_a.config_version(), 11);
    assert_eq!(request_a.snapshot().generation(), row_a.generation());
    assert_eq!(
        resolver_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "request A must not re-resolve after green is promoted"
    );

    let request_b = query_service.begin(tenant_scope).await?;
    let row_b = request_b
        .find(&key)
        .await?
        .ok_or_else(|| std::io::Error::other("request B green row is missing"))?;
    assert_eq!(request_b.snapshot().generation().as_str(), "green");
    assert_eq!(row_b.generation().as_str(), "green");
    assert_eq!(row_b.config_version(), 22);
    assert_eq!(request_b.snapshot().generation(), row_b.generation());
    assert_eq!(
        resolver_calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "request B must resolve exactly once"
    );

    let rolled_back_blue = projection_operator_swap_once(
        operator.pool(),
        &tenant.to_string(),
        blue.version().as_str(),
        Some(green.version().as_str()),
        Some(2),
    )
    .await?;
    assert_eq!(rolled_back_blue.outcome, "applied");
    assert_eq!(rolled_back_blue.active_generation.as_deref(), Some("blue"));
    assert_eq!(rolled_back_blue.result_token, Some(3));

    let request_c = query_service.begin(tenant_scope).await?;
    let row_c = request_c
        .find(&key)
        .await?
        .ok_or_else(|| std::io::Error::other("request C blue row is missing"))?;
    assert_eq!(request_c.snapshot().generation().as_str(), "blue");
    assert_eq!(row_c.generation().as_str(), "blue");
    assert_eq!(row_c.config_version(), 11);
    assert_eq!(request_c.snapshot().generation(), row_c.generation());
    assert_eq!(
        resolver_calls.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "each request must invoke the production resolver exactly once"
    );
    let retained_green: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.settings_config_projection_rows \
         WHERE tenant_id = $1::uuid AND generation = 'green' \
           AND config_key = 'projection.metadata' AND config_version = 22",
    )
    .bind(tenant.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        retained_green, 1,
        "rollback must retain green candidate data"
    );

    operator.store_arc().shutdown().await?;
    reader.store_arc().shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_active_swap_serializes_concurrent_generation_changes() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    owner.run_migrations().await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let operator = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let pool = operator.store_arc().pool.clone();
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == generated::projection::settings_v3::CONTRACT_ID)
        .ok_or_else(|| std::io::Error::other("generated Settings projection input is missing"))?;
    append_projection_source_event_for_tenant(
        &app,
        binding,
        &unique_event_id("settings-active-swap-concurrency"),
        tenant,
    )
    .await?;
    let high_water: i64 = sqlx::query_scalar(
        "SELECT max(id) FROM public.projection_events \
         WHERE metadata ->> 'tenantId' = $1",
    )
    .bind(tenant.to_string())
    .fetch_one(&owner.pool)
    .await?;
    for generation in ["blue", "green", "red"] {
        let selector = eventexec::ProjectionSelector::new(
            tenant,
            eventexec::ProjectionId::parse(generated::projection::settings_v3::CONTRACT_ID)?,
            eventexec::ProjectionVersion::parse(generation)?,
        );
        insert_settings_projection_generation(&owner, &selector, u64::try_from(high_water)?)
            .await?;
        insert_projection_shadow_checkpoint(&owner, &selector, u64::try_from(high_water)?).await?;
    }

    let initial_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let initial_a = tokio::spawn(projection_operator_swap_call(
        pool.clone(),
        Arc::clone(&initial_barrier),
        tenant.to_string(),
        "blue".to_owned(),
        None,
        None,
    ));
    let initial_b = tokio::spawn(projection_operator_swap_call(
        pool.clone(),
        Arc::clone(&initial_barrier),
        tenant.to_string(),
        "green".to_owned(),
        None,
        None,
    ));
    let initial_results = [initial_a.await??, initial_b.await??];
    assert_eq!(
        initial_results
            .iter()
            .filter(|row| row.outcome == "applied" && row.result_token == Some(1))
            .count(),
        1,
        "exactly one concurrent ExpectUnset mutation must apply"
    );
    assert_eq!(
        initial_results
            .iter()
            .filter(|row| row.outcome == "conflict" && row.result_token == Some(1))
            .count(),
        1,
        "the concurrent ExpectUnset loser must observe the installed pointer"
    );
    let (initial_generation, initial_token): (String, i64) = sqlx::query_as(
        "SELECT generation, token \
         FROM public.rss_projection_operator_status_active($1::uuid)",
    )
    .bind(tenant.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(initial_token, 1);
    let (update_a_generation, update_b_generation) = if initial_generation == "blue" {
        ("green", "red")
    } else {
        ("blue", "red")
    };

    let update_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let update_a = tokio::spawn(projection_operator_swap_call(
        pool.clone(),
        Arc::clone(&update_barrier),
        tenant.to_string(),
        update_a_generation.to_owned(),
        Some(initial_generation.clone()),
        Some(1),
    ));
    let update_b = tokio::spawn(projection_operator_swap_call(
        pool.clone(),
        Arc::clone(&update_barrier),
        tenant.to_string(),
        update_b_generation.to_owned(),
        Some(initial_generation.clone()),
        Some(1),
    ));
    let update_results = [update_a.await??, update_b.await??];
    assert_eq!(
        update_results
            .iter()
            .filter(|row| row.outcome == "applied" && row.result_token == Some(2))
            .count(),
        1,
        "exactly one same-token concurrent update must apply"
    );
    assert_eq!(
        update_results
            .iter()
            .filter(|row| row.outcome == "fenced" && row.result_token == Some(2))
            .count(),
        1,
        "the stale concurrent update must be fenced deterministically"
    );
    let final_row: (String, i64) = sqlx::query_as(
        "SELECT generation, token \
         FROM public.rss_projection_operator_status_active($1::uuid)",
    )
    .bind(tenant.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(final_row.1, 2);
    assert!(final_row.0 == update_a_generation || final_row.0 == update_b_generation);

    operator.store_arc().shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_first_apply_read_update_tombstone_and_scope_isolation() -> TestResult {
    use eventexec::ProjectionTargetStoreOutcome;
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    let (_app, reader, writer) = settings_projection_runtime_parts(&owner, &fixture).await?;
    let tenant_a = vocab::TenantId::parse(COTX_TENANT_A)?;
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B)?;
    let generation = format!("settings-red-{}", uuid::Uuid::new_v4().simple());
    let other_generation = format!("settings-red-{}", uuid::Uuid::new_v4().simple());
    let key = settings::ports::SettingKey::parse("projection.metadata")?;
    let scope = settings_projection_apply_scope(tenant_a, &generation)?;

    assert!(
        reader
            .find(settings_projection_read_scope(tenant_a, &generation)?, &key)
            .await?
            .is_none()
    );
    let first_event = unique_event_id("settings-projection-first");
    assert_eq!(
        writer
            .apply(
                scope.clone(),
                settings_projection_mutation(
                    &scope,
                    tenant_a,
                    key.as_str(),
                    1,
                    SettingsConfigChangeKind::Published,
                    TEST_OCCURRED_SECS,
                    &first_event,
                    10,
                    [0x11; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied
    );
    let first = reader
        .find(settings_projection_read_scope(tenant_a, &generation)?, &key)
        .await?
        .ok_or("first Settings projection row missing")?;
    assert_eq!(first.tenant(), tenant_a);
    assert_eq!(first.generation().as_str(), generation);
    assert_eq!(first.key(), &key);
    assert_eq!(first.config_version(), 1);
    assert_eq!(first.change_kind(), SettingsConfigChangeKind::Published);
    assert_eq!(first.source_event_id(), first_event);
    assert_eq!(first.source_lsn(), consistency::Lsn::new(10));
    assert_eq!(first.source_occurred_at_secs(), TEST_OCCURRED_SECS);

    let update_event = unique_event_id("settings-projection-update");
    assert_eq!(
        writer
            .apply(
                scope.clone(),
                settings_projection_mutation(
                    &scope,
                    tenant_a,
                    key.as_str(),
                    2,
                    SettingsConfigChangeKind::RolledBack,
                    TEST_OCCURRED_SECS + 1,
                    &update_event,
                    11,
                    [0x22; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied
    );
    let rolled_back = reader
        .find(settings_projection_read_scope(tenant_a, &generation)?, &key)
        .await?
        .ok_or("Settings projection rollback row missing")?;
    assert_eq!(rolled_back.config_version(), 2);
    assert_eq!(
        rolled_back.change_kind(),
        SettingsConfigChangeKind::RolledBack
    );
    assert_eq!(rolled_back.source_event_id(), update_event);
    assert_eq!(rolled_back.source_lsn(), consistency::Lsn::new(11));
    assert_eq!(
        rolled_back.source_occurred_at_secs(),
        TEST_OCCURRED_SECS + 1
    );
    let delete_event = unique_event_id("settings-projection-delete");
    assert_eq!(
        writer
            .apply(
                scope.clone(),
                settings_projection_mutation(
                    &scope,
                    tenant_a,
                    key.as_str(),
                    3,
                    SettingsConfigChangeKind::Deleted,
                    TEST_OCCURRED_SECS + 2,
                    &delete_event,
                    12,
                    [0x33; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied
    );
    let tombstone = reader
        .find(settings_projection_read_scope(tenant_a, &generation)?, &key)
        .await?
        .ok_or("Settings projection tombstone missing")?;
    assert_eq!(tombstone.config_version(), 3);
    assert_eq!(tombstone.change_kind(), SettingsConfigChangeKind::Deleted);

    assert!(
        reader
            .find(settings_projection_read_scope(tenant_b, &generation)?, &key)
            .await?
            .is_none(),
        "RLS must hide another tenant's current row"
    );
    assert!(
        reader
            .find(
                settings_projection_read_scope(tenant_a, &other_generation)?,
                &key,
            )
            .await?
            .is_none(),
        "a generation selector must not fall back to another generation"
    );

    let second_scope = settings_projection_apply_scope(tenant_a, &other_generation)?;
    assert_eq!(
        writer
            .apply(
                second_scope.clone(),
                settings_projection_mutation(
                    &second_scope,
                    tenant_a,
                    key.as_str(),
                    1,
                    SettingsConfigChangeKind::Published,
                    TEST_OCCURRED_SECS,
                    &unique_event_id("settings-projection-other-generation"),
                    1,
                    [0x44; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied,
        "a new generation owns independent version and ordering state"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_real_roles_enforce_rls_and_exact_acl_negatives() -> TestResult {
    use eventexec::ProjectionTargetStoreOutcome;
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    let (app, _repo_reader, writer) = settings_projection_runtime_parts(&owner, &fixture).await?;
    let reader = connect_pg_rss_app_read_role(&fixture, &owner).await?;
    let tenant_a = vocab::TenantId::parse(COTX_TENANT_A)?;
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B)?;
    let generation = format!("settings-rls-{}", uuid::Uuid::new_v4().simple());
    let scope = settings_projection_apply_scope(tenant_a, &generation)?;
    assert_eq!(
        writer
            .apply(
                scope.clone(),
                settings_projection_mutation(
                    &scope,
                    tenant_a,
                    "projection.rls",
                    1,
                    SettingsConfigChangeKind::Published,
                    TEST_OCCURRED_SECS,
                    &unique_event_id("settings-projection-rls"),
                    1,
                    [0xa1; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied
    );

    let mut cross_tenant = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant_b.to_string())
        .execute(&mut *cross_tenant)
        .await?;
    let hidden = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM public.settings_config_projection_rows \
         WHERE tenant_id = $1::uuid AND generation = $2",
    )
    .bind(tenant_a.to_string())
    .bind(&generation)
    .fetch_one(&mut *cross_tenant)
    .await?;
    assert_eq!(
        hidden, 0,
        "RLS must hide an explicitly addressed other-tenant row"
    );
    let cross_insert = sqlx::query(
        "INSERT INTO public.settings_projection_generations (tenant_id, projection_id, \
         generation, definition_version, definition_schema_digest, input_generation, high_water_lsn) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6, NULL)",
    )
    .bind(tenant_a.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(format!("settings-cross-{}", uuid::Uuid::new_v4().simple()))
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&mut *cross_tenant)
    .await;
    assert!(
        matches!(cross_insert, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "writer cross-tenant insert must be rejected by WITH CHECK: {cross_insert:?}"
    );
    cross_tenant.rollback().await?;

    let mut reader_tx = reader.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant_b.to_string())
        .execute(&mut *reader_tx)
        .await?;
    let reader_hidden = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM public.settings_config_projection_rows \
         WHERE tenant_id = $1::uuid AND generation = $2",
    )
    .bind(tenant_a.to_string())
    .bind(&generation)
    .fetch_one(&mut *reader_tx)
    .await?;
    assert_eq!(reader_hidden, 0);
    let reader_insert = sqlx::query(
        "INSERT INTO public.settings_projection_generations (tenant_id, projection_id, \
         generation, definition_version, definition_schema_digest, input_generation) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(tenant_b.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(format!(
        "settings-reader-write-{}",
        uuid::Uuid::new_v4().simple()
    ))
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&mut *reader_tx)
    .await;
    assert!(reader_insert.is_err(), "rss_app_read must not insert");
    reader_tx.rollback().await?;

    let rls: (bool, i64) = sqlx::query_as(
        "SELECT bool_and(c.relrowsecurity AND c.relforcerowsecurity), \
            (SELECT count(*) FROM pg_catalog.pg_policies p \
             WHERE p.schemaname = 'public' AND p.policyname = 'tenant_isolation' \
               AND p.tablename = ANY($1::text[])) \
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = ANY($1::text[])",
    )
    .bind(vec![
        "settings_projection_generations",
        "settings_config_projection_rows",
        "settings_projection_dedupe_receipts",
    ])
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(rls, (true, 3));

    let acl: (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT \
          has_table_privilege('rss_app_read', 'public.settings_config_projection_rows', 'SELECT'), \
          has_table_privilege('rss_app_read', 'public.settings_config_projection_rows', 'INSERT'), \
          has_table_privilege('rss_app', 'public.settings_projection_dedupe_receipts', 'UPDATE'), \
          has_table_privilege('rss_app', 'public.settings_projection_generations', 'DELETE'), \
          has_table_privilege('rss_app', 'public.settings_config_projection_rows', 'DELETE'), \
          has_table_privilege('rss_app', 'public.settings_projection_dedupe_receipts', 'DELETE'), \
          has_table_privilege('rss_app', 'public.settings_projection_generations', 'TRUNCATE'), \
          has_table_privilege('rss_app', 'public.settings_config_projection_rows', 'TRUNCATE'), \
          has_table_privilege('rss_app_read', 'public.settings_config_projection_rows', 'UPDATE'), \
          has_table_privilege('rss_app_read', 'public.settings_config_projection_rows', 'DELETE'), \
          has_table_privilege('rss_app', 'public.settings_projection_dedupe_receipts', 'TRUNCATE'), \
          has_table_privilege('rss_app_read', 'public.settings_projection_active_pointer', 'SELECT')",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        acl,
        (
            true, false, false, false, false, false, false, false, false, false, false, false
        )
    );

    let funnel_acl: (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
          to_regprocedure('public.rss_settings_projection_apply(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)') IS NULL, \
          has_function_privilege('rss_app', 'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE'), \
          has_function_privilege('rss_projection_operator', 'public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE'), \
          has_function_privilege('rss_projection_worker', 'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE'), \
          NOT has_function_privilege('rss_projection_operator', 'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE'), \
          NOT has_function_privilege('rss_projection_worker', 'public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE'), \
          NOT has_function_privilege('public', 'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE') \
            AND NOT has_function_privilege('public', 'public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)', 'EXECUTE'), \
          has_table_privilege('rss_app', 'public.settings_projection_generations', 'INSERT,UPDATE'), \
          has_table_privilege('rss_projection_operator', 'public.settings_projection_dedupe_receipts', 'INSERT,UPDATE'), \
          NOT EXISTS (SELECT 1 FROM information_schema.role_table_grants \
                      WHERE grantee = 'rss_projection_worker' AND table_schema = 'public'), \
          NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c \
                       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                       JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid \
                      WHERE n.nspname = 'public' \
                        AND c.relname = ANY(ARRAY['settings_projection_generations', 'settings_config_projection_rows', 'settings_projection_dedupe_receipts']) \
                        AND a.attnum > 0 AND NOT a.attisdropped \
                        AND (has_column_privilege('rss_app', c.oid, a.attnum, 'INSERT') \
                             OR has_column_privilege('rss_app', c.oid, a.attnum, 'UPDATE'))), \
          (SELECT count(*) = 2 FROM pg_catalog.pg_roles WHERE rolname IN \
             ('rss_projection_operator_owner', 'rss_projection_worker_owner') \
             AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        funnel_acl,
        (
            true, false, true, true, true, true, true, false, false, true, true, true
        ),
        "worker/operator purpose entrypoints and raw-table denial must be exact"
    );

    provision_runtime_logins(&fixture).await?;
    let operator = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    assert_settings_funnel_requires_bound_tenant(
        &operator.store_arc().pool,
        tenant_a,
        tenant_b,
        "operator",
    )
    .await?;

    let drift_generation = format!("settings-drift-{}", uuid::Uuid::new_v4().simple());
    let identity_drift = sqlx::query_scalar::<_, String>(
        "SELECT public.rss_settings_projection_apply_operator(\
             $1::uuid, $2, $3, 'v999', $4, $5, 'projection.drift', 1, 'published', \
             'settings-identity-drift', 2, $6, $7\
         )",
    )
    .bind(tenant_a.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&drift_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x44_u8; 32])
    .fetch_one(&operator.store_arc().pool)
    .await;
    assert!(
        matches!(identity_drift, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1901")),
        "direct SQL definition drift must fail before persistence: {identity_drift:?}"
    );
    let drift_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.settings_projection_generations WHERE generation = $1",
    )
    .bind(&drift_generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(drift_rows, 0, "identity drift must not create a generation");

    let mut receipt_update = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant_a.to_string())
        .execute(&mut *receipt_update)
        .await?;
    let denied = sqlx::query(
        "UPDATE public.settings_projection_dedupe_receipts SET fact_digest = $1 \
         WHERE tenant_id = $2::uuid AND generation = $3",
    )
    .bind(vec![0xff_u8; 32])
    .bind(tenant_a.to_string())
    .bind(&generation)
    .execute(&mut *receipt_update)
    .await;
    assert!(
        matches!(denied, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "receipt UPDATE must be privilege denied: {denied:?}"
    );
    receipt_update.rollback().await?;

    let reader_config = rss_app_read_config(&fixture, &owner).await?;
    sqlx::query("GRANT SELECT ON TABLE public.settings_projection_active_pointer TO rss_app_read")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgStore::connect_verified_read(&reader_config).await,
        Err(PgError::TenantReadRelationPrivileges)
    ));
    sqlx::query(
        "REVOKE SELECT ON TABLE public.settings_projection_active_pointer FROM rss_app_read",
    )
    .execute(&owner.pool)
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_operator_lane_reuses_the_only_apply_function() -> TestResult {
    use eventexec::ProjectionTargetStoreOutcome;
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    provision_runtime_logins(&fixture).await?;
    owner.run_migrations().await?;
    let operator = crate::PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let writer = SettingsTargetHarness::new(std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_operator(&operator),
    ));
    let tenant = vocab::TenantId::parse(COTX_TENANT_A)?;
    let generation = format!("settings-operator-{}", uuid::Uuid::new_v4().simple());
    let scope = settings_projection_apply_scope(tenant, &generation)?;
    assert_eq!(
        writer
            .apply(
                scope.clone(),
                settings_projection_mutation(
                    &scope,
                    tenant,
                    "projection.operator",
                    1,
                    SettingsConfigChangeKind::Published,
                    TEST_OCCURRED_SECS,
                    &unique_event_id("settings-projection-operator"),
                    1,
                    [0x7a; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied
    );
    let state: (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM public.settings_config_projection_rows WHERE tenant_id = $1::uuid AND generation = $2), \
           (SELECT count(*) FROM public.settings_projection_dedupe_receipts WHERE tenant_id = $1::uuid AND generation = $2), \
           (SELECT high_water_lsn FROM public.settings_projection_generations WHERE tenant_id = $1::uuid AND generation = $2)",
    )
    .bind(tenant.to_string())
    .bind(&generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(state, (1, 1, Some(1)));

    let denied = sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts \
         (tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest) \
         VALUES ($1::uuid, $2, $3, 'raw-bypass', 2, $4)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .bind(vec![0x7b_u8; 32])
    .execute(&operator.store_arc().pool)
    .await;
    assert!(
        matches!(denied, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "operator raw table write must remain privilege denied: {denied:?}"
    );
    operator.store_arc().shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_worker_role_is_function_only_and_purpose_bound() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    register_generated_projection_input_catalog(&owner).await?;
    let worker = PgStore::connect_verified_projection_worker(
        &crate::PgProjectionWorkerConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_WORKER_ROLE,
            TEST_PROJECTION_WORKER_PASSWORD,
        )),
    )
    .await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let generation = "v3".to_owned();
    let event_id = unique_event_id("settings-worker-purpose");
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, NULL)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_active_pointer (\
             tenant_id, projection_id, generation, promoted_high_water_lsn, token\
         ) VALUES ($1::uuid, $2, $3, 0, 1)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .execute(&owner.pool)
    .await?;

    let tenants: Vec<String> = sqlx::query_scalar(
        "SELECT tenant_id::text FROM public.rss_projection_worker_list_tenants(\
         $1, $2, $3, $4, NULL::uuid, 100)",
    )
    .bind(SETTINGS_PROJECTION_ID)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_all(worker.pool_for_integration())
    .await?;
    assert!(tenants.is_empty());

    let mut denied_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *denied_tx)
        .await?;
    let arbitrary_generation = sqlx::query_scalar::<_, String>(
        "SELECT public.rss_settings_projection_apply_worker(\
         $1::uuid, $2, 'worker-controlled-generation', $3, $4, $5, \
         'projection.worker', 1, 'published', $6, 1, $7, $8)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(&event_id)
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x5c_u8; 32])
    .fetch_one(&mut *denied_tx)
    .await;
    assert!(
        matches!(arbitrary_generation, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1901")),
        "worker must not materialize a generation outside the tenant active pointer: {arbitrary_generation:?}"
    );
    denied_tx.rollback().await?;

    let mut tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let applied: String = sqlx::query_scalar(
        "SELECT public.rss_settings_projection_apply_worker(\
         $1::uuid, $2, $3, $4, $5, $6, 'projection.worker', 1, 'published', \
         $7, 1, $8, $9)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(&event_id)
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x5c_u8; 32])
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(applied, "applied");
    let duplicate: String = sqlx::query_scalar(
        "SELECT public.rss_settings_projection_apply_worker(\
         $1::uuid, $2, $3, $4, $5, $6, 'projection.worker', 1, 'published', \
         $7, 1, $8, $9)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(&event_id)
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x5c_u8; 32])
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(duplicate, "duplicate");
    let saved: bool = sqlx::query_scalar(
        "SELECT public.rss_projection_worker_save_checkpoint(\
         $1::uuid, $2, 'v3', $3, $4, $5, 1, 0)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *tx)
    .await?;
    assert!(saved);
    let checkpoint: Option<(i64, i64)> = sqlx::query_as(
        "SELECT offset_lsn, version FROM public.rss_projection_worker_get_checkpoint(\
         $1::uuid, $2, 'v3', $3, $4, $5)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_optional(&mut *tx)
    .await?;
    assert_eq!(checkpoint, Some((1, 1)));
    tx.commit().await?;

    let attribution: (String, String) = sqlx::query_as(
        "SELECT actor, purpose FROM public.settings_projection_dedupe_receipts \
         WHERE tenant_id = $1::uuid AND generation = $2 AND source_event_id = $3",
    )
    .bind(tenant.to_string())
    .bind(&generation)
    .bind(&event_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        attribution,
        (
            "rss-projection-worker".to_owned(),
            "background-worker".to_owned()
        )
    );
    let rollback_generation = "rollback-blue";
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, NULL)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "UPDATE public.settings_projection_active_pointer \
         SET generation = $2, promoted_high_water_lsn = 0, token = 2, \
             updated_at = pg_catalog.now() \
         WHERE tenant_id = $1::uuid AND projection_id = $3",
    )
    .bind(tenant.to_string())
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_ID)
    .execute(&owner.pool)
    .await?;
    let mut rollback_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *rollback_tx)
        .await?;
    let rollback_event = unique_event_id("settings-worker-rollback-generation");
    let rollback_applied: String = sqlx::query_scalar(
        "SELECT public.rss_settings_projection_apply_worker(\
         $1::uuid, $2, $3, $4, $5, $6, 'projection.worker.rollback', 1, 'published', \
         $7, 1, $8, $9)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(&rollback_event)
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x6c_u8; 32])
    .fetch_one(&mut *rollback_tx)
    .await?;
    assert_eq!(rollback_applied, "applied");
    rollback_tx.commit().await?;
    sqlx::query(
        "INSERT INTO public.projection_worker_tenant_quarantine (\
             tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn\
         ) VALUES ($1::uuid, $2, $3, 'quarantined', 'provider_permanent', 1)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .execute(&owner.pool)
    .await?;
    let mut resolver_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *resolver_tx)
        .await?;
    let resolved: (String, i64) = sqlx::query_as(
        "SELECT generation, token FROM public.rss_settings_projection_resolve_active()",
    )
    .fetch_one(&mut *resolver_tx)
    .await?;
    assert_eq!(resolved, (rollback_generation.to_owned(), 2));
    resolver_tx.rollback().await?;
    let mut quarantine_probe = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *quarantine_probe)
        .await?;
    let selected_is_quarantined: bool = sqlx::query_scalar(
        "SELECT public.rss_projection_worker_tenant_is_quarantined(\
             $1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *quarantine_probe)
    .await?;
    assert!(selected_is_quarantined);
    let bootstrap_is_quarantined = sqlx::query_scalar::<_, bool>(
        "SELECT public.rss_projection_worker_tenant_is_quarantined(\
             $1::uuid, $2, 'v3', $3, $4, $5)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *quarantine_probe)
    .await;
    assert!(
        matches!(bootstrap_is_quarantined, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("22023")),
        "non-active generation quarantine probes must fail closed: {bootstrap_is_quarantined:?}"
    );
    quarantine_probe.rollback().await?;

    let raw_write = sqlx::query(
        "UPDATE public.settings_projection_dedupe_receipts SET fact_digest = fact_digest \
         WHERE tenant_id = $1::uuid AND generation = $2",
    )
    .bind(tenant.to_string())
    .bind(&generation)
    .execute(worker.pool_for_integration())
    .await;
    assert!(
        matches!(raw_write, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "worker raw relation mutation must be denied: {raw_write:?}"
    );
    let operator_apply = sqlx::query_scalar::<_, String>(
        "SELECT public.rss_settings_projection_apply_operator(\
         $1::uuid, $2, $3, $4, $5, $6, 'projection.worker', 2, 'published', \
         'worker-cross-purpose', 2, $7, $8)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .bind(TEST_OCCURRED_SECS as i64)
    .bind(vec![0x5d_u8; 32])
    .fetch_one(worker.pool_for_integration())
    .await;
    assert!(
        matches!(operator_apply, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "worker must not cross into operator apply: {operator_apply:?}"
    );

    let observe_selector = eventexec::ProjectionSelector::new(
        tenant,
        eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)?,
        eventexec::ProjectionVersion::parse(rollback_generation)?,
    );
    let observe_checkpoint_id = observe_selector.shadow_checkpoint_id();
    let observe_owner = observe_selector.shadow_checkpoint_owner();
    sqlx::query(
        "INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version, updated_at) \
         VALUES ($1, $2, 40, 1, to_timestamp(1_700_000_000)) \
         ON CONFLICT (owner, checkpoint_id) DO UPDATE \
         SET offset_lsn = EXCLUDED.offset_lsn, version = EXCLUDED.version, \
             updated_at = EXCLUDED.updated_at",
    )
    .bind(observe_owner.as_str())
    .bind(observe_checkpoint_id.as_str())
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.dead_letter (\
             tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic, \
             consumer_group, replay_capsule, replay_capsule_key_ref, payload_len, \
             replay_capsule_encoding, metadata_digest, error_summary, num_attempts, source_kind\
         ) VALUES (\
             $1::uuid, 'observe-dlq-1', 'settings', 'settings', 'settings.config-version-changed', \
             'settings.config-version-changed', $2, $3::jsonb, 'key', 0, \
             'key-provider-v3', decode(repeat('ab', 32), 'hex'), 'observe', 1, 'projection') \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant.to_string())
    .bind(observe_checkpoint_id.as_str())
    .bind(r#"{"ciphertext":[]}"#)
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_events (\
             event_id, domain, aggregate_id, event_type, payload, \
             contract_id, contract_version, schema_hash, metadata\
         )
         SELECT $1, binding.source_domain, $1, binding.topic, decode('00', 'hex'), \
                binding.contract_id, binding.contract_version, binding.schema_hash, \
                jsonb_build_object('tenantId', $2::text)
         FROM public.projection_input_bindings AS binding
         WHERE binding.generation = $3
         LIMIT 1",
    )
    .bind(unique_event_id("observe-hw"))
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await?;
    let mut observe_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *observe_tx)
        .await?;
    let expected_high_water: Option<i64> = sqlx::query_scalar(
        "SELECT public.rss_projection_worker_source_high_water(\
             $1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *observe_tx)
    .await?;
    let observed: (Option<i64>, Option<i64>, Option<i64>, i64) =
        sqlx::query_as(crate::projection_worker::PROJECTION_WORKER_OBSERVE_TENANT_SQL)
            .bind(tenant.to_string())
            .bind(SETTINGS_PROJECTION_ID)
            .bind(rollback_generation)
            .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
            .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
            .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
            .fetch_one(&mut *observe_tx)
            .await?;
    assert_eq!(observed.0, expected_high_water);
    assert_eq!(observed.1, Some(40));
    let expected_updated: i64 = sqlx::query_scalar(
        "SELECT (pg_catalog.date_part('epoch', updated_at) * 1000000)::bigint \
         FROM public.checkpoint WHERE owner = $1 AND checkpoint_id = $2",
    )
    .bind(observe_owner.as_str())
    .bind(observe_checkpoint_id.as_str())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(observed.2, Some(expected_updated));
    assert!(
        observed.3 >= 1,
        "projection-origin DLQ backlog must be visible"
    );
    let foreign = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let cross_tenant = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>, i64)>(
        crate::projection_worker::PROJECTION_WORKER_OBSERVE_TENANT_SQL,
    )
    .bind(foreign.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *observe_tx)
    .await;
    assert!(
        matches!(cross_tenant, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("22023")),
        "observe must refuse cross-tenant reads: {cross_tenant:?}"
    );
    observe_tx.rollback().await?;

    let mut wrong_generation_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *wrong_generation_tx)
        .await?;
    let wrong_generation = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>, i64)>(
        crate::projection_worker::PROJECTION_WORKER_OBSERVE_TENANT_SQL,
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind("not-the-active-generation")
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *wrong_generation_tx)
    .await;
    assert!(
        matches!(wrong_generation, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("22023")),
        "observe must refuse wrong target_generation: {wrong_generation:?}"
    );
    wrong_generation_tx.rollback().await?;

    let mut wrong_digest_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *wrong_digest_tx)
        .await?;
    let wrong_digest = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>, i64)>(
        crate::projection_worker::PROJECTION_WORKER_OBSERVE_TENANT_SQL,
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(rollback_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *wrong_digest_tx)
    .await;
    assert!(
        matches!(wrong_digest, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("22023")),
        "observe must refuse wrong definition digest: {wrong_digest:?}"
    );
    wrong_digest_tx.rollback().await?;

    // Missing checkpoint must not surface a fake freshness via the observe row.
    sqlx::query("DELETE FROM public.checkpoint WHERE owner = $1 AND checkpoint_id = $2")
        .bind(observe_owner.as_str())
        .bind(observe_checkpoint_id.as_str())
        .execute(&owner.pool)
        .await?;
    let mut missing_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *missing_tx)
        .await?;
    let missing_cp: (Option<i64>, Option<i64>, Option<i64>, i64) =
        sqlx::query_as(crate::projection_worker::PROJECTION_WORKER_OBSERVE_TENANT_SQL)
            .bind(tenant.to_string())
            .bind(SETTINGS_PROJECTION_ID)
            .bind(rollback_generation)
            .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
            .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
            .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
            .fetch_one(&mut *missing_tx)
            .await?;
    assert_eq!(missing_cp.1, None);
    assert_eq!(missing_cp.2, None);
    missing_tx.rollback().await?;

    worker.shutdown_for_integration().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_worker_quarantine_survives_restart_and_operator_recovery() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&fixture, &owner).await?;
    let binding = generated::event::PROJECTION_INPUTS
        .iter()
        .copied()
        .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
        .ok_or_else(|| std::io::Error::other("Settings projection binding is missing"))?;
    let quarantined = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let healthy = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let quarantined_generation = "quarantine-blue";
    let healthy_generation = "healthy-green";
    append_projection_source_event_for_tenant(
        &app,
        binding,
        &unique_event_id("projection-quarantine"),
        quarantined,
    )
    .await?;
    for (tenant, generation) in [
        (quarantined, quarantined_generation),
        (healthy, healthy_generation),
    ] {
        sqlx::query(
            "INSERT INTO public.settings_projection_generations (\
                 tenant_id, projection_id, generation, definition_version, \
                 definition_schema_digest, input_generation, high_water_lsn\
             ) VALUES ($1::uuid, $2, $3, $4, $5, $6, 0)",
        )
        .bind(tenant.to_string())
        .bind(SETTINGS_PROJECTION_ID)
        .bind(generation)
        .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
        .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
        .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
        .execute(&owner.pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.settings_projection_active_pointer (\
                 tenant_id, projection_id, generation, promoted_high_water_lsn, token\
             ) VALUES ($1::uuid, $2, $3, 0, 1)",
        )
        .bind(tenant.to_string())
        .bind(SETTINGS_PROJECTION_ID)
        .bind(generation)
        .execute(&owner.pool)
        .await?;
    }
    append_projection_source_event_for_tenant(
        &app,
        binding,
        &unique_event_id("projection-healthy"),
        healthy,
    )
    .await?;

    let worker_config = crate::PgProjectionWorkerConfig::new(runtime_pg_config(
        fixture.owner_params(),
        TEST_PROJECTION_WORKER_ROLE,
        TEST_PROJECTION_WORKER_PASSWORD,
    ));
    let worker = PgStore::connect_verified_projection_worker(&worker_config).await?;
    let registered: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT projection_definition_version, projection_definition_schema_digest, generation \
         FROM public.projection_input_bindings WHERE projection_id = $1",
    )
    .bind(SETTINGS_PROJECTION_ID)
    .fetch_all(&owner.pool)
    .await?;
    assert!(
        registered.iter().any(|(version, digest, generation)| {
            version == SETTINGS_PROJECTION_DEFINITION_VERSION
                && digest == SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST
                && generation == SETTINGS_PROJECTION_INPUT_GENERATION
        }),
        "registered Settings binding does not match worker scope: {registered:?}"
    );
    let list_tenants = |pool: sqlx::PgPool| async move {
        sqlx::query_scalar::<_, String>(
            "SELECT tenant_id::text FROM public.rss_projection_worker_list_tenants(\
             $1, $2, $3, $4, NULL::uuid, 100)",
        )
        .bind(SETTINGS_PROJECTION_ID)
        .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
        .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
        .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
        .fetch_all(&pool)
        .await
    };
    let initial = list_tenants(worker.pool_for_integration().clone()).await?;
    assert!(initial.contains(&quarantined.to_string()));
    assert!(initial.contains(&healthy.to_string()));
    for (tenant, expected_generation) in [
        (quarantined, quarantined_generation),
        (healthy, healthy_generation),
    ] {
        let mut resolve_tx = worker.pool_for_integration().begin().await?;
        sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *resolve_tx)
            .await?;
        let resolved: String = sqlx::query_scalar(
            "SELECT generation FROM public.rss_settings_projection_resolve_active()",
        )
        .fetch_one(&mut *resolve_tx)
        .await?;
        assert_eq!(resolved, expected_generation);
        resolve_tx.rollback().await?;
    }

    let healthy_next_generation = "healthy-next";
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, 0)",
    )
    .bind(healthy.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(healthy_next_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "UPDATE public.settings_projection_active_pointer \
         SET generation = $2, token = token + 1, updated_at = pg_catalog.now() \
         WHERE tenant_id = $1::uuid AND projection_id = $3",
    )
    .bind(healthy.to_string())
    .bind(healthy_next_generation)
    .bind(SETTINGS_PROJECTION_ID)
    .execute(&owner.pool)
    .await?;
    let mut next_quantum = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(healthy.to_string())
        .execute(&mut *next_quantum)
        .await?;
    let next_resolved: String = sqlx::query_scalar(
        "SELECT generation FROM public.rss_settings_projection_resolve_active()",
    )
    .fetch_one(&mut *next_quantum)
    .await?;
    assert_eq!(next_resolved, healthy_next_generation);
    let stale_checkpoint = sqlx::query_scalar::<_, bool>(
        "SELECT public.rss_projection_worker_save_checkpoint(\
         $1::uuid, $2, $3, $4, $5, $6, 1, 0)",
    )
    .bind(healthy.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(healthy_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *next_quantum)
    .await;
    assert!(
        matches!(stale_checkpoint, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("22023")),
        "the next worker quantum must fence the generation that was active before the swap: {stale_checkpoint:?}"
    );
    next_quantum.rollback().await?;
    let mut next_quantum = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(healthy.to_string())
        .execute(&mut *next_quantum)
        .await?;
    let next_checkpoint: bool = sqlx::query_scalar(
        "SELECT public.rss_projection_worker_save_checkpoint(\
         $1::uuid, $2, $3, $4, $5, $6, 1, 0)",
    )
    .bind(healthy.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(healthy_next_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *next_quantum)
    .await?;
    assert!(next_checkpoint);
    next_quantum.commit().await?;

    sqlx::query(
        "UPDATE public.settings_projection_generations \
         SET definition_schema_digest = 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
         WHERE tenant_id = $1::uuid AND projection_id = $2 AND generation = $3",
    )
    .bind(healthy.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(healthy_next_generation)
    .execute(&owner.pool)
    .await?;
    let mut drift_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(healthy.to_string())
        .execute(&mut *drift_tx)
        .await?;
    let drift = sqlx::query_scalar::<_, String>(
        "SELECT generation FROM public.rss_settings_projection_resolve_active()",
    )
    .fetch_one(&mut *drift_tx)
    .await;
    assert!(
        matches!(drift, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1901")),
        "active generation identity drift must fail closed: {drift:?}"
    );
    drift_tx.rollback().await?;
    sqlx::query(
        "UPDATE public.settings_projection_generations SET definition_schema_digest = $4 \
         WHERE tenant_id = $1::uuid AND projection_id = $2 AND generation = $3",
    )
    .bind(healthy.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(healthy_next_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .execute(&owner.pool)
    .await?;

    let mut quarantine_tx = worker.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(quarantined.to_string())
        .execute(&mut *quarantine_tx)
        .await?;
    sqlx::query(
        "SELECT public.rss_projection_worker_quarantine_tenant(\
         $1::uuid, $2, $3, $4, $5, $6, 'provider_permanent', 42)",
    )
    .bind(quarantined.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(quarantined_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&mut *quarantine_tx)
    .await?;
    quarantine_tx.commit().await?;
    let durable: (String, String, i64, String) = sqlx::query_as(
        "SELECT state, reason, failed_lsn, updated_at::text \
         FROM public.projection_worker_tenant_quarantine \
         WHERE tenant_scope_id = $1::uuid AND projection_id = $2 AND target_generation = $3",
    )
    .bind(quarantined.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(quarantined_generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        (&durable.0, &durable.1, durable.2),
        (
            &"quarantined".to_owned(),
            &"provider_permanent".to_owned(),
            42
        )
    );
    for _ in 0..3 {
        let active = list_tenants(worker.pool_for_integration().clone()).await?;
        assert!(
            active.contains(&quarantined.to_string()),
            "generation-neutral discovery must not hide a tenant before its active scope is resolved"
        );
        assert!(
            active.contains(&healthy.to_string()),
            "healthy tenant must continue"
        );
    }
    let unchanged: String = sqlx::query_scalar(
        "SELECT updated_at::text FROM public.projection_worker_tenant_quarantine \
         WHERE tenant_scope_id = $1::uuid AND projection_id = $2 AND target_generation = $3",
    )
    .bind(quarantined.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(quarantined_generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        unchanged, durable.3,
        "catalog scans must not hot-loop or rewrite quarantine"
    );

    worker.shutdown_for_integration().await?;
    let restarted = PgStore::connect_verified_projection_worker(&worker_config).await?;
    let after_restart = list_tenants(restarted.pool_for_integration().clone()).await?;
    assert!(after_restart.contains(&quarantined.to_string()));
    assert!(after_restart.contains(&healthy.to_string()));
    let mut restarted_probe = restarted.pool_for_integration().begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(quarantined.to_string())
        .execute(&mut *restarted_probe)
        .await?;
    let has_quarantine: bool = sqlx::query_scalar(
        "SELECT public.rss_projection_worker_tenant_is_quarantined(\
             $1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(quarantined.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(quarantined_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .fetch_one(&mut *restarted_probe)
    .await?;
    restarted_probe.rollback().await?;
    assert!(
        has_quarantine,
        "restart must preserve degraded aggregate state"
    );

    let projection = eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)?;
    let selector = eventexec::ProjectionSelector::new(
        quarantined,
        projection.clone(),
        eventexec::ProjectionVersion::parse(quarantined_generation)?,
    );
    let scope = eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
        &projection,
        quarantined,
    )
    .ok_or_else(|| std::io::Error::other("Settings projection source scope is missing"))?;
    let operator = crate::PgProjectionOperatorDeps::connect(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
        fixed_clock_arc(),
    )
    .await?;
    let stale = operator
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                quarantined,
                SETTINGS_PROJECTION_ID,
            ),
            crate::ProjectionReplayAction,
            &selector,
            scope.clone(),
        )?
        .recover_quarantined_tenant(consistency::Lsn::new(41))
        .await?;
    assert!(!stale, "operator recovery must fence a stale failed LSN");
    let recovered = operator
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                quarantined,
                SETTINGS_PROJECTION_ID,
            ),
            crate::ProjectionReplayAction,
            &selector,
            scope,
        )?
        .recover_quarantined_tenant(consistency::Lsn::new(42))
        .await?;
    assert!(recovered);
    let after_recovery = list_tenants(restarted.pool_for_integration().clone()).await?;
    assert!(after_recovery.contains(&quarantined.to_string()));
    let released: (String, String, i64) = sqlx::query_as(
        "SELECT state, reason, failed_lsn FROM public.projection_worker_tenant_quarantine \
         WHERE tenant_scope_id = $1::uuid AND projection_id = $2 AND target_generation = $3",
    )
    .bind(quarantined.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(quarantined_generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        released,
        ("released".to_owned(), "provider_permanent".to_owned(), 42)
    );

    operator.shutdown().await?;
    restarted.shutdown_for_integration().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_generation_bytes_are_bounded_in_all_three_tables() -> TestResult {
    let (_fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let tenant = uuid::Uuid::new_v4().to_string();
    let max_generation = "v".repeat(eventexec::PROJECTION_VERSION_MAX_BYTES);
    let oversized_generation = "v".repeat(eventexec::PROJECTION_VERSION_MAX_BYTES + 1);

    sqlx::query(
        "INSERT INTO public.settings_projection_generations (tenant_id, projection_id, \
         generation, definition_version, definition_schema_digest, input_generation) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(&tenant)
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&max_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "INSERT INTO public.settings_config_projection_rows (tenant_id, projection_id, \
         generation, config_key, config_version, change_kind, source_event_id, source_lsn, \
         source_occurred_at_secs) VALUES ($1::uuid, $2, $3, 'projection.length', 1, \
         'published', 'settings-projection-length-row', 1, 1)",
    )
    .bind(&tenant)
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&max_generation)
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (tenant_id, projection_id, \
         generation, source_event_id, source_lsn, fact_digest, actor, purpose) \
         VALUES ($1::uuid, $2, $3, 'settings-projection-length-receipt', 1, $4, \
                 'rss-projection-replay', 'operator-replay')",
    )
    .bind(&tenant)
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&max_generation)
    .bind([0x91_u8; 32].as_slice())
    .execute(&owner.pool)
    .await?;

    let oversized_generation_insert = sqlx::query(
        "INSERT INTO public.settings_projection_generations (tenant_id, projection_id, \
         generation, definition_version, definition_schema_digest, input_generation) \
         VALUES ($1::uuid, $2, $3, $4, $5, $6)",
    )
    .bind(&tenant)
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&oversized_generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await;
    assert_database_constraint(
        oversized_generation_insert,
        "settings_projection_generations_generation_bounded",
    );

    let oversized_row_insert = sqlx::query(
        "INSERT INTO public.settings_config_projection_rows (tenant_id, projection_id, \
         generation, config_key, config_version, change_kind, source_event_id, source_lsn, \
         source_occurred_at_secs) VALUES ($1::uuid, $2, $3, 'projection.length-over', 1, \
         'published', 'settings-projection-length-row-over', 2, 1)",
    )
    .bind(&tenant)
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&oversized_generation)
    .execute(&owner.pool)
    .await;
    assert_database_constraint(
        oversized_row_insert,
        "settings_config_projection_rows_generation_bounded",
    );

    let oversized_receipt_insert = sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (tenant_id, projection_id, \
         generation, source_event_id, source_lsn, fact_digest, actor, purpose) \
         VALUES ($1::uuid, $2, $3, 'settings-projection-length-receipt-over', 2, $4, \
                 'rss-projection-replay', 'operator-replay')",
    )
    .bind(&tenant)
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&oversized_generation)
    .bind([0x92_u8; 32].as_slice())
    .execute(&owner.pool)
    .await;
    assert_database_constraint(
        oversized_receipt_insert,
        "settings_projection_dedupe_receipts_generation_bounded",
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_receipt_precedes_ordering_and_persists_across_reconstruction()
-> TestResult {
    use eventexec::{ProjectionTargetStoreErrorKind, ProjectionTargetStoreOutcome};
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    let (app, _reader, writer) = settings_projection_runtime_parts(&owner, &fixture).await?;
    let tenant = vocab::TenantId::parse(COTX_TENANT_A)?;
    let generation = format!("settings-order-{}", uuid::Uuid::new_v4().simple());
    let scope = settings_projection_apply_scope(tenant, &generation)?;
    let old_event = unique_event_id("settings-projection-old-receipt");
    let old = || {
        settings_projection_mutation(
            &scope,
            tenant,
            "projection.ordering",
            1,
            SettingsConfigChangeKind::Published,
            TEST_OCCURRED_SECS,
            &old_event,
            10,
            [0x51; 32],
        )
    };
    assert_eq!(
        writer.apply(scope.clone(), old()?).await?,
        ProjectionTargetStoreOutcome::Applied
    );
    assert_eq!(
        writer
            .apply(
                scope.clone(),
                settings_projection_mutation(
                    &scope,
                    tenant,
                    "projection.ordering",
                    2,
                    SettingsConfigChangeKind::Published,
                    TEST_OCCURRED_SECS + 1,
                    &unique_event_id("settings-projection-new-high-water"),
                    20,
                    [0x52; 32],
                )?,
            )
            .await?,
        ProjectionTargetStoreOutcome::Applied
    );
    assert_eq!(
        writer.apply(scope.clone(), old()?).await?,
        ProjectionTargetStoreOutcome::Duplicate,
        "an old committed receipt must win before the high-water check"
    );

    let conflict = writer
        .apply(
            scope.clone(),
            settings_projection_mutation(
                &scope,
                tenant,
                "projection.ordering",
                1,
                SettingsConfigChangeKind::Published,
                TEST_OCCURRED_SECS,
                &old_event,
                10,
                [0x99; 32],
            )?,
        )
        .await
        .expect_err("same event with another digest must conflict");
    assert_eq!(conflict.kind(), ProjectionTargetStoreErrorKind::Conflict);

    let out_of_order = writer
        .apply(
            scope.clone(),
            settings_projection_mutation(
                &scope,
                tenant,
                "projection.ordering",
                3,
                SettingsConfigChangeKind::Published,
                TEST_OCCURRED_SECS + 2,
                &unique_event_id("settings-projection-out-of-order"),
                19,
                [0x53; 32],
            )?,
        )
        .await
        .expect_err("unreceipted older LSN must fail");
    assert_eq!(
        out_of_order.kind(),
        ProjectionTargetStoreErrorKind::OutOfOrder
    );

    let regression = writer
        .apply(
            scope.clone(),
            settings_projection_mutation(
                &scope,
                tenant,
                "projection.ordering",
                2,
                SettingsConfigChangeKind::Published,
                TEST_OCCURRED_SECS + 3,
                &unique_event_id("settings-projection-regression"),
                21,
                [0x54; 32],
            )?,
        )
        .await
        .expect_err("config version must strictly increase");
    assert_eq!(regression.kind(), ProjectionTargetStoreErrorKind::Permanent);

    let same_lsn_conflict = writer
        .apply(
            scope.clone(),
            settings_projection_mutation(
                &scope,
                tenant,
                "projection.ordering",
                3,
                SettingsConfigChangeKind::Published,
                TEST_OCCURRED_SECS + 4,
                &unique_event_id("settings-projection-same-lsn"),
                20,
                [0x56; 32],
            )?,
        )
        .await
        .expect_err("a different event cannot reuse the scope's source LSN");
    assert_eq!(
        same_lsn_conflict.kind(),
        ProjectionTargetStoreErrorKind::Conflict
    );
    let unchanged: (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT \
            (SELECT config_version FROM public.settings_config_projection_rows \
             WHERE tenant_id = $1::uuid AND generation = $2 AND config_key = $3), \
            (SELECT count(*) FROM public.settings_projection_dedupe_receipts \
             WHERE tenant_id = $1::uuid AND generation = $2), \
            (SELECT high_water_lsn FROM public.settings_projection_generations \
             WHERE tenant_id = $1::uuid AND generation = $2)",
    )
    .bind(COTX_TENANT_A)
    .bind(&generation)
    .bind("projection.ordering")
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(unchanged, (2, 2, Some(20)));

    drop(writer);
    let verified = PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let reconstructed = SettingsTargetHarness::new(std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_operator(&verified),
    ));
    drop(app);
    assert_eq!(
        reconstructed.apply(scope.clone(), old()?).await?,
        ProjectionTargetStoreOutcome::Duplicate,
        "receipt must survive provider object reconstruction"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_concurrent_duplicate_is_single_effect() -> TestResult {
    use eventexec::ProjectionTargetStoreOutcome;
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    let (_app, _reader, writer) = settings_projection_runtime_parts(&owner, &fixture).await?;
    let tenant = vocab::TenantId::parse(COTX_TENANT_A)?;
    let generation = format!("settings-race-{}", uuid::Uuid::new_v4().simple());
    let scope = settings_projection_apply_scope(tenant, &generation)?;
    let event_id = unique_event_id("settings-projection-concurrent");
    let first_mutation = settings_projection_mutation(
        &scope,
        tenant,
        "projection.concurrent",
        1,
        SettingsConfigChangeKind::Published,
        TEST_OCCURRED_SECS,
        &event_id,
        1,
        [0x61; 32],
    )?;
    let second_mutation = settings_projection_mutation(
        &scope,
        tenant,
        "projection.concurrent",
        1,
        SettingsConfigChangeKind::Published,
        TEST_OCCURRED_SECS,
        &event_id,
        1,
        [0x61; 32],
    )?;
    let (first, second) = tokio::join!(
        writer.apply(scope.clone(), first_mutation),
        writer.apply(scope.clone(), second_mutation),
    );
    let mut outcomes = [first?, second?];
    outcomes.sort_by_key(|outcome| match outcome {
        ProjectionTargetStoreOutcome::Applied => 0,
        ProjectionTargetStoreOutcome::Duplicate => 1,
    });
    assert_eq!(
        outcomes,
        [
            ProjectionTargetStoreOutcome::Applied,
            ProjectionTargetStoreOutcome::Duplicate,
        ]
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT count(*) FROM public.settings_config_projection_rows \
             WHERE tenant_id = $1::uuid AND generation = $2 AND config_key = $3), \
            (SELECT count(*) FROM public.settings_projection_dedupe_receipts \
             WHERE tenant_id = $1::uuid AND generation = $2 AND source_event_id = $4)",
    )
    .bind(COTX_TENANT_A)
    .bind(&generation)
    .bind("projection.concurrent")
    .bind(&event_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        counts,
        (1, 1),
        "one current row and one receipt must commit"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_dual_worker_same_generation_checkpoint_fences_stale_writer()
-> TestResult {
    const EVENT_END: u64 = 3;
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    register_generated_projection_input_catalog(&owner).await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let generation = format!("fencing-{}", uuid::Uuid::new_v4().simple());
    let projection = eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)?;
    let target_generation = eventexec::ProjectionVersion::parse(&generation)?;
    let selector =
        eventexec::ProjectionSelector::new(tenant, projection.clone(), target_generation.clone());
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, NULL)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .bind(SETTINGS_PROJECTION_DEFINITION_VERSION)
    .bind(SETTINGS_PROJECTION_DEFINITION_SCHEMA_DIGEST)
    .bind(SETTINGS_PROJECTION_INPUT_GENERATION)
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_active_pointer (\
             tenant_id, projection_id, generation, promoted_high_water_lsn, token\
         ) VALUES ($1::uuid, $2, $3, 0, 1)",
    )
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .execute(&owner.pool)
    .await?;

    let worker_config = crate::PgProjectionWorkerConfig::new(runtime_pg_config(
        fixture.owner_params(),
        TEST_PROJECTION_WORKER_ROLE,
        TEST_PROJECTION_WORKER_PASSWORD,
    ));
    let worker_a = PgStore::connect_verified_projection_worker(&worker_config).await?;
    let worker_b = PgStore::connect_verified_projection_worker(&worker_config).await?;
    let binding = eventexec::WorkflowRuntimePlan::generated_projection_runtime_binding_fixture(
        &projection,
        &target_generation,
    )
    .ok_or("Settings projection runtime binding fixture missing")?;
    let target_scope =
        crate::projection_worker::ProjectionWorkerTarget::from_binding_for_test(&binding);
    let execution = binding.background_execution_issuer().issue(tenant);
    let event_specs = (1..=EVENT_END)
        .map(|lsn| {
            let event_id = unique_event_id(&format!("settings-dual-worker-{lsn}"));
            let key = format!("projection.dual-worker-{lsn}");
            (lsn, event_id, key)
        })
        .collect::<Vec<_>>();
    let events = event_specs
        .iter()
        .map(|(lsn, event_id, key)| {
            settings_projection_record_for_tenant(tenant, *lsn, event_id, key)
        })
        .collect::<Vec<_>>();
    let source = SettingsDualWorkerBarrierSource {
        events: std::sync::Arc::new(events),
        barrier: std::sync::Arc::new(tokio::sync::Barrier::new(2)),
    };
    let target_a = target(std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_worker(&worker_a, &target_scope),
    ));
    let target_b = target(std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_worker(&worker_b, &target_scope),
    ));
    let harness_a = settings_dual_worker_harness(
        &worker_a,
        &target_scope,
        tenant,
        target_a,
        execution.clone(),
        &source,
    )?;
    let harness_b = settings_dual_worker_harness(
        &worker_b,
        &target_scope,
        tenant,
        target_b,
        execution,
        &source,
    )?;
    let runner = settings_dual_worker_runner_config()?;
    let (run_a, run_b) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            eventexec::projection_runner_once(&source, &harness_a, runner),
            eventexec::projection_runner_once(&source, &harness_b, runner),
        )
    })
    .await
    .expect("dual projection workers must rendezvous and finish before timeout");

    assert_settings_dual_worker_stops(&run_a, &run_b);

    let checkpoint_and_generation: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT checkpoint.offset_lsn, checkpoint.version, generation.high_water_lsn \
         FROM public.checkpoint AS checkpoint \
         JOIN public.settings_projection_generations AS generation \
           ON generation.tenant_id = $3::uuid \
          AND generation.projection_id = $4 \
          AND generation.generation = $5 \
         WHERE checkpoint.owner = $1 AND checkpoint.checkpoint_id = $2",
    )
    .bind(selector.shadow_checkpoint_owner().as_str())
    .bind(selector.shadow_checkpoint_id().as_str())
    .bind(tenant.to_string())
    .bind(SETTINGS_PROJECTION_ID)
    .bind(&generation)
    .fetch_optional(&owner.pool)
    .await?;
    assert_eq!(
        checkpoint_and_generation,
        Some((
            i64::try_from(EVENT_END)?,
            1,
            Some(i64::try_from(EVENT_END)?)
        )),
        "shadow checkpoint and generation high-water must converge exactly once"
    );
    assert_eq!(settings_projection_dlx_count(&owner, &selector).await?, 0);

    for (_lsn, event_id, key) in &event_specs {
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT \
                (SELECT count(*) FROM public.settings_config_projection_rows \
                 WHERE tenant_id = $1::uuid AND generation = $2 AND config_key = $3), \
                (SELECT count(*) FROM public.settings_projection_dedupe_receipts \
                 WHERE tenant_id = $1::uuid AND generation = $2 AND source_event_id = $4)",
        )
        .bind(tenant.to_string())
        .bind(&generation)
        .bind(key)
        .bind(event_id)
        .fetch_one(&owner.pool)
        .await?;
        assert_eq!(
            counts,
            (1, 1),
            "each event must leave one read-model row and one dedupe receipt"
        );
    }
    let attribution: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT actor, purpose FROM public.settings_projection_dedupe_receipts \
         WHERE tenant_id = $1::uuid AND generation = $2",
    )
    .bind(tenant.to_string())
    .bind(&generation)
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        attribution,
        vec![(
            "rss-projection-worker".to_owned(),
            "background-worker".to_owned()
        )],
        "worker actor/purpose must remain production closed values"
    );

    let total_applied = run_a.applied + run_b.applied;
    let total_duplicates = run_a.duplicates + run_b.duplicates;
    assert_eq!(total_applied, EVENT_END as usize);
    assert_eq!(total_duplicates, EVENT_END as usize);

    worker_a.shutdown_for_integration().await?;
    worker_b.shutdown_for_integration().await?;
    owner.shutdown().await?;
    Ok(())
}

// ── residual: rollback-failed leaves zero generation rows ────────────────────
// Error kind / rows / receipts / checkpoint are owned by
// `pg_settings_conformance_rollback_failed` via `rollback_observation` +
// `verify_projection_case(RollbackFailed)`.
//
// Residual why generations: `settings_projection_conformance_counts` and
// `rollback_observation` only observe rows+receipts; generation metadata is
// outside that aggregate and must stay empty after rollback-failed.

/// PostgreSQL residual: after RollbackFailed fault setup, generation metadata
/// must not leak (`settings_projection_generations=0`).
#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_rollback_failed_leaves_zero_generations() -> TestResult {
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let verified = PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            fixture.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let store = std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_operator(&verified),
    );
    // setup: exercise RollbackFailed fault path (kind/effects owned by canonical).
    store
        .inject_test_fault(crate::settings_projection::SettingsProjectionTestFault::RollbackFailed);
    let writer = SettingsTargetHarness::new(store);
    let tenant = vocab::TenantId::parse(COTX_TENANT_A)?;
    let generation = format!("settings-rollback-failed-{}", uuid::Uuid::new_v4().simple());
    let scope = settings_projection_apply_scope(tenant, &generation)?;
    let _failure = writer
        .apply(
            scope.clone(),
            settings_projection_mutation(
                &scope,
                tenant,
                "projection.rollback-failed",
                1,
                SettingsConfigChangeKind::Published,
                TEST_OCCURRED_SECS,
                "rollback-failed-direct",
                1,
                [0x92; 32],
            )?,
        )
        .await
        .expect_err("rollback ACK loss must fail closed");

    let generations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.settings_projection_generations WHERE tenant_id = $1::uuid AND generation = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        generations, 0,
        "rollback-failed must leave no settings_projection_generations row"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_receipt_failure_rolls_back_row_and_high_water() -> TestResult {
    use generated::event::settings_v1::SettingsConfigChangeKind;

    let (fixture, owner) = connect_pg().await?;
    let (_app, _reader, writer) = settings_projection_runtime_parts(&owner, &fixture).await?;
    sqlx::query(
        "CREATE OR REPLACE FUNCTION public.rss_test_fail_settings_projection_receipt() \
         RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF NEW.source_event_id LIKE 'settings-projection-atomic-fail-%' THEN \
             RAISE EXCEPTION 'injected receipt failure' USING ERRCODE = '40001'; \
           END IF; \
           RETURN NEW; \
         END $$",
    )
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "DROP TRIGGER IF EXISTS rss_test_fail_settings_projection_receipt \
         ON public.settings_projection_dedupe_receipts",
    )
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "CREATE TRIGGER rss_test_fail_settings_projection_receipt \
         BEFORE INSERT ON public.settings_projection_dedupe_receipts \
         FOR EACH ROW EXECUTE FUNCTION public.rss_test_fail_settings_projection_receipt()",
    )
    .execute(&owner.pool)
    .await?;

    let tenant = vocab::TenantId::parse(COTX_TENANT_A)?;
    let generation = format!("settings-atomic-{}", uuid::Uuid::new_v4().simple());
    let scope = settings_projection_apply_scope(tenant, &generation)?;
    let event_id = format!(
        "settings-projection-atomic-fail-{}",
        uuid::Uuid::new_v4().simple()
    );
    writer
        .apply(
            scope.clone(),
            settings_projection_mutation(
                &scope,
                tenant,
                "projection.atomic",
                1,
                SettingsConfigChangeKind::Published,
                TEST_OCCURRED_SECS,
                &event_id,
                77,
                [0x71; 32],
            )?,
        )
        .await
        .expect_err("receipt trigger must abort the projection transaction");

    let state: (i64, i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM public.settings_config_projection_rows \
            WHERE tenant_id = $1::uuid AND generation = $2), \
           (SELECT count(*) FROM public.settings_projection_dedupe_receipts \
            WHERE tenant_id = $1::uuid AND generation = $2), \
           (SELECT count(*) FROM public.settings_projection_generations \
            WHERE tenant_id = $1::uuid AND generation = $2), \
           (SELECT high_water_lsn FROM public.settings_projection_generations \
            WHERE tenant_id = $1::uuid AND generation = $2)",
    )
    .bind(COTX_TENANT_A)
    .bind(&generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        state,
        (0, 0, 0, None),
        "row, receipt, generation and high-water must roll back"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_shadow_replay_a_b_c_converges_after_restart_and_checkpoint_loss()
-> TestResult {
    let (pg, owner) = connect_pg().await?;
    provision_runtime_logins(&pg).await?;
    setup_outbox(&owner).await?;
    register_generated_projection_input_catalog(&owner).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let verified_operator = PgStore::connect_verified_projection_operator(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
    )
    .await?;
    let tenant = vocab::TenantId::parse(COTX_TENANT_A)?;
    let other_tenant = vocab::TenantId::parse(COTX_TENANT_B)?;
    let binding = *generated::event::PROJECTION_INPUTS
        .iter()
        .find(|binding| binding.projection_id() == SETTINGS_PROJECTION_ID)
        .ok_or("Settings projection binding missing")?;
    let projection = eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)?;
    let scope = eventexec::WorkflowRuntimePlan::generated_projection_source_scope_fixture(
        &projection,
        tenant,
    )
    .ok_or("Settings projection source scope missing")?;
    let generation_a = format!("settings-a-{}", uuid::Uuid::new_v4().simple());
    let generation_b = format!("settings-b-{}", uuid::Uuid::new_v4().simple());
    let generation_c = format!("settings-c-{}", uuid::Uuid::new_v4().simple());
    let selector = |generation: &str| -> Result<eventexec::ProjectionSelector, TestError> {
        Ok(eventexec::ProjectionSelector::new(
            tenant,
            projection.clone(),
            eventexec::ProjectionVersion::parse(generation)?,
        ))
    };
    let serving_a = std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_operator(&verified_operator),
    );
    let serving_b = std::sync::Arc::new(
        crate::PgSettingsProjectionApplyStore::new_projection_operator(&verified_operator),
    );
    let target_a = target(serving_a);
    let target_b = target(serving_b);

    let first_id = unique_event_id("settings-parity-published");
    let second_id = unique_event_id("settings-parity-rolled-back");
    let third_id = unique_event_id("settings-parity-deleted");
    let first_payload = serde_json::to_vec(&serde_json::json!({
        "tenantId": tenant.to_string(), "key": "projection.a", "version": 1,
        "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
    }))?;
    let second_payload = serde_json::to_vec(&serde_json::json!({
        "tenantId": tenant.to_string(), "key": "projection.b", "version": 1,
        "changeKind": "rolledBack", "occurredAt": TEST_OCCURRED_SECS + 1,
    }))?;
    let third_payload = serde_json::to_vec(&serde_json::json!({
        "tenantId": tenant.to_string(), "key": "projection.c", "version": 1,
        "changeKind": "deleted", "occurredAt": TEST_OCCURRED_SECS + 2,
    }))?;
    let first_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        binding,
        &first_id,
        tenant,
        &first_payload,
    )
    .await?;
    let second_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        binding,
        &second_id,
        tenant,
        &second_payload,
    )
    .await?;
    let third_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        binding,
        &third_id,
        tenant,
        &third_payload,
    )
    .await?;
    append_projection_source_event_with_payload_for_tenant(
        &app,
        binding,
        &unique_event_id("settings-parity-other-tenant"),
        other_tenant,
        &serde_json::to_vec(&serde_json::json!({
            "tenantId": other_tenant.to_string(), "key": "projection.foreign", "version": 1,
            "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
        }))?,
    )
    .await?;

    let records = [
        projection_record_from_journal(&owner, tenant, first_lsn).await?,
        projection_record_from_journal(&owner, tenant, second_lsn).await?,
        projection_record_from_journal(&owner, tenant, third_lsn).await?,
    ];
    for record in records.iter().cloned() {
        assert_eq!(
            eventexec::ProjectionTarget::apply(
                target_b.as_ref(),
                &settings_operator_execution(tenant),
                &selector(&generation_b)?,
                record
            )
            .await?,
            consistency::ProjectionApplyOutcome::Applied
        );
    }
    assert_eq!(
        eventexec::ProjectionTarget::apply(
            target_b.as_ref(),
            &settings_operator_execution(tenant),
            &selector(&generation_b)?,
            records[0].clone(),
        )
        .await?,
        consistency::ProjectionApplyOutcome::Duplicate,
        "duplicate serving delivery must converge by receipt"
    );

    let deps = crate::PgProjectionOperatorDeps::connect(
        &crate::PgProjectionOperatorConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_OPERATOR_ROLE,
            TEST_PROJECTION_OPERATOR_PASSWORD,
        )),
        &crate::PgProjectionSourceReadConfig::new(runtime_pg_config(
            pg.owner_params(),
            TEST_PROJECTION_READER_ROLE,
            TEST_PROJECTION_READER_PASSWORD,
        )),
        fixed_clock_arc(),
    )
    .await?;
    let selector_c = selector(&generation_c)?;
    let runner_config = eventexec::ProjectionRunnerConfig::new(
        consistency::ProjectionBatchLimit::new(10)?,
        std::time::Duration::from_millis(100),
        eventexec::ProjectionPoisonPolicy::Isolate,
    )?;
    let selector_a = selector(&generation_a)?;
    let active_from_lsn_zero = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                tenant,
                SETTINGS_PROJECTION_ID,
            ),
            crate::ProjectionReplayAction,
            &selector_a,
            scope.clone(),
        )?
        .into_replay_stores(
            settings_operator_execution(tenant),
            target_a,
            test_dlx_payload_protector(),
        )?;
    let active_run = active_from_lsn_zero.run_once(runner_config).await;
    assert_eq!(active_run.stop, eventexec::ProjectionStop::Completed);
    assert_eq!((active_run.scanned, active_run.applied), (3, 3));
    drop(active_from_lsn_zero);

    let replay = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                tenant,
                SETTINGS_PROJECTION_ID,
            ),
            crate::ProjectionReplayAction,
            &selector_c,
            scope.clone(),
        )?
        .into_settings_replay_stores(
            settings_operator_execution(tenant),
            eventexec::ProjectionTargetDefinition::new(
                generated::projection::settings_v3::CONTRACT,
                generated::event::PROJECTION_INPUT_GENERATION,
            )?,
            vec![binding],
            test_dlx_payload_protector(),
        )?;
    let first_run = replay.run_once(runner_config).await;
    assert_eq!(first_run.stop, eventexec::ProjectionStop::Completed);
    assert_eq!((first_run.scanned, first_run.applied), (3, 3));
    assert_eq!(
        settings_projection_generation_state(&owner, tenant, &generation_a).await?,
        settings_projection_generation_state(&owner, tenant, &generation_b).await?
    );
    assert_eq!(
        settings_projection_generation_state(&owner, tenant, &generation_b).await?,
        settings_projection_generation_state(&owner, tenant, &generation_c).await?
    );
    drop(replay);

    sqlx::query("DELETE FROM public.checkpoint WHERE owner = $1 AND checkpoint_id = $2")
        .bind(selector_c.shadow_checkpoint_owner().as_str())
        .bind(selector_c.shadow_checkpoint_id().as_str())
        .execute(&owner.pool)
        .await?;
    let rebuilt = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                tenant,
                SETTINGS_PROJECTION_ID,
            ),
            crate::ProjectionReplayAction,
            &selector_c,
            scope.clone(),
        )?
        .into_settings_replay_stores(
            settings_operator_execution(tenant),
            eventexec::ProjectionTargetDefinition::new(
                generated::projection::settings_v3::CONTRACT,
                generated::event::PROJECTION_INPUT_GENERATION,
            )?,
            vec![binding],
            test_dlx_payload_protector(),
        )?;
    let replay_after_checkpoint_loss = rebuilt.run_once(runner_config).await;
    assert_eq!(
        replay_after_checkpoint_loss.stop,
        eventexec::ProjectionStop::Completed
    );
    assert_eq!(
        (
            replay_after_checkpoint_loss.scanned,
            replay_after_checkpoint_loss.duplicates
        ),
        (3, 3)
    );
    assert_eq!(
        settings_projection_generation_state(&owner, tenant, &generation_b).await?,
        settings_projection_generation_state(&owner, tenant, &generation_c).await?,
        "operator target reconstruction and checkpoint loss must not duplicate durable state"
    );

    drop(rebuilt);
    let poison_id = unique_event_id("settings-parity-poison");
    let poison_lsn = append_projection_source_event_with_payload_for_tenant(
        &app,
        binding,
        &poison_id,
        tenant,
        &serde_json::to_vec(&serde_json::json!({
            "tenantId": tenant.to_string(), "unknown": "unsupported-settings-payload",
        }))?,
    )
    .await?;
    let after_poison_id = unique_event_id("settings-parity-after-poison");
    append_projection_source_event_with_payload_for_tenant(
        &app,
        binding,
        &after_poison_id,
        tenant,
        &serde_json::to_vec(&serde_json::json!({
            "tenantId": tenant.to_string(), "key": "projection.after-poison", "version": 1,
            "changeKind": "published", "occurredAt": TEST_OCCURRED_SECS,
        }))?,
    )
    .await?;
    let poisoned = deps
        .authorize_projection_target(
            projection_maintenance_receipt(
                authn::ProjectionMaintenanceAction::Replay,
                tenant,
                SETTINGS_PROJECTION_ID,
            ),
            crate::ProjectionReplayAction,
            &selector_c,
            scope,
        )?
        .into_settings_replay_stores(
            settings_operator_execution(tenant),
            eventexec::ProjectionTargetDefinition::new(
                generated::projection::settings_v3::CONTRACT,
                generated::event::PROJECTION_INPUT_GENERATION,
            )?,
            vec![binding],
            test_dlx_payload_protector(),
        )?;
    let poison_run = poisoned.run_once(runner_config).await;
    assert_eq!(poison_run.dead_lettered, 1, "poison run: {poison_run:?}");
    assert!(matches!(
        poison_run.stop,
        eventexec::ProjectionStop::ApplyFailed {
            reason: consistency::ProjectionApplyErrorReason::PayloadMalformed,
            ..
        }
    ));
    let poison_checkpoint = settings_projection_checkpoint(&owner, &selector_c).await?;
    assert_eq!(
        poison_checkpoint,
        Some(third_lsn),
        "checkpoint must not advance to poison LSN {poison_lsn} or the later valid event"
    );
    let poison_dlx = settings_projection_dlx_count(&owner, &selector_c).await?;
    assert_eq!(
        poison_dlx, 1,
        "unknown Settings payload must enter one controlled DLQ row"
    );
    let after_poison_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.settings_config_projection_rows \
         WHERE tenant_id = $1::uuid AND generation = $2 AND config_key = 'projection.after-poison'",
    )
    .bind(tenant.to_string())
    .bind(&generation_c)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        after_poison_rows, 0,
        "replay must stop before the event after poison"
    );

    drop(poisoned);
    deps.shutdown().await?;
    verified_operator.store_arc().shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_commit_unknown_preserves_checkpoint_and_dlx() -> TestResult {
    settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::CommitUnknown).await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_rollback_failed_preserves_checkpoint_and_dlx() -> TestResult {
    settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::RollbackFailed)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_tenant_drift_is_controlled_poison() -> TestResult {
    settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::TenantDrift).await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_persistent_order_is_controlled_poison() -> TestResult {
    settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::PersistentOrder)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_schema_drift_is_controlled_poison() -> TestResult {
    settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::SchemaDrift).await
}

testkit::projection_target_conformance! {
    cases: {
        atomic_apply => { #[tokio::test] pg_settings_conformance_atomic => pg_settings_atomic },
        same_fact_duplicate => { #[tokio::test] pg_settings_conformance_duplicate => pg_settings_duplicate },
        same_key_conflict => { #[tokio::test] pg_settings_conformance_conflict => pg_settings_conflict },
        persistent_out_of_order => { #[tokio::test] pg_settings_conformance_order => pg_settings_order },
        identity_mismatch => { #[tokio::test] pg_settings_conformance_identity => pg_settings_identity },
        confirmed_rollback => { #[tokio::test] pg_settings_conformance_rollback => pg_settings_rollback },
        commit_unknown_replay => { #[tokio::test] pg_settings_conformance_commit_unknown => pg_settings_commit_unknown },
        rollback_failed => { #[tokio::test] pg_settings_conformance_rollback_failed => pg_settings_rollback_failed },
    }
}
