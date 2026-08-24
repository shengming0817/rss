use super::*;

/// Integration-only tenant authority. This module is compiled only behind the test/integration
/// boundary, and the private carrier cannot be imported by production adapters.
#[derive(Clone, Copy)]
pub(in super::super) struct IntegrationTenantScope {
    pub(in super::super) tenant: rss_request_context::TenantId,
    pub(in super::super) _seal: (),
}

impl crate::cotx::TenantScopeHandle for IntegrationTenantScope {
    fn tenant(self) -> rss_request_context::TenantId {
        self.tenant
    }
}

pub(in super::super) fn integration_tenant_scope(
    tenant: rss_request_context::TenantId,
) -> IntegrationTenantScope {
    IntegrationTenantScope { tenant, _seal: () }
}

impl PgStore {
    /// Test-fixture-only raw transaction for global setup and observation.
    pub(in super::super) async fn raw_fixture_transaction<F, T, E>(
        &self,
        operation: F,
    ) -> Result<T, E>
    where
        F: for<'c> FnOnce(&'c mut sqlx::PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
        E: From<sqlx::Error> + Send,
        T: Send,
    {
        let mut transaction = self.pool.begin().await.map_err(E::from)?;
        let result = operation(&mut transaction).await;
        match result {
            Ok(value) => {
                transaction.commit().await.map_err(E::from)?;
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
    }

    /// Test-only serving write funnel for eventing facts. The closure receives only the exact
    /// serving-write transaction surface, matching production construction and tenant scoping.
    pub(in super::super) async fn serving_write_fixture<F, T, E>(
        &self,
        tenant: rss_request_context::TenantId,
        operation: F,
    ) -> Result<T, E>
    where
        F: for<'c, 'tx> FnOnce(
                &'c mut crate::cotx::eventing::OutboxTx<'tx>,
            ) -> BoxFuture<'c, Result<T, E>>
            + Send
            + 'static,
        E: From<sqlx::Error> + std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        crate::cotx::TenantDb::<crate::cotx::ServingWriteLane>::from_unverified_for_test(self)
            .test_write(integration_tenant_scope(tenant), operation, E::from)
            .await
    }
}

pub(in super::super) const TEST_APP_ROLE: &str = "rss_app";

pub(in super::super) const TEST_APP_PASSWORD: &str = "rss_app_test_pw";

pub(in super::super) const TEST_READ_ROLE: &str = "rss_app_read";

pub(in super::super) const TEST_READ_PASSWORD: &str = "rss_app_read_test_pw";

pub(in super::super) const TEST_PROJECTION_READER_ROLE: &str = "rss_projection_reader";

pub(in super::super) const TEST_PROJECTION_READER_PASSWORD: &str = "rss_projection_reader_test_pw";

pub(in super::super) const TEST_PROJECTION_OPERATOR_ROLE: &str = "rss_projection_operator";

pub(in super::super) const TEST_PROJECTION_OPERATOR_PASSWORD: &str =
    "rss_projection_operator_test_pw";

pub(in super::super) const TEST_PROJECTION_WORKER_ROLE: &str = "rss_projection_worker";

pub(in super::super) const TEST_PROJECTION_WORKER_PASSWORD: &str = "rss_projection_worker_test_pw";

pub(in super::super) const TEST_SAGA_OPERATOR_ROLE: &str = "rss_saga_operator";

pub(in super::super) const TEST_SAGA_OPERATOR_PASSWORD: &str = "rss_saga_operator_test_pw";

pub(in super::super) const TEST_L2_DR_RECOVERY_AUDITOR_ROLE: &str = "rss_l2_dr_recovery_auditor";

pub(in super::super) const TEST_L2_DR_RECOVERY_AUDITOR_PASSWORD: &str =
    "rss_l2_dr_recovery_auditor_test_pw";

pub(in super::super) const TEST_L2_DR_RECOVERY_EXECUTOR_ROLE: &str = "rss_l2_dr_recovery_executor";

pub(in super::super) const TEST_L2_DR_RECOVERY_EXECUTOR_PASSWORD: &str =
    "rss_l2_dr_recovery_executor_test_pw";

pub(in super::super) const COTX_TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

pub(in super::super) const COTX_TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

pub(in super::super) const SESSION_CREATED_TOPIC: &str = "identity.session-created";

pub(in super::super) use crate::test_pg::{
    connect_pg, connect_pg_audit_admin_role, connect_pg_nobypass_role,
    connect_pg_rss_app_read_role, connect_pg_rss_app_role, connect_pg_rss_app_role_with_limits,
    rss_app_read_config,
};

#[allow(clippy::unwrap_used)]
pub(in super::super) fn test_tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse(COTX_TENANT_A).unwrap()
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn test_inbox_ctx(group: &str) -> InboxReceiptContext {
    test_inbox_ctx_for(test_tenant(), group)
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn test_inbox_ctx_for(
    tenant: rss_request_context::TenantId,
    group: &str,
) -> InboxReceiptContext {
    InboxReceiptContext::new(
        tenant,
        ConsumerGroup::parse(group).unwrap(),
        "identity",
        "identity.session-created",
        "identity.session-created",
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )
    .unwrap()
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn reviewed_payload(bytes: &[u8]) -> OutboxPayload {
    OutboxPayload::from_reviewed_event_bytes(bytes.to_vec())
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn subject_id(raw: &str) -> diport::EnvelopeSubjectId {
    diport::EnvelopeSubjectId::from_opaque(raw).unwrap()
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn actor_for(tenant: rss_request_context::TenantId) -> diport::OutboxActor {
    diport::OutboxActor::scoped(
        rss_request_context::PrincipalKind::Admin,
        diport::OpaqueActorId::from_opaque("pg-integration-actor").unwrap(),
        tenant,
        rss_request_context::RowScope::Tenant,
    )
}

pub(in super::super) fn identity_scope(
    tenant: rss_request_context::TenantId,
) -> identity::ports::TenantRepoScope {
    identity::ports::TenantRepoScope::for_test(tenant)
}

pub(in super::super) fn device_certificate_status_query(
    scope: DeviceCertificateScope,
) -> Result<
    AuthorizedDeviceCertificateStatusRead,
    identity::ports::device_certificate::DeviceCertificateStatusAuthorizationError,
> {
    let subject = httpserve::AuthorizedSubject::for_test(
        generated::http::identity_v2::device_certificate_status_get::CONTRACT_ID,
        vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead,
        scope.tenant(),
        rss_request_context::PrincipalKind::Admin,
        "status-test-operator",
        httpserve::RouteResource::new(scope.device().as_uuid().hyphenated().to_string()),
    );
    AuthorizedDeviceCertificateStatusRead::from_authorized_subject(&subject, scope.device())
}

pub(in super::super) fn login_producer_receipt() -> identity::ports::LoginProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::login::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn refresh_producer_receipt() -> identity::ports::RefreshProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::refresh::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn logout_current_producer_receipt()
-> identity::ports::LogoutCurrentProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::logout::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn logout_all_producer_receipt() -> identity::ports::LogoutAllProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::logout_all::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn password_change_producer_receipt()
-> identity::ports::PasswordChangeProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::password_change::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn account_status_set_producer_receipt()
-> identity::ports::AccountStatusSetProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::account_status_set::PRODUCER)
        .into_receipt()
}

pub(in super::super) async fn execute_logout_current_route(
    lifecycle: &crate::PgIdentitySecurityLifecycle,
    tenant: rss_request_context::TenantId,
    command: identity::ports::LogoutCurrentCommand,
) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
    lifecycle
        .execute_logout_current(
            logout_current_producer_receipt(),
            identity_scope(tenant),
            command,
        )
        .await
}

pub(in super::super) async fn execute_logout_all_route(
    lifecycle: &crate::PgIdentitySecurityLifecycle,
    tenant: rss_request_context::TenantId,
    command: identity::ports::LogoutAllCommand,
) -> Result<identity::ports::CredentialSecurityReceipt, identity::ports::IdentityError> {
    lifecycle
        .execute_logout_all(
            logout_all_producer_receipt(),
            identity_scope(tenant),
            command,
        )
        .await
}

pub(in super::super) fn policies_create_producer_receipt()
-> identity::ports::PoliciesCreateProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::policies_create::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn policies_update_producer_receipt()
-> identity::ports::PoliciesUpdateProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::policies_update::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn policies_deactivate_producer_receipt()
-> identity::ports::PoliciesDeactivateProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::policies_deactivate::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn roles_assign_producer_receipt()
-> identity::ports::RolesAssignProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::roles_assign::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn roles_revoke_producer_receipt()
-> identity::ports::RolesRevokeProducerReceipt {
    httpserve::ProducerMarker::for_test(generated::http::identity_v1::roles_revoke::PRODUCER)
        .into_receipt()
}

pub(in super::super) fn settings_scope(
    tenant: rss_request_context::TenantId,
) -> settings::ports::TenantRepoScope {
    settings::ports::TenantRepoScope::for_test(tenant)
}

pub(in super::super) fn audit_scope(
    tenant: rss_request_context::TenantId,
) -> audit::ports::TenantRepoScope {
    audit::ports::TenantRepoScope::for_test(tenant)
}

/// 测试用固定事件发生时刻（unix 秒）——t10/t11 断言 envelope `occurred_at`（#1129）。
pub(in super::super) const TEST_OCCURRED_SECS: u64 = 1_700_000_000;

pub(in super::super) const TEST_SCHEMA_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub(in super::super) const EMPTY_PROJECTION_INPUT_GENERATION: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const fn lower_projection_conformance_binding(
    fixture: ProjectionConformanceFixture,
    binding: ProjectionConformanceBinding,
) -> vocab::ProjectionInputBinding {
    test_projection_input_binding(
        fixture.projection_id(),
        binding.source_domain(),
        binding.contract_id(),
        binding.contract_version(),
        binding.schema_hash(),
        binding.topic(),
    )
}

pub(in super::super) fn projection_conformance_inputs(
    fixture: ProjectionConformanceFixture,
) -> Vec<vocab::ProjectionInputBinding> {
    let mut bindings = vec![lower_projection_conformance_binding(
        fixture,
        fixture.binding(),
    )];
    if let Some(binding) = fixture.secondary_binding() {
        bindings.push(lower_projection_conformance_binding(fixture, binding));
    }
    bindings
}

#[allow(clippy::panic)]
pub(in super::super) static PROJECTION_CONFORMANCE_INPUTS: &[vocab::ProjectionInputBinding] = &[
    lower_projection_conformance_binding(
        ProjectionConformanceFixture::primary(),
        ProjectionConformanceFixture::primary().binding(),
    ),
    match ProjectionConformanceFixture::primary().secondary_binding() {
        Some(binding) => {
            lower_projection_conformance_binding(ProjectionConformanceFixture::primary(), binding)
        }
        None => panic!("primary conformance fixture must have its canonical secondary binding"),
    },
    lower_projection_conformance_binding(
        ProjectionConformanceFixture::foreign(),
        ProjectionConformanceFixture::foreign().binding(),
    ),
];

#[cfg(all(test, feature = "integration"))]
pub(in super::super) fn projection_conformance_definition(
    fixture: ProjectionConformanceFixture,
) -> Result<eventexec::ProjectionTargetDefinition, eventexec::ProjectionTargetConfigError> {
    eventexec::ProjectionTargetDefinition::new(
        test_contract_binding(
            fixture.definition_domain(),
            fixture.projection_id(),
            fixture.definition_version(),
            fixture.definition_schema_hash(),
        ),
        fixture.input_generation(),
    )
}

pub(in super::super) fn projection_conformance_registry(
    fixture: ProjectionConformanceFixture,
) -> Result<eventexec::ProjectionTargetRegistry, eventexec::ProjectionTargetConfigError> {
    let definition = projection_conformance_definition(fixture)?;
    let bindings = projection_conformance_inputs(fixture);
    eventexec::ProjectionTargetRegistry::from_conformance_fixture(&definition, &bindings)
}

pub(in super::super) const SESSION_PROJECTION_INPUT_GENERATION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(in super::super) static SESSION_PROJECTION_INPUTS: &[vocab::ProjectionInputBinding] =
    &[test_projection_input_binding(
        "test-projection",
        "identity",
        generated::event::identity_v1::session_created::CONTRACT.contract_id(),
        generated::event::identity_v1::session_created::CONTRACT.version(),
        generated::event::identity_v1::session_created::CONTRACT.schema_hash(),
        generated::event::identity_v1::session_created::TOPIC,
    )];

pub(in super::super) fn test_contract() -> vocab::ContractBinding {
    test_contract_binding("test", "test.contract", "v1", TEST_SCHEMA_HASH)
}

pub(in super::super) async fn reviewed_reconcile_command(
    store: &PgStore,
    attempt: &ReconcileAttempt,
    semantic_intent: &str,
    amount: i64,
) -> Result<ReviewedFencedCommand, TestError> {
    reviewed_reconcile_command_at_generation(store, attempt, semantic_intent, amount, 1).await
}

pub(in super::super) async fn reviewed_reconcile_command_at_generation(
    store: &PgStore,
    attempt: &ReconcileAttempt,
    semantic_intent: &str,
    amount: i64,
    generation: u64,
) -> Result<ReviewedFencedCommand, TestError> {
    let semantic_suffix = format!("{:x}", Sha256::digest(semantic_intent.as_bytes()));
    let artifact_id = format!("certificate-artifact-{amount}-{}", &semantic_suffix[..16]);
    let scope = DeviceCertificateScope::for_test(
        attempt.target().tenant(),
        ids::DeviceId::parse(attempt.target().resource_id())?,
    );
    let fence = CertificateAttemptFence::for_test(
        scope,
        attempt,
        ExpectedGeneration::try_new(generation)?,
    )?;
    let (authorization, snapshot) = authorized_artifact(
        store,
        scope,
        generation,
        &[0x11; 32],
        &artifact_id,
        vec![0x19, u8::try_from(amount).unwrap_or(0)],
    )
    .await?;
    let repository = crate::device_certificate::PgDeviceCertificateRepository::<
        ProductionEligibility,
    >::from_unverified_for_test(store);
    let append = repository
        .append_artifact_receipt(&fence, authorization)
        .await?;
    if append == ArtifactAppendOutcome::StaleFence {
        return Err("test artifact authority unexpectedly lost its fence".into());
    }
    let artifact_digest = snapshot.artifact_digest().as_bytes();
    let authorization_receipt_id: String = sqlx::query_scalar(
        "SELECT authorization_receipt_id::text FROM device_certificate_desired_generation_lineage \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=$3",
    )
    .bind(attempt.target().tenant().to_string())
    .bind(attempt.target().resource_id())
    .bind(i64::try_from(generation)?)
    .fetch_one(&store.pool)
    .await?;
    let command = crate::reconcile_test_driver::canonical_device_command(serde_json::json!({
        "deviceId": attempt.target().resource_id(),
        "authorizationReceiptId": authorization_receipt_id,
        "desiredGeneration": generation,
        "fenceEpoch": attempt.target().epoch(),
        "policyHash": format!("sha256:{}", "1".repeat(64)),
        "artifactId": artifact_id,
        "artifactDigest": format!("sha256:{}", artifact_digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()),
        "deadlineEpochSeconds": 4_000_000_000_u64
    }))?;
    Ok(crate::reconcile_test_driver::drive_reviewed_device_command(
        attempt,
        command,
        Arc::clone(&command_keyring()),
    )
    .await?)
}

pub(in super::super) async fn reviewed_bound_certificate_command(
    store: &PgStore,
    attempt: &ReconcileAttempt,
    generation: u64,
    policy_hash: &[u8],
    artifact_id: &str,
    artifact_digest: &[u8],
) -> Result<ReviewedFencedCommand, TestError> {
    reviewed_bound_certificate_command_with_deadline(
        store,
        attempt,
        generation,
        policy_hash,
        artifact_id,
        artifact_digest,
        4_000_000_000,
    )
    .await
}

pub(in super::super) async fn reviewed_bound_certificate_command_with_deadline(
    store: &PgStore,
    attempt: &ReconcileAttempt,
    generation: u64,
    policy_hash: &[u8],
    artifact_id: &str,
    artifact_digest: &[u8],
    deadline_epoch_seconds: u64,
) -> Result<ReviewedFencedCommand, TestError> {
    let encoded = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let authorization_receipt_id: String = sqlx::query_scalar(
        "SELECT authorization_receipt_id::text FROM device_certificate_desired_generation_lineage \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=$3",
    )
    .bind(attempt.target().tenant().to_string())
    .bind(attempt.target().resource_id())
    .bind(i64::try_from(generation)?)
    .fetch_one(&store.pool)
    .await?;
    let command = crate::reconcile_test_driver::canonical_device_command(serde_json::json!({
        "deviceId": attempt.target().resource_id(),
        "authorizationReceiptId": authorization_receipt_id,
        "desiredGeneration": generation,
        "fenceEpoch": attempt.target().epoch(),
        "policyHash": format!("sha256:{}", encoded(policy_hash)),
        "artifactId": artifact_id,
        "artifactDigest": format!("sha256:{}", encoded(artifact_digest)),
        "deadlineEpochSeconds": deadline_epoch_seconds
    }))?;
    Ok(crate::reconcile_test_driver::drive_reviewed_device_command(
        attempt,
        command,
        Arc::clone(&command_keyring()),
    )
    .await?)
}

pub(in super::super) async fn reviewed_bound_certificate_command_with_receipt(
    attempt: &ReconcileAttempt,
    generation: u64,
    authorization_receipt_id: uuid::Uuid,
    policy_hash: &[u8],
    artifact_id: &str,
    artifact_digest: &[u8],
) -> Result<ReviewedFencedCommand, TestError> {
    let encoded = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let command = crate::reconcile_test_driver::canonical_device_command(serde_json::json!({
        "deviceId": attempt.target().resource_id(),
        "authorizationReceiptId": authorization_receipt_id,
        "desiredGeneration": generation,
        "fenceEpoch": attempt.target().epoch(),
        "policyHash": format!("sha256:{}", encoded(policy_hash)),
        "artifactId": artifact_id,
        "artifactDigest": format!("sha256:{}", encoded(artifact_digest)),
        "deadlineEpochSeconds": 4_000_000_000_u64
    }))?;
    Ok(crate::reconcile_test_driver::drive_reviewed_device_command(
        attempt,
        command,
        Arc::clone(&command_keyring()),
    )
    .await?)
}

pub(in super::super) async fn rss_app_write_device_certificate_condition_vector(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    device: &str,
    fence: &CertificateAttemptFence,
    vector: [(&str, &str, &str); 6],
    commit: bool,
) -> Result<bool, sqlx::Error> {
    let condition_types = vector
        .iter()
        .map(|(kind, _, _)| (*kind).to_owned())
        .collect::<Vec<_>>();
    let statuses = vector
        .iter()
        .map(|(_, status, _)| (*status).to_owned())
        .collect::<Vec<_>>();
    let reasons = vector
        .iter()
        .map(|(_, _, reason)| (*reason).to_owned())
        .collect::<Vec<_>>();
    let generation = i64::try_from(fence.expected_generation().get())
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let epoch = i64::try_from(fence.epoch().get())
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let wake_version = i64::try_from(fence.wake_version().get())
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
    let mut transaction = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *transaction)
        .await?;
    let outcome = sqlx::query_scalar(
        "SELECT public.rss_write_device_certificate_conditions( \
         $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(tenant.to_string())
    .bind(device)
    .bind(fence.attempt_id())
    .bind(fence.lease_token())
    .bind(epoch)
    .bind(wake_version)
    .bind(generation)
    .bind(condition_types)
    .bind(statuses)
    .bind(reasons)
    .bind(vec![generation; 6])
    .fetch_one(&mut *transaction)
    .await;
    if outcome.is_ok() && commit {
        transaction.commit().await?;
    } else {
        transaction.rollback().await?;
    }
    outcome
}

pub(in super::super) async fn device_certificate_condition_rows(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    device: &str,
) -> Result<Vec<(String, String, String, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT condition_type,status,reason,observed_generation \
         FROM device_certificate_conditions \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid ORDER BY condition_type",
    )
    .bind(tenant.to_string())
    .bind(device)
    .fetch_all(&store.pool)
    .await
}

pub(in super::super) async fn insert_device_desired(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    device_id: &str,
) -> Result<(), sqlx::Error> {
    insert_device_certificate_desired(store, &tenant.to_string(), device_id, true, false, &[])
        .await?;
    Ok(())
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn command_keyring() -> std::sync::Arc<CommandIdempotencyKeyring> {
    std::sync::Arc::new(
        CommandIdempotencyKeyring::new(
            CommandAliasKey::new("k2", vec![0x42; 32]).unwrap(),
            vec![CommandAliasKey::new("k1", vec![0x24; 32]).unwrap()],
        )
        .unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn command_keyring_k1_only() -> std::sync::Arc<CommandIdempotencyKeyring> {
    std::sync::Arc::new(
        CommandIdempotencyKeyring::new(CommandAliasKey::new("k1", vec![0x24; 32]).unwrap(), vec![])
            .unwrap(),
    )
}

pub(in super::super) fn session_contract() -> vocab::ContractBinding {
    generated::event::identity_v1::session_created::CONTRACT
}

pub(in super::super) fn config_contract() -> vocab::ContractBinding {
    generated::event::settings_v1::CONTRACT
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn projection_maintenance_receipt(
    action: authn::ProjectionMaintenanceAction,
    tenant: rss_request_context::TenantId,
    projection: &str,
) -> authn::ProjectionMaintenanceReceipt {
    let principal =
        authn::test_support::service_principal(vocab::ServiceCallerDomain::MaintenanceOperator);
    let grants = authn::ProjectionMaintenanceGrantSet::new(vec![
        authn::ProjectionMaintenanceGrant::new(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            action,
            tenant,
            projection,
        )
        .unwrap(),
    ])
    .unwrap();
    grants
        .authorize(&principal, action, tenant, projection)
        .unwrap()
}

pub(in super::super) async fn insert_projection_shadow_checkpoint(
    store: &PgStore,
    selector: &eventexec::ProjectionSelector,
    offset: u64,
) -> TestResult {
    let saved: bool = sqlx::query_scalar(
        "SELECT public.rss_projection_operator_save_checkpoint($1::uuid, $2, $3, $4, 0)",
    )
    .bind(selector.tenant().to_string())
    .bind(selector.projection().as_str())
    .bind(selector.version().as_str())
    .bind(i64::try_from(offset)?)
    .fetch_one(&store.pool)
    .await?;
    assert!(saved, "fresh projection shadow checkpoint must be inserted");
    Ok(())
}

pub(in super::super) async fn insert_settings_projection_generation(
    store: &PgStore,
    selector: &eventexec::ProjectionSelector,
    high_water: u64,
) -> TestResult {
    let definition = generated::projection::settings_v3::CONTRACT;
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)",
    )
    .bind(selector.tenant().to_string())
    .bind(definition.contract_id())
    .bind(selector.version().as_str())
    .bind(definition.version())
    .bind(definition.schema_hash())
    .bind(generated::event::PROJECTION_INPUT_GENERATION)
    .bind(i64::try_from(high_water)?)
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// 固定时钟时刻（`Duration::from_secs` 取 `u64`）。
pub(in super::super) fn fixed_clock_time() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(TEST_OCCURRED_SECS)
}

/// DB 中 `occurred_at` 的期望编码值——经生产共享的 typed epoch 编码 owner 求得（`i64`），
/// 避免断言端 `u64` 字面量与写入端 `i64` 在边界值上漂移（review F4）。
pub(in super::super) fn expected_occurred_at() -> i64 {
    rss_contract::Timepoint::saturating_from_system_time(fixed_clock_time()).unix_seconds()
}

pub(in super::super) fn assert_metadata_text_has_standard_schema_header(
    metadata: &str,
    expected_schema_hash: &str,
    context: &str,
) {
    let compact = metadata.replace(' ', "");
    assert!(
        compact.contains(r#""schemaVersion":"v1""#),
        "{context} metadata 应含 schemaVersion: {metadata}"
    );
    assert!(
        compact.contains(&format!(r#""schemaHash":"{expected_schema_hash}""#)),
        "{context} metadata 应含 schemaHash: {metadata}"
    );
}

/// 集成测试固定时钟（impl [`diport::Clock`]）：确定性 `occurred_at`，不取系统时钟（#1129）。
/// 本地定义——**不**引 `memory` adapter 作 dev-dep（避免 adapter→adapter 依赖），同 oidc/relay 各自定义替身范式。
pub(in super::super) struct FixedClock(std::time::SystemTime);

impl diport::Clock for FixedClock {
    fn now(&self) -> std::time::SystemTime {
        self.0
    }
}

/// 构造注入用 clock（`Box<dyn Clock>`，emitter / session lifecycle 注入约定，固定 [`fixed_clock_time`]）。
pub(in super::super) fn fixed_clock() -> Box<dyn diport::Clock> {
    Box::new(FixedClock(fixed_clock_time()))
}

/// Projection operator 测试时钟（`Arc<dyn Clock>`，固定 [`fixed_clock_time`]）。
pub(in super::super) fn projection_clock() -> std::sync::Arc<dyn diport::Clock> {
    std::sync::Arc::new(FixedClock(fixed_clock_time()))
}

pub(in super::super) fn runtime_pg_config(
    p: &testkit::PgConnParams,
    username: &str,
    password: &str,
) -> PgConfig {
    PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        p.database.clone(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_acquire_timeout(std::time::Duration::from_secs(5))
}

pub(in super::super) async fn connect_pg_maintenance(
    fixture: &testkit::OwnedPgFixture,
) -> Result<crate::PgMaintenanceDeps, TestError> {
    let params = fixture.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    Ok(PgRuntimeDeps::connect_maintenance(&config).await?)
}

pub(in super::super) async fn provision_runtime_logins(
    fixture: &testkit::OwnedPgFixture,
) -> TestResult {
    fixture
        .resolve_app_roles([
            testkit::PgAppRoleSpec::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PgAppRoleSpec::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
            testkit::PgAppRoleSpec::new(
                TEST_PROJECTION_READER_ROLE,
                TEST_PROJECTION_READER_PASSWORD,
            ),
            testkit::PgAppRoleSpec::new(
                TEST_PROJECTION_OPERATOR_ROLE,
                TEST_PROJECTION_OPERATOR_PASSWORD,
            ),
            testkit::PgAppRoleSpec::new(
                TEST_PROJECTION_WORKER_ROLE,
                TEST_PROJECTION_WORKER_PASSWORD,
            ),
            testkit::PgAppRoleSpec::new(TEST_SAGA_OPERATOR_ROLE, TEST_SAGA_OPERATOR_PASSWORD),
            testkit::PgAppRoleSpec::new(
                TEST_L2_DR_RECOVERY_AUDITOR_ROLE,
                TEST_L2_DR_RECOVERY_AUDITOR_PASSWORD,
            ),
            testkit::PgAppRoleSpec::new(
                TEST_L2_DR_RECOVERY_EXECUTOR_ROLE,
                TEST_L2_DR_RECOVERY_EXECUTOR_PASSWORD,
            ),
        ])
        .await?;
    Ok(())
}

pub(in super::super) struct TestCaFile {
    path: std::path::PathBuf,
    pem: Vec<u8>,
}

impl TestCaFile {
    pub(in super::super) fn write(label: &str, pem: &str) -> Result<Self, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "rss-postgres-{label}-{}-{}.pem",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let pem = pem.as_bytes().to_vec();
        std::fs::write(&path, &pem)?;
        Ok(Self { path, pem })
    }

    pub(in super::super) fn private_ca(&self) -> Result<PgPrivateCa, crate::PgPrivateCaError> {
        PgPrivateCa::from_pem(self.pem.clone())
    }
}

impl Drop for TestCaFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(in super::super) fn private_ca_pg_config(
    params: &testkit::PgConnParams,
    username: &str,
    password: &str,
    ca_file: &TestCaFile,
) -> Result<PgConfig, crate::PgPrivateCaError> {
    Ok(PgConfig::new(
        params.host.clone(),
        params.port,
        params.database.clone(),
        username,
        PgPassword::new(password),
        ca_file.private_ca()?,
    )
    .with_acquire_timeout(std::time::Duration::from_secs(5)))
}

pub(in super::super) async fn setup_runtime_deps_with_projection_inputs(
    projection_input_generation: &'static str,
    projection_inputs: &'static [vocab::ProjectionInputBinding],
) -> Result<(testkit::OwnedPgFixture, PgRuntimeDeps), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::owned_postgres().await?;
    let p = fixture.owner_params();
    provision_runtime_logins(&fixture).await?;
    let owner_config = runtime_pg_config(p, &p.username, &p.password);
    let tenant_read_config = crate::pool::PgTenantReadConfig::new(runtime_pg_config(
        p,
        TEST_READ_ROLE,
        TEST_READ_PASSWORD,
    ));
    let deps = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
        &owner_config,
        &runtime_pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        &tenant_read_config,
        None,
        projection_input_generation,
        projection_inputs,
    )
    .await?;
    Ok((fixture, deps))
}

pub(in super::super) async fn runtime_assertion_pool(
    p: &testkit::PgConnParams,
) -> Result<sqlx::PgPool, Box<dyn std::error::Error + Send + Sync>> {
    let options = sqlx::postgres::PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username(&p.username)
        .password(&p.password)
        .ssl_mode(sqlx::postgres::PgSslMode::Prefer);
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?)
}

pub(in super::super) fn isolated_database_config(
    p: &testkit::PgConnParams,
    database: &str,
) -> PgConfig {
    PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        database.to_string(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_acquire_timeout(std::time::Duration::from_secs(5))
}

pub(in super::super) fn isolated_database_role_config(
    p: &testkit::PgConnParams,
    database: &str,
    username: &str,
    password: &str,
) -> PgConfig {
    PgConfig::new_for_test_plaintext(
        p.host.clone(),
        p.port,
        database.to_string(),
        username.to_string(),
        PgPassword::new(password.to_string()),
    )
    .with_acquire_timeout(std::time::Duration::from_secs(5))
}

pub(in super::super) fn isolated_tenant_read_config(
    p: &testkit::PgConnParams,
    database: &str,
) -> crate::pool::PgTenantReadConfig {
    crate::pool::PgTenantReadConfig::new(
        PgConfig::new_for_test_plaintext(
            p.host.clone(),
            p.port,
            database.to_string(),
            TEST_READ_ROLE,
            PgPassword::new(TEST_READ_PASSWORD),
        )
        .with_acquire_timeout(std::time::Duration::from_secs(5)),
    )
}

pub(in super::super) async fn create_isolated_database(
    store: &PgStore,
    prefix: &str,
) -> Result<String, sqlx::Error> {
    let suffix = unique_event_id("db").replace('-', "_");
    let database = format!("{prefix}_{suffix}_test");
    debug_assert!(
        database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!("CREATE DATABASE \"{database}\""))
        .execute(&store.pool)
        .await?;
    Ok(database)
}

pub(in super::super) async fn drop_isolated_database(
    store: &PgStore,
    database: &str,
) -> Result<(), sqlx::Error> {
    debug_assert!(
        database
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    );
    sqlx::query(&format!(
        "DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)"
    ))
    .execute(&store.pool)
    .await?;
    Ok(())
}

pub(in super::super) async fn assert_serving_ledger_rejected(
    config: &PgConfig,
    case: &str,
) -> TestResult {
    assert!(
        matches!(
            PgStore::connect_verified_writer(config).await,
            Err(PgError::SchemaLedgerProbe(_) | PgError::SchemaLedgerMismatch { .. })
        ),
        "serving ledger drift must fail closed: {case}"
    );
    Ok(())
}

#[allow(clippy::unwrap_used)]
// reason: UUID v4 is canonical and generated inside the integration fixture.
pub(in super::super) fn unique_revocation_scope() -> diport::CertScope {
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let device = ids::DeviceId::new(uuid::Uuid::new_v4());
    diport::CertScope::new(tenant, device)
}

#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
// reason: integration assertions need a whole-second expiry relative to the authoritative DB clock.
pub(in super::super) fn revocation_expiry_after(seconds: u64) -> diport::CertNotAfter {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    diport::CertNotAfter::try_from_system_time(
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now + seconds),
    )
    .unwrap()
}

#[allow(clippy::unwrap_used)]
// reason: integration fixtures use a canonical positive UNIX timestamp.
pub(in super::super) fn revocation_expiry_at_unix(seconds: u64) -> diport::CertNotAfter {
    diport::CertNotAfter::try_from_system_time(
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds),
    )
    .unwrap()
}

#[allow(clippy::unwrap_used)]
// reason: integration fixtures use fixed valid 1-20 byte certificate serials.
pub(in super::super) fn revocation_serial(bytes: &[u8]) -> diport::CertSerial {
    diport::CertSerial::try_new(bytes.to_vec()).unwrap()
}

pub(in super::super) async fn shutdown_runtime_deps(deps: PgRuntimeDeps) -> TestResult {
    let config = crate::PgRuntimeMonitorConfig::new(
        crate::PgReadinessInterval::try_new(std::time::Duration::from_secs(1)).expect("interval"),
        crate::PgRlsAttestationInterval::default(),
    );
    let (resources, _sampler_factory) = deps.into_runtime_parts(config);
    for resource in resources.into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}

pub(in super::super) async fn replace_test_projection_generation(
    store: &PgStore,
    generation: &str,
    bindings: &[(&str, &str, &str, &str, &str, &str)],
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT public.rss_retire_projection_input_generation($1)")
        .bind(generation)
        .execute(&store.pool)
        .await?;
    for (projection_id, source_domain, contract_id, contract_version, schema_hash, topic) in
        bindings
    {
        sqlx::query(
            "SELECT public.rss_register_projection_input_binding(\
             $1, $2, 'v1', $3, $4, $5, $6, $7, $8)",
        )
        .bind(generation)
        .bind(projection_id)
        .bind(schema_hash)
        .bind(source_domain)
        .bind(contract_id)
        .bind(contract_version)
        .bind(schema_hash)
        .bind(topic)
        .execute(&store.pool)
        .await?;
    }
    Ok(())
}

pub(in super::super) async fn connect_test_projection_runtime(
    params: &testkit::PgConnParams,
    generation: &'static str,
    bindings: &'static [vocab::ProjectionInputBinding],
) -> Result<PgRuntimeDeps, PgError> {
    PgRuntimeDeps::connect_serving_with_projection_bindings(
        &runtime_pg_config(params, TEST_APP_ROLE, TEST_APP_PASSWORD),
        &crate::pool::PgTenantReadConfig::new(runtime_pg_config(
            params,
            TEST_READ_ROLE,
            TEST_READ_PASSWORD,
        )),
        None,
        generation,
        bindings,
    )
    .await
}

pub(in super::super) fn saga_receipt_protection(
    provider: Box<diport::DynKeyProvider<'static>>,
) -> Result<crate::PgSagaReceiptProtection, TestError> {
    Ok(crate::PgSagaReceiptProtection::new(
        provider,
        secure::SagaReceiptIntegrityKeyring::new(
            secure::VersionedSagaReceiptIntegrityKey::new(
                secure::SagaReceiptIntegrityKeyId::parse("receipt-test-v1")?,
                secure::RedactionHashKey::from_bytes(vec![0x42; 32])?,
            ),
            vec![],
        )?,
    ))
}

pub(in super::super) fn saga_receipt_test_protection()
-> Result<crate::PgSagaReceiptProtection, TestError> {
    saga_receipt_protection(diport::DynKeyProvider::new_box(AadBoundKeyProvider))
}

pub(in super::super) async fn run_migrations_through(
    store: &PgStore,
    last_version: i64,
) -> TestResult {
    use std::borrow::Cow;

    let embedded = sqlx::migrate!("./migrations");
    let migrations = embedded
        .iter()
        .filter(|migration| migration.version <= last_version)
        .cloned()
        .collect();
    let migrator = sqlx::migrate::Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
        no_tx: embedded.no_tx,
    };
    migrator.run(&store.pool).await?;
    Ok(())
}

pub(in super::super) async fn insert_account_security_pair(
    store: &PgStore,
    tenant_id: &str,
    user_id: &str,
    login: &str,
) -> TestResult {
    let mut tx = store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO public.credentials \
         (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, $3, 'phc-for-migration-contract', 1)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(login)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO public.account_security_states \
         (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at) \
         VALUES ($1::uuid, $2::uuid, 'active', 0, 1, now(), now())",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::panic)]
pub(in super::super) fn assert_database_constraint<T>(
    result: Result<T, sqlx::Error>,
    expected: &str,
) {
    match result {
        Err(sqlx::Error::Database(error)) => {
            assert_eq!(
                error.constraint(),
                Some(expected),
                "statement failed through the wrong database constraint: {error}"
            );
        }
        Err(error) => panic!("expected database constraint {expected}, got {error}"),
        Ok(_) => panic!("expected database constraint {expected}, statement succeeded"),
    }
}

pub(in super::super) fn l2_dr_recovery_plan(
    epoch_id: uuid::Uuid,
    tenant: rss_request_context::TenantId,
    database_restore_point: i64,
    broker_restore_point: i64,
    event_ids: &[String],
) -> Result<eventexec::L2DrRecoveryPlan, TestError> {
    let events = event_ids
        .iter()
        .map(|event_id| IdemKey::parse(event_id))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(eventexec::L2DrRecoveryPlan::new(
        eventexec::RecoveryEpochId::new(epoch_id)?,
        tenant,
        eventexec::UtcEpochMicros::new(database_restore_point)?,
        eventexec::UtcEpochMicros::new(broker_restore_point)?,
        eventexec::RecoveryEventSet::new(events)?,
        eventexec::RecoveryChangeTicket::parse("CHG-1837-PG")?,
    )?)
}

pub(in super::super) async fn authorize_l2_dr_recovery(
    owner: &PgStore,
    deps: &crate::PgL2DrRecoveryDeps,
    plan: eventexec::L2DrRecoveryPlan,
    start_audit_id: uuid::Uuid,
) -> Result<eventexec::RequiredAdmissionFence, TestError> {
    authorize_l2_dr_recovery_as(owner, deps, plan, "service:l2-dr-test", start_audit_id).await
}

pub(in super::super) async fn authorize_l2_dr_recovery_as(
    owner: &PgStore,
    deps: &crate::PgL2DrRecoveryDeps,
    plan: eventexec::L2DrRecoveryPlan,
    operator_subject: &str,
    start_audit_id: uuid::Uuid,
) -> Result<eventexec::RequiredAdmissionFence, TestError> {
    let admission_epoch = arm_l2_dr_admission(owner, deps, &plan).await?;
    authorize_l2_dr_recovery_as_with_admission(
        deps,
        plan,
        operator_subject,
        start_audit_id,
        admission_epoch,
    )
    .await
}

pub(in super::super) async fn authorize_l2_dr_recovery_as_with_admission(
    deps: &crate::PgL2DrRecoveryDeps,
    plan: eventexec::L2DrRecoveryPlan,
    operator_subject: &str,
    start_audit_id: uuid::Uuid,
    admission_epoch: primitives::AdmissionEpochId,
) -> Result<eventexec::RequiredAdmissionFence, TestError> {
    let operator_subject = eventexec::L2DrRecoveryOperatorSubject::parse(operator_subject)?;
    let proof = deps
        .record_l2_dr_recovery_start_audit_subject(&operator_subject, &plan, start_audit_id)
        .await?;
    let authorized = eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
        plan,
        proof,
        eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator(),
    )?;
    Ok(authorized.require_admission(admission_epoch))
}

pub(in super::super) async fn arm_l2_dr_admission(
    owner: &PgStore,
    deps: &crate::PgL2DrRecoveryDeps,
    plan: &eventexec::L2DrRecoveryPlan,
) -> Result<primitives::AdmissionEpochId, TestError> {
    sqlx::query("DELETE FROM public.event_l2_dr_admission_epoch WHERE singleton")
        .execute(&owner.pool)
        .await?;
    let admission_epoch = primitives::AdmissionEpochId::new(uuid::Uuid::new_v4())?;
    let assembly_identity = "runtime";
    let runtime_plan_fingerprint = "sha256:test-runtime-plan";
    let instance_id = uuid::Uuid::new_v4();
    let boot_id = uuid::Uuid::new_v4();
    let declared = serde_json::json!([{
        "assemblyIdentity": assembly_identity,
        "runtimePlanFingerprint": runtime_plan_fingerprint,
        "instanceId": instance_id.to_string(),
    }]);
    deps.request_l2_dr_admission_pause(admission_epoch, &plan, &declared, true)
        .await?;
    let acknowledged: bool = sqlx::query_scalar(
        "SELECT public.rss_l2_dr_admission_ack(\
         $1::uuid, $2, $3, $4::uuid, $5::uuid, 'drained', $1::uuid)",
    )
    .bind(admission_epoch.as_uuid().to_string())
    .bind(assembly_identity)
    .bind(runtime_plan_fingerprint)
    .bind(instance_id.to_string())
    .bind(boot_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    if !acknowledged {
        return Err("test admission fence acknowledgement was rejected".into());
    }
    Ok(admission_epoch)
}

pub(in super::super) fn mint_l2_dr_authorized_without_durable_start(
    plan: eventexec::L2DrRecoveryPlan,
    operator_subject: &str,
    start_audit_id: uuid::Uuid,
    admission_epoch: primitives::AdmissionEpochId,
) -> Result<eventexec::RequiredAdmissionFence, TestError> {
    let operator_subject = eventexec::L2DrRecoveryOperatorSubject::parse(operator_subject)?;
    let proof = eventexec::L2DrRecoveryDurableStartProof::from_store(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_subject,
        plan.tenant(),
        plan.epoch_id(),
        *plan.digest(),
        start_audit_id,
    )?;
    let authorized = eventexec::AuthorizedL2DrRecoveryPlan::from_authenticated_and_authorized(
        plan,
        proof,
        eventexec::OperatorL2DrRecoveryCapability::issue_for_authorized_operator(),
    )?;
    Ok(authorized.require_admission(admission_epoch))
}

pub(in super::super) async fn l2_dr_receipt_count(
    store: &PgStore,
    epoch_id: uuid::Uuid,
) -> Result<i64, TestError> {
    Ok(sqlx::query_scalar(
        "SELECT count(*)::bigint FROM public.event_l2_dr_recovery_receipt \
             WHERE epoch_id = $1::uuid",
    )
    .bind(epoch_id.to_string())
    .fetch_one(&store.pool)
    .await?)
}

pub(in super::super) async fn l2_dr_outbox_snapshot(
    store: &PgStore,
    event_id: &str,
) -> Result<Option<String>, TestError> {
    Ok(
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM public.outbox WHERE event_id = $1")
            .bind(event_id)
            .fetch_optional(&store.pool)
            .await?,
    )
}

pub(in super::super) async fn forge_l2_dr_start_audit_as_rss_app(
    app: &PgStore,
    plan: &eventexec::L2DrRecoveryPlan,
    operator_subject: &str,
    start_audit_id: uuid::Uuid,
) -> TestResult {
    let correlation_id = format!(
        "sha256:{}",
        plan.digest()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    sqlx::query(
        "INSERT INTO public.auth_audit_events (
            occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
            resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
         ) VALUES (
            1, 0, $1, 'service', $2::uuid, 'eventing.l2-dr-recovery', $3,
            'eventing.l2-dr-recovery.apply.start', 'success', NULL, $4, $5
         )",
    )
    .bind(operator_subject)
    .bind(plan.tenant().to_string())
    .bind(plan.epoch_id().as_uuid().to_string())
    .bind(start_audit_id.to_string())
    .bind(correlation_id)
    .execute(&app.pool)
    .await?;
    Ok(())
}

pub(in super::super) async fn insert_l2_dr_published_fact(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    event_id: &str,
    deadline_offset_seconds: i64,
) -> TestResult {
    let metadata = serde_json::json!({
        "tenantId": tenant.to_string(),
        "schemaVersion": "v1",
        "schemaHash": TEST_SCHEMA_HASH,
    })
    .to_string();
    sqlx::query(
        r#"
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
            payload, metadata, status, automatic_retry_deadline, published_at, updated_at
        ) VALUES (
            $1, $2::uuid, 'l2-dr-test', 'l2-dr.test', 'l2-dr.test', 'v1', $3,
            decode('1837', 'hex'), $4::jsonb, 'published',
            clock_timestamp() + make_interval(secs => $5::double precision),
            clock_timestamp() + make_interval(secs => $5::double precision) - interval '1 hour',
            clock_timestamp()
        )
        "#,
    )
    .bind(event_id)
    .bind(tenant.to_string())
    .bind(TEST_SCHEMA_HASH)
    .bind(metadata)
    .bind(deadline_offset_seconds)
    .execute(&store.pool)
    .await?;
    Ok(())
}

pub(in super::super) fn l2_dr_lane_configs(
    params: &testkit::PgConnParams,
) -> (
    crate::PgL2DrRecoveryAuditConfig,
    crate::PgL2DrRecoveryExecutorConfig,
) {
    (
        crate::PgL2DrRecoveryAuditConfig::new(runtime_pg_config(
            params,
            TEST_L2_DR_RECOVERY_AUDITOR_ROLE,
            TEST_L2_DR_RECOVERY_AUDITOR_PASSWORD,
        )),
        crate::PgL2DrRecoveryExecutorConfig::new(runtime_pg_config(
            params,
            TEST_L2_DR_RECOVERY_EXECUTOR_ROLE,
            TEST_L2_DR_RECOVERY_EXECUTOR_PASSWORD,
        )),
    )
}

#[derive(Debug, PartialEq, Eq)]
pub(in super::super) enum ConcurrentL2DrApplyObservation {
    AlreadyApplied {
        operator_subject: String,
        start_audit_id: uuid::Uuid,
        applied_at: eventexec::UtcEpochMicros,
    },
    Applied {
        operator_subject: String,
        start_audit_id: uuid::Uuid,
        applied_at: eventexec::UtcEpochMicros,
    },
    EpochConflict,
}

impl ConcurrentL2DrApplyObservation {
    pub(in super::super) const fn label(&self) -> &'static str {
        match self {
            Self::AlreadyApplied { .. } => "already_applied",
            Self::Applied { .. } => "applied",
            Self::EpochConflict => "epoch_conflict",
        }
    }

    pub(in super::super) fn from_result(
        result: Result<eventexec::L2DrRecoveryReceipt, eventexec::L2DrRecoveryError>,
    ) -> Result<Self, eventexec::L2DrRecoveryError> {
        match result {
            Ok(receipt) => {
                let operator_subject = receipt.operator_subject().as_str().to_owned();
                let start_audit_id = receipt.start_audit_id();
                let applied_at = receipt.applied_at();
                match receipt.outcome() {
                    eventexec::L2DrRecoveryOutcome::Applied => Ok(Self::Applied {
                        operator_subject,
                        start_audit_id,
                        applied_at,
                    }),
                    eventexec::L2DrRecoveryOutcome::AlreadyApplied => Ok(Self::AlreadyApplied {
                        operator_subject,
                        start_audit_id,
                        applied_at,
                    }),
                }
            }
            Err(eventexec::L2DrRecoveryError::EpochConflict) => Ok(Self::EpochConflict),
            Err(error) => Err(error),
        }
    }
}

pub(in super::super) async fn tenant_reader_gate_verdict(
    reader_config: &crate::PgTenantReadConfig,
) -> Result<Result<(), crate::PgError>, TestError> {
    let reader = PgStore::connect(reader_config.as_pg_config()).await?;
    let verdict = reader.verify_tenant_read_capability().await;
    reader.shutdown().await?;
    Ok(verdict)
}

pub(in super::super) fn secret_repo_conformance_category(
    error: &SecretRepoError,
) -> rss_conformance::ConformanceErrorCategory {
    match error {
        SecretRepoError::VersionConflict => rss_conformance::ConformanceErrorCategory::Conflict,
        SecretRepoError::Storage(_) => rss_conformance::ConformanceErrorCategory::Storage,
        _ => rss_conformance::ConformanceErrorCategory::Other,
    }
}

pub(in super::super) fn secret_repo_classified(
    error: SecretRepoError,
) -> rss_conformance::localtx::ClassifiedError<SecretRepoError> {
    let category = secret_repo_conformance_category(&error);
    rss_conformance::localtx::ClassifiedError::new(category, error)
}

#[derive(Debug)]
pub(in super::super) struct AuditLocalTxProfileError {
    pub(in super::super) category: rss_conformance::ConformanceErrorCategory,
    pub(in super::super) source: Box<dyn std::error::Error + Send + Sync>,
}

impl AuditLocalTxProfileError {
    pub(in super::super) fn provider(
        category: rss_conformance::ConformanceErrorCategory,
        source: diport::AuditSinkError,
    ) -> Self {
        Self {
            category,
            source: Box::new(source),
        }
    }

    pub(in super::super) fn storage(
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            category: rss_conformance::ConformanceErrorCategory::Storage,
            source: Box::new(source),
        }
    }
}

impl std::fmt::Display for AuditLocalTxProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "audit LocalTx provider profile failed ({})",
            self.category
        )
    }
}

impl std::error::Error for AuditLocalTxProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(in super::super) fn audit_profile_category(
    error: &AuditLocalTxProfileError,
) -> rss_conformance::ConformanceErrorCategory {
    error.category
}

pub(in super::super) fn audit_profile_classified(
    error: AuditLocalTxProfileError,
) -> rss_conformance::localtx::ClassifiedError<AuditLocalTxProfileError> {
    rss_conformance::localtx::ClassifiedError::new(error.category, error)
}

pub(in super::super) fn audit_list_tenant_command(
    tenant: rss_request_context::TenantId,
) -> audit::ports::AuditListTenantAppend {
    audit::ports::AuditListTenantAppend::for_test(
        tenant,
        diport::AuditEvent {
            occurred_at: std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(TEST_OCCURRED_SECS),
            principal_id: "localtx-audit-super-admin".to_string(),
            principal_kind: rss_request_context::PrincipalKind::SuperAdmin,
            tenant_id: None,
            resource_kind: "audit_entries",
            resource_id: tenant.to_string(),
            action: "audit:list-cross-tenant",
            outcome: diport::AuditOutcome::Success,
            request_id: Some("localtx-audit-request".to_string()),
            correlation_id: Some("localtx-audit-correlation".to_string()),
        },
    )
}

pub(in super::super) async fn auth_audit_snapshot(
    owner: &PgStore,
    tenant: rss_request_context::TenantId,
) -> Result<usize, AuditLocalTxProfileError> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM auth_audit_events WHERE tenant_context = $1::uuid")
            .bind(tenant.to_string())
            .fetch_one(&owner.pool)
            .await
            .map_err(AuditLocalTxProfileError::storage)?;
    usize::try_from(count).map_err(AuditLocalTxProfileError::storage)
}

pub(in super::super) async fn poll_with_local_recorder<R, F>(recorder: &R, future: F) -> F::Output
where
    R: metrics::Recorder,
    F: Future,
{
    let mut future = Box::pin(future);
    poll_fn(|cx| metrics::with_local_recorder(recorder, || future.as_mut().poll(cx))).await
}

pub(in super::super) async fn insert_outbox_log_with_metadata(
    store: &PgStore,
    event_id: &str,
    tenant: rss_request_context::TenantId,
    metadata: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let mut tx = store.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO outbox_log \
         (event_id, tenant_id, aggregate_type, aggregate_id, topic, contract_id, \
          contract_version, schema_hash, payload, metadata, causation_id) \
         VALUES \
         ($1, $2::uuid, 'identity', $1, 'identity.session-created', \
          'identity.session-created', 'v1', $3, decode('70', 'hex'), $4::jsonb, NULL)",
    )
    .bind(event_id)
    .bind(tenant.to_string())
    .bind(TEST_SCHEMA_HASH)
    .bind(metadata.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(in super::super) async fn claim_device_certificate_attempt(
    store: &PgStore,
    tenant: rss_request_context::TenantId,
    device: &str,
    holder: &str,
) -> Result<ReconcileAttempt, TestError> {
    let reconcile = store.reconcile();
    let key =
        ReconcileTargetKey::parse("identity.device-certificate", "device-certificate", device)?;
    reconcile.upsert_target(tenant, &key).await?;
    let claim = ReconcileScheduleStore::claim_due_targets(
        &reconcile,
        tenant,
        "identity.device-certificate",
        holder,
        reconcile_limit(1),
        Duration::from_secs(30),
    )
    .await?
    .pop()
    .ok_or("device-certificate target was not claimable")?;
    match ReconcileScheduleStore::append_attempt(&reconcile, &claim, holder).await? {
        ScheduleAttemptOutcome::Started(attempt) => Ok(attempt),
        ScheduleAttemptOutcome::Lost => Err("fresh device-certificate lease was lost".into()),
    }
}

pub(in super::super) async fn authorized_artifact(
    store: &PgStore,
    scope: DeviceCertificateScope,
    generation: u64,
    policy_hash: &[u8],
    artifact_id: &str,
    serial: Vec<u8>,
) -> Result<
    (
        ArtifactAppendAuthorization<ProductionEligibility>,
        PersistedCertificateArtifactSnapshot<ProductionEligibility>,
    ),
    TestError,
> {
    let receipt_id: String = sqlx::query_scalar(
        "SELECT authorization_receipt_id::text \
         FROM device_certificate_desired_generation_lineage \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid AND generation=$3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.device().as_uuid().to_string())
    .bind(i64::try_from(generation)?)
    .fetch_one(&store.pool)
    .await?;
    authorized_artifact_with_receipt(
        scope,
        generation,
        policy_hash,
        artifact_id,
        serial,
        uuid::Uuid::parse_str(&receipt_id)?,
    )
}

pub(in super::super) fn authorized_artifact_with_receipt(
    scope: DeviceCertificateScope,
    generation: u64,
    policy_hash: &[u8],
    artifact_id: &str,
    serial: Vec<u8>,
    authorization_receipt_id: uuid::Uuid,
) -> Result<
    (
        ArtifactAppendAuthorization<ProductionEligibility>,
        PersistedCertificateArtifactSnapshot<ProductionEligibility>,
    ),
    TestError,
> {
    let receipt_id =
        identity::ports::device_certificate::DevicePolicyAuthorizationReceiptId::restore(
            authorization_receipt_id,
        )?;
    let generation = ExpectedGeneration::try_new(generation)?;
    let policy_hash = PolicyHash::restore(policy_hash)?;
    let public_key_digest = CertificatePublicKeyDigest::restore(&[0x21_u8; 32])?;
    let artifact = format!("certificate-material:{artifact_id}").into_bytes();
    let artifact_digest = ArtifactDigest::restore(&Sha256::digest(&artifact))?;
    let state_hash = ReportedStateHash::restore(&[0x41_u8; 32])?;
    let artifact_id = CertificateArtifactId::parse(artifact_id)?;
    let cert_scope = CertScope::new(scope.tenant(), scope.device());
    let serial = CertSerial::try_new(serial)?;
    let not_after = CertNotAfter::try_from_system_time(
        std::time::UNIX_EPOCH + Duration::from_secs(4_000_000_000),
    )?;
    let expected = CertificateArtifactRequest::for_test_with_receipt(
        scope,
        generation,
        policy_hash,
        receipt_id,
        CertificateArtifactMaterial::new(
            public_key_digest,
            artifact_digest,
            state_hash,
            artifact_id,
            cert_scope,
            serial,
            not_after,
        ),
    )?;
    let authorization = ProviderCertificateCandidate::new(artifact, expected.binding().clone())
        .authorize_production_for_test(&expected)?
        .into_append_authorization();
    let snapshot = PersistedCertificateArtifactSnapshot::restore(expected.binding().clone());
    Ok((authorization, snapshot))
}

pub(in super::super) async fn artifact_append_fixture(
    store: &PgStore,
    holder: &str,
) -> Result<
    (
        DeviceCertificateScope,
        CertificateAttemptFence,
        Vec<u8>,
        ReconcileAttempt,
    ),
    TestError,
> {
    let tenant = rss_request_context::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let device = uuid::Uuid::new_v4().to_string();
    insert_device_desired(store, tenant, &device).await?;
    let policy_hash = sqlx::query_scalar(
        "SELECT policy_hash FROM device_certificate_desired_states \
         WHERE tenant_id=$1::uuid AND device_id=$2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&device)
    .fetch_one(&store.pool)
    .await?;
    let attempt = claim_device_certificate_attempt(store, tenant, &device, holder).await?;
    let scope = DeviceCertificateScope::for_test(tenant, ids::DeviceId::parse(&device)?);
    let fence =
        CertificateAttemptFence::for_test(scope, &attempt, ExpectedGeneration::try_new(1)?)?;
    Ok((scope, fence, policy_hash, attempt))
}

/// 在独立事务内读 `rss_tx_probe` 行数（committed 数据跨池连接可见）。
pub(in super::super) async fn probe_count(store: &PgStore) -> Result<i64, sqlx::Error> {
    store
        .raw_fixture_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                let row: (i64,) = sqlx::query_as("SELECT count(*) FROM rss_tx_probe")
                    .fetch_one(&mut *cap)
                    .await?;
                Ok(row.0)
            }) as BoxFuture<'_, Result<i64, sqlx::Error>>
        })
        .await
}

pub(in super::super) use crate::outbox::STATUS_PENDING;

pub(in super::super) async fn create_rss_app_role_for_migration_test(
    store: &PgStore,
) -> TestResult {
    sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app NOLOGIN NOBYPASSRLS;
            END IF;
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_outbox_maintenance') THEN
                CREATE ROLE rss_outbox_maintenance NOLOGIN BYPASSRLS;
            END IF;
        END
        $$;
        GRANT USAGE ON SCHEMA public TO rss_app;
        "#,
    )
    .execute(&store.pool)
    .await?;
    Ok(())
}

pub(in super::super) fn migrations_through(max_version: i64) -> sqlx::migrate::Migrator {
    let all = sqlx::migrate!("./migrations");
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            all.iter()
                .filter(|migration| migration.version <= max_version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

pub(in super::super) async fn apply_outbox_legacy_prereqs_through_0031(
    store: &PgStore,
) -> TestResult {
    create_rss_app_role_for_migration_test(store).await?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0031_harden_outbox_tenant_scope.sql"
    ))
    .execute(&store.pool)
    .await?;
    Ok(())
}
