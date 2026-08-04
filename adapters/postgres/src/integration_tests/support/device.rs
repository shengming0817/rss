use super::*;

// ── Device certificate desired/reported/condition authority (#1896) ──────────────

pub(in super::super) fn device_certificate_policy_hash(
    validity_seconds: i32,
    renew_before_seconds: i32,
    client_auth: bool,
    server_auth: bool,
    sans: &[String],
) -> Vec<u8> {
    use deviceloop::CertificatePolicy;
    use sha2::{Digest as _, Sha256};

    let key_usages = [
        client_auth.then_some("clientAuth"),
        server_auth.then_some("serverAuth"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let policy = CertificatePolicy::restore(
        validity_seconds as u64,
        renew_before_seconds as u64,
        key_usages,
        sans.to_vec(),
    )
    .expect("test policy must be accepted by the production domain constructor");
    Sha256::digest(policy.canonical_bytes()).to_vec()
}

pub(in super::super) async fn insert_device_certificate_desired(
    store: &PgStore,
    tenant: &str,
    device: &str,
    client_auth: bool,
    server_auth: bool,
    sans: &[String],
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_certificate_desired_states ( \
             tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
             client_auth, server_auth, sans \
         ) VALUES ($1::uuid, $2::uuid, 1, 3600, 600, $3, $4, $5)",
    )
    .bind(tenant)
    .bind(device)
    .bind(client_auth)
    .bind(server_auth)
    .bind(sans)
    .execute(&store.pool)
    .await
}

pub(in super::super) fn reconcile_limit(value: usize) -> ReconcileMaxInFlight {
    let Ok(limit) = ReconcileMaxInFlight::try_new(value) else {
        unreachable!("fixed integration concurrency is valid");
    };
    limit
}

pub(in super::super) fn operator_repair_authorization(
    caller: vocab::ServiceCallerDomain,
    identity: diport::SagaWorkerIdentity,
    instance: consistency::SagaInstanceRef,
    reason: consistency::SagaOperatorReason,
    change_ticket: diport::SagaOperatorChangeTicket,
    start_audit_id: diport::SagaOperatorStartAuditId,
) -> Result<
    diport::SagaOperatorAuthorization<diport::saga_operator_action::Repair>,
    diport::SagaOperatorRepairReasonError,
> {
    let evidence = diport::SagaOperatorRepairExpectation::new(
        diport::SagaOperatorRepairReason::try_from(reason)?,
        diport::SagaOperatorReasonText::parse("provider evidence reviewed")
            .map_err(|_| diport::SagaOperatorRepairReasonError)?,
        change_ticket,
    );
    Ok(diport::test_support::saga_operator_authorization(
        caller,
        identity,
        instance,
        evidence,
        start_audit_id,
    ))
}

pub(in super::super) fn settings_operator_execution(
    tenant: vocab::TenantId,
) -> eventexec::ProjectionExecutionContext {
    let projection = eventexec::ProjectionId::parse(SETTINGS_PROJECTION_ID)
        .expect("generated Settings projection id");
    eventexec::WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
        &projection,
        tenant,
    )
    .expect("plan-issued Settings operator execution")
}
