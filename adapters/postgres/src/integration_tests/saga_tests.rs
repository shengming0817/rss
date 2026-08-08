//! Postgres integration tests — saga seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn saga_candidate_tenants_are_runnable_only_keyset_pages() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let mut runnable = Vec::new();
    for _ in 0..5 {
        let tenant = uuid::Uuid::new_v4();
        runnable.push(tenant);
        sqlx::query(
            "INSERT INTO public.saga_instances (\
             tenant_id, saga_id, owner, contract_id, definition_version,\
             definition_schema_digest, action_registry_generation, status,\
             start_actor, start_audit_id)\
             VALUES ($1::uuid, $2::uuid, 'billing', 'billing-v1', 'v1',\
             'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',\
             'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',\
             'ready', 'integration-test', 'candidate-runnable')",
        )
        .bind(tenant.to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&owner.pool)
        .await?;
    }
    for (status, operator_reason, compensation_cause) in [
        ("operator_required", Some("forward_outcome_unknown"), None),
        ("degraded", None, None),
        ("compensation_failed", None, Some("business_failure")),
    ] {
        sqlx::query(
            "INSERT INTO public.saga_instances (\
             tenant_id, saga_id, owner, contract_id, definition_version,\
             definition_schema_digest, action_registry_generation, status, operator_reason,\
             compensation_cause, start_actor, start_audit_id)\
             VALUES ($1::uuid, $2::uuid, 'billing', 'billing-v1', 'v1',\
             'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',\
             'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',\
             $3, $4, $5, 'integration-test', 'candidate-unresolved')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(status)
        .bind(operator_reason)
        .bind(compensation_cause)
        .execute(&owner.pool)
        .await?;
    }
    runnable.sort();

    let mut observed = Vec::new();
    let mut after: Option<String> = None;
    for expected_len in [2_usize, 2, 1] {
        let page: Vec<String> = sqlx::query_scalar(
            "SELECT tenant_id::text FROM public.rss_saga_candidate_tenants(\
             'billing', 'billing-v1', $1::uuid, 2)",
        )
        .bind(after.as_deref())
        .fetch_all(&app.pool)
        .await?;
        assert_eq!(page.len(), expected_len);
        after = page.last().cloned();
        observed.extend(page);
    }
    assert_eq!(
        observed,
        runnable
            .iter()
            .map(uuid::Uuid::to_string)
            .collect::<Vec<_>>()
    );
    let unresolved: (i64, i64, i64, Option<String>) = sqlx::query_as(
        "SELECT operator_required_count, degraded_count, compensation_failed_count, \
                oldest_unresolved_at::text \
         FROM public.rss_saga_observe_unresolved('billing', 'billing-v1')",
    )
    .fetch_one(&app.pool)
    .await?;
    assert_eq!((unresolved.0, unresolved.1, unresolved.2), (1, 1, 1));
    assert!(unresolved.3.is_some());

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_unresolved_observation_adapter_preserves_oldest_across_claim_and_clear() -> TestResult
{
    use diport::{SagaDurableStore as _, SagaOperatorStore as _, SagaTenantSource as _};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let store = app.saga_durable_store(saga_receipt_test_protection()?);
    let identity = diport::SagaWorkerIdentity::new(
        "observe-adapter",
        diport::SagaContractId::parse("observe-adapter-v1")?,
    )?;
    let definition =
        consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
    let operator_tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let operator_instance = consistency::SagaInstanceRef::new(
        operator_tenant,
        consistency::SagaId::new(uuid::Uuid::new_v4()),
    )?;
    let mut inserted_epoch_micros = Vec::new();

    for (tenant, saga_id, status, operator_reason, compensation_cause) in [
        (
            operator_tenant,
            operator_instance.saga_id(),
            "operator_required",
            Some("forward_outcome_unknown"),
            None,
        ),
        (
            vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?,
            consistency::SagaId::new(uuid::Uuid::new_v4()),
            "degraded",
            None,
            None,
        ),
        (
            vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?,
            consistency::SagaId::new(uuid::Uuid::new_v4()),
            "compensation_failed",
            None,
            Some("business_failure"),
        ),
    ] {
        let unresolved_epoch_micros: i64 = sqlx::query_scalar(
            "INSERT INTO public.saga_instances (\
             tenant_id, saga_id, owner, contract_id, definition_version,\
             definition_schema_digest, action_registry_generation, status, operator_reason,\
             compensation_cause, start_actor, start_audit_id)\
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10,\
                     'integration-test', 'observe-adapter-start')\
             RETURNING (EXTRACT(EPOCH FROM unresolved_at) * 1000000)::bigint",
        )
        .bind(tenant.to_string())
        .bind(saga_id.as_uuid().to_string())
        .bind(identity.owner())
        .bind(identity.contract_id().as_str())
        .bind(definition.version())
        .bind(definition.schema_digest())
        .bind(definition.action_registry_generation())
        .bind(status)
        .bind(operator_reason)
        .bind(compensation_cause)
        .fetch_one(&owner.pool)
        .await?;
        inserted_epoch_micros.push(unresolved_epoch_micros);
    }
    let expected_oldest_micros = inserted_epoch_micros
        .into_iter()
        .min()
        .ok_or_else(|| std::io::Error::other("unresolved fixture was empty"))?;

    let observed = store.observe_unresolved(&identity).await?;
    assert_eq!(observed.operator_required(), 1);
    assert_eq!(observed.degraded(), 1);
    assert_eq!(observed.compensation_failed(), 1);
    let oldest = observed
        .oldest_unresolved_at()
        .ok_or_else(|| std::io::Error::other("non-empty unresolved set lost oldest timestamp"))?;
    assert_eq!(
        oldest
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_micros(),
        u128::try_from(expected_oldest_micros)?,
        "adapter hydration must preserve PostgreSQL microsecond precision",
    );

    let authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        operator_instance,
        consistency::SagaOperatorReason::ForwardOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-OBSERVE-CLAIM")?,
        diport::SagaOperatorStartAuditId::parse("audit-observe-claim")?,
    )?;
    let claim = store
        .claim_repair(
            authorization,
            diport::SagaLeaseHolder::parse("observe-adapter-claim")?,
            diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
        )
        .await?;
    assert!(matches!(
        claim,
        diport::SagaOperatorClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        store
            .observe_unresolved(&identity)
            .await?
            .oldest_unresolved_at(),
        Some(oldest),
        "operator lease claim must not refresh unresolved backlog age",
    );

    sqlx::query("DELETE FROM public.saga_instances WHERE owner = $1 AND contract_id = $2")
        .bind(identity.owner())
        .bind(identity.contract_id().as_str())
        .execute(&owner.pool)
        .await?;
    let cleared = store.observe_unresolved(&identity).await?;
    assert!(cleared.is_clear());
    assert_eq!(cleared.oldest_unresolved_at(), None);

    store.shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_retry_and_terminate_are_single_winner_across_independent_connections() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&pg).await?;
    let operator_config = crate::PgSagaOperatorConfig::new(runtime_pg_config(
        pg.owner_params(),
        TEST_SAGA_OPERATOR_ROLE,
        TEST_SAGA_OPERATOR_PASSWORD,
    ));
    let operator_a = crate::PgSagaOperatorDeps::connect(&operator_config).await?;
    let operator_b = crate::PgSagaOperatorDeps::connect(&operator_config).await?;
    let tenant = uuid::Uuid::new_v4();
    let retry_saga = uuid::Uuid::new_v4();
    let terminate_saga = uuid::Uuid::new_v4();
    let effect_key = vec![0x2a_u8; 32];
    let tenant_id = vocab::TenantId::parse(&tenant.to_string())?;
    let identity = diport::SagaWorkerIdentity::new(
        "orders",
        diport::SagaContractId::parse("orders.checkout.v1")?,
    )?;
    let retry_instance =
        consistency::SagaInstanceRef::new(tenant_id, consistency::SagaId::new(retry_saga))?;
    let terminate_instance =
        consistency::SagaInstanceRef::new(tenant_id, consistency::SagaId::new(terminate_saga))?;

    sqlx::query(
        "INSERT INTO public.saga_instances (\
         tenant_id, saga_id, owner, contract_id, definition_version,\
         definition_schema_digest, action_registry_generation, status, compensation_cause,\
         start_actor, start_audit_id) VALUES\
         ($1::uuid, $2::uuid, 'orders', 'orders.checkout.v1', 'v1',\
          'sha256:1111111111111111111111111111111111111111111111111111111111111111',\
          'sha256:2222222222222222222222222222222222222222222222222222222222222222',\
          'compensation_failed', 'business_failure',\
          'integration-test', 'start-retry-race'),\
         ($1::uuid, $3::uuid, 'orders', 'orders.checkout.v1', 'v1',\
          'sha256:3333333333333333333333333333333333333333333333333333333333333333',\
          'sha256:2222222222222222222222222222222222222222222222222222222222222222',\
          'ready', NULL, 'integration-test', 'start-terminate-race')",
    )
    .bind(tenant.to_string())
    .bind(retry_saga.to_string())
    .bind(terminate_saga.to_string())
    .execute(&owner.pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.saga_journal (\
         tenant_id, saga_id, seq, step_name, status, error_summary, attempt, effect_key,\
         compensation_cause) VALUES\
         ($1::uuid, $2::uuid, 1, 'charge', 'compensation_intent', NULL, 1, $3, 'business_failure'),\
         ($1::uuid, $2::uuid, 2, 'charge', 'compensation_failed', 'provider unavailable', 1, $3, NULL)",
    )
    .bind(tenant.to_string())
    .bind(retry_saga.to_string())
    .bind(&effect_key)
    .execute(&owner.pool)
    .await?;

    let retry_journal = diport::SagaOperatorJournalExpectation::new(
        consistency::SagaJournalRecord::replayed(
            2,
            vocab::StepName::parse("charge")?,
            consistency::SagaJournalStatus::CompensationFailed,
        ),
        consistency::SagaAttempt::new(1)?,
        consistency::SagaIdempotencyKey::from_storage(
            [0x2a_u8; 32],
            consistency::SagaEffectPhase::Compensation,
        ),
    )?;
    let retry_authorization_a = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        retry_instance,
        diport::SagaRetryCompensationExpectation::new(
            retry_journal.clone(),
            diport::SagaOperatorReasonText::parse("dependency restored")?,
            diport::SagaOperatorChangeTicket::parse("CHG-RETRY-A")?,
        )?,
        diport::SagaOperatorStartAuditId::parse("audit-retry-a")?,
    );
    let retry_authorization_b = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        retry_instance,
        diport::SagaRetryCompensationExpectation::new(
            retry_journal,
            diport::SagaOperatorReasonText::parse("dependency restored")?,
            diport::SagaOperatorChangeTicket::parse("CHG-RETRY-B")?,
        )?,
        diport::SagaOperatorStartAuditId::parse("audit-retry-b")?,
    );
    let retry_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let retry_a = async {
        retry_barrier.wait().await;
        operator_a.retry_compensation(retry_authorization_a).await
    };
    let retry_barrier = std::sync::Arc::clone(&retry_barrier);
    let retry_b = async {
        retry_barrier.wait().await;
        operator_b.retry_compensation(retry_authorization_b).await
    };
    let (retry_a, retry_b) = tokio::join!(retry_a, retry_b);
    let retry_outcomes = [retry_a?, retry_b?];
    assert_eq!(
        retry_outcomes
            .iter()
            .filter(|outcome| **outcome == diport::SagaOperatorCasOutcome::Applied)
            .count(),
        1
    );
    assert_eq!(
        retry_outcomes
            .iter()
            .filter(|outcome| **outcome == diport::SagaOperatorCasOutcome::StaleJournal)
            .count(),
        1
    );

    let terminate_authorization_a = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        terminate_instance,
        diport::SagaTerminateExpectation::new(
            diport::SagaOperatorReasonText::parse("request withdrawn")?,
            diport::SagaOperatorChangeTicket::parse("CHG-TERMINATE-A")?,
        ),
        diport::SagaOperatorStartAuditId::parse("audit-terminate-a")?,
    );
    let terminate_authorization_b = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity,
        terminate_instance,
        diport::SagaTerminateExpectation::new(
            diport::SagaOperatorReasonText::parse("request withdrawn")?,
            diport::SagaOperatorChangeTicket::parse("CHG-TERMINATE-B")?,
        ),
        diport::SagaOperatorStartAuditId::parse("audit-terminate-b")?,
    );
    let terminate_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let terminate_a = async {
        terminate_barrier.wait().await;
        operator_a.terminate(terminate_authorization_a).await
    };
    let terminate_barrier = std::sync::Arc::clone(&terminate_barrier);
    let terminate_b = async {
        terminate_barrier.wait().await;
        operator_b.terminate(terminate_authorization_b).await
    };
    let (terminate_a, terminate_b) = tokio::join!(terminate_a, terminate_b);
    let terminate_outcomes = [terminate_a?, terminate_b?];
    assert_eq!(
        terminate_outcomes
            .iter()
            .filter(|outcome| **outcome == diport::SagaOperatorCasOutcome::Applied)
            .count(),
        1
    );
    assert_eq!(
        terminate_outcomes
            .iter()
            .filter(|outcome| **outcome == diport::SagaOperatorCasOutcome::StaleJournal)
            .count(),
        1
    );

    let rows: Vec<(String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT instance.saga_id::text, instance.status, instance.epoch, \
         count(operator_transition.saga_id), count(DISTINCT operator_transition.transition_epoch) \
         FROM public.saga_instances AS instance \
         LEFT JOIN public.saga_operator_transitions AS operator_transition \
           ON operator_transition.tenant_id = instance.tenant_id \
          AND operator_transition.saga_id = instance.saga_id \
         WHERE instance.tenant_id = $1::uuid AND instance.saga_id IN ($2::uuid, $3::uuid) \
         GROUP BY instance.saga_id, instance.status, instance.epoch",
    )
    .bind(tenant.to_string())
    .bind(retry_saga.to_string())
    .bind(terminate_saga.to_string())
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        rows.len(),
        2,
        "both race fixtures must survive for anti-vacuity"
    );
    for (saga_id, status, epoch, transition_count, distinct_epochs) in rows {
        let expected_status = if saga_id == retry_saga.to_string() {
            "compensating"
        } else {
            "terminated"
        };
        assert_eq!(status, expected_status);
        assert_eq!(
            epoch, 1,
            "the winning CAS must increment epoch exactly once"
        );
        assert_eq!(transition_count, 1, "the race must append one transition");
        assert_eq!(distinct_epochs, 1, "the transition epoch must be unique");
    }

    operator_a.shutdown().await?;
    operator_b.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_operator_transitions_rls_fences_serving_and_read_roles() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&pg).await?;
    let operator_config = crate::PgSagaOperatorConfig::new(runtime_pg_config(
        pg.owner_params(),
        TEST_SAGA_OPERATOR_ROLE,
        TEST_SAGA_OPERATOR_PASSWORD,
    ));
    let operator = crate::PgSagaOperatorDeps::connect(&operator_config).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;
    let tenant_a = uuid::Uuid::new_v4();
    let tenant_b = uuid::Uuid::new_v4();
    let saga_a = uuid::Uuid::new_v4();
    let saga_b = uuid::Uuid::new_v4();

    for (tenant, saga, suffix) in [(tenant_a, saga_a, "a"), (tenant_b, saga_b, "b")] {
        sqlx::query(
            "INSERT INTO public.saga_instances (\
             tenant_id, saga_id, owner, contract_id, definition_version,\
             definition_schema_digest, action_registry_generation, status, start_actor,\
             start_audit_id) VALUES ($1::uuid, $2::uuid, 'orders', 'orders.checkout.v1', 'v1',\
             'sha256:4444444444444444444444444444444444444444444444444444444444444444',\
             'sha256:5555555555555555555555555555555555555555555555555555555555555555',\
             'ready', 'integration-test', $3)",
        )
        .bind(tenant.to_string())
        .bind(saga.to_string())
        .bind(format!("start-rls-{suffix}"))
        .execute(&owner.pool)
        .await?;
        let instance = consistency::SagaInstanceRef::new(
            vocab::TenantId::parse(&tenant.to_string())?,
            consistency::SagaId::new(saga),
        )?;
        let authorization = diport::test_support::saga_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            diport::SagaWorkerIdentity::new(
                "orders",
                diport::SagaContractId::parse("orders.checkout.v1")?,
            )?,
            instance,
            diport::SagaTerminateExpectation::new(
                diport::SagaOperatorReasonText::parse("request withdrawn")?,
                diport::SagaOperatorChangeTicket::parse(&format!("CHG-RLS-{suffix}"))?,
            ),
            diport::SagaOperatorStartAuditId::parse(&format!("audit-rls-{suffix}"))?,
        );
        assert_eq!(
            operator.terminate(authorization).await?,
            diport::SagaOperatorCasOutcome::Applied,
            "RLS fixture transition must be real",
        );
    }

    for (expected_role, store) in [("rss_app", &app), ("rss_app_read", &reader)] {
        let role: (String, bool) = sqlx::query_as(
            "SELECT current_user, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(role, (expected_role.to_owned(), false));

        let without_tenant: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.saga_operator_transitions")
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(
            without_tenant, 0,
            "{expected_role} without tenant GUC must see zero rows"
        );

        for (tenant, expected_saga) in [(tenant_a, saga_a), (tenant_b, saga_b)] {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
                .bind(tenant.to_string())
                .execute(&mut *tx)
                .await?;
            let visible: Vec<String> = sqlx::query_scalar(
                "SELECT saga_id::text FROM public.saga_operator_transitions ORDER BY saga_id",
            )
            .fetch_all(&mut *tx)
            .await?;
            tx.rollback().await?;
            assert_eq!(
                visible,
                vec![expected_saga.to_string()],
                "{expected_role} must see exactly its selected tenant transition"
            );
        }
    }

    app.shutdown().await?;
    reader.shutdown().await?;
    operator.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn saga_durable_store_commits_and_recovers_one_atomic_view() -> TestResult {
    use diport::{SagaDurableStore as _, SagaOperatorStore as _};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    for (relation, statement) in [
        (
            "saga_instances.insert",
            "INSERT INTO public.saga_instances DEFAULT VALUES",
        ),
        (
            "saga_instances.update",
            "UPDATE public.saga_instances SET updated_at = updated_at WHERE false",
        ),
        (
            "saga_instances.delete",
            "DELETE FROM public.saga_instances WHERE false",
        ),
        (
            "saga_journal.insert",
            "INSERT INTO public.saga_journal DEFAULT VALUES",
        ),
        (
            "saga_journal.update",
            "UPDATE public.saga_journal SET status = status WHERE false",
        ),
        (
            "saga_journal.delete",
            "DELETE FROM public.saga_journal WHERE false",
        ),
        (
            "saga_step_receipts.insert",
            "INSERT INTO public.saga_step_receipts DEFAULT VALUES",
        ),
        (
            "saga_step_receipts.update",
            "UPDATE public.saga_step_receipts SET committed_at = committed_at WHERE false",
        ),
        (
            "saga_step_receipts.delete",
            "DELETE FROM public.saga_step_receipts WHERE false",
        ),
        (
            "saga_operator_decisions.insert",
            "INSERT INTO public.saga_operator_decisions DEFAULT VALUES",
        ),
        (
            "saga_operator_decisions.update",
            "UPDATE public.saga_operator_decisions SET decision = decision WHERE false",
        ),
        (
            "saga_operator_decisions.delete",
            "DELETE FROM public.saga_operator_decisions WHERE false",
        ),
        (
            "saga_operator_transitions.insert",
            "INSERT INTO public.saga_operator_transitions DEFAULT VALUES",
        ),
        (
            "saga_operator_transitions.update",
            "UPDATE public.saga_operator_transitions SET transitioned_at = transitioned_at WHERE false",
        ),
        (
            "saga_operator_transitions.delete",
            "DELETE FROM public.saga_operator_transitions WHERE false",
        ),
    ] {
        let error = sqlx::query(statement)
            .execute(&app.pool)
            .await
            .expect_err("rss_app raw Saga DML must be denied");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|database| database.code())
                .as_deref(),
            Some("42501"),
            "rss_app raw DML was not privilege-denied for {relation}: {error}"
        );
    }
    let store = app.saga_durable_store(saga_receipt_test_protection()?);
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let instance =
        consistency::SagaInstanceRef::new(tenant, consistency::SagaId::new(uuid::Uuid::new_v4()))?;
    let definition =
        consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
    let identity = diport::SagaWorkerIdentity::new(
        generated::saga::billing_v1::CONTRACT.domain(),
        diport::SagaContractId::parse(generated::saga::billing_v1::CONTRACT_ID)?,
    )?;
    let authorization = diport::test_support::saga_start_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        instance,
        diport::SagaStartAuditId::parse("durable-integration-start")?,
    );
    store
        .register(
            authorization,
            diport::SagaInstanceRegistration::new(instance, identity.clone(), definition.clone())?,
        )
        .await?;
    let runnable = diport::SagaRunnableInstance::new(
        instance,
        consistency::SagaInstanceStatus::Ready,
        identity.clone(),
        definition.clone(),
    )?;
    let lease = match store
        .claim(diport::SagaClaimRequest::new(
            runnable,
            diport::SagaLeaseHolder::parse("durable-integration")?,
            diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
        ))
        .await?
    {
        diport::SagaClaimOutcome::Acquired(lease) => lease,
        outcome => return Err(std::io::Error::other(format!("claim failed: {outcome:?}")).into()),
    };
    let step = generated::saga::billing_v1::STEP_0;
    let effect_key = consistency::SagaIdempotencyKey::derive(
        instance,
        &definition,
        step,
        consistency::SagaEffectPhase::Forward,
    );
    let scope = consistency::SagaReceiptScope::new(
        instance,
        identity.clone(),
        definition.clone(),
        step,
        effect_key.clone(),
    )?;
    let attempt = consistency::SagaAttempt::new(1)?;
    let completion = |completed_seq| {
        diport::SagaForwardCompletion::new(
            diport::SagaStepCompletion::new(
                scope.clone(),
                attempt,
                consistency::SagaReceiptFormatVersion::V1,
                secure::Plaintext::new(br#"{"reservation_id":"protected"}"#.to_vec()),
                completed_seq,
            ),
            diport::SagaForwardProgress::Continue,
        )
    };
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardCompleted(completion(1)),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Conflict,
        "forward completion must not create its own missing intent"
    );
    let skipped_first_attempt = diport::SagaForwardIntent::new(
        0,
        vocab::StepName::parse(step.name())?,
        consistency::SagaAttempt::new(9)?,
        effect_key.clone(),
    )?;
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardIntent(skipped_first_attempt),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Conflict,
        "first forward intent attempt must be one"
    );
    let intent = diport::SagaForwardIntent::new(
        0,
        vocab::StepName::parse(step.name())?,
        attempt,
        effect_key,
    )?;
    assert_eq!(
        store
            .mutate(&lease, diport::SagaDurableMutation::ForwardIntent(intent))
            .await?,
        diport::SagaDurableMutationOutcome::Applied
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardCompleted(completion(2)),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Conflict,
        "forward completion must be adjacent to its exact intent"
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardCompleted(completion(1)),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Applied
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardCompleted(completion(1)),
            )
            .await?,
        diport::SagaDurableMutationOutcome::IdempotentDuplicate
    );
    let snapshot = store
        .recovery_snapshot(diport::SagaRecoveryRequest::new(
            lease.clone(),
            vec![scope.clone()],
        )?)
        .await?;
    let diport::SagaRecoveryOutcome::Available(snapshot) = snapshot else {
        return Err(std::io::Error::other("held lease did not produce recovery snapshot").into());
    };
    assert_eq!(snapshot.journal().len(), 2);
    assert_eq!(snapshot.receipts().len(), 1);
    assert_eq!(
        snapshot.receipts()[0].plaintext().expose(),
        br#"{"reservation_id":"protected"}"#
    );

    let second_step = generated::saga::billing_v1::STEP_1;
    let second_effect_key = consistency::SagaIdempotencyKey::derive(
        instance,
        &definition,
        second_step,
        consistency::SagaEffectPhase::Forward,
    );
    let second_scope = consistency::SagaReceiptScope::new(
        instance,
        snapshot.instance().identity().clone(),
        definition.clone(),
        second_step,
        second_effect_key.clone(),
    )?;
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardIntent(diport::SagaForwardIntent::new(
                    2,
                    vocab::StepName::parse(second_step.name())?,
                    attempt,
                    second_effect_key,
                )?),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Applied
    );
    store.inject_commit_unknown_after_next_completion();
    let read_back = store
        .mutate(
            &lease,
            diport::SagaDurableMutation::ForwardCompleted(diport::SagaForwardCompletion::new(
                diport::SagaStepCompletion::new(
                    second_scope.clone(),
                    attempt,
                    consistency::SagaReceiptFormatVersion::V1,
                    secure::Plaintext::new(br#"{"capture_id":"commit-unknown"}"#.to_vec()),
                    3,
                ),
                diport::SagaForwardProgress::Continue,
            )),
        )
        .await?;
    assert_eq!(
        read_back,
        diport::SagaDurableMutationOutcome::Applied,
        "complete commit-unknown read-back must converge to applied",
    );
    let recovery = store
        .recovery_snapshot(diport::SagaRecoveryRequest::new(
            lease.clone(),
            vec![scope, second_scope],
        )?)
        .await?;
    let diport::SagaRecoveryOutcome::Available(recovery) = recovery else {
        return Err(std::io::Error::other("commit-unknown lost the fenced recovery view").into());
    };
    assert_eq!(recovery.journal().len(), 4);
    assert_eq!(recovery.receipts().len(), 2);

    let compensation_key = consistency::SagaIdempotencyKey::derive(
        instance,
        &definition,
        second_step,
        consistency::SagaEffectPhase::Compensation,
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::CompensationIntent(
                    diport::SagaCompensationIntent::new(
                        4,
                        vocab::StepName::parse(second_step.name())?,
                        attempt,
                        compensation_key.clone(),
                        consistency::SagaCompensationCause::BusinessFailure,
                    )?,
                ),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Applied
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::CompensationIntent(
                    diport::SagaCompensationIntent::new(
                        5,
                        vocab::StepName::parse(second_step.name())?,
                        consistency::SagaAttempt::new(2)?,
                        compensation_key.clone(),
                        consistency::SagaCompensationCause::Expired,
                    )?,
                ),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Conflict,
        "compensation intent must retain the pinned instance cause"
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::CompensationCompleted(
                    diport::SagaCompensationCompletion::new(
                        5,
                        vocab::StepName::parse(second_step.name())?,
                        consistency::SagaAttempt::new(2)?,
                        compensation_key,
                        diport::SagaCompensationProgress::Continue,
                    )?,
                ),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Conflict,
        "compensation completion must match the exact prior intent attempt"
    );
    let first_compensation_key = consistency::SagaIdempotencyKey::derive(
        instance,
        &definition,
        step,
        consistency::SagaEffectPhase::Compensation,
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::CompensationFailed(
                    diport::SagaCompensationFailure::new(
                        6,
                        vocab::StepName::parse(step.name())?,
                        attempt,
                        first_compensation_key,
                        "compensation failed",
                    )?,
                ),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Conflict,
        "compensation failure must match the exact prior intent step and effect key"
    );

    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::OperatorRequired(
                    consistency::SagaOperatorReason::CompensationOutcomeUnknown,
                ),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Applied
    );
    let mut observation = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *observation)
        .await?;
    let resolution: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, operator_reason, compensation_cause FROM public.saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(instance.saga_id().as_uuid().to_string())
    .fetch_one(&mut *observation)
    .await?;
    observation.rollback().await?;
    assert_eq!(resolution.0, "operator_required");
    assert_eq!(
        resolution.1.as_deref(),
        Some("compensation_outcome_unknown")
    );
    assert_eq!(resolution.2.as_deref(), Some("business_failure"));

    let operator_identity = diport::SagaWorkerIdentity::new(
        generated::saga::billing_v1::CONTRACT.domain(),
        diport::SagaContractId::parse(generated::saga::billing_v1::CONTRACT_ID)?,
    )?;
    let inspection = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        instance,
        (),
        diport::SagaOperatorStartAuditId::parse("audit-list-653")?,
    );
    let visible = store.operator_status(inspection).await?;
    let diport::SagaOperatorStatusOutcome::Found(visible) = visible else {
        return Err(std::io::Error::other("operator-required instance was not visible").into());
    };
    assert_eq!(visible.record().instance(), instance);
    assert!(visible.unresolved_at().is_some());

    let authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        instance,
        consistency::SagaOperatorReason::CompensationOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-653")?,
        diport::SagaOperatorStartAuditId::parse("audit-start-653")?,
    )?;
    let claim = match store
        .claim_repair(
            authorization,
            diport::SagaLeaseHolder::parse("operator-integration")?,
            diport::SagaLeaseTtl::new(std::time::Duration::from_millis(200))?,
        )
        .await?
    {
        diport::SagaOperatorClaimOutcome::Acquired(claim) => claim,
        _ => return Err(std::io::Error::other("operator claim was not acquired").into()),
    };
    let busy_authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        instance,
        consistency::SagaOperatorReason::CompensationOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-653-BUSY")?,
        diport::SagaOperatorStartAuditId::parse("audit-busy-653")?,
    )?;
    assert!(matches!(
        store
            .claim_repair(
                busy_authorization,
                diport::SagaLeaseHolder::parse("operator-busy")?,
                diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
            )
            .await?,
        diport::SagaOperatorClaimOutcome::Busy
    ));
    let foreign_authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        diport::SagaWorkerIdentity::new(
            "inventory",
            diport::SagaContractId::parse(generated::saga::billing_v1::CONTRACT_ID)?,
        )?,
        instance,
        consistency::SagaOperatorReason::CompensationOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-653-FOREIGN")?,
        diport::SagaOperatorStartAuditId::parse("audit-foreign-653")?,
    )?;
    assert!(matches!(
        store
            .claim_repair(
                foreign_authorization,
                diport::SagaLeaseHolder::parse("operator-foreign")?,
                diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
            )
            .await?,
        diport::SagaOperatorClaimOutcome::Missing
    ));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let reclaim_authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        instance,
        consistency::SagaOperatorReason::CompensationOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-653")?,
        diport::SagaOperatorStartAuditId::parse("audit-start-653")?,
    )?;
    let reclaimed = match store
        .claim_repair(
            reclaim_authorization,
            diport::SagaLeaseHolder::parse("operator-reclaimed")?,
            diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
        )
        .await?
    {
        diport::SagaOperatorClaimOutcome::Acquired(claim) => claim,
        _ => return Err(std::io::Error::other("expired operator claim was not reclaimed").into()),
    };
    let compensation_key = consistency::SagaIdempotencyKey::derive(
        instance,
        &definition,
        second_step,
        consistency::SagaEffectPhase::Compensation,
    );
    let stale_decision = diport::SagaCompensationNotApplied::new(
        5,
        vocab::StepName::parse(second_step.name())?,
        attempt,
        compensation_key.clone(),
        consistency::SagaCompensationCause::BusinessFailure,
    )?;
    assert_eq!(
        store
            .commit_repair(
                claim,
                diport::SagaOperatorRepair::CompensationNotApplied(stale_decision),
            )
            .await?,
        diport::SagaOperatorCasOutcome::LeaseLost,
        "expired provider claim must be fenced after reclaim",
    );
    let decision = diport::SagaCompensationNotApplied::new(
        5,
        vocab::StepName::parse(second_step.name())?,
        attempt,
        compensation_key,
        consistency::SagaCompensationCause::BusinessFailure,
    )?;
    store.inject_commit_unknown_after_next_completion();
    assert_eq!(
        store
            .commit_repair(
                reclaimed,
                diport::SagaOperatorRepair::CompensationNotApplied(decision),
            )
            .await?,
        diport::SagaOperatorCasOutcome::Applied,
    );
    let stale_authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        instance,
        consistency::SagaOperatorReason::CompensationOutcomeUnknown,
        diport::SagaOperatorChangeTicket::parse("CHG-653-STALE")?,
        diport::SagaOperatorStartAuditId::parse("audit-stale-653")?,
    )?;
    assert!(matches!(
        store
            .claim_repair(
                stale_authorization,
                diport::SagaLeaseHolder::parse("operator-stale")?,
                diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
            )
            .await?,
        diport::SagaOperatorClaimOutcome::StaleStatus(
            consistency::SagaInstanceStatus::Compensating
        )
    ));
    let mut audit_tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *audit_tx)
        .await?;
    let repaired: (String, Option<String>) = sqlx::query_as(
        "SELECT status, operator_reason FROM public.saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(instance.saga_id().as_uuid().to_string())
    .fetch_one(&mut *audit_tx)
    .await?;
    let audit: (String, String, String, String, String, String, i64) = sqlx::query_as(
        "SELECT phase, decision, operator_reason_text, operator_actor, change_ticket, start_audit_id, repair_epoch \
         FROM public.saga_operator_decisions \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(instance.saga_id().as_uuid().to_string())
    .fetch_one(&mut *audit_tx)
    .await?;
    audit_tx.rollback().await?;
    assert_eq!(repaired, ("compensating".to_string(), None));
    assert_eq!(audit.0, "compensation");
    assert_eq!(audit.1, "confirmed_not_applied");
    assert_eq!(audit.2, "provider evidence reviewed");
    assert_eq!(audit.3, "rss-maintenance-operator");
    assert_eq!(audit.4, "CHG-653");
    assert_eq!(audit.5, "audit-start-653");
    assert!(audit.6 > 0);

    for repair_case in [
        PgOperatorRepairCase::ForwardApplied,
        PgOperatorRepairCase::ForwardNotApplied,
        PgOperatorRepairCase::CompensationApplied,
    ] {
        exercise_pg_operator_repair_case(
            &app,
            &store,
            tenant,
            &identity,
            &definition,
            &operator_identity,
            repair_case,
        )
        .await?;
    }

    let terminate_instance =
        consistency::SagaInstanceRef::new(tenant, consistency::SagaId::new(uuid::Uuid::new_v4()))?;
    let start = diport::test_support::saga_start_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        terminate_instance,
        diport::SagaStartAuditId::parse("operator-terminate-integration-start")?,
    );
    store
        .register(
            start,
            diport::SagaInstanceRegistration::new(
                terminate_instance,
                identity.clone(),
                definition.clone(),
            )?,
        )
        .await?;
    let terminate = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        terminate_instance,
        diport::SagaTerminateExpectation::new(
            diport::SagaOperatorReasonText::parse("request withdrawn")?,
            diport::SagaOperatorChangeTicket::parse("CHG-653-TERMINATE")?,
        ),
        diport::SagaOperatorStartAuditId::parse("audit-653-terminate")?,
    );
    assert_eq!(
        store.terminate(terminate).await?,
        diport::SagaOperatorCasOutcome::Applied
    );
    assert_eq!(
        store
            .get(&terminate_instance)
            .await?
            .ok_or_else(|| std::io::Error::other("terminated instance disappeared"))?
            .status(),
        consistency::SagaInstanceStatus::Terminated
    );

    store.shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_receipt_pair_trigger_and_fixed_retention_delete_only_whole_aggregates() -> TestResult
{
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let tenant = uuid::Uuid::new_v4();
    let saga_id = uuid::Uuid::new_v4();
    let orphan_id = uuid::Uuid::new_v4();
    let mut tx = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    for id in [saga_id, orphan_id] {
        sqlx::query(
            "INSERT INTO saga_instances \
                 (tenant_id, saga_id, owner, contract_id, definition_version, \
                  definition_schema_digest, action_registry_generation, start_actor, \
                  start_audit_id) \
             VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', \
                     $3, $4, 'integration-test', 'receipt-retention')",
        )
        .bind(tenant.to_string())
        .bind(id.to_string())
        .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
        .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO saga_step_receipts \
             (tenant_id, saga_id, owner, contract_id, definition_version, \
              definition_schema_digest, action_registry_generation, step_name, effect_key, \
              receipt_schema, format_version, ciphertext, key_ref, content_hmac_key_id, \
              content_hmac, successful_attempt, completed_seq) \
         VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', $3, $4, \
                 'reserve_funds', $5, 'reserve.schema.json', 1, $6, \
                 'rss-saga-receipt:1', 'retention-v1', $7, 1, 1)",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
    .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
    .bind(vec![0x11_u8; 32])
    .bind(vec![0x22_u8; 16])
    .bind(vec![0x33_u8; 32])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key) \
         VALUES ($1::uuid, $2::uuid, 0, 'reserve_funds', 'forward_intent', 1, $3)",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .bind(vec![0x11_u8; 32])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key) \
         VALUES ($1::uuid, $2::uuid, 1, 'reserve_funds', 'forward_completed', 1, $3)",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .bind(vec![0x11_u8; 32])
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE saga_instances SET status = 'succeeded' \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut invalid = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *invalid)
        .await?;
    sqlx::query(
        "INSERT INTO saga_step_receipts \
             (tenant_id, saga_id, owner, contract_id, definition_version, \
              definition_schema_digest, action_registry_generation, step_name, effect_key, \
              receipt_schema, format_version, ciphertext, key_ref, content_hmac_key_id, \
              content_hmac, successful_attempt, completed_seq) \
         VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', $3, $4, \
                 'capture', $5, 'capture.schema.json', 1, $6, \
                 'rss-saga-receipt:1', 'retention-v1', $7, 1, 1)",
    )
    .bind(tenant.to_string())
    .bind(orphan_id.to_string())
    .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
    .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
    .bind(vec![0x51_u8; 32])
    .bind(vec![0x52_u8; 16])
    .bind(vec![0x53_u8; 32])
    .execute(&mut *invalid)
    .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key) \
         VALUES ($1::uuid, $2::uuid, 1, 'capture', 'forward_completed', 1, $3)",
    )
    .bind(tenant.to_string())
    .bind(orphan_id.to_string())
    .bind(vec![0x51_u8; 32])
    .execute(&mut *invalid)
    .await?;
    assert!(
        invalid.commit().await.is_err(),
        "deferred trigger must reject a paired forward completion without exact prior intent"
    );

    let mut skipped_attempt = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *skipped_attempt)
        .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key) \
         VALUES ($1::uuid, $2::uuid, 0, 'capture', 'forward_intent', 2, $3)",
    )
    .bind(tenant.to_string())
    .bind(orphan_id.to_string())
    .bind(vec![0x51_u8; 32])
    .execute(&mut *skipped_attempt)
    .await?;
    assert!(
        skipped_attempt.commit().await.is_err(),
        "deferred trigger must reject a non-contiguous first intent attempt"
    );
    let mut wrong_cause = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *wrong_cause)
        .await?;
    sqlx::query(
        "UPDATE saga_instances \
         SET status = 'compensating', compensation_cause = 'business_failure' \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(orphan_id.to_string())
    .execute(&mut *wrong_cause)
    .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key, \
              compensation_cause) \
         VALUES ($1::uuid, $2::uuid, 0, 'capture', 'compensation_intent', 1, $3, 'expired')",
    )
    .bind(tenant.to_string())
    .bind(orphan_id.to_string())
    .bind(vec![0x60_u8; 32])
    .execute(&mut *wrong_cause)
    .await?;
    assert!(
        wrong_cause.commit().await.is_err(),
        "deferred trigger must reject a compensation intent with a foreign pinned cause"
    );
    for (status, error_summary, key_byte) in [
        ("compensation_completed", None, 0x61_u8),
        (
            "compensation_failed",
            Some("fault-injected compensation failure"),
            0x62_u8,
        ),
    ] {
        let mut orphan_compensation = owner.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *orphan_compensation)
            .await?;
        sqlx::query(
            "INSERT INTO saga_journal \
                 (tenant_id, saga_id, seq, step_name, status, error_summary, attempt, effect_key) \
             VALUES ($1::uuid, $2::uuid, 0, 'capture', $3, $4, 1, $5)",
        )
        .bind(tenant.to_string())
        .bind(orphan_id.to_string())
        .bind(status)
        .bind(error_summary)
        .bind(vec![key_byte; 32])
        .execute(&mut *orphan_compensation)
        .await?;
        assert!(
            orphan_compensation.commit().await.is_err(),
            "deferred trigger must reject orphan {status}"
        );
    }

    sqlx::raw_sql("ALTER TABLE saga_instances DISABLE TRIGGER saga_instances_terminal_at_guard;")
        .execute(&owner.pool)
        .await?;
    sqlx::query(
        "UPDATE saga_instances SET terminal_at = clock_timestamp() - interval '31 days' \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .execute(&owner.pool)
    .await?;
    sqlx::raw_sql("ALTER TABLE saga_instances ENABLE TRIGGER saga_instances_terminal_at_guard;")
        .execute(&owner.pool)
        .await?;

    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let swept: (i64, i64, i64) = sqlx::query_as("SELECT * FROM rss_sweep_terminal_sagas()")
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(swept, (1, 0, 0));
    let remaining: (i64, i64, i64) = sqlx::query_as(
        "SELECT \
             (SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND saga_id = $2::uuid), \
             (SELECT count(*) FROM saga_journal WHERE tenant_id = $1::uuid AND saga_id = $2::uuid), \
             (SELECT count(*) FROM saga_step_receipts WHERE tenant_id = $1::uuid AND saga_id = $2::uuid)",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        remaining,
        (0, 0, 0),
        "retention must delete the saga root and cascade its whole aggregate"
    );
    let orphan_root: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(orphan_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(orphan_root, 1, "non-terminal saga roots must not be swept");

    let eligible_failed = "retention-eligible-1";
    let eligible_with_expired_lease = "retention-eligible-2";
    let recent_terminal = uuid::Uuid::new_v4();
    let live_lease_terminal = uuid::Uuid::new_v4();
    let nonterminal = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO saga_instances \
             (tenant_id, saga_id, owner, contract_id, status, lease_token, holder_id, \
              acquired_at, expires_at, heartbeat_at, definition_version, \
              definition_schema_digest, action_registry_generation, start_actor, \
              start_audit_id) \
         SELECT $1::uuid, md5('retention-eligible-' || series::text)::uuid, \
                'retention-eligible', 'billing.checkout', \
                'succeeded', \
                CASE WHEN series = 2 THEN md5('expired-lease')::uuid ELSE NULL END, \
                CASE WHEN series = 2 THEN 'expired-holder' ELSE NULL END, \
                CASE WHEN series = 2 THEN clock_timestamp() - interval '40 days' ELSE NULL END, \
                CASE WHEN series = 2 THEN clock_timestamp() - interval '31 days' ELSE NULL END, \
                CASE WHEN series = 2 THEN clock_timestamp() - interval '31 days' ELSE NULL END, \
                'v1', $2, $3, 'integration-test', 'retention-batch' \
         FROM generate_series(1, 1001) AS series",
    )
    .bind(tenant.to_string())
    .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
    .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
    .execute(&owner.pool)
    .await?;
    for (id, owner_name, status, leased) in [
        (recent_terminal, "retention-recent", "succeeded", false),
        (live_lease_terminal, "retention-live", "succeeded", true),
        (nonterminal, "retention-ready", "ready", false),
    ] {
        sqlx::query(
            "INSERT INTO saga_instances \
                 (tenant_id, saga_id, owner, contract_id, status, lease_token, holder_id, \
                  acquired_at, expires_at, heartbeat_at, definition_version, \
                  definition_schema_digest, action_registry_generation, start_actor, \
                  start_audit_id) \
             VALUES ($1::uuid, $2::uuid, $3, 'billing.checkout', $4, \
                     CASE WHEN $5 THEN md5('live-lease')::uuid ELSE NULL END, \
                     CASE WHEN $5 THEN 'live-holder' ELSE NULL END, \
                     CASE WHEN $5 THEN clock_timestamp() - interval '1 day' ELSE NULL END, \
                     CASE WHEN $5 THEN clock_timestamp() + interval '1 day' ELSE NULL END, \
                     CASE WHEN $5 THEN clock_timestamp() ELSE NULL END, \
                     'v1', $6, $7, 'integration-test', 'retention-single')",
        )
        .bind(tenant.to_string())
        .bind(id.to_string())
        .bind(owner_name)
        .bind(status)
        .bind(leased)
        .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
        .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
        .execute(&owner.pool)
        .await?;
    }

    sqlx::raw_sql("ALTER TABLE saga_instances DISABLE TRIGGER saga_instances_terminal_at_guard;")
        .execute(&owner.pool)
        .await?;
    sqlx::query(
        "UPDATE saga_instances SET terminal_at = clock_timestamp() - interval '31 days' \
         WHERE tenant_id = $1::uuid \
           AND (owner = 'retention-eligible' OR saga_id = $2::uuid)",
    )
    .bind(tenant.to_string())
    .bind(live_lease_terminal.to_string())
    .execute(&owner.pool)
    .await?;
    sqlx::raw_sql("ALTER TABLE saga_instances ENABLE TRIGGER saga_instances_terminal_at_guard;")
        .execute(&owner.pool)
        .await?;

    let aggregate_id: String = sqlx::query_scalar("SELECT md5($1)::uuid::text")
        .bind(eligible_failed)
        .fetch_one(&owner.pool)
        .await?;
    let mut aggregate_tx = owner.pool.begin().await?;
    sqlx::query(
        "INSERT INTO saga_step_receipts \
             (tenant_id, saga_id, owner, contract_id, definition_version, \
              definition_schema_digest, action_registry_generation, step_name, effect_key, \
              receipt_schema, format_version, ciphertext, key_ref, content_hmac_key_id, \
              content_hmac, successful_attempt, completed_seq) \
         VALUES ($1::uuid, $2::uuid, 'retention-eligible', 'billing.checkout', 'v1', \
                 $3, $4, 'retained_step', $5, 'retention.schema', 1, $6, \
                 'rss-saga-receipt:1', 'retention-v1', $7, 1, 1)",
    )
    .bind(tenant.to_string())
    .bind(&aggregate_id)
    .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
    .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
    .bind(vec![0x41_u8; 32])
    .bind(vec![0x42_u8; 16])
    .bind(vec![0x43_u8; 32])
    .execute(&mut *aggregate_tx)
    .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key) \
         VALUES ($1::uuid, $2::uuid, 0, 'retained_step', 'forward_intent', 1, $3)",
    )
    .bind(tenant.to_string())
    .bind(&aggregate_id)
    .bind(vec![0x41_u8; 32])
    .execute(&mut *aggregate_tx)
    .await?;
    sqlx::query(
        "INSERT INTO saga_journal \
             (tenant_id, saga_id, seq, step_name, status, attempt, effect_key) \
         VALUES ($1::uuid, $2::uuid, 1, 'retained_step', 'forward_completed', 1, $3)",
    )
    .bind(tenant.to_string())
    .bind(&aggregate_id)
    .bind(vec![0x41_u8; 32])
    .execute(&mut *aggregate_tx)
    .await?;
    aggregate_tx.commit().await?;

    let first_sweep: (i64, i64, i64) = sqlx::query_as("SELECT * FROM rss_sweep_terminal_sagas()")
        .fetch_one(&app.pool)
        .await?;
    assert_eq!((first_sweep.0, first_sweep.1), (1000, 1));
    assert!(first_sweep.2 >= 31 * 24 * 60 * 60);
    let eligible_remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM saga_instances \
         WHERE tenant_id = $1::uuid AND owner = 'retention-eligible'",
    )
    .bind(tenant.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(eligible_remaining, 1);
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>("SELECT * FROM rss_sweep_terminal_sagas()")
            .fetch_one(&app.pool)
            .await?,
        (1, 0, 0)
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>("SELECT * FROM rss_sweep_terminal_sagas()")
            .fetch_one(&app.pool)
            .await?,
        (0, 0, 0)
    );

    let survivors: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND owner = 'retention-eligible'), \
           (SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND saga_id = $2::uuid), \
           (SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND saga_id = $3::uuid), \
           (SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND saga_id = $4::uuid)",
    )
    .bind(tenant.to_string())
    .bind(recent_terminal.to_string())
    .bind(live_lease_terminal.to_string())
    .bind(nonterminal.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(survivors, (0, 1, 1, 1));
    let aggregate_children: (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM saga_journal WHERE tenant_id = $1::uuid AND saga_id = $2::uuid), \
           (SELECT count(*) FROM saga_step_receipts WHERE tenant_id = $1::uuid AND saga_id = $2::uuid)",
    )
    .bind(tenant.to_string())
    .bind(&aggregate_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(aggregate_children, (0, 0));
    let expired_lease_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = md5($2)::uuid",
    )
    .bind(tenant.to_string())
    .bind(eligible_with_expired_lease)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(expired_lease_count, 0);

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_terminal_sweeper_exposes_only_the_fixed_typed_retention_tick() -> TestResult {
    let (fixture, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let observer = runtime_assertion_pool(fixture.owner_params()).await?;
    let tenant = uuid::Uuid::new_v4();
    let saga_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO saga_instances ( \
             tenant_id, saga_id, owner, contract_id, definition_version, \
             definition_schema_digest, action_registry_generation, start_actor, start_audit_id \
         ) VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', $3, $4, \
                   'integration-test', 'typed-terminal-retention')",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
    .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
    .execute(&observer)
    .await?;
    sqlx::query(
        "UPDATE saga_instances SET status = 'terminated' \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .execute(&observer)
    .await?;
    sqlx::raw_sql("ALTER TABLE saga_instances DISABLE TRIGGER saga_instances_terminal_at_guard;")
        .execute(&observer)
        .await?;
    sqlx::query(
        "UPDATE saga_instances SET terminal_at = clock_timestamp() - interval '31 days' \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .execute(&observer)
    .await?;
    sqlx::raw_sql("ALTER TABLE saga_instances ENABLE TRIGGER saga_instances_terminal_at_guard;")
        .execute(&observer)
        .await?;

    let report = deps
        .handle()
        .infra()
        .saga_terminal_sweeper()
        .sweep_expired(crate::SagaTerminalSweepDeadline::from_timeout(
            std::time::Duration::from_secs(5),
        )?)
        .await?;
    assert_eq!(report.deleted(), 1);
    assert_eq!(report.backlog_depth(), 0);
    assert_eq!(report.oldest_expired_age_seconds(), 0);
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM saga_instances WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .fetch_one(&observer)
    .await?;
    assert_eq!(remaining, 0);

    observer.close().await;
    shutdown_runtime_deps(deps).await
}

/// INVARIANT: SAGA-RECEIPT-CATALOG-GATE-01 { level = "Medium", exec = "integration-critical", source = "code", synthetic_red = "integration_tests::saga_tests::saga_receipt_startup_catalog_gate_rejects_critical_drift_matrix", anti_vacuity = "integration_tests::saga_tests::saga_receipt_startup_catalog_gate_accepts_exact_catalog" }
#[tokio::test(flavor = "multi_thread")]
async fn saga_receipt_startup_catalog_gate_accepts_exact_catalog() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    app.shutdown().await?;
    let writer = PgStore::connect_verified_writer(&runtime_pg_config(
        pg.owner_params(),
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    ))
    .await?;

    writer.verify_saga_receipt_capability().await?;

    writer.store_arc().shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_receipt_startup_catalog_gate_rejects_critical_drift_matrix() -> TestResult {
    struct DriftCase {
        label: &'static str,
        mutate: &'static str,
        restore: &'static str,
    }

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    app.shutdown().await?;
    let writer = PgStore::connect_verified_writer(&runtime_pg_config(
        pg.owner_params(),
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    ))
    .await?;
    writer.verify_saga_receipt_capability().await?;

    let cases = [
        DriftCase {
            label: "terminal failed classification",
            mutate: "ALTER TABLE public.saga_instances DROP CONSTRAINT saga_instances_terminal_time_consistent; \
                     ALTER TABLE public.saga_instances ADD CONSTRAINT saga_instances_terminal_time_consistent \
                     CHECK ((status IN ('succeeded', 'compensated', 'expired')) = (terminal_at IS NOT NULL));",
            restore: "ALTER TABLE public.saga_instances DROP CONSTRAINT saga_instances_terminal_time_consistent; \
                      ALTER TABLE public.saga_instances ADD CONSTRAINT saga_instances_terminal_time_consistent \
                      CHECK ((status IN ('succeeded', 'compensated', 'expired', 'terminated')) = (terminal_at IS NOT NULL));",
        },
        DriftCase {
            label: "deferred pair trigger enabled",
            mutate: "ALTER TABLE public.saga_step_receipts DISABLE TRIGGER saga_receipt_requires_completed;",
            restore: "ALTER TABLE public.saga_step_receipts ENABLE TRIGGER saga_receipt_requires_completed;",
        },
        DriftCase {
            label: "serving delete authority",
            mutate: "GRANT DELETE ON TABLE public.saga_instances TO rss_app;",
            restore: "REVOKE DELETE ON TABLE public.saga_instances FROM rss_app;",
        },
        DriftCase {
            label: "serving raw insert authority",
            mutate: "GRANT INSERT ON TABLE public.saga_journal TO rss_app;",
            restore: "REVOKE INSERT ON TABLE public.saga_journal FROM rss_app;",
        },
        DriftCase {
            label: "writer function execute missing",
            mutate: "REVOKE EXECUTE ON FUNCTION public.rss_saga_append_journal(uuid, uuid, bigint, bigint, text, text, text, integer, bytea, text) FROM rss_app;",
            restore: "GRANT EXECUTE ON FUNCTION public.rss_saga_append_journal(uuid, uuid, bigint, bigint, text, text, text, integer, bytea, text) TO rss_app;",
        },
        DriftCase {
            label: "candidate function search path",
            mutate: "ALTER FUNCTION public.rss_saga_candidate_tenants(text, text, uuid, bigint) SET search_path = public;",
            restore: "ALTER FUNCTION public.rss_saga_candidate_tenants(text, text, uuid, bigint) SET search_path = pg_catalog, pg_temp;",
        },
        DriftCase {
            label: "maintenance membership",
            mutate: "GRANT rss_app TO rss_saga_receipt_maintenance;",
            restore: "REVOKE rss_app FROM rss_saga_receipt_maintenance;",
        },
        DriftCase {
            label: "maintenance extra relation capability",
            mutate: "GRANT SELECT ON TABLE public._sqlx_migrations TO rss_saga_receipt_maintenance;",
            restore: "REVOKE SELECT ON TABLE public._sqlx_migrations FROM rss_saga_receipt_maintenance;",
        },
        DriftCase {
            label: "sweeper security definer",
            mutate: "ALTER FUNCTION public.rss_sweep_terminal_sagas() SECURITY INVOKER;",
            restore: "ALTER FUNCTION public.rss_sweep_terminal_sagas() SECURITY DEFINER;",
        },
        DriftCase {
            label: "fixed sweeper execute",
            mutate: "REVOKE EXECUTE ON FUNCTION public.rss_sweep_terminal_sagas() FROM rss_app;",
            restore: "GRANT EXECUTE ON FUNCTION public.rss_sweep_terminal_sagas() TO rss_app;",
        },
    ];

    for case in cases {
        sqlx::raw_sql(case.mutate).execute(&owner.pool).await?;
        assert!(
            matches!(
                writer.verify_saga_receipt_capability().await,
                Err(PgError::SagaReceiptCatalog { .. })
            ),
            "saga receipt capability gate accepted drift: {}",
            case.label
        );
        sqlx::raw_sql(case.restore).execute(&owner.pool).await?;
        writer.verify_saga_receipt_capability().await?;
    }

    writer.store_arc().shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_maintenance_audit_preserves_resource_kind_and_shared_start_audit_id() -> TestResult {
    let (fixture, store) = connect_pg().await?;
    store.run_migrations().await?;
    let params = fixture.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let maintenance = PgRuntimeDeps::connect_maintenance(&config).await?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let resource_id = format!("owner/contract/tenant/saga-{nonce}");
    let start_audit_id = format!("saga-start-{nonce}");
    let operator_subject = "service:saga-operator-test";

    maintenance
        .record_saga_maintenance_audit(
            operator_subject,
            test_tenant(),
            "saga.operator.status.start",
            crate::MaintenanceAuditOutcome::Success,
            &resource_id,
            &start_audit_id,
        )
        .await?;
    maintenance
        .record_saga_maintenance_audit(
            operator_subject,
            test_tenant(),
            "saga.operator.status.finish",
            crate::MaintenanceAuditOutcome::Failure {
                reason: "operator observation failed",
            },
            &resource_id,
            &start_audit_id,
        )
        .await?;

    let rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        r#"
        SELECT principal_id, resource_kind, resource_id, action, outcome, failure_reason, request_id,
               tenant_context::text
        FROM auth_audit_events
        WHERE request_id = $1
        ORDER BY action
        "#,
    )
    .bind(&start_audit_id)
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        rows,
        vec![
            (
                operator_subject.to_string(),
                "saga.operator".to_string(),
                resource_id.clone(),
                "saga.operator.status.finish".to_string(),
                "failure".to_string(),
                Some("operator observation failed".to_string()),
                Some(start_audit_id.clone()),
                Some(test_tenant().as_uuid().to_string()),
            ),
            (
                operator_subject.to_string(),
                "saga.operator".to_string(),
                resource_id,
                "saga.operator.status.start".to_string(),
                "success".to_string(),
                None,
                Some(start_audit_id),
                Some(test_tenant().as_uuid().to_string()),
            ),
        ],
        "Saga start/finish audits must keep exact resource identity and shared durable audit ID",
    );

    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_operator_lane_is_function_only_and_records_correlated_audit() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let config = crate::PgSagaOperatorConfig::new(runtime_pg_config(
        fixture.owner_params(),
        TEST_SAGA_OPERATOR_ROLE,
        TEST_SAGA_OPERATOR_PASSWORD,
    ));
    let deps = crate::PgSagaOperatorDeps::connect(&config).await?;
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let resource_id = format!("owner/contract/tenant/saga-{nonce}");
    let start_audit_id = format!("saga-start-{nonce}");
    deps.record_saga_maintenance_audit(
        "service:saga-operator-test",
        test_tenant(),
        "saga.operator.status.start",
        crate::MaintenanceAuditOutcome::Success,
        &resource_id,
        &start_audit_id,
    )
    .await?;

    let app = crate::PgStore::connect(&runtime_pg_config(
        fixture.owner_params(),
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    ))
    .await?;
    let reader = crate::PgStore::connect(&runtime_pg_config(
        fixture.owner_params(),
        TEST_READ_ROLE,
        TEST_READ_PASSWORD,
    ))
    .await?;
    for (role, store) in [("rss_app", &app), ("rss_app_read", &reader)] {
        for forbidden in [
            "SELECT public.rss_saga_retry_compensation(\
             '00000000-0000-0000-0000-000000000001'::uuid, 'owner', 'contract', 1, \
             'step', 1, '\\x00'::bytea, 'actor', 'reason', 'CHG-1', 'audit-1')",
            "SELECT public.rss_saga_terminate(\
             '00000000-0000-0000-0000-000000000001'::uuid, 'owner', 'contract', \
             'actor', 'reason', 'CHG-1', 'audit-1')",
        ] {
            let error = match sqlx::query(forbidden).execute(&store.pool).await {
                Ok(_) => {
                    return Err(format!(
                        "ordinary {role} unexpectedly executed Saga operator mutation: {forbidden}"
                    )
                    .into());
                }
                Err(error) => error,
            };
            assert_eq!(
                error
                    .as_database_error()
                    .and_then(|database| database.code().map(|code| code.into_owned())),
                Some("42501".to_owned()),
                "{role} mutation denial must come from PostgreSQL ACL",
            );
        }
    }
    app.shutdown().await?;
    reader.shutdown().await?;

    let missing = consistency::SagaInstanceRef::new(
        test_tenant(),
        consistency::SagaId::new(uuid::Uuid::new_v4()),
    )?;
    let authorization = diport::test_support::saga_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        diport::SagaWorkerIdentity::new("owner", diport::SagaContractId::parse("owner.contract")?)?,
        missing,
        diport::SagaTerminateExpectation::new(
            diport::SagaOperatorReasonText::parse("withdraw missing fixture")?,
            diport::SagaOperatorChangeTicket::parse("CHG-OPERATOR-LANE")?,
        ),
        diport::SagaOperatorStartAuditId::parse("audit-operator-lane")?,
    );
    assert_eq!(
        deps.terminate(authorization).await?,
        diport::SagaOperatorCasOutcome::StaleJournal,
        "dedicated operator credential must own the mutation façade",
    );

    let audit: (String, String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT resource_kind, action, request_id, tenant_context::text FROM public.auth_audit_events \
         WHERE resource_id = $1",
    )
    .bind(&resource_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        audit,
        (
            "saga.operator".to_string(),
            "saga.operator.status.start".to_string(),
            Some(start_audit_id),
            Some(test_tenant().as_uuid().to_string()),
        )
    );

    let lane = crate::PgStore::connect_verified_saga_operator(&config).await?;
    assert!(
        sqlx::query("SELECT count(*) FROM public.auth_audit_events")
            .execute(&lane.store_arc().pool)
            .await
            .is_err(),
        "Saga operator login must not receive raw audit relation access",
    );
    assert!(
        sqlx::query("SELECT public.rss_saga_observe_unresolved('owner', 'contract')")
            .execute(&lane.store_arc().pool)
            .await
            .is_err(),
        "Saga operator login must not inherit serving/maintenance Saga functions",
    );

    lane.store_arc().shutdown().await?;
    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn saga_operator_lane_rejects_role_and_grant_drift() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let config = crate::PgSagaOperatorConfig::new(runtime_pg_config(
        fixture.owner_params(),
        TEST_SAGA_OPERATOR_ROLE,
        TEST_SAGA_OPERATOR_PASSWORD,
    ));

    sqlx::query("ALTER ROLE rss_saga_operator BYPASSRLS")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgSagaOperatorDeps::connect(&config).await,
        Err(PgError::SagaOperatorRoleOrGrantMismatch)
    ));
    sqlx::query("ALTER ROLE rss_saga_operator NOBYPASSRLS")
        .execute(&owner.pool)
        .await?;

    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text,text) \
         TO rss_saga_operator",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgSagaOperatorDeps::connect(&config).await,
        Err(PgError::SagaOperatorRoleOrGrantMismatch)
    ));
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text,text) \
         FROM rss_saga_operator",
    )
    .execute(&owner.pool)
    .await?;

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_operator_lane_is_function_only_and_exact() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let epoch_id = uuid::Uuid::new_v4();
    let start_audit_id = uuid::Uuid::new_v4();
    let operator_subject =
        eventexec::L2DrRecoveryOperatorSubject::parse("service:l2-dr-audit-test")?;
    let audit_plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        2_000,
        1_000,
        &[unique_event_id("l2-dr-lane-audit")],
    )?;

    deps.record_l2_dr_recovery_start_audit_subject(&operator_subject, &audit_plan, start_audit_id)
        .await?;
    deps.record_l2_dr_recovery_finish_audit_subject(
        &operator_subject,
        tenant,
        epoch_id,
        start_audit_id,
        crate::MaintenanceAuditOutcome::Failure {
            reason: "execution",
        },
    )
    .await?;

    let audits: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT principal_id, resource_id, action, outcome, failure_reason FROM auth_audit_events \
         WHERE request_id = $1 ORDER BY action",
    )
    .bind(start_audit_id.to_string())
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        audits,
        vec![
            (
                "service:l2-dr-audit-test".to_string(),
                epoch_id.to_string(),
                "eventing.l2-dr-recovery.apply.finish".to_string(),
                "failure".to_string(),
                Some("execution".to_string()),
            ),
            (
                "service:l2-dr-audit-test".to_string(),
                epoch_id.to_string(),
                "eventing.l2-dr-recovery.apply.start".to_string(),
                "success".to_string(),
                None,
            ),
        ]
    );

    let auditor = crate::PgStore::connect_verified_l2_dr_recovery_auditor(&audit_config).await?;
    let executor =
        crate::PgStore::connect_verified_l2_dr_recovery_executor(&executor_config).await?;
    for forbidden in [
        "SELECT count(*) FROM public.event_l2_dr_recovery_receipt",
        "UPDATE public.outbox SET retry_count = retry_count",
    ] {
        for lane in [&auditor.store_arc().pool, &executor.store_arc().pool] {
            assert!(
                sqlx::query(forbidden).execute(lane).await.is_err(),
                "L2 DR lane must not have raw relation persistence: {forbidden}",
            );
        }
    }
    assert!(
        sqlx::query(
            "SELECT public.rss_l2_dr_recovery_record_start_audit(1,0,'subject',\
             gen_random_uuid(),gen_random_uuid(),decode(repeat('00',32),'hex'),gen_random_uuid())",
        )
        .execute(&executor.store_arc().pool)
        .await
        .is_err(),
        "executor must not mint audit evidence",
    );
    assert!(
        sqlx::query(
            "SELECT * FROM public.rss_l2_dr_recovery_apply(\
             gen_random_uuid(),gen_random_uuid(),'database_ahead_broker_earlier',2000,1000,\
             'CHG-1837-PG',ARRAY['event'],decode(repeat('00',32),'hex'),'subject',gen_random_uuid())",
        )
        .execute(&auditor.store_arc().pool)
        .await
        .is_err(),
        "auditor must not execute recovery mutation",
    );
    let wrong_tenant = vocab::TenantId::parse(COTX_TENANT_B)?;
    let wrong_tenant_result = {
        let mut tx = executor.store_arc().pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, wrong_tenant).await?;
        let result = sqlx::query(
            "SELECT * FROM public.rss_l2_dr_recovery_apply(\
             $1::uuid, $2::uuid, 'database_ahead_broker_earlier', 2000, 1000, \
             'CHG-1837-PG', $3::text[], $4::bytea, $5, $6::uuid)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant.as_uuid().to_string())
        .bind(vec![unique_event_id("l2-dr-wrong-tenant")])
        .bind(vec![0_u8; 32])
        .bind(vocab::ServiceCallerDomain::MaintenanceOperator.as_str())
        .bind(start_audit_id.to_string())
        .execute(&mut *tx)
        .await;
        tx.rollback().await?;
        result
    };
    assert!(
        matches!(
            wrong_tenant_result,
            Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1831")
        ),
        "tenant mismatch must be rejected by the function boundary: {wrong_tenant_result:?}",
    );
    let nil_epoch_result = {
        let mut tx = executor.store_arc().pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, tenant).await?;
        let result = sqlx::query(
            "SELECT * FROM public.rss_l2_dr_recovery_apply(\
             '00000000-0000-0000-0000-000000000000'::uuid, $1::uuid, \
             'database_ahead_broker_earlier', 2000, 1000, 'CHG-1837-PG', \
             $2::text[], $3::bytea, $4, $5::uuid)",
        )
        .bind(tenant.as_uuid().to_string())
        .bind(vec![unique_event_id("l2-dr-nil-epoch")])
        .bind(vec![0_u8; 32])
        .bind("service:l2-dr-test")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        tx.rollback().await?;
        result
    };
    assert!(
        matches!(
            nil_epoch_result,
            Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("P1832")
        ),
        "nil epoch must be rejected as an invalid durable plan: {nil_epoch_result:?}",
    );

    sqlx::query(
        "GRANT SELECT ON TABLE public.event_l2_dr_recovery_receipt \
         TO rss_l2_dr_recovery_executor",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await,
        Err(PgError::L2DrRecoveryLanePrivileges)
    ));
    sqlx::query(
        "REVOKE SELECT ON TABLE public.event_l2_dr_recovery_receipt \
         FROM rss_l2_dr_recovery_executor",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "GRANT USAGE ON SEQUENCE public.auth_audit_events_id_seq \
         TO rss_l2_dr_recovery_auditor",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await,
        Err(PgError::L2DrRecoveryLaneExternalPersistencePrivileges)
    ));
    sqlx::query(
        "REVOKE USAGE ON SEQUENCE public.auth_audit_events_id_seq \
         FROM rss_l2_dr_recovery_auditor",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text,text) \
         TO rss_l2_dr_recovery_executor",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await,
        Err(PgError::L2DrRecoveryLanePrivileges)
    ));
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text,text) \
         FROM rss_l2_dr_recovery_executor",
    )
    .execute(&owner.pool)
    .await?;

    sqlx::query("GRANT SELECT ON TABLE public.event_l2_dr_recovery_receipt TO PUBLIC")
        .execute(&owner.pool)
        .await?;
    assert!(matches!(
        crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await,
        Err(PgError::L2DrRecoveryLanePrivileges)
    ));
    sqlx::query("REVOKE SELECT ON TABLE public.event_l2_dr_recovery_receipt FROM PUBLIC")
        .execute(&owner.pool)
        .await?;

    sqlx::query(
        "GRANT EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text,text) TO PUBLIC",
    )
    .execute(&owner.pool)
    .await?;
    assert!(matches!(
        crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await,
        Err(PgError::L2DrRecoveryLanePrivileges)
    ));
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text,text) FROM PUBLIC",
    )
    .execute(&owner.pool)
    .await?;

    auditor.store_arc().shutdown().await?;
    executor.store_arc().shutdown().await?;
    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_pg_ahead_is_atomic_and_deadline_bound() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let valid_id = unique_event_id("l2-dr-valid");
    let invalid_state_id = unique_event_id("l2-dr-invalid-state");
    let expired_id = unique_event_id("l2-dr-expired");
    insert_l2_dr_published_fact(&owner, tenant, &valid_id, 3_600).await?;
    insert_l2_dr_published_fact(&owner, tenant, &invalid_state_id, 3_600).await?;
    insert_l2_dr_published_fact(&owner, tenant, &expired_id, -172_800).await?;
    sqlx::query(
        "UPDATE outbox SET status = 'pending', published_at = NULL \
         WHERE event_id = $1",
    )
    .bind(&invalid_state_id)
    .execute(&owner.pool)
    .await?;

    let valid_before: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(&valid_id)
            .fetch_one(&owner.pool)
            .await?;
    let state_plan = l2_dr_recovery_plan(
        uuid::Uuid::new_v4(),
        tenant,
        2_000,
        1_000,
        &[valid_id.clone(), invalid_state_id.clone()],
    )?;
    assert_eq!(
        deps.apply_l2_dr_recovery(
            authorize_l2_dr_recovery(&deps, state_plan, uuid::Uuid::new_v4()).await?,
        )
        .await,
        Err(eventexec::L2DrRecoveryError::FactNotPublished)
    );
    let valid_after_state_failure: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(&valid_id)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(valid_after_state_failure, valid_before);

    let missing_plan = l2_dr_recovery_plan(
        uuid::Uuid::new_v4(),
        tenant,
        2_000,
        1_000,
        &[valid_id.clone(), unique_event_id("l2-dr-missing")],
    )?;
    assert_eq!(
        deps.apply_l2_dr_recovery(
            authorize_l2_dr_recovery(&deps, missing_plan, uuid::Uuid::new_v4()).await?,
        )
        .await,
        Err(eventexec::L2DrRecoveryError::FactNotFound)
    );

    let expired_plan = l2_dr_recovery_plan(
        uuid::Uuid::new_v4(),
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&expired_id),
    )?;
    assert_eq!(
        deps.apply_l2_dr_recovery(
            authorize_l2_dr_recovery(&deps, expired_plan, uuid::Uuid::new_v4()).await?,
        )
        .await,
        Err(eventexec::L2DrRecoveryError::DeadlineExpired)
    );

    let before_identity: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT tenant_id::text, domain, topic, contract_id, contract_version, schema_hash, \
                    encode(payload, 'hex'), metadata::text, encode(fact_fingerprint, 'hex') \
             FROM outbox WHERE event_id = $1",
    )
    .bind(&valid_id)
    .fetch_one(&owner.pool)
    .await?;
    let frozen_deadline: String = sqlx::query_scalar(
        "SELECT LEAST(automatic_retry_deadline + make_interval(secs => policy.same_id_redrive_horizon_seconds::double precision), \
                      published_at + make_interval(secs => policy.same_id_redrive_horizon_seconds::double precision))::text \
         FROM outbox CROSS JOIN event_delivery_policy AS policy \
         WHERE event_id = $1 AND policy.singleton",
    )
    .bind(&valid_id)
    .fetch_one(&owner.pool)
    .await?;
    let apply_plan = l2_dr_recovery_plan(
        uuid::Uuid::new_v4(),
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&valid_id),
    )?;
    let receipt = deps
        .apply_l2_dr_recovery(
            authorize_l2_dr_recovery(&deps, apply_plan, uuid::Uuid::new_v4()).await?,
        )
        .await?;
    assert_eq!(receipt.outcome(), eventexec::L2DrRecoveryOutcome::Applied);
    let after_identity: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT tenant_id::text, domain, topic, contract_id, contract_version, schema_hash, \
                    encode(payload, 'hex'), metadata::text, encode(fact_fingerprint, 'hex') \
             FROM outbox WHERE event_id = $1",
    )
    .bind(&valid_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(after_identity, before_identity);
    let armed: (String, String, Option<String>, bool) = sqlx::query_as(
        "SELECT status, same_id_delivery_phase, same_id_redrive_deadline::text, \
                published_at IS NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&valid_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        armed,
        (
            "pending".to_string(),
            "redrive".to_string(),
            Some(frozen_deadline),
            true,
        )
    );

    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_epoch_is_idempotent_conflict_safe_and_receipt_immutable() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let first_deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let retry_deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("l2-dr-idempotent");
    insert_l2_dr_published_fact(&owner, tenant, &event_id, 3_600).await?;
    let epoch_id = uuid::Uuid::new_v4();
    let start_audit_id = uuid::Uuid::new_v4();
    let plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&event_id),
    )?;
    let first_operator_subject = "service:l2-dr-first-operator";
    let retry_start_audit_id = uuid::Uuid::new_v4();
    let retry_operator_subject = "service:l2-dr-retry-operator";
    let first_authorized = authorize_l2_dr_recovery_as(
        &first_deps,
        plan.clone(),
        first_operator_subject,
        start_audit_id,
    )
    .await?;
    let retry_authorized = authorize_l2_dr_recovery_as(
        &retry_deps,
        plan.clone(),
        retry_operator_subject,
        retry_start_audit_id,
    )
    .await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let first_barrier = std::sync::Arc::clone(&barrier);
    let retry_barrier = std::sync::Arc::clone(&barrier);
    let first_apply = async {
        first_barrier.wait().await;
        first_deps.apply_l2_dr_recovery(first_authorized).await
    };
    let retry_apply = async {
        retry_barrier.wait().await;
        retry_deps.apply_l2_dr_recovery(retry_authorized).await
    };
    let (first_result, retry_result) = tokio::join!(first_apply, retry_apply);
    let first_observation = ConcurrentL2DrApplyObservation::from_result(first_result)?;
    let retry_observation = ConcurrentL2DrApplyObservation::from_result(retry_result)?;
    first_deps
        .record_l2_dr_recovery_finish_audit_subject(
            &eventexec::L2DrRecoveryOperatorSubject::parse(first_operator_subject)?,
            tenant,
            epoch_id,
            start_audit_id,
            crate::MaintenanceAuditOutcome::Success,
        )
        .await?;
    retry_deps
        .record_l2_dr_recovery_finish_audit_subject(
            &eventexec::L2DrRecoveryOperatorSubject::parse(retry_operator_subject)?,
            tenant,
            epoch_id,
            retry_start_audit_id,
            crate::MaintenanceAuditOutcome::Success,
        )
        .await?;
    let mut observations = [first_observation, retry_observation];
    observations.sort_by_key(ConcurrentL2DrApplyObservation::label);
    assert_eq!(
        observations
            .each_ref()
            .map(|observation| observation.label()),
        ["already_applied", "applied"]
    );
    let (
        retry_receipt_subject,
        retry_receipt_start_audit_id,
        retry_receipt_applied_at,
        applied_subject,
        applied_start_audit_id,
        applied_at,
    ) = match &observations {
        [
            ConcurrentL2DrApplyObservation::AlreadyApplied {
                operator_subject: retry_receipt_subject,
                start_audit_id: retry_receipt_start_audit_id,
                applied_at: retry_receipt_applied_at,
            },
            ConcurrentL2DrApplyObservation::Applied {
                operator_subject: applied_subject,
                start_audit_id: applied_start_audit_id,
                applied_at,
            },
        ] => (
            retry_receipt_subject,
            retry_receipt_start_audit_id,
            retry_receipt_applied_at,
            applied_subject,
            applied_start_audit_id,
            applied_at,
        ),
        _ => {
            return Err(std::io::Error::other(
                "same-plan concurrent outcomes must be closed and sorted",
            )
            .into());
        }
    };
    assert_eq!(retry_receipt_subject, applied_subject);
    assert_eq!(retry_receipt_start_audit_id, applied_start_audit_id);
    assert_eq!(retry_receipt_applied_at, applied_at);
    assert!(
        (applied_subject == first_operator_subject && *applied_start_audit_id == start_audit_id)
            || (applied_subject == retry_operator_subject
                && *applied_start_audit_id == retry_start_audit_id)
    );
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
    )
    .bind(epoch_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(receipt_count, 1);

    let reader_config = rss_app_read_config(&fixture, &owner).await?;
    let reader = crate::PgStore::connect_verified_read(&reader_config).await?;
    let visible_to_tenant: i64 = {
        let mut tx = reader.store_arc().pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, tenant).await?;
        let count = sqlx::query_scalar(
            "SELECT count(*) FROM event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
        )
        .bind(epoch_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        count
    };
    assert_eq!(visible_to_tenant, 1);
    let hidden_from_other_tenant: i64 = {
        let mut tx = reader.store_arc().pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, vocab::TenantId::parse(COTX_TENANT_B)?).await?;
        let count = sqlx::query_scalar(
            "SELECT count(*) FROM event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
        )
        .bind(epoch_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        count
    };
    assert_eq!(hidden_from_other_tenant, 0);
    let reader_mutation = {
        let mut tx = reader.store_arc().pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, tenant).await?;
        let result = sqlx::query(
            "UPDATE event_l2_dr_recovery_receipt SET outcome = outcome \
             WHERE epoch_id = $1::uuid",
        )
        .bind(epoch_id.to_string())
        .execute(&mut *tx)
        .await;
        tx.rollback().await?;
        result
    };
    assert!(
        reader_mutation.is_err(),
        "tenant reader must retain SELECT-only receipt access",
    );
    reader.store_arc().shutdown().await?;

    let conflicting = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        3_000,
        1_000,
        std::slice::from_ref(&event_id),
    )?;
    assert_eq!(
        first_deps
            .apply_l2_dr_recovery(
                authorize_l2_dr_recovery(&first_deps, conflicting, uuid::Uuid::new_v4()).await?,
            )
            .await,
        Err(eventexec::L2DrRecoveryError::EpochConflict)
    );

    for statement in [
        "UPDATE event_l2_dr_recovery_receipt SET outcome = outcome WHERE epoch_id = $1::uuid",
        "DELETE FROM event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
    ] {
        let mutation = sqlx::query(statement)
            .bind(epoch_id.to_string())
            .execute(&owner.pool)
            .await;
        assert!(
            matches!(
                mutation,
                Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("55000")
            ),
            "receipt must reject UPDATE and DELETE: {mutation:?}",
        );
    }

    retry_deps.shutdown().await?;
    first_deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_different_epochs_do_not_share_a_global_lock() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let first_deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let second_deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let first_event_id = unique_event_id("l2-dr-independent-epoch-first");
    let second_event_id = unique_event_id("l2-dr-independent-epoch-second");
    insert_l2_dr_published_fact(&owner, tenant, &first_event_id, 3_600).await?;
    insert_l2_dr_published_fact(&owner, tenant, &second_event_id, 3_600).await?;
    let first_epoch_id = uuid::Uuid::new_v4();
    let second_epoch_id = uuid::Uuid::new_v4();
    let first_plan = l2_dr_recovery_plan(
        first_epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&first_event_id),
    )?;
    let second_plan = l2_dr_recovery_plan(
        second_epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&second_event_id),
    )?;
    let first_authorized =
        authorize_l2_dr_recovery(&first_deps, first_plan, uuid::Uuid::new_v4()).await?;
    let second_authorized =
        authorize_l2_dr_recovery(&second_deps, second_plan, uuid::Uuid::new_v4()).await?;

    let first_lock_key: i64 = sqlx::query_scalar("SELECT pg_catalog.hashtextextended($1, 1837)")
        .bind(first_epoch_id.to_string())
        .fetch_one(&owner.pool)
        .await?;
    let mut first_epoch_blocker = owner.pool.begin().await?;
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
        .bind(first_lock_key)
        .execute(&mut *first_epoch_blocker)
        .await?;

    let first_task = tokio::spawn(async move {
        let result = first_deps.apply_l2_dr_recovery(first_authorized).await;
        (first_deps, result)
    });
    let first_is_waiting = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if first_task.is_finished() {
                return Ok::<bool, sqlx::Error>(false);
            }
            let waiting: bool = sqlx::query_scalar(
                "SELECT pg_catalog.count(*) > 0 FROM pg_catalog.pg_stat_activity \
                 WHERE usename = $1 AND wait_event_type = 'Lock' AND wait_event = 'advisory' \
                 AND query LIKE '%rss_l2_dr_recovery_apply%'",
            )
            .bind(TEST_L2_DR_RECOVERY_EXECUTOR_ROLE)
            .fetch_one(&owner.pool)
            .await?;
            if waiting {
                return Ok(true);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| std::io::Error::other("first L2 DR epoch did not reach its advisory lock"))??;
    assert!(
        first_is_waiting,
        "first L2 DR apply must block on its exact epoch key before the independence assertion"
    );

    let second_observed = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        second_deps.apply_l2_dr_recovery(second_authorized),
    )
    .await;
    first_epoch_blocker.commit().await?;
    let (first_deps, first_result) = first_task.await?;
    let first_receipt = first_result?;
    let second_receipt = second_observed.map_err(|_| {
        std::io::Error::other("a different L2 DR epoch was serialized behind the first epoch")
    })??;
    assert_eq!(
        first_receipt.outcome(),
        eventexec::L2DrRecoveryOutcome::Applied
    );
    assert_eq!(
        second_receipt.outcome(),
        eventexec::L2DrRecoveryOutcome::Applied
    );
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM event_l2_dr_recovery_receipt WHERE epoch_id = ANY($1::uuid[])",
    )
    .bind(vec![
        first_epoch_id.to_string(),
        second_epoch_id.to_string(),
    ])
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(receipt_count, 2);

    second_deps.shutdown().await?;
    first_deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_concurrent_same_epoch_different_digest_has_one_atomic_winner() -> TestResult
{
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let first_deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let second_deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let first_event_id = unique_event_id("l2-dr-conflict-first");
    let second_event_id = unique_event_id("l2-dr-conflict-second");
    insert_l2_dr_published_fact(&owner, tenant, &first_event_id, 3_600).await?;
    insert_l2_dr_published_fact(&owner, tenant, &second_event_id, 3_600).await?;
    let first_before: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(&first_event_id)
            .fetch_one(&owner.pool)
            .await?;
    let second_before: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(&second_event_id)
            .fetch_one(&owner.pool)
            .await?;
    let epoch_id = uuid::Uuid::new_v4();
    let first_subject = "service:l2-dr-conflict-first";
    let second_subject = "service:l2-dr-conflict-second";
    let first_start_audit_id = uuid::Uuid::new_v4();
    let second_start_audit_id = uuid::Uuid::new_v4();
    let first_plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&first_event_id),
    )?;
    let second_plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&second_event_id),
    )?;
    let first_authorized =
        authorize_l2_dr_recovery_as(&first_deps, first_plan, first_subject, first_start_audit_id)
            .await?;
    let second_authorized = authorize_l2_dr_recovery_as(
        &second_deps,
        second_plan,
        second_subject,
        second_start_audit_id,
    )
    .await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let first_barrier = std::sync::Arc::clone(&barrier);
    let second_barrier = std::sync::Arc::clone(&barrier);
    let first_apply = async {
        first_barrier.wait().await;
        first_deps.apply_l2_dr_recovery(first_authorized).await
    };
    let second_apply = async {
        second_barrier.wait().await;
        second_deps.apply_l2_dr_recovery(second_authorized).await
    };
    let (first_result, second_result) = tokio::join!(first_apply, second_apply);
    let first_observation = ConcurrentL2DrApplyObservation::from_result(first_result)?;
    let second_observation = ConcurrentL2DrApplyObservation::from_result(second_result)?;
    first_deps
        .record_l2_dr_recovery_finish_audit_subject(
            &eventexec::L2DrRecoveryOperatorSubject::parse(first_subject)?,
            tenant,
            epoch_id,
            first_start_audit_id,
            if matches!(
                &first_observation,
                ConcurrentL2DrApplyObservation::Applied { .. }
            ) {
                crate::MaintenanceAuditOutcome::Success
            } else {
                crate::MaintenanceAuditOutcome::Failure {
                    reason: "epoch_conflict",
                }
            },
        )
        .await?;
    second_deps
        .record_l2_dr_recovery_finish_audit_subject(
            &eventexec::L2DrRecoveryOperatorSubject::parse(second_subject)?,
            tenant,
            epoch_id,
            second_start_audit_id,
            if matches!(
                &second_observation,
                ConcurrentL2DrApplyObservation::Applied { .. }
            ) {
                crate::MaintenanceAuditOutcome::Success
            } else {
                crate::MaintenanceAuditOutcome::Failure {
                    reason: "epoch_conflict",
                }
            },
        )
        .await?;
    let first_won = matches!(
        &first_observation,
        ConcurrentL2DrApplyObservation::Applied { .. }
    );
    let (winner_event_id, loser_event_id, loser_before) = if first_won {
        (&first_event_id, &second_event_id, &second_before)
    } else {
        (&second_event_id, &first_event_id, &first_before)
    };
    let mut observations = [first_observation, second_observation];
    observations.sort_by_key(ConcurrentL2DrApplyObservation::label);
    assert_eq!(
        observations.map(|observation| observation.label()),
        ["applied", "epoch_conflict"]
    );

    let receipt: (Vec<String>, String, String) = sqlx::query_as(
        "SELECT event_ids, operator_subject, start_audit_id::text \
         FROM event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
    )
    .bind(epoch_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(receipt.0, vec![winner_event_id.to_owned()]);
    let expected_receipt_provenance = if first_won {
        (first_subject, first_start_audit_id)
    } else {
        (second_subject, second_start_audit_id)
    };
    assert_eq!(receipt.1, expected_receipt_provenance.0);
    assert_eq!(receipt.2, expected_receipt_provenance.1.to_string());
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
    )
    .bind(epoch_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(receipt_count, 1);
    let winner_state: (String, String, bool) = sqlx::query_as(
        "SELECT status, same_id_delivery_phase, published_at IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(winner_event_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        winner_state,
        ("pending".to_owned(), "redrive".to_owned(), true)
    );
    let loser_after: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(loser_event_id)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(&loser_after, loser_before);
    let redriven_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox WHERE event_id = ANY($1) \
         AND status = 'pending' AND same_id_delivery_phase = 'redrive'",
    )
    .bind(vec![first_event_id, second_event_id])
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(redriven_count, 1);

    second_deps.shutdown().await?;
    first_deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_rabbit_ahead_preserves_outbox_and_inbox_exactly() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("l2-dr-rabbit-ahead");
    insert_l2_dr_published_fact(&owner, tenant, &event_id, 3_600).await?;
    sqlx::query(
        "INSERT INTO inbox_receipts (tenant_id, event_id, consumer_group, domain, topic, \
          contract_id, contract_version, schema_hash, status, lease_token, committed_at) \
         VALUES ($1::uuid, $2, 'l2-dr-test', 'l2-dr-test', 'l2-dr.test', 'l2-dr.test', \
                 'v1', $3, 'done', gen_random_uuid(), clock_timestamp())",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(&event_id)
    .bind(TEST_SCHEMA_HASH)
    .execute(&owner.pool)
    .await?;
    let outbox_before: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&owner.pool)
            .await?;
    let inbox_before: String = sqlx::query_scalar(
        "SELECT to_jsonb(inbox_receipts)::text FROM inbox_receipts \
         WHERE tenant_id = $1::uuid AND event_id = $2",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(&event_id)
    .fetch_one(&owner.pool)
    .await?;

    let plan = l2_dr_recovery_plan(
        uuid::Uuid::new_v4(),
        tenant,
        1_000,
        2_000,
        std::slice::from_ref(&event_id),
    )?;
    let receipt = deps
        .apply_l2_dr_recovery(authorize_l2_dr_recovery(&deps, plan, uuid::Uuid::new_v4()).await?)
        .await?;
    assert_eq!(receipt.outcome(), eventexec::L2DrRecoveryOutcome::Applied);
    assert_eq!(
        receipt.direction(),
        eventexec::RecoveryDirection::BrokerAheadDatabaseEarlier
    );
    let outbox_after: String =
        sqlx::query_scalar("SELECT to_jsonb(outbox)::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&owner.pool)
            .await?;
    let inbox_after: String = sqlx::query_scalar(
        "SELECT to_jsonb(inbox_receipts)::text FROM inbox_receipts \
         WHERE tenant_id = $1::uuid AND event_id = $2",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(&event_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(outbox_after, outbox_before);
    assert_eq!(inbox_after, inbox_before);

    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_rejects_forged_auth_audit_start_proof() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let app = connect_pg_rss_app_role(&fixture, &owner).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("l2-dr-forge");
    insert_l2_dr_published_fact(&owner, tenant, &event_id, 3_600).await?;
    let epoch_id = uuid::Uuid::new_v4();
    let start_audit_id = uuid::Uuid::new_v4();
    let plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&event_id),
    )?;
    let outbox_before = l2_dr_outbox_snapshot(&owner, &event_id).await?;
    forge_l2_dr_start_audit_as_rss_app(&app, &plan, "service:l2-dr-test", start_audit_id).await?;
    let forged =
        mint_l2_dr_authorized_without_durable_start(plan, "service:l2-dr-test", start_audit_id)?;

    assert_eq!(
        deps.apply_l2_dr_recovery(forged).await,
        Err(eventexec::L2DrRecoveryError::StartAuditMismatch)
    );
    assert_eq!(l2_dr_receipt_count(&owner, epoch_id).await?, 0);
    assert_eq!(
        l2_dr_outbox_snapshot(&owner, &event_id).await?,
        outbox_before
    );
    let private_proofs: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM public.event_l2_dr_recovery_start_proof \
         WHERE start_audit_id = $1::uuid",
    )
    .bind(start_audit_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(private_proofs, 0);

    deps.shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_rejects_missing_and_mismatched_start_proof_without_mutation() -> TestResult
{
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("l2-dr-p1839");
    insert_l2_dr_published_fact(&owner, tenant, &event_id, 3_600).await?;
    let outbox_before = l2_dr_outbox_snapshot(&owner, &event_id).await?;

    let missing_epoch = uuid::Uuid::new_v4();
    let missing_plan = l2_dr_recovery_plan(
        missing_epoch,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&event_id),
    )?;
    let missing = mint_l2_dr_authorized_without_durable_start(
        missing_plan,
        "service:l2-dr-test",
        uuid::Uuid::new_v4(),
    )?;
    assert_eq!(
        deps.apply_l2_dr_recovery(missing).await,
        Err(eventexec::L2DrRecoveryError::StartAuditMismatch)
    );
    assert_eq!(l2_dr_receipt_count(&owner, missing_epoch).await?, 0);
    assert_eq!(
        l2_dr_outbox_snapshot(&owner, &event_id).await?,
        outbox_before
    );

    let recorded_epoch = uuid::Uuid::new_v4();
    let recorded_start = uuid::Uuid::new_v4();
    let recorded_plan = l2_dr_recovery_plan(
        recorded_epoch,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&event_id),
    )?;
    let _ = authorize_l2_dr_recovery(&deps, recorded_plan.clone(), recorded_start).await?;
    let mismatched_plan = l2_dr_recovery_plan(
        recorded_epoch,
        tenant,
        2_000,
        1_000,
        &[unique_event_id("l2-dr-p1839-mismatch")],
    )?;
    let mismatched = mint_l2_dr_authorized_without_durable_start(
        mismatched_plan,
        "service:l2-dr-test",
        recorded_start,
    )?;
    assert_eq!(
        deps.apply_l2_dr_recovery(mismatched).await,
        Err(eventexec::L2DrRecoveryError::StartAuditMismatch)
    );
    assert_eq!(l2_dr_receipt_count(&owner, recorded_epoch).await?, 0);
    assert_eq!(
        l2_dr_outbox_snapshot(&owner, &event_id).await?,
        outbox_before
    );

    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_rejects_policy_mismatch_without_mutation() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    let event_id = unique_event_id("l2-dr-p1834");
    insert_l2_dr_published_fact(&owner, tenant, &event_id, 3_600).await?;
    let outbox_before = l2_dr_outbox_snapshot(&owner, &event_id).await?;
    let epoch_id = uuid::Uuid::new_v4();
    let plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        2_000,
        1_000,
        std::slice::from_ref(&event_id),
    )?;
    let authorized = authorize_l2_dr_recovery(&deps, plan, uuid::Uuid::new_v4()).await?;

    sqlx::query("DELETE FROM public.event_delivery_policy WHERE singleton")
        .execute(&owner.pool)
        .await?;

    assert_eq!(
        deps.apply_l2_dr_recovery(authorized).await,
        Err(eventexec::L2DrRecoveryError::DeliveryPolicyMismatch)
    );
    assert_eq!(l2_dr_receipt_count(&owner, epoch_id).await?, 0);
    assert_eq!(
        l2_dr_outbox_snapshot(&owner, &event_id).await?,
        outbox_before
    );

    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn l2_dr_recovery_broker_ahead_allows_absent_outbox_events_as_noop_receipt() -> TestResult {
    use eventexec::L2DrRecoveryStore as _;

    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    provision_runtime_logins(&fixture).await?;
    let (audit_config, executor_config) = l2_dr_lane_configs(fixture.owner_params());
    let deps = crate::PgL2DrRecoveryDeps::connect(&audit_config, &executor_config).await?;
    let tenant = test_tenant();
    // Broker-ahead freezes an event set attested by the operator; PostgreSQL may not retain those
    // outbox rows after an earlier restore. Apply must still record a no-op receipt without mutating
    // outbox/inbox and must not invent a P1835 existence check on this direction.
    let absent_event_id = unique_event_id("l2-dr-broker-absent");
    let outbox_before: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM public.outbox WHERE event_id = $1")
            .bind(&absent_event_id)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(outbox_before, 0);

    let epoch_id = uuid::Uuid::new_v4();
    let plan = l2_dr_recovery_plan(
        epoch_id,
        tenant,
        1_000,
        2_000,
        std::slice::from_ref(&absent_event_id),
    )?;
    let receipt = deps
        .apply_l2_dr_recovery(authorize_l2_dr_recovery(&deps, plan, uuid::Uuid::new_v4()).await?)
        .await?;
    assert_eq!(receipt.outcome(), eventexec::L2DrRecoveryOutcome::Applied);
    assert_eq!(
        receipt.direction(),
        eventexec::RecoveryDirection::BrokerAheadDatabaseEarlier
    );
    let store_outcome: String = sqlx::query_scalar(
        "SELECT outcome FROM public.event_l2_dr_recovery_receipt WHERE epoch_id = $1::uuid",
    )
    .bind(epoch_id.to_string())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(store_outcome, "normal_consume_resume");
    let outbox_after: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM public.outbox WHERE event_id = $1")
            .bind(&absent_event_id)
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(outbox_after, 0);
    assert_eq!(l2_dr_receipt_count(&owner, epoch_id).await?, 1);

    deps.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PgOperatorRepairCase {
    ForwardApplied,
    ForwardNotApplied,
    CompensationApplied,
}

async fn exercise_pg_operator_repair_case(
    app: &crate::PgStore,
    store: &crate::saga::PgSagaDurableStore,
    tenant: vocab::TenantId,
    identity: &diport::SagaWorkerIdentity,
    definition: &consistency::SagaDefinitionIdentity,
    operator_identity: &diport::SagaWorkerIdentity,
    repair_case: PgOperatorRepairCase,
) -> TestResult {
    use diport::{SagaDurableStore as _, SagaOperatorStore as _};

    let instance =
        consistency::SagaInstanceRef::new(tenant, consistency::SagaId::new(uuid::Uuid::new_v4()))?;
    let authorization = diport::test_support::saga_start_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        identity.clone(),
        instance,
        diport::SagaStartAuditId::parse("operator-repair-integration-start")?,
    );
    store
        .register(
            authorization,
            diport::SagaInstanceRegistration::new(instance, identity.clone(), definition.clone())?,
        )
        .await?;
    let runnable = diport::SagaRunnableInstance::new(
        instance,
        consistency::SagaInstanceStatus::Ready,
        identity.clone(),
        definition.clone(),
    )?;
    let lease = match store
        .claim(diport::SagaClaimRequest::new(
            runnable,
            diport::SagaLeaseHolder::parse(format!("operator-matrix-{repair_case:?}"))?,
            diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
        ))
        .await?
    {
        diport::SagaClaimOutcome::Acquired(lease) => lease,
        outcome => {
            return Err(std::io::Error::other(format!(
                "operator matrix claim failed for {repair_case:?}: {outcome:?}"
            ))
            .into());
        }
    };
    let step = generated::saga::billing_v1::STEP_0;
    let attempt = consistency::SagaAttempt::new(1)?;
    let forward_key = consistency::SagaIdempotencyKey::derive(
        instance,
        definition,
        step,
        consistency::SagaEffectPhase::Forward,
    );
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::ForwardIntent(diport::SagaForwardIntent::new(
                    0,
                    vocab::StepName::parse(step.name())?,
                    attempt,
                    forward_key.clone(),
                )?),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Applied,
    );

    let repair = match repair_case {
        PgOperatorRepairCase::ForwardApplied => diport::SagaOperatorRepair::ForwardApplied(
            Box::new(diport::SagaForwardCompletion::new(
                diport::SagaStepCompletion::new(
                    consistency::SagaReceiptScope::new(
                        instance,
                        identity.clone(),
                        definition.clone(),
                        step,
                        forward_key.clone(),
                    )?,
                    attempt,
                    consistency::SagaReceiptFormatVersion::V1,
                    secure::Plaintext::new(br#"{"reservation_id":"operator-matrix"}"#.to_vec()),
                    1,
                ),
                diport::SagaForwardProgress::Continue,
            )),
        ),
        PgOperatorRepairCase::ForwardNotApplied => {
            diport::SagaOperatorRepair::ForwardNotApplied(diport::SagaForwardNotApplied::new(
                1,
                vocab::StepName::parse(step.name())?,
                attempt,
                forward_key,
            )?)
        }
        PgOperatorRepairCase::CompensationApplied => {
            assert_eq!(
                store
                    .mutate(
                        &lease,
                        diport::SagaDurableMutation::ForwardCompleted(
                            diport::SagaForwardCompletion::new(
                                diport::SagaStepCompletion::new(
                                    consistency::SagaReceiptScope::new(
                                        instance,
                                        identity.clone(),
                                        definition.clone(),
                                        step,
                                        forward_key,
                                    )?,
                                    attempt,
                                    consistency::SagaReceiptFormatVersion::V1,
                                    secure::Plaintext::new(
                                        br#"{"reservation_id":"operator-compensation"}"#.to_vec(),
                                    ),
                                    1,
                                ),
                                diport::SagaForwardProgress::Continue,
                            ),
                        ),
                    )
                    .await?,
                diport::SagaDurableMutationOutcome::Applied,
            );
            let compensation_key = consistency::SagaIdempotencyKey::derive(
                instance,
                definition,
                step,
                consistency::SagaEffectPhase::Compensation,
            );
            assert_eq!(
                store
                    .mutate(
                        &lease,
                        diport::SagaDurableMutation::CompensationIntent(
                            diport::SagaCompensationIntent::new(
                                2,
                                vocab::StepName::parse(step.name())?,
                                attempt,
                                compensation_key.clone(),
                                consistency::SagaCompensationCause::BusinessFailure,
                            )?,
                        ),
                    )
                    .await?,
                diport::SagaDurableMutationOutcome::Applied,
            );
            diport::SagaOperatorRepair::CompensationApplied(
                diport::SagaCompensationCompletion::new(
                    3,
                    vocab::StepName::parse(step.name())?,
                    attempt,
                    compensation_key,
                    diport::SagaCompensationProgress::Continue,
                )?,
            )
        }
    };
    let reason = match repair_case {
        PgOperatorRepairCase::ForwardApplied | PgOperatorRepairCase::ForwardNotApplied => {
            consistency::SagaOperatorReason::ForwardOutcomeUnknown
        }
        PgOperatorRepairCase::CompensationApplied => {
            consistency::SagaOperatorReason::CompensationOutcomeUnknown
        }
    };
    assert_eq!(
        store
            .mutate(
                &lease,
                diport::SagaDurableMutation::OperatorRequired(reason),
            )
            .await?,
        diport::SagaDurableMutationOutcome::Applied,
    );
    let authorization = operator_repair_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        operator_identity.clone(),
        instance,
        reason,
        diport::SagaOperatorChangeTicket::parse(format!("CHG-653-{repair_case:?}"))?,
        diport::SagaOperatorStartAuditId::parse(format!("audit-653-{repair_case:?}"))?,
    )?;
    let claim = match store
        .claim_repair(
            authorization,
            diport::SagaLeaseHolder::parse(format!("repair-653-{repair_case:?}"))?,
            diport::SagaLeaseTtl::new(std::time::Duration::from_secs(60))?,
        )
        .await?
    {
        diport::SagaOperatorClaimOutcome::Acquired(claim) => claim,
        _ => {
            return Err(std::io::Error::other(format!(
                "operator matrix repair claim failed for {repair_case:?}"
            ))
            .into());
        }
    };
    assert_eq!(
        store.commit_repair(claim, repair).await?,
        diport::SagaOperatorCasOutcome::Applied,
        "repair case {repair_case:?}",
    );
    let record = store
        .get(&instance)
        .await?
        .ok_or_else(|| std::io::Error::other("operator matrix instance disappeared"))?;
    assert_eq!(
        record.status(),
        match repair_case {
            PgOperatorRepairCase::CompensationApplied => {
                consistency::SagaInstanceStatus::Compensating
            }
            PgOperatorRepairCase::ForwardApplied | PgOperatorRepairCase::ForwardNotApplied => {
                consistency::SagaInstanceStatus::Running
            }
        },
        "{repair_case:?}",
    );
    assert_eq!(record.operator_reason(), None, "{repair_case:?}");

    let mut audit_tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *audit_tx)
        .await?;
    let (decision,): (String,) = sqlx::query_as(
        "SELECT decision FROM public.saga_operator_decisions \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(instance.saga_id().as_uuid().to_string())
    .fetch_one(&mut *audit_tx)
    .await?;
    audit_tx.rollback().await?;
    assert_eq!(
        decision,
        match repair_case {
            PgOperatorRepairCase::ForwardApplied | PgOperatorRepairCase::CompensationApplied =>
                "confirmed_applied",
            PgOperatorRepairCase::ForwardNotApplied => "confirmed_not_applied",
        },
    );
    Ok(())
}
