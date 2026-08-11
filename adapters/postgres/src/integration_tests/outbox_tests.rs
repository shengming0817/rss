//! Postgres integration tests — outbox seam.

use std::collections::{BTreeMap, BTreeSet};

use super::support::*;
use crate::outbox_routine::{
    OUTBOX_ROUTINES, OutboxRoutineOwnerPolicy, OutboxRoutineRole, OutboxRoutineSpec,
};

const DLQ_TEST_OPERATOR: &str = "postgres-dlq-operator";

fn dlq_authorization<A: diport::DlqOperatorAction>(
    tenant: vocab::TenantId,
) -> diport::DlqOperatorAuthorization<A> {
    dlq_authorization_with_audit_id(
        tenant,
        diport::DlqOperatorStartAuditId::parse("postgres-dlq-integration").unwrap(),
    )
}

fn dlq_authorization_with_audit_id<A: diport::DlqOperatorAction>(
    tenant: vocab::TenantId,
    start_audit_id: diport::DlqOperatorStartAuditId,
) -> diport::DlqOperatorAuthorization<A> {
    diport::test_support::dlq_operator_authorization(
        vocab::ServiceCallerDomain::MaintenanceOperator,
        DLQ_TEST_OPERATOR,
        tenant,
        start_audit_id,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct OutboxRoutineObservation {
    signature: String,
    owner: String,
    owner_can_login: bool,
    security_definer: bool,
    fixed_search_path: bool,
    public_execute: bool,
    app_execute: bool,
    maintenance_execute: bool,
    recovery_execute: bool,
}

fn validate_outbox_routine_catalog(actual: &[OutboxRoutineObservation]) -> Result<(), String> {
    let expected = OUTBOX_ROUTINES
        .iter()
        .map(|spec| (spec.signature, spec))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != OUTBOX_ROUTINES.len() {
        return Err("duplicate expected outbox routine signature".to_string());
    }
    let actual_by_signature = actual
        .iter()
        .map(|routine| (routine.signature.as_str(), routine))
        .collect::<BTreeMap<_, _>>();
    if actual_by_signature.len() != actual.len() {
        return Err("duplicate discovered outbox routine signature".to_string());
    }

    let expected_ids = expected.keys().copied().collect::<BTreeSet<_>>();
    let actual_ids = actual_by_signature.keys().copied().collect::<BTreeSet<_>>();
    let missing = expected_ids
        .difference(&actual_ids)
        .copied()
        .collect::<Vec<_>>();
    let extra = actual_ids
        .difference(&expected_ids)
        .copied()
        .collect::<Vec<_>>();
    let mut drift = Vec::new();
    for signature in expected_ids.intersection(&actual_ids) {
        let spec = expected[*signature];
        let observed = actual_by_signature[*signature];
        let policy = spec.role.policy();
        let owner_matches = match policy.owner {
            OutboxRoutineOwnerPolicy::NotServingRole => observed.owner != "rss_app",
            OutboxRoutineOwnerPolicy::MaintenanceNoLogin => {
                observed.owner == "rss_outbox_maintenance" && !observed.owner_can_login
            }
        };
        if !owner_matches
            || observed.security_definer != policy.security_definer
            || observed.fixed_search_path != policy.fixed_search_path
            || observed.public_execute != policy.public_execute
            || observed.app_execute != policy.app_execute
            || observed.maintenance_execute != policy.maintenance_execute
            || observed.recovery_execute != policy.recovery_execute
        {
            drift.push(format!("{} ({:?})", spec.signature, spec.id));
        }
    }

    if missing.is_empty() && extra.is_empty() && drift.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "outbox routine catalog drift: missing={missing:?}, extra={extra:?}, policy={drift:?}"
        ))
    }
}

fn conforming_outbox_routine(spec: &OutboxRoutineSpec) -> OutboxRoutineObservation {
    let policy = spec.role.policy();
    let (owner, owner_can_login) = match policy.owner {
        OutboxRoutineOwnerPolicy::NotServingRole => ("migration_owner", true),
        OutboxRoutineOwnerPolicy::MaintenanceNoLogin => ("rss_outbox_maintenance", false),
    };
    OutboxRoutineObservation {
        signature: spec.signature.to_string(),
        owner: owner.to_string(),
        owner_can_login,
        security_definer: policy.security_definer,
        fixed_search_path: policy.fixed_search_path,
        public_execute: policy.public_execute,
        app_execute: policy.app_execute,
        maintenance_execute: policy.maintenance_execute,
        recovery_execute: policy.recovery_execute,
    }
}

#[test]
fn outbox_routine_catalog_rejects_missing_extra_equal_replacement_and_policy_drift() {
    let baseline = OUTBOX_ROUTINES
        .iter()
        .map(conforming_outbox_routine)
        .collect::<Vec<_>>();
    assert!(validate_outbox_routine_catalog(&baseline).is_ok());

    let mut missing = baseline.clone();
    missing.pop();
    assert!(validate_outbox_routine_catalog(&missing).is_err());

    let mut extra = baseline.clone();
    let mut unexpected = extra[0].clone();
    unexpected.signature = "rss_outbox_unexpected(text)".to_string();
    extra.push(unexpected);
    assert!(validate_outbox_routine_catalog(&extra).is_err());

    let mut equal_replacement = baseline.clone();
    equal_replacement[0].signature = "rss_outbox_replaced(text)".to_string();
    assert!(validate_outbox_routine_catalog(&equal_replacement).is_err());

    let mut owner_drift = baseline.clone();
    let mut owner_mutated = false;
    for observed in &mut owner_drift {
        if observed.owner == "rss_outbox_maintenance" {
            observed.owner = "rss_app".to_string();
            owner_mutated = true;
            break;
        }
    }
    assert!(owner_mutated);
    assert!(validate_outbox_routine_catalog(&owner_drift).is_err());

    let operator_signatures = OUTBOX_ROUTINES
        .iter()
        .filter(|spec| spec.role == OutboxRoutineRole::OperatorAuthority)
        .map(|spec| spec.signature)
        .collect::<BTreeSet<_>>();
    let mut mechanism_drift = baseline.clone();
    let mut mechanism_mutated = false;
    for observed in &mut mechanism_drift {
        if operator_signatures.contains(observed.signature.as_str()) {
            observed.app_execute = true;
            mechanism_mutated = true;
            break;
        }
    }
    assert!(mechanism_mutated);
    assert!(validate_outbox_routine_catalog(&mechanism_drift).is_err());

    let mut acl_drift = baseline;
    acl_drift[0].maintenance_execute = !acl_drift[0].maintenance_execute;
    assert!(validate_outbox_routine_catalog(&acl_drift).is_err());
}

/// A successful settings ConsumerTx attempt must commit the claimed receipt to `done`; the next
/// provider claim is then the durable duplicate decision owned by Postgres.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: fixed integration metadata is valid and unique_event_id always yields a non-empty key.
async fn settings_consumer_tx_commit_marks_done_and_next_claim_is_duplicate() -> TestResult {
    let (fixture, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = std::sync::Arc::new(connect_pg_rss_app_role(&fixture, &owner).await?);
    let inbox = app.inbox();
    let group = format!("settings-reconcile-success-{}", uuid::Uuid::new_v4());
    let ctx = InboxReceiptContext::new(
        test_tenant(),
        ConsumerGroup::parse(&group).unwrap(),
        "settings",
        CONFIG_VERSION_CHANGED_TOPIC,
        CONFIG_VERSION_CHANGED_TOPIC,
        "v1",
        TEST_SCHEMA_HASH,
        None,
        None,
    )
    .unwrap();
    let event_id = unique_event_id("settings-reconcile-success");
    let key = IdemKey::parse(&event_id).unwrap();
    let lease = LeaseToken::mint();
    assert_eq!(inbox.try_claim(&ctx, &key, &lease).await?, SeenState::Fresh);

    let stores = crate::pool::PgRuntimeStores::from_unverified_for_test(
        std::sync::Arc::clone(&app),
        std::sync::Arc::clone(&app),
    );
    let handler = crate::consumer_tx::PgSettingsConsumerTx::config_version_changed(
        stores.writer_capability(),
        std::sync::Arc::new(settings::ConfigVersionReconciler::test_ack()),
    );
    let outcome = std::sync::Arc::new(handler)
        .handle(
            diport::Message::new(&event_id, b"{}".to_vec()),
            ctx.clone(),
            key.clone(),
            lease,
        )
        .await;
    assert!(matches!(outcome, crate::PgConsumerTxOutcome::Committed(_)));

    let receipt: (String, Option<String>) = sqlx::query_as(
        "SELECT status, committed_at::text FROM inbox_receipts \
         WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
    )
    .bind(ctx.tenant_id().to_string())
    .bind(&event_id)
    .bind(&group)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(receipt.0, "done");
    assert!(
        receipt.1.is_some(),
        "committed receipt records completion time"
    );
    assert_eq!(
        inbox.try_claim(&ctx, &key, &LeaseToken::mint()).await?,
        SeenState::Duplicate
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

// ── outbox_log CDC schema (#1630) ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn outbox_log_schema_catalog_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name, data_type, is_nullable \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'outbox_log' \
         ORDER BY ordinal_position",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        columns,
        vec![
            ("event_id".to_string(), "text".to_string(), "NO".to_string()),
            (
                "tenant_id".to_string(),
                "uuid".to_string(),
                "NO".to_string()
            ),
            (
                "aggregate_type".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "aggregate_id".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("topic".to_string(), "text".to_string(), "NO".to_string()),
            (
                "contract_id".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "contract_version".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            (
                "schema_hash".to_string(),
                "text".to_string(),
                "NO".to_string()
            ),
            ("payload".to_string(), "bytea".to_string(), "NO".to_string()),
            (
                "metadata".to_string(),
                "jsonb".to_string(),
                "NO".to_string()
            ),
            (
                "causation_id".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            (
                "created_at".to_string(),
                "timestamp with time zone".to_string(),
                "NO".to_string()
            ),
            (
                "occurred_at".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            ("trace".to_string(), "text".to_string(), "YES".to_string()),
            (
                "correlation_id".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            (
                "partition_key".to_string(),
                "text".to_string(),
                "YES".to_string()
            ),
            (
                "fact_fingerprint".to_string(),
                "bytea".to_string(),
                "NO".to_string()
            ),
        ],
        "outbox_log columns must match the CDC append-only contract"
    );

    let generated_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT attname, attgenerated::text \
         FROM pg_attribute \
         WHERE attrelid = 'outbox_log'::regclass \
           AND attname IN ('occurred_at', 'trace', 'correlation_id', 'fact_fingerprint') \
         ORDER BY attname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        generated_columns,
        vec![
            ("correlation_id".to_string(), "s".to_string()),
            ("fact_fingerprint".to_string(), "s".to_string()),
            ("occurred_at".to_string(), "s".to_string()),
            ("trace".to_string(), "s".to_string()),
        ],
        "CDC header projection columns must be stored generated columns"
    );

    let constraint_text: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname, pg_get_constraintdef(oid) \
         FROM pg_constraint \
         WHERE conrelid = 'outbox_log'::regclass \
         ORDER BY conname",
    )
    .fetch_all(&store.pool)
    .await?;
    let constraint_text = constraint_text
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    for name in [
        "outbox_log_event_id_unique",
        "outbox_log_event_id_nonempty",
        "outbox_log_aggregate_type_nonempty",
        "outbox_log_aggregate_id_nonempty",
        "outbox_log_contract_version_valid",
        "outbox_log_schema_hash_valid",
        "outbox_log_metadata_object",
        "outbox_log_metadata_tenant_matches_column",
        "outbox_log_metadata_schema_matches_columns",
        "outbox_log_metadata_occurred_at_present",
        "outbox_log_trace_valid",
        "outbox_log_correlation_id_valid",
        "outbox_log_causation_id_valid",
    ] {
        assert!(
            constraint_text.contains(name),
            "missing outbox_log constraint `{name}` in:\n{constraint_text}"
        );
    }

    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT indexname, indexdef \
         FROM pg_indexes \
         WHERE schemaname = 'public' AND tablename = 'outbox_log' \
         ORDER BY indexname",
    )
    .fetch_all(&store.pool)
    .await?;
    let indexes = indexes
        .iter()
        .map(|(name, def)| format!("{name}: {def}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        indexes.contains("idx_outbox_log_contract_schema"),
        "outbox_log contract/schema lookup index missing in:\n{indexes}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_log_rejects_missing_or_mismatched_schema_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let good_metadata = serde_json::json!({
        "tenantId": tenant.to_string(),
        "schemaVersion": "v1",
        "schemaHash": TEST_SCHEMA_HASH,
        "occurredAt": 0,
    });
    insert_outbox_log_with_metadata(
        &store,
        &unique_event_id("outbox-log-good-schema"),
        tenant,
        good_metadata,
    )
    .await?;

    for (label, metadata) in [
        (
            "missing schemaVersion",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaHash": TEST_SCHEMA_HASH,
                "occurredAt": 0,
            }),
        ),
        (
            "missing schemaHash",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "occurredAt": 0,
            }),
        ),
        (
            "wrong schemaHash",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "schemaHash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "occurredAt": 0,
            }),
        ),
        (
            "non-string schemaVersion",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": 1,
                "schemaHash": TEST_SCHEMA_HASH,
                "occurredAt": 0,
            }),
        ),
    ] {
        let err = match insert_outbox_log_with_metadata(
            &store,
            &unique_event_id("outbox-log-bad-schema"),
            tenant,
            metadata,
        )
        .await
        {
            Err(err) => err,
            Ok(()) => {
                return Err(std::io::Error::other(format!(
                    "{label} unexpectedly satisfied schema metadata CHECK"
                ))
                .into());
            }
        };
        assert!(
            err.as_database_error().is_some_and(|db| db
                .message()
                .contains("outbox_log_metadata_schema_matches_columns")),
            "{label} should fail the schema metadata CHECK, got: {err:?}"
        );
    }

    for (label, metadata) in [
        (
            "missing occurredAt",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "schemaHash": TEST_SCHEMA_HASH,
            }),
        ),
        (
            "string occurredAt",
            serde_json::json!({
                "tenantId": tenant.to_string(),
                "schemaVersion": "v1",
                "schemaHash": TEST_SCHEMA_HASH,
                "occurredAt": "0",
            }),
        ),
    ] {
        let err = match insert_outbox_log_with_metadata(
            &store,
            &unique_event_id("outbox-log-bad-occurred-at"),
            tenant,
            metadata,
        )
        .await
        {
            Err(err) => err,
            Ok(()) => {
                return Err(std::io::Error::other(format!(
                    "{label} unexpectedly satisfied occurredAt metadata CHECK"
                ))
                .into());
            }
        };
        assert!(
            err.as_database_error().is_some_and(|db| db
                .message()
                .contains("outbox_log_metadata_occurred_at_present")),
            "{label} should fail the occurredAt metadata CHECK, got: {err:?}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_log_append_only_grants_and_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let (rls_enabled, rls_forced, can_select, can_insert, can_update, can_delete): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT c.relrowsecurity, c.relforcerowsecurity, \
                has_table_privilege('rss_app', 'outbox_log', 'SELECT'), \
                has_table_privilege('rss_app', 'outbox_log', 'INSERT'), \
                has_table_privilege('rss_app', 'outbox_log', 'UPDATE'), \
                has_table_privilege('rss_app', 'outbox_log', 'DELETE') \
         FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = 'outbox_log'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(rls_enabled, "outbox_log must ENABLE RLS");
    assert!(rls_forced, "outbox_log must FORCE RLS");
    assert!(can_select, "rss_app must SELECT outbox_log");
    assert!(can_insert, "rss_app must INSERT outbox_log");
    assert!(
        !can_update,
        "rss_app must not UPDATE append-only outbox_log"
    );
    assert!(
        !can_delete,
        "rss_app must not DELETE append-only outbox_log"
    );

    let (qual, with_check): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT qual, with_check \
         FROM pg_policies \
         WHERE schemaname = 'public' \
           AND tablename = 'outbox_log' \
           AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&store.pool)
    .await?;
    for body in [qual.as_deref(), with_check.as_deref()] {
        let body = body.ok_or_else(|| {
            std::io::Error::other("outbox_log tenant policy must define USING and WITH CHECK")
        })?;
        assert!(
            body.to_lowercase().contains("nullif(current_setting"),
            "tenant policy must use NULLIF(current_setting(...)): {body}"
        );
        assert!(
            body.contains("rss.tenant_id"),
            "tenant policy must reference rss.tenant_id: {body}"
        );
    }

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let event_id = unique_event_id("outbox-log-rls");
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO outbox_log \
             (event_id, tenant_id, aggregate_type, aggregate_id, topic, contract_id, \
              contract_version, schema_hash, payload, metadata, causation_id) \
             VALUES \
             ($1, $2::uuid, 'identity', $1, 'identity.session-created', \
              'identity.session-created', 'v1', $3, decode('70', 'hex'), \
              jsonb_build_object('tenantId', $2, 'schemaVersion', 'v1', 'schemaHash', $3, \
                                 'occurredAt', 0), NULL)",
        )
        .bind(&event_id)
        .bind(&tenant_a)
        .bind(TEST_SCHEMA_HASH)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let update =
            sqlx::query("UPDATE outbox_log SET aggregate_id = 'mutated' WHERE event_id = $1")
                .bind(&event_id)
                .execute(&mut *tx)
                .await;
        assert!(
            update.is_err(),
            "rss_app must not update append-only outbox_log"
        );
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let delete = sqlx::query("DELETE FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .execute(&mut *tx)
            .await;
        assert!(
            delete.is_err(),
            "rss_app must not delete append-only outbox_log"
        );
        tx.rollback().await?;
    }

    for (tenant, expected, label) in [(&tenant_a, 1_i64, "tenant A"), (&tenant_b, 0, "tenant B")] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(cnt.0, expected, "{label} outbox_log visibility mismatch");
        tx.rollback().await?;
    }

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "missing rss.tenant_id must fail closed for outbox_log"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

#[cfg(feature = "fault-matrix-test-support")]
#[tokio::test(flavor = "multi_thread")]
async fn fault_matrix_exact_claim_does_not_mutate_other_eligible_rows() -> TestResult {
    type DurableClaimState = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    );

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("fault_matrix_exact_claim");
    let other_id = unique_event_id("fault-matrix-other");
    let target_id = unique_event_id("fault-matrix-target");
    for event_id in [&other_id, &target_id] {
        let entry = make_entry(event_id);
        let domain = domain.clone();
        eventing_test_db(&store)
            .test_write(
                integration_tenant_scope(test_tenant()),
                |cap| {
                    Box::pin(async move {
                        let _outcome =
                            append_outbox(cap, &entry, &make_test_env(&domain, "contract-1"))
                                .await
                                .map_err(test_append_error)?;
                        Ok(())
                    }) as BoxFuture<'_, Result<(), sqlx::Error>>
                },
                std::convert::identity,
            )
            .await?;
    }

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let other_before: DurableClaimState = sqlx::query_as(
        "SELECT status, lease_token::text, lease_until::text, \
                automatic_retry_deadline::text, published_at::text, dlx_at::text, \
                updated_at::text \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&other_id)
    .fetch_one(&store.pool)
    .await?;
    let claimed = outbox
        .fault_matrix_claim_exact(&store.pool, &target_id)
        .await?
        .ok_or("target row was not claimed")?;
    assert_eq!(claimed.idem_key().as_str(), target_id);

    let other_after: DurableClaimState = sqlx::query_as(
        "SELECT status, lease_token::text, lease_until::text, \
                automatic_retry_deadline::text, published_at::text, dlx_at::text, \
                updated_at::text \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&other_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        other_after, other_before,
        "exact target claim must leave every durable state/lease column of another eligible row unchanged"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_outbox_append_serializes_same_fact_and_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let same_id = unique_event_id("outbox-concurrent-same");
    let same_entry_a = projection_conformance_entry(&same_id)?;
    let same_entry_b = same_entry_a.clone();
    let same_env_a = projection_conformance_env();
    let same_env_b = same_env_a.clone();
    let projection_registry_a = crate::projection_events::ProjectionWriteRegistry::from_selected(
        PROJECTION_CONFORMANCE_INPUTS,
    );
    let projection_registry_b = projection_registry_a.clone();
    let same_db_a = eventing_test_db(&store);
    let same_db_b = eventing_test_db(&store);
    let same_a = same_db_a.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| {
            Box::pin(async move {
                append_outbox_with_projection(
                    cap,
                    &same_entry_a,
                    &same_env_a,
                    &projection_registry_a,
                )
                .await
            })
        },
        OutboxAppendError::from,
    );
    let same_b = same_db_b.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| {
            Box::pin(async move {
                append_outbox_with_projection(
                    cap,
                    &same_entry_b,
                    &same_env_b,
                    &projection_registry_b,
                )
                .await
            })
        },
        OutboxAppendError::from,
    );
    let (same_a, same_b) = tokio::join!(same_a, same_b);
    let same_outcomes = [same_a?, same_b?];
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::Inserted)
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM projection_events WHERE event_id = $1",)
            .bind(&same_id)
            .fetch_one(&store.pool)
            .await?,
        1,
        "concurrent same-fact retries must mirror exactly one projection row"
    );
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::SameFact)
            .count(),
        1
    );

    let conflict_id = unique_event_id("outbox-concurrent-conflict");
    let conflict_entry_a = make_entry(&conflict_id);
    let conflict_entry_b = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(b"different-payload".to_vec()),
    );
    let conflict_env_a = make_test_env("identity", "identity.session-created");
    let conflict_env_b = conflict_env_a.clone();
    let conflict_db_a = eventing_test_db(&store);
    let conflict_db_b = eventing_test_db(&store);
    let conflict_a = conflict_db_a.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| Box::pin(async move { append_outbox(cap, &conflict_entry_a, &conflict_env_a).await }),
        OutboxAppendError::from,
    );
    let conflict_b = conflict_db_b.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| Box::pin(async move { append_outbox(cap, &conflict_entry_b, &conflict_env_b).await }),
        OutboxAppendError::from,
    );
    let (conflict_a, conflict_b) = tokio::join!(conflict_a, conflict_b);
    let inserted = usize::from(matches!(
        conflict_a.as_ref(),
        Ok(OutboxAppendOutcome::Inserted)
    )) + usize::from(matches!(
        conflict_b.as_ref(),
        Ok(OutboxAppendOutcome::Inserted)
    ));
    let conflicts = usize::from(matches!(
        conflict_a.as_ref(),
        Err(OutboxAppendError::Conflict(_))
    )) + usize::from(matches!(
        conflict_b.as_ref(),
        Err(OutboxAppendError::Conflict(_))
    ));
    assert_eq!(inserted, 1);
    assert_eq!(conflicts, 1);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_cdc_append_serializes_same_fact_and_typed_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let same_id = unique_event_id("cdc-concurrent-same");
    let same_entry_a = make_entry(&same_id);
    let same_entry_b = same_entry_a.clone();
    let same_env_a = make_test_env("identity", "identity.session-created");
    let same_env_b = same_env_a.clone();
    let same_db_a = eventing_test_db(&store);
    let same_db_b = eventing_test_db(&store);
    let same_a = same_db_a.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| {
            Box::pin(async move {
                append_outbox_log(cap, &same_entry_a, &same_env_a, "aggregate-same").await
            })
        },
        OutboxAppendError::from,
    );
    let same_b = same_db_b.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| {
            Box::pin(async move {
                append_outbox_log(cap, &same_entry_b, &same_env_b, "aggregate-same").await
            })
        },
        OutboxAppendError::from,
    );
    let (same_a, same_b) = tokio::join!(same_a, same_b);
    let same_outcomes = [same_a?, same_b?];
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::Inserted)
            .count(),
        1
    );
    assert_eq!(
        same_outcomes
            .iter()
            .filter(|outcome| **outcome == OutboxAppendOutcome::SameFact)
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox_log WHERE event_id = $1")
            .bind(&same_id)
            .fetch_one(&store.pool)
            .await?,
        1
    );

    let conflict_id = unique_event_id("cdc-concurrent-conflict");
    let first_payload = b"cdc-first".to_vec();
    let second_payload = b"cdc-second".to_vec();
    let conflict_entry_a = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(first_payload.clone()),
    );
    let conflict_entry_b = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(second_payload.clone()),
    );
    let conflict_env_a = make_test_env("identity", "identity.session-created");
    let conflict_env_b = conflict_env_a.clone();
    let conflict_db_a = eventing_test_db(&store);
    let conflict_db_b = eventing_test_db(&store);
    let conflict_a = conflict_db_a.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| {
            Box::pin(async move {
                append_outbox_log(
                    cap,
                    &conflict_entry_a,
                    &conflict_env_a,
                    "aggregate-conflict",
                )
                .await
            })
        },
        OutboxAppendError::from,
    );
    let conflict_b = conflict_db_b.test_write(
        integration_tenant_scope(test_tenant()),
        |cap| {
            Box::pin(async move {
                append_outbox_log(
                    cap,
                    &conflict_entry_b,
                    &conflict_env_b,
                    "aggregate-conflict",
                )
                .await
            })
        },
        OutboxAppendError::from,
    );
    let (conflict_a, conflict_b) = tokio::join!(conflict_a, conflict_b);
    assert_eq!(
        usize::from(matches!(
            conflict_a.as_ref(),
            Ok(OutboxAppendOutcome::Inserted)
        )) + usize::from(matches!(
            conflict_b.as_ref(),
            Ok(OutboxAppendOutcome::Inserted)
        )),
        1
    );
    assert_eq!(
        usize::from(matches!(
            conflict_a.as_ref(),
            Err(OutboxAppendError::Conflict(_))
        )) + usize::from(matches!(
            conflict_b.as_ref(),
            Err(OutboxAppendError::Conflict(_))
        )),
        1
    );

    let original: (i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT count(*) OVER (), payload, fact_fingerprint FROM outbox_log WHERE event_id = $1",
    )
    .bind(&conflict_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(original.0, 1);
    assert!(original.1 == first_payload || original.1 == second_payload);
    let retry_payload = if original.1 == first_payload {
        second_payload
    } else {
        first_payload
    };
    let retry_entry = EventEntry::new(
        EventTopic::parse("test.event")?,
        IdemKey::parse(&conflict_id)?,
        OutboxPayload::from_reviewed_event_bytes(retry_payload),
    );
    let retry_env = make_test_env("identity", "identity.session-created");
    let retry = eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(test_tenant()),
            move |cap| {
                Box::pin(async move {
                    append_outbox_log(cap, &retry_entry, &retry_env, "aggregate-conflict").await
                })
            },
            OutboxAppendError::from,
        )
        .await;
    assert!(matches!(retry, Err(OutboxAppendError::Conflict(_))));
    let after: (i64, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT count(*) OVER (), payload, fact_fingerprint FROM outbox_log WHERE event_id = $1",
    )
    .bind(&conflict_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after, original,
        "typed conflicts must preserve the original CDC fact"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_fact_sql_matches_rust_known_vectors() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let fixture: OutboxFactGoldenFixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/consistency/outbox-fact-v1-vectors.json"
    )))?;
    assert_eq!(fixture.schema_version, 1);
    assert!(!fixture.cases.is_empty());
    for case in fixture.cases {
        let actual = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT rss_outbox_fact_fingerprint($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
        )
        .bind(&case.event_id)
        .bind(&case.tenant_id)
        .bind(&case.domain)
        .bind(&case.topic)
        .bind(&case.contract_id)
        .bind(&case.contract_version)
        .bind(&case.schema_hash)
        .bind(case.payload.as_slice())
        .bind(case.partition_key.as_deref())
        .bind(case.causation_id.as_deref())
        .bind(case.metadata.to_string())
        .fetch_one(&store.pool)
        .await?;
        let rust = OutboxFactIdentity::new(
            &case.event_id,
            &case.tenant_id,
            &case.domain,
            &case.topic,
            &case.contract_id,
            &case.contract_version,
            &case.schema_hash,
            &case.payload,
            case.partition_key.as_deref(),
            case.causation_id.as_deref(),
            &case.metadata,
        )
        .fingerprint();
        assert_eq!(
            actual.as_slice(),
            rust.as_bytes(),
            "Rust/SQL parity: {}",
            case.label
        );
        assert_eq!(
            actual.as_slice(),
            case.expected_digest,
            "fixed digest: {}",
            case.label
        );
    }
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn outbox_relay_and_cdc_envelope_parity_conformance() -> TestResult {
    use consistency::PartitionKey;
    use diport::EnvelopeCausationId;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("relay-cdc-parity");
    let tenant = test_tenant();
    let subject = "parity-subject-opaque";
    let entry = EventEntry::new(
        EventTopic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        reviewed_payload(br#"{"sessionId":"parity"}"#),
    );
    let env = OutboxEnvelope::new(
        "identity".to_string(),
        SESSION_CREATED_TOPIC.to_string(),
        OutboxMetadata::new(expected_occurred_at(), tenant, session_contract())
            .with_subject_id(subject_id(subject))
            .with_actor(actor_for(tenant)),
    )
    .with_partition_key_opt(Some(PartitionKey::parse("tenant-7:session-9").unwrap()))
    .with_causation_id_opt(Some(
        EnvelopeCausationId::from_opaque("cause-parity-1645").unwrap(),
    ));

    let relay_entry = entry.clone();
    let relay_env = env.clone();
    eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(tenant),
            move |cap| {
                let entry = relay_entry.clone();
                let env = relay_env.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            },
            std::convert::identity,
        )
        .await?;

    eventing_test_db(&store)
        .test_write(
            integration_tenant_scope(tenant),
            move |tx| {
                Box::pin(async move {
                    let _outcome = append_outbox_log(tx, &entry, &env, subject).await?;
                    Ok(())
                })
            },
            OutboxAppendError::from,
        )
        .await?;

    let (relay_fingerprint, cdc_fingerprint): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT o.fact_fingerprint, l.fact_fingerprint \
         FROM outbox o JOIN outbox_log l USING (event_id) WHERE o.event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        relay_fingerprint, cdc_fingerprint,
        "mutable and CDC modes must share one canonical fingerprint"
    );

    let (publisher, captured_requests) = CapturedPublishRequestPublisher::new();
    let outbox = make_pg_outbox_with_publisher(&store, publisher);
    let pending = claim_entry_for_relay(&outbox, &event_id)
        .await
        .map_err(std::io::Error::other)?;
    let disposition = outbox.relay(pending).await?;
    assert_eq!(disposition, Disposition::Ack);

    let relay_request = {
        let mut requests = captured_requests.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            requests.len(),
            1,
            "relay should publish the logical fact exactly once"
        );
        requests
            .pop()
            .ok_or_else(|| std::io::Error::other("missing captured relay publish request"))?
    };
    let relay_envelope = relay_common_envelope(&relay_request);

    let cdc_row = modeled_debezium_eventrouter_outbox_log(&store, &event_id).await?;
    assert_eq!(cdc_row.aggregate_id, subject, "CDC aggregate_id");
    assert_ne!(
        cdc_row.aggregate_id, "tenant-7:session-9",
        "CDC aggregate_id must not be the relay partition key"
    );
    assert_eq!(cdc_row.contract_id, SESSION_CREATED_TOPIC);
    assert_eq!(
        cdc_row
            .metadata
            .get(KEY_SUBJECT_ID)
            .and_then(serde_json::Value::as_str),
        Some(subject),
        "subjectId stays persisted in metadata"
    );
    assert!(
        cdc_row.metadata.get(KEY_ACTOR).is_some(),
        "actor stays persisted in metadata"
    );
    assert!(cdc_row.metadata.get(KEY_TRACE).is_none());
    assert!(cdc_row.metadata.get(KEY_CORRELATION).is_none());
    assert_eq!(
        cdc_row
            .metadata
            .get(KEY_OCCURRED_AT)
            .and_then(serde_json::Value::as_i64),
        Some(expected_occurred_at())
    );

    let cdc_envelope = cdc_row.common_envelope();
    assert_eq!(
        relay_envelope, cdc_envelope,
        "relay PublishRequest and modeled Debezium EventRouter output must share the common broker envelope"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T1: INVARIANT OUTBOX-ATOMIC-IDEM-01：回滚→无 entry ──────────────────────

/// INVARIANT: OUTBOX-ATOMIC-IDEM-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
/// L1 原子性：append_outbox 在事务内，业务返回 Err → 回滚 → outbox 无该行。
#[tokio::test(flavor = "multi_thread")]
async fn t1_rollback_leaves_no_outbox_entry() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t1");
    let entry = make_entry(&event_id);
    let env = make_envelope("t1-domain", &event_id);
    let event_id_for_write = event_id.clone();

    // 事务内 append_outbox，然后返回 Err → 回滚。
    let result = store
        .serving_write_fixture::<_, (), sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract())
                    .with_subject_id(subject_id(event_id_for_write.as_str())),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                // 强制回滚。
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(result.is_err(), "should have rolled back");

    // 验证 outbox 无该行。
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        count.0, 0,
        "rollback must leave no outbox entry (OUTBOX-ATOMIC-IDEM-01)"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T2: 提交→恰 1 行 pending（T1 anti-vacuity 配对）─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t2_commit_creates_exactly_one_pending_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t2");
    let entry = make_entry(&event_id);
    let env = make_envelope("t2-domain", &event_id);
    let event_id_for_write = event_id.clone();

    // 事务内 append_outbox + Ok → commit。
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract())
                    .with_subject_id(subject_id(event_id_for_write.as_str())),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 验证恰 1 行，status=pending，字段正确。
    let row: (i64, String, String, String) = sqlx::query_as(
        "SELECT count(*), status, domain, topic FROM outbox WHERE event_id = $1 GROUP BY status, domain, topic",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;

    assert_eq!(row.0, 1, "should have exactly 1 row");
    assert_eq!(row.1, "pending", "status should be pending");
    assert_eq!(row.2, "t2-domain", "domain should match");
    assert_eq!(row.3, "test.event", "topic should match");

    store.shutdown().await?;
    Ok(())
}

// ── T4 residual: requeue clears lease + future retry_after blocks reclaim ────
// Disposition/status/retry_count/retry_after-set owned by
// `assert_outbox_transient_retry` via `eventing_conformance_outbox_enrolls_postgres`.

/// PostgreSQL residual: after transient requeue, lease is cleared and claim_batch
/// cannot reclaim while `retry_after > now()` (backoff window).
#[tokio::test(flavor = "multi_thread")]
async fn t4_requeue_clears_lease_and_defers_reclaim() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t4");
    let entry = make_entry(&event_id);

    // setup: seed pending, claim, then transient relay (disposition owned by canonical).
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "t4_domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant(), test_contract()),
            );
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, _) = RecordingPublisher::always_transient();
    let outbox = make_pg_outbox_for_domain(&store, "t4_domain", pub_);

    let pending = claim_entry_for_relay(&outbox, &event_id).await?;
    let _disposition = outbox.relay(pending).await?;

    let lease_cleared: (bool,) =
        sqlx::query_as("SELECT lease_token IS NULL FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(
        lease_cleared.0,
        "lease_token should be cleared after requeue"
    );

    let future_check: (bool,) =
        sqlx::query_as("SELECT retry_after > now() FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(future_check.0, "retry_after should be in the future");

    let re = outbox.claim_batch(10).await?;
    assert!(
        !re.iter().any(|e| e.idem_key().as_str() == event_id),
        "requeued entry must not be reclaimed within backoff window"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T6 residual: cross-domain stale recovery join (claim→relay→published) ──
// Basic stale reclaim presence/sample owned by `assert_outbox_stale_and_sample`;
// this carrier keeps the PG residual join: domain isolation + recovery + no reclaim.

#[tokio::test(flavor = "multi_thread")]
async fn t6_crash_recovery_stale_lease_redelivered() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t6");
    let entry = make_entry(&event_id);

    // seed: 1 行，手动置为 status='publishing' 且 lease_until 已过期（模拟崩溃残留）。
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = make_test_env("crash_domain", "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 模拟崩溃：把行置 publishing + updated_at 很久之前。
    let lease_ttl = test_relay_lease_ttl_seconds();
    sqlx::query(
        "UPDATE outbox SET status='publishing', lease_token=gen_random_uuid(), \
         automatic_retry_deadline=COALESCE(automatic_retry_deadline, now()+interval '24 hours'), \
         updated_at=now()-make_interval(secs => $1), lease_until=now()-interval '10 seconds' \
         WHERE event_id = $2",
    )
    .bind(lease_ttl + 10)
    .bind(&event_id)
    .execute(&store.pool)
    .await?;

    // 跨域隔离负向：另插一条 other-domain 的 stale publishing 行；claim("crash-domain") 不应返回它
    //（令下方 entries.len()==1 断言具 anti-vacuity 意义）。
    let other_id = unique_event_id("t6-other");
    let other_entry = make_entry(&other_id);
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = other_entry.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &make_test_env("other_domain", "c"))
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET status='publishing', lease_token=gen_random_uuid(), \
         automatic_retry_deadline=COALESCE(automatic_retry_deadline, now()+interval '24 hours'), \
         updated_at=now()-make_interval(secs => $1), lease_until=now()-interval '10 seconds' \
         WHERE event_id = $2",
    )
    .bind(lease_ttl + 10)
    .bind(&other_id)
    .execute(&store.pool)
    .await?;

    // claim_batch 能原子重捞 stale publishing 行。
    let (pub_, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain(&store, "crash_domain", pub_);

    let mut entries = outbox.claim_batch(10).await?;
    assert_eq!(
        entries.len(),
        1,
        "stale publishing row should be returned by claim_batch"
    );
    assert_eq!(entries[0].idem_key().as_str(), event_id);

    // relay → published。
    let disposition = outbox.relay(entries.remove(0)).await?;
    assert_eq!(disposition, Disposition::Ack);

    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    // 已 published 行无法再次 claim，publisher 不再被调用（calls = 1）。
    let outbox2 = make_pg_outbox_for_domain(
        &store,
        "crash_domain",
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    assert!(outbox2.claim_batch(10).await?.is_empty());

    #[allow(clippy::unwrap_used)]
    let call_count = *calls.lock().unwrap();
    assert_eq!(
        call_count, 1,
        "publisher should only be called once (at-least-once idempotent)"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T7: 并发 CAS fencing（两连接各 relay → 至多 publish 一次）────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t7_concurrent_relay_publishes_at_most_once() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t7");
    let entry = make_entry(&event_id);

    // seed 1 行 pending。
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = make_test_env("t7_domain", "c");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 两个独立 PgOutbox 各自 relay 同一行——共享 calls 计数器。
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);

    let pub1 = RecordingPublisher {
        result: || Ok(()),
        calls: Arc::clone(&calls),
    };
    let pub2 = RecordingPublisher {
        result: || Ok(()),
        calls: calls_clone,
    };

    let outbox1 = make_pg_outbox_for_domain(&store, "t7_domain", pub1);
    let outbox2 = make_pg_outbox_for_domain(&store, "t7_domain", pub2);

    // 两个独立连接并发 claim：原子 SQL 保证同一 row 只会出现在一个结果集。
    let (claims1, claims2) = tokio::join!(outbox1.claim_batch(10), outbox2.claim_batch(10));
    let mut claims1 = claims1?;
    let mut claims2 = claims2?;
    assert_eq!(claims1.len() + claims2.len(), 1);
    let disposition = if let Some(claimed) = claims1.pop() {
        outbox1.relay(claimed).await?
    } else {
        outbox2
            .relay(claims2.pop().ok_or("missing concurrent claim winner")?)
            .await?
    };
    assert_eq!(disposition, Disposition::Ack);

    // publisher 至多调用一次。
    #[allow(clippy::unwrap_used)]
    let total_calls = *calls.lock().unwrap();
    assert_eq!(
        total_calls, 1,
        "publisher should be called at most once across concurrent relays"
    );

    // 行终态 published。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t7b_atomic_claim_uses_independent_database_connections() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t7b_domain");
    let event_id = unique_event_id("t7b");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "concurrent.claim");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let mut first = store.pool.acquire().await?;
    let mut second = store.pool.acquire().await?;
    let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *first)
        .await?;
    let second_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *second)
        .await?;
    assert_ne!(
        first_pid, second_pid,
        "test must exercise independent sessions"
    );

    let first_domain = domain.clone();
    let second_domain = domain.clone();
    let relay_budget = test_relay_budget();
    let (first_claim, second_claim) = tokio::join!(
        async {
            sqlx::query_scalar::<_, String>(
                "SELECT event_id FROM rss_outbox_claim_batch($1, 10, $2, $3)",
            )
            .bind(first_domain)
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_all(&mut *first)
            .await
        },
        async {
            sqlx::query_scalar::<_, String>(
                "SELECT event_id FROM rss_outbox_claim_batch($1, 10, $2, $3)",
            )
            .bind(second_domain)
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_all(&mut *second)
            .await
        }
    );
    let claimed: Vec<String> = first_claim?.into_iter().chain(second_claim?).collect();
    assert_eq!(claimed, vec![event_id.clone()]);

    let durable: (String, bool, bool) = sqlx::query_as(
        "SELECT status, lease_token IS NOT NULL, lease_until IS NOT NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        durable,
        (crate::outbox::STATUS_PUBLISHING.to_string(), true, true),
        "exactly one independent session must durably own the claim"
    );

    drop(first);
    drop(second);
    store.shutdown().await?;
    Ok(())
}

/// Provider 边界必须在任何数据库 I/O 前拒绝非法 batch limit，并分类为永久 invariant。
#[tokio::test(flavor = "multi_thread")]
async fn claim_batch_rejects_invalid_provider_limits_before_database_io() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    let outbox = make_pg_outbox_for_domain(
        &store,
        "identity",
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    store.shutdown().await?;

    for limit in [0, 10_001] {
        let Err(error) = outbox.claim_batch(limit).await else {
            return Err(format!("provider must reject invalid claim limit {limit}").into());
        };
        assert_eq!(
            error.kind(),
            EngineErrorKind::Invariant,
            "invalid provider limit {limit} is permanent caller input, not transient database I/O"
        );
    }
    Ok(())
}

/// Claim provenance binds the exact provider instance, not only a matching textual domain.
#[tokio::test(flavor = "multi_thread")]
async fn relay_rejects_claim_from_another_provider_instance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("provider-provenance");
    let event_id = unique_event_id("provider-provenance");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "provider.provenance");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (claim_publisher, claim_calls) = RecordingPublisher::always_ok();
    let claim_provider = make_pg_outbox_for_domain(&store, &domain, claim_publisher);
    let claim = claim_entry_for_relay(&claim_provider, &event_id).await?;

    let (other_publisher, other_calls) = RecordingPublisher::always_ok();
    let other_provider = make_pg_outbox_for_domain(&store, &domain, other_publisher);
    let Err(error) = other_provider.relay(claim).await else {
        return Err("another provider instance must not relay the claim".into());
    };
    assert_eq!(error.kind(), EngineErrorKind::Invariant);
    #[allow(clippy::unwrap_used)]
    {
        assert_eq!(*claim_calls.lock().unwrap(), 0);
        assert_eq!(*other_calls.lock().unwrap(), 0);
    }

    let status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status, crate::outbox::STATUS_PUBLISHING);

    store.shutdown().await?;
    Ok(())
}

/// Publish preflight reserves the complete typed required budget inside the configured lease.
#[tokio::test(flavor = "multi_thread")]
async fn lease_publish_preflight_requires_full_publish_budget() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("publish-budget");
    let event_id = unique_event_id("publish-budget");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "publish.budget");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    let relay_budget = test_relay_budget();

    let short_deadline: i64 = sqlx::query_scalar(
        "UPDATE outbox SET lease_until = clock_timestamp() + interval '49 seconds' \
         WHERE event_id = $1 \
         RETURNING (EXTRACT(EPOCH FROM lease_until) * 1000000)::bigint",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    let short_budget: i16 =
        sqlx::query_scalar("SELECT rss_outbox_publish_preflight($1, $2::uuid, $3, $4, $5)")
            .bind(&event_id)
            .bind(claim.test_lease_token())
            .bind(short_deadline)
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_one(&store.pool)
            .await?;
    assert!(
        short_budget == 1,
        "49 seconds cannot fund a 40-second publish plus settle margin"
    );

    let full_deadline: i64 = sqlx::query_scalar(
        "UPDATE outbox SET lease_until = clock_timestamp() + interval '55 seconds' \
         WHERE event_id = $1 \
         RETURNING (EXTRACT(EPOCH FROM lease_until) * 1000000)::bigint",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    let full_budget: i16 =
        sqlx::query_scalar("SELECT rss_outbox_publish_preflight($1, $2::uuid, $3, $4, $5)")
            .bind(&event_id)
            .bind(claim.test_lease_token())
            .bind(full_deadline)
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_one(&store.pool)
            .await?;
    assert!(
        full_budget == 0,
        "55 seconds must satisfy the 50-second preflight budget"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_budget_sql_boundary_is_fail_closed_and_claim_uses_configured_ttl() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let invalid_budgets: &[(Option<i64>, Option<i64>)] = &[
        (None, Some(1_i64)),
        (Some(1), None),
        (Some(0), Some(1)),
        (Some(1), Some(0)),
        (Some(1), Some(1)),
        (Some(1), Some(2)),
        (Some(86_400_001), Some(1)),
        (Some(86_400_000), Some(86_400_001)),
        (Some(9_223_372_036_854_776), Some(1)),
    ];
    for &(lease_ms, required_ms) in invalid_budgets {
        let claim =
            sqlx::query("SELECT * FROM rss_outbox_claim_batch('invalid-budget', 1, $1, $2)")
                .bind(lease_ms)
                .bind(required_ms)
                .execute(&store.pool)
                .await;
        assert!(claim.is_err(), "claim accepted invalid relay budget");

        let preflight = sqlx::query(
            "SELECT rss_outbox_publish_preflight('missing', \
             '550e8400-e29b-41d4-a716-446655440000'::uuid, 1, $1, $2)",
        )
        .bind(lease_ms)
        .bind(required_ms)
        .execute(&store.pool)
        .await;
        assert!(
            preflight.is_err(),
            "preflight accepted invalid relay budget"
        );
    }

    let legacy_overloads: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (VALUES \
         ('rss_outbox_claim_batch(text,bigint)'), \
         ('rss_outbox_publish_preflight(text,uuid,bigint)')) AS old(signature) \
         WHERE to_regprocedure(signature) IS NOT NULL",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(legacy_overloads, 0);

    let maximum_domain = unique_domain("maximum-relay-budget");
    let maximum_event_id = unique_event_id("maximum-relay-budget");
    let maximum_entry = make_entry(&maximum_event_id);
    let maximum_env = make_test_env(&maximum_domain, "maximum.relay.budget");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _ = append_outbox(cap, &maximum_entry, &maximum_env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    let maximum_budget = RelayBudget::new(
        Duration::from_millis(86_400_000),
        Duration::from_millis(86_399_997),
        Duration::from_millis(1),
        Duration::from_millis(1),
    )?;
    set_test_relay_budget_policy(&store, maximum_budget).await?;
    let maximum_claim: (String, String, i64) = sqlx::query_as(
        "SELECT event_id, lease_token, deadline_epoch_micros \
         FROM rss_outbox_claim_batch($1, 1, $2, $3)",
    )
    .bind(&maximum_domain)
    .bind(maximum_budget.lease_ttl_millis())
    .bind(maximum_budget.required_budget_millis())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(maximum_claim.0, maximum_event_id);
    // The configured safety gap is exactly 2 ms. Cross it deliberately so the preflight result
    // proves the maximum-width interval arithmetic without depending on host scheduling latency.
    await_delay(Duration::from_millis(5)).await;
    let maximum_preflight: i16 =
        sqlx::query_scalar("SELECT rss_outbox_publish_preflight($1, $2::uuid, $3, $4, $5)")
            .bind(&maximum_claim.0)
            .bind(&maximum_claim.1)
            .bind(maximum_claim.2)
            .bind(maximum_budget.lease_ttl_millis())
            .bind(maximum_budget.required_budget_millis())
            .fetch_one(&store.pool)
            .await?;
    assert!(
        matches!(maximum_preflight, 0 | 1),
        "maximum representable required budget must complete without interval/timestamp overflow"
    );

    let budget = RelayBudget::new(
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_millis(500),
        Duration::from_millis(500),
    )?;
    set_test_relay_budget_policy(&store, budget).await?;
    let domain = unique_domain("configured-lease");
    let event_id = unique_event_id("configured-lease");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "configured.lease");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _ = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    let outbox = make_pg_outbox_for_domain_with_budget(
        &store,
        &domain,
        RecordingPublisher::always_ok().0,
        budget,
    );
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    let db_now_micros: i64 =
        sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&store.pool)
            .await?;
    let remaining_ms = (claim.test_lease_deadline_epoch_micros() - db_now_micros) / 1000;
    assert!(
        (1_500..=3_000).contains(&remaining_ms),
        "claim must use configured 3s lease, remaining_ms={remaining_ms}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_pool_starvation_expires_inside_safety_margin_without_publishing() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let app = connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(5)).await?;
    let budget = RelayBudget::new(
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_millis(500),
        Duration::from_millis(100),
    )?;
    set_test_relay_budget_policy(&owner, budget).await?;

    let domain = unique_domain("preflight-starvation");
    let event_id = unique_event_id("preflight-starvation");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "preflight.starvation");
    owner
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _ = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    let (publisher, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain_with_budget(&app, &domain, publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    let held = app.pool.acquire().await?;

    let result = tokio::time::timeout(Duration::from_secs(1), outbox.relay(claim)).await?;
    assert!(
        matches!(result, Err(error) if error.kind() == EngineErrorKind::Transient),
        "starved preflight must return transient"
    );
    #[allow(clippy::unwrap_used)]
    {
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    drop(held);
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}
// ── T8 residual: published_at retention anchor + cutoff boundaries ───────────
// Old-published delete / old-DLX keep owned by `assert_outbox_sweeper` via
// `eventing_conformance_outbox_enrolls_postgres`.

/// PostgreSQL residual (#1740): sweep retention anchors on `published_at`, not
/// aged `created_at`; exact 3599/3601 cutoff; fresh published and pending survive.
#[tokio::test(flavor = "multi_thread")]
async fn t8_sweep_retention_anchors_on_published_at() -> TestResult {
    let _sweep_guard = OUTBOX_SWEEP_TEST_LOCK.lock().await;
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    // #1740: long-lived pending that publishes now must survive even when created_at
    // is already outside retention — retention starts at publish terminal time.
    let delayed_event = unique_event_id("t8-delayed-publish");
    let delayed_entry = make_entry(&delayed_event);
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let delayed_entry = delayed_entry.clone();
            Box::pin(async move {
                let _outcome =
                    append_outbox(cap, &delayed_entry, &make_test_env("sweep_domain", "c"))
                        .await
                        .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET created_at = now() - make_interval(secs=>7200) WHERE event_id=$1",
    )
    .bind(&delayed_event)
    .execute(&store.pool)
    .await?;
    let delayed_outbox = make_pg_outbox_for_domain(
        &store,
        "sweep_domain",
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let delayed_pending = delayed_outbox.claim_batch(100).await?;
    let delayed_pending = delayed_pending
        .into_iter()
        .find(|entry| entry.idem_key().as_str() == delayed_event)
        .ok_or("delayed pending row must be claimable")?;
    assert_eq!(
        delayed_outbox.relay(delayed_pending).await?,
        Disposition::Ack
    );

    // anti-vacuity: in-retention published + pending must survive.
    let event_fresh = unique_event_id("t8-fresh");
    let event_pending = unique_event_id("t8-pending");
    for (eid, new_status) in [(&event_fresh, "published"), (&event_pending, "pending")] {
        let entry_c = make_entry(eid);
        let eid_c = eid.to_string();
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry_c, &make_test_env("sweep_domain", "c"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if new_status == STATUS_PUBLISHED {
            set_outbox_terminal_for_test(&store, &eid_c, new_status, 0).await?;
        }
    }

    let event_within_cutoff = unique_event_id("t8-within-cutoff");
    let event_beyond_cutoff = unique_event_id("t8-beyond-cutoff");
    for (event_id, age_seconds) in [
        (&event_within_cutoff, 3599_i64),
        (&event_beyond_cutoff, 3601_i64),
    ] {
        let entry = make_entry(event_id);
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &make_test_env("sweep_domain", "c"))
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        set_outbox_terminal_for_test(&store, event_id, STATUS_PUBLISHED, age_seconds).await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let _deleted = outbox.sweep(3600).await?;

    let delayed_remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
        .bind(&delayed_event)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        delayed_remaining.0, 1,
        "just-published row must survive even when created_at is outside retention"
    );

    for (event_id, expected, message) in [
        (
            &event_within_cutoff,
            1_i64,
            "3599s published row must survive",
        ),
        (
            &event_beyond_cutoff,
            0_i64,
            "3601s published row must be swept",
        ),
    ] {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id=$1")
            .bind(event_id)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(count, expected, "{message}");
    }

    for eid in [&event_fresh, &event_pending] {
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
            .bind(eid)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(cnt.0, 1, "in-retention row must survive sweep: {eid}");
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t_outbox_published_sweep_deletes_1001_rows_in_two_stable_batches() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let domain = unique_domain("outbox-bounded-sweep");
    let seed_id = unique_event_id("outbox-bounded-seed");
    let entry = make_entry(&seed_id);
    let envelope = make_test_env(&domain, "bounded.sweep");
    let outcome = store
        .serving_write_fixture::<_, _, crate::outbox::OutboxAppendError>(
            test_tenant(),
            move |cap| Box::pin(async move { append_outbox(cap, &entry, &envelope).await }),
        )
        .await?;
    assert_eq!(outcome, consistency::OutboxAppendOutcome::Inserted);

    sqlx::query(
        r#"
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
            payload, metadata, partition_key, causation_id
        )
        SELECT $1 || '-' || series.value::text,
               seed.tenant_id,
               seed.domain,
               seed.topic,
               seed.contract_id,
               seed.contract_version,
               seed.schema_hash,
               seed.payload,
               seed.metadata,
               NULL,
               NULL
        FROM outbox AS seed
        CROSS JOIN generate_series(1, 1000) AS series(value)
        WHERE seed.event_id = $2
        "#,
    )
    .bind(&seed_id)
    .bind(&seed_id)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        r#"
        UPDATE outbox
        SET status = 'published',
            automatic_retry_deadline = COALESCE(
                automatic_retry_deadline,
                now() + interval '24 hours'
            ),
            lease_token = NULL,
            lease_until = NULL,
            published_at = now() - interval '2 days',
            dlx_at = NULL,
            updated_at = now() - interval '2 days'
        WHERE domain = $1
        "#,
    )
    .bind(&domain)
    .execute(&store.pool)
    .await?;

    let first: i64 = sqlx::query_scalar("SELECT rss_sweep_outbox_published(86400)")
        .fetch_one(&store.pool)
        .await?;
    let second: i64 = sqlx::query_scalar("SELECT rss_sweep_outbox_published(86400)")
        .fetch_one(&store.pool)
        .await?;
    let third: i64 = sqlx::query_scalar("SELECT rss_sweep_outbox_published(86400)")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!((first, second, third), (1000, 1, 0));
    store.shutdown().await?;
    Ok(())
}

async fn seed_consumer_replay_dead_letter(
    store: &crate::PgStore,
    tenant: vocab::TenantId,
    binding: vocab::ProjectionInputBinding,
    producer_domain: &str,
    suffix: &str,
) -> Result<(String, String), TestError> {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore as _, DeadLetterSummary,
        EnvelopeMetadata, KEY_CORRELATION, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_TENANT_ID,
    };

    let message_id = unique_event_id(suffix);
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(KEY_TENANT_ID, tenant.to_string());
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, binding.version());
    metadata.insert_wire_pair(KEY_SCHEMA_HASH, binding.schema_hash());
    metadata.insert_wire_pair(KEY_CORRELATION, "corr-dlq-replay");
    store
        .dead_letter(test_dlx_payload_protector())
        .write_dead_letter(DeadLetterRecord::new(
            tenant,
            &message_id,
            DeadLetterProvenance::consumer(producer_domain, "dlq-replay-consumer"),
            binding.contract_id(),
            binding.topic(),
            Some("dlq-replay-consumer".to_string()),
            b"consumer-payload".to_vec(),
            DeadLetterSummary::new("consumer exhausted"),
            3,
            metadata,
        ))
        .await?;

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let dead_letter_id = sqlx::query_scalar(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(tenant.to_string())
    .bind(&message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((dead_letter_id, message_id))
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_dead_letter_replay_wrong_domain_writes_outbox_without_projection_mirror() -> TestResult {
    use eventexec::{DeadLetterId, DlqReplayOutcome, DlqReplayRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    register_generated_projection_input_catalog(&store).await?;
    let params = pg.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let maintenance = crate::PgRuntimeDeps::connect_maintenance(&config).await?;
    let plan = eventexec::WorkflowRuntimePlan::generated_projection_capture_fixture();
    let binding = generated::event::PROJECTION_INPUTS[0];
    let tenant = vocab::TenantId::parse(COTX_TENANT_B).unwrap();
    let wrong_domain = unique_domain("dlq-replay-wrong-domain");
    let (dead_letter_id, _) = seed_consumer_replay_dead_letter(
        &store,
        tenant,
        binding,
        &wrong_domain,
        "consumer-wrong-domain",
    )
    .await?;
    let replay_id = IdemKey::parse(&unique_event_id("replay-wrong-domain")).unwrap();
    let dlq = maintenance.dlq_store(test_dlx_payload_protector(), plan.projection_capture());

    let outcome = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
        ))
        .await?;
    assert_eq!(outcome.outcome(), &DlqReplayOutcome::Inserted);
    let outbox_domain: String = sqlx::query_scalar("SELECT domain FROM outbox WHERE event_id = $1")
        .bind(replay_id.as_str())
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(outbox_domain, wrong_domain);
    let projection_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(projection_count, 0);
    let dead_letter_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE id = $1::uuid")
            .bind(&dead_letter_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        dead_letter_count, 1,
        "replay must retain the source dead letter"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_dead_letter_replay_projection_catalog_drift_rolls_back_atomically() -> TestResult {
    use eventexec::{DeadLetterId, DlqError, DlqReplayRequest, DlqReplayStoreStage, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    register_generated_projection_input_catalog(&store).await?;
    let params = pg.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let maintenance = crate::PgRuntimeDeps::connect_maintenance(&config).await?;
    let plan = eventexec::WorkflowRuntimePlan::generated_projection_capture_fixture();
    let binding = generated::event::PROJECTION_INPUTS[0];
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let (dead_letter_id, _) = seed_consumer_replay_dead_letter(
        &store,
        tenant,
        binding,
        binding.domain(),
        "consumer-projection-drift",
    )
    .await?;
    let retired: i64 = sqlx::query_scalar("SELECT rss_retire_projection_input_generation($1)")
        .bind(generated::event::PROJECTION_INPUT_GENERATION)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        retired > 0,
        "fixture must remove the live projection catalog"
    );
    let replay_id = IdemKey::parse(&unique_event_id("replay-projection-drift")).unwrap();
    let dlq = maintenance.dlq_store(test_dlx_payload_protector(), plan.projection_capture());

    let replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
        ))
        .await;
    assert!(matches!(
        replay,
        Err(DlqError::ReplayStore(DlqReplayStoreStage::ProjectionMirror))
    ));
    let outbox_count: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(replay_id.as_str())
        .fetch_one(&store.pool)
        .await?;
    let projection_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!((outbox_count, projection_count), (0, 0));
    let dead_letter_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE id = $1::uuid")
            .bind(&dead_letter_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        dead_letter_count, 1,
        "rollback must retain the source dead letter"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_dead_letter_replay_aad_tamper_is_invalid_without_writes() -> TestResult {
    use eventexec::{DeadLetterId, DlqError, DlqReplayRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    register_generated_projection_input_catalog(&store).await?;
    let params = pg.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let maintenance = crate::PgRuntimeDeps::connect_maintenance(&config).await?;
    let plan = eventexec::WorkflowRuntimePlan::generated_projection_capture_fixture();
    let binding = generated::event::PROJECTION_INPUTS[0];
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let (dead_letter_id, _) = seed_consumer_replay_dead_letter(
        &store,
        tenant,
        binding,
        binding.domain(),
        "consumer-aad-tamper",
    )
    .await?;
    let dlq = maintenance.dlq_store(test_dlx_payload_protector(), plan.projection_capture());
    let contract_replay_id = IdemKey::parse(&unique_event_id("replay-contract-tampered")).unwrap();
    let group_replay_id = IdemKey::parse(&unique_event_id("replay-group-tampered")).unwrap();

    sqlx::query("UPDATE dead_letter SET contract_id = $1 WHERE id = $2::uuid")
        .bind("contract-dlq-tampered")
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;
    let contract_result = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            contract_replay_id.clone(),
        ))
        .await;
    assert!(matches!(contract_result, Err(DlqError::InvalidPayload)));
    sqlx::query("UPDATE dead_letter SET contract_id = $1 WHERE id = $2::uuid")
        .bind(binding.contract_id())
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;

    sqlx::query("UPDATE dead_letter SET consumer_group = $1 WHERE id = $2::uuid")
        .bind("dlq-replay-consumer-tampered")
        .bind(&dead_letter_id)
        .execute(&store.pool)
        .await?;
    let group_result = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            group_replay_id.clone(),
        ))
        .await;
    assert!(matches!(group_result, Err(DlqError::InvalidPayload)));

    let replay_write_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id = ANY($1)")
            .bind(vec![contract_replay_id.as_str(), group_replay_id.as_str()])
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(replay_write_count, 0);
    let dead_letter_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE id = $1::uuid")
            .bind(&dead_letter_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(dead_letter_count, 1);

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_dead_letter_replay_inserts_new_outbox_id() -> TestResult {
    use diport::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterSource, DeadLetterStore,
        DeadLetterSummary, EnvelopeMetadata, KEY_CORRELATION, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION,
        KEY_TENANT_ID,
    };
    use eventexec::{
        DeadLetterId, DlqCursor, DlqEntryKind, DlqError, DlqListQuery, DlqReplayOutcome,
        DlqReplayRequest, DlqStore as _,
    };

    let (pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    register_generated_projection_input_catalog(&store).await?;
    let params = pg.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let maintenance = crate::PgRuntimeDeps::connect_maintenance(&config).await?;
    let plan = eventexec::WorkflowRuntimePlan::generated_projection_capture_fixture();
    let binding = generated::event::PROJECTION_INPUTS[0];
    let dl = store.dead_letter(test_dlx_payload_protector());
    let dlq = maintenance.dlq_store(test_dlx_payload_protector(), plan.projection_capture());
    let domain = binding.domain().to_string();
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let message_id = unique_event_id("consumer-msg");
    let replay_contract_id = binding.contract_id();
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    metadata.insert_wire_pair(KEY_SCHEMA_VERSION, binding.version());
    metadata.insert_wire_pair(KEY_SCHEMA_HASH, binding.schema_hash());
    metadata.insert_wire_pair(KEY_CORRELATION, "corr-dlq-replay");

    dl.write_dead_letter(DeadLetterRecord::new(
        tenant,
        &message_id,
        DeadLetterProvenance::consumer(domain.as_str(), "dlq-replay-consumer"),
        replay_contract_id,
        binding.topic(),
        Some("dlq-replay-consumer".to_string()),
        b"consumer-payload".to_vec(),
        DeadLetterSummary::new("consumer exhausted"),
        3,
        metadata,
    ))
    .await?;

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (dead_letter_id,): (String,) = sqlx::query_as(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let replay_id = IdemKey::parse(&unique_event_id("replay")).unwrap();

    let outcome = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
        ))
        .await?;
    assert_eq!(outcome.outcome(), &DlqReplayOutcome::Inserted);

    let row: (
        String,
        String,
        String,
        String,
        Vec<u8>,
        String,
        String,
        String,
    ) = sqlx::query_as(
        r#"
        SELECT domain,
               contract_id,
               contract_version,
               schema_hash,
               payload,
               metadata ->> 'tenantId',
               metadata ->> 'deadLetterId',
               metadata ->> 'originalMessageId'
        FROM outbox
        WHERE event_id = $1
        "#,
    )
    .bind(replay_id.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, domain);
    assert_eq!(row.1, replay_contract_id);
    assert_eq!(row.2, binding.version());
    assert_eq!(row.3, binding.schema_hash());
    assert_eq!(row.4, b"consumer-payload".to_vec());
    assert_eq!(row.5, COTX_TENANT_A);
    assert_eq!(row.6, dead_letter_id);
    assert_eq!(row.7, message_id);

    let projection_rows: Vec<(String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT event_id, contract_id, contract_version, schema_hash
        FROM projection_events
        WHERE event_id = $1
        "#,
    )
    .bind(replay_id.as_str())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        projection_rows,
        vec![(
            replay_id.as_str().to_string(),
            replay_contract_id.to_string(),
            binding.version().to_string(),
            binding.schema_hash().to_string(),
        )],
        "registered-bound DLQ replay must mirror exactly one projection event"
    );

    let duplicate = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
        ))
        .await?;
    assert_eq!(duplicate.outcome(), &DlqReplayOutcome::AlreadyExists);
    let projection_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        projection_count.0, 1,
        "duplicate DLQ replay must not insert a second projection event"
    );

    let conflict_replay_id = IdemKey::parse(&unique_event_id("dlq-replay-fact-conflict")).unwrap();
    let seed = seed_conflicting_outbox_fact(&store, tenant, conflict_replay_id.as_str()).await?;
    let conflict = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&dead_letter_id)?,
            conflict_replay_id.clone(),
        ))
        .await;
    assert!(
        matches!(conflict, Err(DlqError::FactConflict(_))),
        "DLQ replay must preserve typed outbox fact conflict: {conflict:?}"
    );
    assert_seed_fact_unchanged(&store, conflict_replay_id.as_str(), &seed).await?;
    let conflict_projection_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM projection_events WHERE event_id = $1")
            .bind(conflict_replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        conflict_projection_count.0, 0,
        "conflicting DLQ replay must not mirror a projection row"
    );

    let missing_id = uuid::Uuid::new_v4().to_string();
    let missing_replay_id = IdemKey::parse(&unique_event_id("missing-replay")).unwrap();
    let missing = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&missing_id)?,
            missing_replay_id,
        ))
        .await;
    assert!(
        matches!(missing, Err(DlqError::NotFound)),
        "missing dead_letter id must map to NotFound"
    );

    let saga_message_id = unique_event_id("saga-msg");
    let saga_replay_id = IdemKey::parse(&unique_event_id("saga-replay")).unwrap();
    dl.write_dead_letter(DeadLetterRecord::new(
        tenant,
        &saga_message_id,
        DeadLetterProvenance::saga(domain.as_str()),
        "contract-dlq",
        "test.saga",
        None,
        b"saga-payload".to_vec(),
        DeadLetterSummary::new("saga compensation failed"),
        2,
        EnvelopeMetadata::empty(),
    ))
    .await?;
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (saga_dead_letter_id,): (String,) = sqlx::query_as(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&saga_message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let saga_replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&saga_dead_letter_id)?,
            saga_replay_id.clone(),
        ))
        .await;
    assert!(
        matches!(saga_replay, Err(DlqError::NotReplayable)),
        "saga dead_letter replay must be explicitly unsupported"
    );
    let saga_outbox_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(saga_replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        saga_outbox_count.0, 0,
        "not-replayable saga dead_letter must not write outbox"
    );

    let projection_message_id = format!("projection:test-owner:test-proj:{}", 77);
    let projection_replay_id = IdemKey::parse(&unique_event_id("projection-replay")).unwrap();
    let mut projection_metadata = EnvelopeMetadata::empty();
    projection_metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    projection_metadata.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
    projection_metadata.insert_wire_pair(KEY_SCHEMA_HASH, TEST_SCHEMA_HASH);
    for _ in 0..2 {
        dl.write_dead_letter(DeadLetterRecord::new(
            tenant,
            &projection_message_id,
            DeadLetterProvenance::projection(domain.as_str(), "test-proj"),
            "contract-dlq",
            "test.projection",
            Some("test-proj".to_string()),
            b"projection-payload".to_vec(),
            DeadLetterSummary::new(
                consistency::ProjectionApplyErrorReason::PayloadValueInvalid.as_label(),
            ),
            1,
            projection_metadata.clone(),
        ))
        .await?;
    }
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (projection_dead_letter_id, projection_count): (String, i64) = sqlx::query_as(
        "SELECT min(id::text), count(*) FROM dead_letter \
         WHERE tenant_id = $1::uuid AND source_kind = 'projection' AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&projection_message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(
        projection_count, 1,
        "projection DLQ poison rows must be idempotent"
    );
    let projection_replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&projection_dead_letter_id)?,
            projection_replay_id.clone(),
        ))
        .await;
    assert!(
        matches!(projection_replay, Err(DlqError::NotReplayable)),
        "projection dead_letter replay must be explicitly unsupported"
    );
    let projection_outbox_count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(projection_replay_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        projection_outbox_count.0, 0,
        "not-replayable projection dead_letter must not write outbox"
    );
    let projection_list = dlq
        .list_dlq(
            DlqListQuery::new(dlq_authorization(tenant))
                .with_producer_domain(domain.as_str())
                .with_source(DeadLetterSource::Projection),
        )
        .await?;
    assert_eq!(projection_list.data().len(), 1);
    assert_eq!(projection_list.data()[0].kind(), DlqEntryKind::DeadLetter);
    assert_eq!(
        projection_list.data()[0].source(),
        DeadLetterSource::Projection
    );
    assert_eq!(
        projection_list.data()[0].message_id(),
        projection_message_id
    );
    assert_eq!(
        projection_list.data()[0].consumer_group(),
        Some("test-proj")
    );

    let invalid_payload_id = unique_event_id("invalid-payload-dl");
    let invalid_entry = serde_json::json!({"ciphertext": true});
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (invalid_dead_letter_id,): (String,) = sqlx::query_as(
        r#"
        INSERT INTO dead_letter
            (tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic,
             replay_capsule, replay_capsule_key_ref, payload_len,
             replay_capsule_encoding, metadata_digest,
             error_summary, num_attempts, source_kind)
        VALUES ($1::uuid, $2, $3, 'dlq-replay-consumer', $4, $5,
                $6, 'dlx-test:1', 3, $7, decode(repeat('00', 32), 'hex'),
                $8, $9, 'consumer')
        RETURNING id::text
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&invalid_payload_id)
    .bind(domain.as_str())
    .bind("contract-dlq")
    .bind("test.invalid")
    .bind(sqlx::types::Json(&invalid_entry))
    .bind(crate::dead_letter_payload::DLX_REPLAY_CAPSULE_ENCODING)
    .bind("invalid payload row")
    .bind(1_i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let invalid_payload = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&invalid_dead_letter_id)?,
            IdemKey::parse(&unique_event_id("invalid-payload-replay")).unwrap(),
        ))
        .await;
    assert!(
        matches!(invalid_payload, Err(DlqError::InvalidPayload)),
        "malformed replay capsule must map to InvalidPayload"
    );

    let first_page = dlq
        .list_dlq(
            DlqListQuery::new(dlq_authorization(tenant))
                .with_producer_domain(domain.as_str())
                .with_source(DeadLetterSource::Consumer)
                .with_limit(1),
        )
        .await?;
    assert!(
        first_page.has_more(),
        "limit=1 over 2 consumer rows must page"
    );
    let cursor = first_page.next_cursor().unwrap();
    let second_page = dlq
        .list_dlq(
            DlqListQuery::new(dlq_authorization(tenant))
                .with_producer_domain(domain.as_str())
                .with_source(DeadLetterSource::Consumer)
                .with_limit(1)
                .with_cursor(DlqCursor::parse(cursor)?),
        )
        .await?;
    assert_eq!(
        second_page.data().len(),
        1,
        "cursor must advance to next row"
    );
    let original_dead_letter_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE id = $1::uuid")
            .bind(&dead_letter_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        original_dead_letter_count, 1,
        "successful and duplicate replay must retain the source dead letter"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_outbox_dlx_registers_dead_letter_and_redrive_is_tenant_scoped() -> TestResult {
    use consistency::PartitionKey;
    use eventexec::{
        DeadLetterId, DlqCursor, DlqEntryKind, DlqError, DlqInspectRequest, DlqInspectTarget,
        DlqListQuery, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayRequest, DlqStore as _,
    };

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let params = pg.owner_params();
    let config = runtime_pg_config(params, &params.username, &params.password);
    let maintenance = crate::PgRuntimeDeps::connect_maintenance(&config).await?;
    let plan = eventexec::WorkflowRuntimePlan::generated_projection_capture_fixture();
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B).unwrap();
    let domain = unique_domain("dlq-outbox");
    let event_id = unique_event_id("outbox-dlx");
    let partition_key = PartitionKey::parse("outbox-dlx-partition").unwrap();
    let entry = make_entry(&event_id);
    let seed_domain = domain.clone();

    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            let env = make_test_env(&seed_domain, "contract-dlq")
                .with_partition_key_opt(Some(partition_key.clone()));
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (publisher, calls) = RecordingPublisher::always_permanent();
    let outbox = make_pg_outbox_for_domain(&store, &domain, publisher);
    let pending = claim_entry_for_relay(&outbox, &event_id).await?;
    let disposition = outbox.relay(pending).await?;
    assert_eq!(disposition, Disposition::Reject);
    assert_eq!(*calls.lock().unwrap(), 1);

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let row: (String, String, String, i32, serde_json::Value, Vec<u8>) = sqlx::query_as(
        r#"
        SELECT id::text, source_kind, message_id, num_attempts, replay_capsule, metadata_digest
        FROM dead_letter
        WHERE tenant_id = $1::uuid
          AND message_id = $2
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&event_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(row.1, "outbox_relay");
    assert_eq!(row.2, event_id);
    assert_eq!(row.3, 1);
    assert!(row.4.get("tenantId").is_none());
    assert!(row.4.get("schemaVersion").is_none());
    assert_eq!(row.5.len(), 32);

    sqlx::query("UPDATE dead_letter SET error_summary = $1 WHERE id = $2::uuid")
        .bind("envelope_invalid_schema_hash")
        .bind(&row.0)
        .execute(&store.pool)
        .await?;

    let dlq = maintenance.dlq_store(test_dlx_payload_protector(), plan.projection_capture());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let replay_id = IdemKey::parse(&unique_event_id("bad-replay")).unwrap();
    let replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            dlq_authorization(tenant),
            DeadLetterId::parse(&row.0)?,
            replay_id,
        ))
        .await;
    assert!(matches!(replay, Err(DlqError::NotReplayable)));

    let older_event_id = unique_event_id("outbox-dlx-older-terminal");
    let older_entry = make_entry(&older_event_id);
    let older_domain = domain.clone();
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let env = make_test_env(&older_domain, "contract-dlq");
            Box::pin(async move {
                let _outcome = append_outbox(cap, &older_entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    for (id, dlx_epoch, updated_epoch) in [
        (&event_id, 1_700_000_200_i64, 1_700_000_000_i64),
        (&older_event_id, 1_700_000_200_i64, 1_700_000_300_i64),
    ] {
        sqlx::query(
            "UPDATE outbox \
             SET status = 'dlx', published_at = NULL, \
                 automatic_retry_deadline = COALESCE(automatic_retry_deadline, clock_timestamp() + interval '24 hours'), \
                 same_id_redrive_deadline = COALESCE(same_id_redrive_deadline, clock_timestamp() + interval '24 hours'), \
                 dlx_at = to_timestamp($2), updated_at = to_timestamp($3) \
             WHERE event_id = $1",
        )
        .bind(id)
        .bind(dlx_epoch)
        .bind(updated_epoch)
        .execute(&store.pool)
        .await?;
    }

    let listed = dlq
        .list_dlq(
            DlqListQuery::new(dlq_authorization(tenant))
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_producer_domain(domain.as_str())
                .with_limit(1),
        )
        .await?;
    assert_eq!(
        listed.data().len(),
        1,
        "current outbox dlx should be listed"
    );
    assert_eq!(listed.data()[0].kind(), DlqEntryKind::OutboxDlx);
    assert_eq!(listed.data()[0].id(), event_id);
    assert_eq!(listed.data()[0].message_id(), event_id);
    assert_eq!(
        listed.data()[0].last_attempt_epoch_secs(),
        1_700_000_200,
        "DLQ display and ordering must use dlx_at, not updated_at"
    );
    assert_eq!(
        listed.data()[0].error_summary(),
        "envelope_invalid_schema_hash",
        "outbox DLQ list must expose only the safe dead-letter summary"
    );
    assert!(listed.has_more(), "two DLX rows with limit=1 must paginate");
    let continuation = dlq
        .list_dlq(
            DlqListQuery::new(dlq_authorization(tenant))
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_producer_domain(domain.as_str())
                .with_limit(1)
                .with_cursor(DlqCursor::parse(listed.next_cursor().unwrap())?),
        )
        .await?;
    assert_eq!(continuation.data().len(), 1);
    assert_eq!(continuation.data()[0].id(), older_event_id);
    assert_eq!(
        continuation.data()[0].last_attempt_epoch_secs(),
        1_700_000_200,
        "same-second cursor pagination must neither omit nor repeat outbox DLQ rows"
    );

    let event_key = IdemKey::parse(&event_id).unwrap();
    let inspected = dlq
        .inspect_dlq(DlqInspectRequest::new(
            dlq_authorization(tenant),
            DlqInspectTarget::OutboxDlx(event_key.clone()),
        ))
        .await?;
    assert_eq!(inspected.kind(), DlqEntryKind::OutboxDlx);
    assert_eq!(inspected.id(), event_id);
    assert_eq!(inspected.error_summary(), "envelope_invalid_schema_hash");
    assert_eq!(
        inspected.last_attempt_epoch_secs(),
        1_700_000_200,
        "inspect must expose the authoritative DLX transition timestamp"
    );

    let before_redrive: (Vec<u8>, i64, String, Option<String>, serde_json::Value, String, String) =
        sqlx::query_as(
            "SELECT payload, seq, partition_key, lease_token::text, metadata, contract_version, schema_hash \
             FROM outbox WHERE event_id = $1",
        )
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        before_redrive.3.is_none(),
        "DLX settlement must clear the failed relay lease before redrive"
    );
    let terminal_before_redrive: (bool, bool, i64, i64) = sqlx::query_as(
        "SELECT published_at IS NULL, dlx_at IS NOT NULL, \
                EXTRACT(EPOCH FROM dlx_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        terminal_before_redrive,
        (true, true, 1_700_000_200, 1_700_000_000),
        "fixture must prove DLQ reads do not alias updated_at"
    );

    let wrong_tenant = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(dlq.redrive_outbox(DlqRedriveRequest::new(
                dlq_authorization(tenant_b),
                event_key.clone(),
            )))
        })
    })?;
    assert_eq!(wrong_tenant.outcome(), &DlqRedriveOutcome::NotFound);

    let status_after_wrong: (String, bool, bool) = sqlx::query_as(
        "SELECT status, published_at IS NULL, dlx_at IS NOT NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(status_after_wrong.0, "dlx");
    assert!(status_after_wrong.1);
    assert!(status_after_wrong.2);

    let redriven = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(dlq.redrive_outbox(DlqRedriveRequest::new(
                dlq_authorization(tenant),
                event_key.clone(),
            )))
        })
    })?;
    assert_eq!(redriven.outcome(), &DlqRedriveOutcome::Redriven);
    type RedrivenOutboxState = (
        String,
        i32,
        bool,
        Option<String>,
        bool,
        bool,
        Vec<u8>,
        i64,
        String,
        serde_json::Value,
        String,
        String,
    );
    let status_after_redrive: RedrivenOutboxState = sqlx::query_as(
        "SELECT status, retry_count, retry_after IS NULL, lease_token::text, \
                published_at IS NULL, dlx_at IS NULL, payload, seq, partition_key, metadata, contract_version, schema_hash \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(status_after_redrive.0, STATUS_PENDING);
    assert_eq!(status_after_redrive.1, 0);
    assert!(status_after_redrive.2);
    assert_eq!(status_after_redrive.3, None);
    assert!(status_after_redrive.4);
    assert!(status_after_redrive.5);
    assert_eq!(status_after_redrive.6, before_redrive.0);
    assert_eq!(status_after_redrive.7, before_redrive.1);
    assert_eq!(status_after_redrive.8, before_redrive.2);
    assert_eq!(status_after_redrive.9, before_redrive.4);
    assert_eq!(status_after_redrive.10, "v1");
    assert_eq!(status_after_redrive.11, TEST_SCHEMA_HASH);

    let pending_redrive = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                dlq.redrive_outbox(DlqRedriveRequest::new(dlq_authorization(tenant), event_key)),
            )
        })
    })?;
    assert_eq!(
        pending_redrive.outcome(),
        &DlqRedriveOutcome::NotFound,
        "redrive must only mutate current dlx rows"
    );
    let rendered = metrics_handle.render();
    assert!(rendered.contains("dlq_redrive_total"), "{rendered}");
    assert!(rendered.contains("outbox_dlx_redrive"), "{rendered}");
    assert!(rendered.contains("redriven"), "{rendered}");
    assert!(rendered.contains("not_found"), "{rendered}");

    let listed_after_redrive = dlq
        .list_dlq(
            DlqListQuery::new(dlq_authorization(tenant))
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_producer_domain(domain.as_str()),
        )
        .await?;
    assert_eq!(listed_after_redrive.data().len(), 1);
    assert_eq!(
        listed_after_redrive.data()[0].id(),
        older_event_id,
        "the redriven row must disappear while unrelated current DLX rows remain"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid ids and mutex assertions fail loud.
async fn same_id_automatic_deadline_is_frozen_and_expiry_never_calls_broker() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let domain = unique_domain("same-id-automatic");
    let event_id = unique_event_id("same-id-automatic");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "same-id-automatic");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (first_publisher, first_calls) = RecordingPublisher::always_ok();
    let first = make_pg_outbox_for_domain(&store, &domain, first_publisher);
    let first_claim = claim_entry_for_relay(&first, &event_id).await?;
    let first_deadline: (String, bool, i64) = sqlx::query_as(
        "SELECT same_id_delivery_phase, same_id_redrive_deadline IS NULL, \
                EXTRACT(EPOCH FROM automatic_retry_deadline)::bigint \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(first_deadline.0, "automatic");
    assert!(first_deadline.1);
    assert!(first_deadline.2 >= first_claim.claim_epoch_seconds() + 86_399);

    let retry: String =
        sqlx::query_scalar("SELECT rss_outbox_settle_retry($1, $2::uuid, $3)::text")
            .bind(&event_id)
            .bind(first_claim.test_lease_token())
            .bind(first_claim.test_lease_deadline_epoch_micros())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(retry, "settled");

    let (second_publisher, second_calls) = RecordingPublisher::always_ok();
    let restarted = make_pg_outbox_for_domain(&store, &domain, second_publisher);
    sqlx::query("UPDATE outbox SET retry_after = NULL WHERE event_id = $1")
        .bind(&event_id)
        .execute(&store.pool)
        .await?;
    let second_claim = claim_entry_for_relay(&restarted, &event_id).await?;
    let deadline_after_restart: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM automatic_retry_deadline)::bigint FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(deadline_after_restart, first_deadline.2);

    sqlx::query(
        "UPDATE outbox SET automatic_retry_deadline = clock_timestamp() WHERE event_id = $1",
    )
    .bind(&event_id)
    .execute(&store.pool)
    .await?;
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let disposition = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(restarted.relay(second_claim))
        })
    })?;
    assert_eq!(disposition, Disposition::Reject);
    assert_eq!(*first_calls.lock().unwrap(), 0);
    assert_eq!(*second_calls.lock().unwrap(), 0);

    let terminal: (String, String, bool, bool) = sqlx::query_as(
        "SELECT status, same_id_delivery_phase, same_id_redrive_deadline IS NOT NULL, \
                automatic_retry_deadline <= clock_timestamp() \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        terminal,
        ("dlx".to_string(), "automatic".to_string(), true, true)
    );
    let durable_reason: String = sqlx::query_scalar(
        "SELECT error_summary FROM dead_letter \
         WHERE message_id = $1 ORDER BY last_attempt_at DESC LIMIT 1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        durable_reason,
        "outbox same-ID automatic delivery window expired"
    );
    let rendered = metrics_handle.render();
    assert!(
        rendered.contains("outbox_same_id_window_expired_total"),
        "{rendered}"
    );
    assert!(rendered.contains("phase=\"automatic\""), "{rendered}");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn dlq_maintenance_audit_binds_tenant_and_start_id() -> TestResult {
    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;
    let tenant = test_tenant();
    let audit_id = diport::DlqOperatorStartAuditId::parse(format!(
        "postgres-dlq-audit-{}",
        uuid::Uuid::new_v4()
    ))?;
    let resource_id = "operation=list tenant=test";

    maintenance
        .record_dlq_maintenance_audit(
            "unauthenticated-dlq-attempt",
            tenant,
            &audit_id,
            "dlq.list.start",
            crate::MaintenanceAuditOutcome::Success,
            resource_id,
        )
        .await?;
    maintenance
        .record_dlq_maintenance_audit(
            "rss-maintenance-operator",
            tenant,
            &audit_id,
            "dlq.list.finish",
            crate::MaintenanceAuditOutcome::Success,
            resource_id,
        )
        .await?;

    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT action, principal_id, tenant_context::text, request_id FROM auth_audit_events \
         WHERE request_id = $1 ORDER BY action",
    )
    .bind(audit_id.as_str())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(rows.len(), 2);
    let expected_tenant = tenant.as_uuid().to_string();
    for (action, principal_id, tenant_context, request_id) in rows {
        assert!(matches!(
            action.as_str(),
            "dlq.list.start" | "dlq.list.finish"
        ));
        assert_eq!(tenant_context.as_deref(), Some(expected_tenant.as_str()));
        assert_eq!(request_id.as_deref(), Some(audit_id.as_str()));
        if action.ends_with(".start") {
            assert_eq!(principal_id, "unauthenticated-dlq-attempt");
        } else {
            assert_eq!(principal_id, "rss-maintenance-operator");
        }
    }

    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid typed identifiers.
async fn dlq_mutation_rolls_back_when_atomic_finish_audit_fails() -> TestResult {
    use eventexec::{DlqRedriveRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;
    let tenant = test_tenant();
    let domain = unique_domain("atomic-audit-rollback");
    let event_id = unique_event_id("atomic-audit-rollback");
    seed_outbox_dlx(&store, &domain, &event_id).await?;
    let audit_id = diport::DlqOperatorStartAuditId::parse(format!(
        "postgres-audit-failure-{}",
        uuid::Uuid::new_v4()
    ))?;

    sqlx::query(
        r#"
        CREATE FUNCTION test_reject_dlq_finish_audit() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.request_id LIKE 'postgres-audit-failure-%' THEN
                RAISE EXCEPTION 'injected DLQ finish audit failure';
            END IF;
            RETURN NEW;
        END
        $$
        "#,
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TRIGGER test_reject_dlq_finish_audit
        BEFORE INSERT ON auth_audit_events
        FOR EACH ROW EXECUTE FUNCTION test_reject_dlq_finish_audit()
        "#,
    )
    .execute(&store.pool)
    .await?;

    let dlq = maintenance.dlq_store_without_payload_replay();
    let result = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            dlq_authorization_with_audit_id(tenant, audit_id.clone()),
            IdemKey::parse(&event_id).unwrap(),
        ))
        .await;
    assert!(
        result.is_err(),
        "injected finish audit failure must surface"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status, "dlx", "the mutation must roll back with its audit");
    let audit_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit_events WHERE request_id = $1")
            .bind(audit_id.as_str())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(audit_count, 0);

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid typed identifiers and inspect a test-only mutex.
async fn same_id_redrive_preflight_expiry_never_calls_broker() -> TestResult {
    use eventexec::{DlqRedriveOutcome, DlqRedriveRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;
    let tenant = test_tenant();
    let domain = unique_domain("same-id-redrive-preflight");
    let event_id = unique_event_id("same-id-redrive-preflight");
    seed_outbox_dlx(&store, &domain, &event_id).await?;
    let finish_audit_id = diport::DlqOperatorStartAuditId::parse(format!(
        "postgres-redrive-finish-{}",
        uuid::Uuid::new_v4()
    ))?;

    let dlq = maintenance.dlq_store_without_payload_replay();
    let redriven = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            dlq_authorization_with_audit_id(tenant, finish_audit_id.clone()),
            IdemKey::parse(&event_id).unwrap(),
        ))
        .await?;
    assert_eq!(redriven.outcome(), &DlqRedriveOutcome::Redriven);
    let finish_audit: (String, String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT action, outcome, tenant_context::text, request_id \
         FROM auth_audit_events WHERE request_id = $1",
    )
    .bind(finish_audit_id.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(finish_audit.0, "dlq.redrive-outbox.finish");
    assert_eq!(finish_audit.1, "success");
    assert_eq!(finish_audit.2.as_deref(), Some(tenant.to_string().as_str()));
    assert_eq!(finish_audit.3.as_deref(), Some(finish_audit_id.as_str()));

    let (publisher, calls) = RecordingPublisher::always_ok();
    let relay = make_pg_outbox_for_domain(&store, &domain, publisher);
    let claim = claim_entry_for_relay(&relay, &event_id).await?;
    sqlx::query(
        "UPDATE outbox SET same_id_redrive_deadline = clock_timestamp() WHERE event_id = $1",
    )
    .bind(&event_id)
    .execute(&store.pool)
    .await?;

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let disposition = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(relay.relay(claim))
        })
    })?;
    assert_eq!(disposition, Disposition::Reject);
    assert_eq!(*calls.lock().unwrap(), 0);

    let durable: (String, String, String) = sqlx::query_as(
        "SELECT o.status, o.same_id_delivery_phase, d.error_summary \
         FROM outbox AS o JOIN dead_letter AS d ON d.message_id = o.event_id \
         WHERE o.event_id = $1 ORDER BY d.last_attempt_at DESC LIMIT 1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        durable,
        (
            "dlx".to_string(),
            "redrive".to_string(),
            "outbox same-ID redrive delivery window expired".to_string(),
        )
    );
    let rendered = metrics_handle.render();
    assert!(
        rendered.contains("outbox_same_id_window_expired_total"),
        "{rendered}"
    );
    assert!(rendered.contains("phase=\"redrive\""), "{rendered}");

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid typed identifiers.
async fn same_id_redrive_deadline_is_preserved_expired_is_noop_and_concurrency_is_atomic()
-> TestResult {
    use eventexec::{DlqRedriveOutcome, DlqRedriveRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;
    let tenant = test_tenant();
    let dlq = Arc::new(maintenance.dlq_store_without_payload_replay());

    let domain = unique_domain("same-id-manual");
    let event_id = unique_event_id("same-id-manual");
    seed_outbox_dlx(&store, &domain, &event_id).await?;
    let original_deadline: String =
        sqlx::query_scalar("SELECT same_id_redrive_deadline::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    let redriven = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            dlq_authorization(tenant),
            IdemKey::parse(&event_id).unwrap(),
        ))
        .await?;
    assert_eq!(redriven.outcome(), &DlqRedriveOutcome::Redriven);
    let claim = claimed_entry_for_event(&store, &event_id).await?;
    let remark: String = sqlx::query_scalar(
        "SELECT settlement_outcome::text FROM rss_outbox_mark_dlx($1, $2::uuid, $3)",
    )
    .bind(&event_id)
    .bind(claim.test_lease_token())
    .bind(claim.test_lease_deadline_epoch_micros())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(remark, "settled");
    let preserved: (String, String) = sqlx::query_as(
        "SELECT same_id_delivery_phase, same_id_redrive_deadline::text \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(preserved, ("redrive".to_string(), original_deadline));

    sqlx::query(
        "UPDATE outbox SET same_id_redrive_deadline = clock_timestamp() WHERE event_id = $1",
    )
    .bind(&event_id)
    .execute(&store.pool)
    .await?;
    let before: (String, String) =
        sqlx::query_as("SELECT to_jsonb(o)::text, xmin::text FROM outbox AS o WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let expired = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(dlq.redrive_outbox(DlqRedriveRequest::new(
                dlq_authorization(tenant),
                IdemKey::parse(&event_id).unwrap(),
            )))
        })
    })?;
    assert_eq!(expired.outcome(), &DlqRedriveOutcome::Expired);
    let after: (String, String) =
        sqlx::query_as("SELECT to_jsonb(o)::text, xmin::text FROM outbox AS o WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        after, before,
        "Expired must not update any outbox column or xmin"
    );
    assert!(metrics_handle.render().contains("expired"));

    let concurrent_id = unique_event_id("same-id-concurrent");
    seed_outbox_dlx(&store, &domain, &concurrent_id).await?;
    let calls = (0..8).map(|_| {
        let dlq = Arc::clone(&dlq);
        let event_key = IdemKey::parse(&concurrent_id).unwrap();
        async move {
            dlq.redrive_outbox(DlqRedriveRequest::new(dlq_authorization(tenant), event_key))
                .await
        }
    });
    let outcomes = futures::future::try_join_all(calls).await?;
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.outcome() == &DlqRedriveOutcome::Redriven)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.outcome() == &DlqRedriveOutcome::NotFound)
            .count(),
        7
    );

    let expired_concurrent_id = unique_event_id("same-id-expired-concurrent");
    seed_outbox_dlx(&store, &domain, &expired_concurrent_id).await?;
    sqlx::query(
        "UPDATE outbox SET same_id_redrive_deadline = clock_timestamp() WHERE event_id = $1",
    )
    .bind(&expired_concurrent_id)
    .execute(&store.pool)
    .await?;
    let calls = (0..8).map(|_| {
        let dlq = Arc::clone(&dlq);
        let event_key = IdemKey::parse(&expired_concurrent_id).unwrap();
        async move {
            dlq.redrive_outbox(DlqRedriveRequest::new(dlq_authorization(tenant), event_key))
                .await
        }
    });
    let outcomes = futures::future::try_join_all(calls).await?;
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.outcome() == &DlqRedriveOutcome::Expired)
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid ids; exact timestamp comparisons exercise DB policy branches.
async fn same_id_first_dlx_deadline_uses_both_exact_least_branches() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let domain = unique_domain("same-id-least");
    let cases = [
        (unique_event_id("same-id-least-automatic"), "-1 hour", true),
        (unique_event_id("same-id-least-dlx"), "1 hour", false),
    ];

    for (event_id, automatic_offset, automatic_branch) in cases {
        let entry = make_entry(&event_id);
        let env = make_test_env(&domain, "same-id-least");
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        let claim = claimed_entry_for_event(&store, &event_id).await?;
        sqlx::query(
            "UPDATE outbox SET automatic_retry_deadline = clock_timestamp() + $2::interval \
             WHERE event_id = $1",
        )
        .bind(&event_id)
        .bind(automatic_offset)
        .execute(&store.pool)
        .await?;
        let marked: String = sqlx::query_scalar(
            "SELECT settlement_outcome::text FROM rss_outbox_mark_dlx($1, $2::uuid, $3)",
        )
        .bind(&event_id)
        .bind(claim.test_lease_token())
        .bind(claim.test_lease_deadline_epoch_micros())
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(marked, "settled");

        let exact: (bool, bool) = sqlx::query_as(
            r#"
            SELECT same_id_redrive_deadline = automatic_retry_deadline
                       + make_interval(secs => policy.same_id_redrive_horizon_seconds::double precision),
                   same_id_redrive_deadline = dlx_at
                       + make_interval(secs => policy.same_id_redrive_horizon_seconds::double precision)
            FROM outbox CROSS JOIN event_delivery_policy AS policy
            WHERE event_id = $1 AND policy.singleton
            "#,
        )
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            exact,
            (automatic_branch, !automatic_branch),
            "LEAST branch must equal exactly one policy-derived absolute deadline"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid typed identifiers and exact durable-state assertions.
async fn expired_outbox_accepted_gap_resolution_is_terminal_audited_and_unblocks_successor()
-> TestResult {
    use consistency::PartitionKey;
    use eventexec::{
        DlqStore as _, OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest,
        OutboxResolutionChangeTicket,
    };

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;
    let tenant = test_tenant();
    let other_tenant = vocab::TenantId::parse(COTX_TENANT_B)?;
    let domain = unique_domain("expired-resolution-gap");
    let partition = PartitionKey::parse("expired-resolution-gap-partition").unwrap();
    let head_id = unique_event_id("expired-resolution-head");
    let successor_id = unique_event_id("expired-resolution-successor");
    for event_id in [&head_id, &successor_id] {
        let entry = make_entry(event_id);
        let env = make_test_env(&domain, "expired-resolution")
            .with_partition_key_opt(Some(partition.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    sqlx::query(
        r#"
        UPDATE outbox
        SET status = 'dlx',
            automatic_retry_deadline = clock_timestamp() - interval '25 hours',
            same_id_redrive_deadline = clock_timestamp() + interval '1 hour',
            dlx_at = clock_timestamp(),
            updated_at = clock_timestamp()
        WHERE event_id = $1
        "#,
    )
    .bind(&head_id)
    .execute(&store.pool)
    .await?;

    let relay_budget = test_relay_budget();
    let blocked: Vec<String> =
        sqlx::query_scalar("SELECT event_id FROM rss_outbox_claim_batch($1, 10, $2, $3)")
            .bind(&domain)
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_all(&store.pool)
            .await?;
    assert!(
        !blocked.iter().any(|id| id == &successor_id),
        "an unresolved DLX head must block its successor"
    );

    let dlq = maintenance.dlq_store_without_payload_replay();
    let ticket = OutboxResolutionChangeTicket::parse("CHG-1742")?;
    let unexpired_before: (String, String) =
        sqlx::query_as("SELECT to_jsonb(o)::text, xmin::text FROM outbox AS o WHERE event_id = $1")
            .bind(&head_id)
            .fetch_one(&store.pool)
            .await?;
    let unexpired = dlq
        .resolve_expired_outbox(OutboxExpiredResolutionRequest::accepted_gap(
            dlq_authorization(tenant),
            IdemKey::parse(&head_id).unwrap(),
            ticket.clone(),
        ))
        .await?;
    assert_eq!(
        unexpired.outcome(),
        &OutboxExpiredResolutionOutcome::NotExpired
    );
    let unexpired_after: (String, String) =
        sqlx::query_as("SELECT to_jsonb(o)::text, xmin::text FROM outbox AS o WHERE event_id = $1")
            .bind(&head_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(unexpired_after, unexpired_before);

    sqlx::query(
        "UPDATE outbox SET same_id_redrive_deadline = clock_timestamp() WHERE event_id = $1",
    )
    .bind(&head_id)
    .execute(&store.pool)
    .await?;
    let wrong_tenant = dlq
        .resolve_expired_outbox(OutboxExpiredResolutionRequest::accepted_gap(
            dlq_authorization(other_tenant),
            IdemKey::parse(&head_id).unwrap(),
            ticket.clone(),
        ))
        .await?;
    assert_eq!(
        wrong_tenant.outcome(),
        &OutboxExpiredResolutionOutcome::NotFound
    );

    let mut direct = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut direct, tenant).await?;
    let invalid_text: i64 = sqlx::query_scalar(
        "SELECT rss_outbox_resolve_expired($1, $2::uuid, 'accepted_gap', \
                 ' CHG-1742', E'verified\\noperator', NULL)",
    )
    .bind(&head_id)
    .bind(tenant.to_string())
    .fetch_one(&mut *direct)
    .await?;
    direct.rollback().await?;
    assert_eq!(
        invalid_text, -2,
        "SQL function must reject dirty evidence text instead of normalizing it"
    );

    let resolved = dlq
        .resolve_expired_outbox(OutboxExpiredResolutionRequest::accepted_gap(
            dlq_authorization(tenant),
            IdemKey::parse(&head_id).unwrap(),
            ticket,
        ))
        .await?;
    assert_eq!(
        resolved.outcome(),
        &OutboxExpiredResolutionOutcome::Resolved
    );
    let terminal: (String, bool, bool, bool) = sqlx::query_as(
        "SELECT status, abandoned_at IS NOT NULL, dlx_at IS NULL, published_at IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&head_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(terminal, ("abandoned".to_owned(), true, true, true));
    let evidence: (String, String, String, Option<String>, bool) = sqlx::query_as(
        "SELECT resolution_kind, change_ticket, operator_subject, evidence_event_id, \
                verified_at = (SELECT abandoned_at FROM outbox WHERE event_id = $1) \
         FROM outbox_expired_resolutions WHERE blocked_event_id = $1",
    )
    .bind(&head_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        evidence,
        (
            "accepted_gap".to_owned(),
            "CHG-1742".to_owned(),
            DLQ_TEST_OPERATOR.to_owned(),
            None,
            true,
        )
    );

    let released: Vec<String> =
        sqlx::query_scalar("SELECT event_id FROM rss_outbox_claim_batch($1, 10, $2, $3)")
            .bind(&domain)
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_all(&store.pool)
            .await?;
    assert!(
        released.iter().any(|id| id == &successor_id),
        "abandoned is an explicit resolved terminal and must release the successor"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration fixtures use known-valid typed identifiers and exact concurrent outcome counts.
async fn expired_outbox_compensation_requires_published_causation_and_resolution_is_single_winner()
-> TestResult {
    use diport::EnvelopeCausationId;
    use eventexec::{
        DlqStore as _, OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest,
        OutboxResolutionChangeTicket,
    };

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;
    let tenant = test_tenant();
    let domain = unique_domain("expired-resolution-compensated");
    let head_id = unique_event_id("expired-compensated-head");
    let bad_evidence_id = unique_event_id("expired-compensated-bad-evidence");
    let evidence_id = unique_event_id("expired-compensated-evidence");

    for (event_id, causation_id) in [
        (&head_id, None),
        (&bad_evidence_id, None),
        (&evidence_id, Some(head_id.as_str())),
    ] {
        let entry = make_entry(event_id);
        let env = make_test_env(&domain, "expired-compensated").with_causation_id_opt(
            causation_id.map(|value| EnvelopeCausationId::from_opaque(value).unwrap()),
        );
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    sqlx::query(
        r#"
        UPDATE outbox
        SET status = CASE WHEN event_id = $1 THEN 'dlx' ELSE 'published' END,
            automatic_retry_deadline = clock_timestamp() + interval '24 hours',
            same_id_redrive_deadline = CASE WHEN event_id = $1
                                            THEN clock_timestamp() - interval '1 second'
                                            ELSE NULL END,
            published_at = CASE WHEN event_id = $1 THEN NULL ELSE clock_timestamp() END,
            dlx_at = CASE WHEN event_id = $1 THEN clock_timestamp() ELSE NULL END,
            updated_at = clock_timestamp()
        WHERE event_id = ANY($2)
        "#,
    )
    .bind(&head_id)
    .bind(vec![
        head_id.clone(),
        bad_evidence_id.clone(),
        evidence_id.clone(),
    ])
    .execute(&store.pool)
    .await?;

    let dlq = Arc::new(maintenance.dlq_store_without_payload_replay());
    let ticket = OutboxResolutionChangeTicket::parse("CHG-1742-COMP")?;
    let rejected = dlq
        .resolve_expired_outbox(OutboxExpiredResolutionRequest::compensated(
            dlq_authorization(tenant),
            IdemKey::parse(&head_id).unwrap(),
            IdemKey::parse(&bad_evidence_id).unwrap(),
            ticket.clone(),
        ))
        .await?;
    assert_eq!(
        rejected.outcome(),
        &OutboxExpiredResolutionOutcome::EvidenceRejected
    );

    let resolved = dlq
        .resolve_expired_outbox(OutboxExpiredResolutionRequest::compensated(
            dlq_authorization(tenant),
            IdemKey::parse(&head_id).unwrap(),
            IdemKey::parse(&evidence_id).unwrap(),
            ticket,
        ))
        .await?;
    assert_eq!(
        resolved.outcome(),
        &OutboxExpiredResolutionOutcome::Resolved
    );
    let durable: (String, String) = sqlx::query_as(
        "SELECT resolution_kind, evidence_event_id FROM outbox_expired_resolutions \
         WHERE blocked_event_id = $1",
    )
    .bind(&head_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(durable, ("compensated".to_owned(), evidence_id));

    let concurrent_id = unique_event_id("expired-resolution-concurrent");
    seed_outbox_dlx(&store, &domain, &concurrent_id).await?;
    sqlx::query(
        "UPDATE outbox SET same_id_redrive_deadline = clock_timestamp() WHERE event_id = $1",
    )
    .bind(&concurrent_id)
    .execute(&store.pool)
    .await?;
    let calls = (0..8).map(|_| {
        let dlq = Arc::clone(&dlq);
        let event_id = IdemKey::parse(&concurrent_id).unwrap();
        let ticket = OutboxResolutionChangeTicket::parse("CHG-1742-CONCURRENT").unwrap();
        async move {
            dlq.resolve_expired_outbox(OutboxExpiredResolutionRequest::accepted_gap(
                dlq_authorization(tenant),
                event_id,
                ticket,
            ))
            .await
        }
    });
    let outcomes = futures::future::try_join_all(calls).await?;
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| { outcome.outcome() == &OutboxExpiredResolutionOutcome::Resolved })
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| { outcome.outcome() == &OutboxExpiredResolutionOutcome::NotFound })
            .count(),
        7
    );

    let invalid_evidence = sqlx::query(
        r#"
        INSERT INTO outbox_expired_resolutions (
            tenant_id, blocked_event_id, resolution_kind, change_ticket,
            operator_subject, evidence_event_id, verified_at
        ) VALUES ($1::uuid, $2, 'accepted_gap', ' leading-space',
                  E'verified\noperator', NULL, clock_timestamp())
        "#,
    )
    .bind(tenant.to_string())
    .bind(unique_event_id("invalid-resolution-evidence"))
    .execute(&store.pool)
    .await;
    assert!(
        matches!(
            invalid_evidence,
            Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("23514")
        ),
        "DB CHECK must reject whitespace/control characters: {invalid_evidence:?}"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t9b_settle_rejects_expired_current_lease_before_reclaim() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t9b");
    let entry = make_entry(&event_id);
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome =
                    append_outbox(cap, &entry, &make_test_env("t9b_domain", "strict-expiry"))
                        .await
                        .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let original = claimed_entry_for_event(&store, &event_id).await?;
    let expired_deadline_epoch_micros: i64 = sqlx::query_scalar(
        r#"
        UPDATE outbox
        SET updated_at = clock_timestamp() - interval '61 seconds',
            lease_until = clock_timestamp() - interval '1 second'
        WHERE event_id = $1
        RETURNING (EXTRACT(EPOCH FROM lease_until) * 1000000)::bigint
        "#,
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    let changed: String =
        sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
            .bind(&event_id)
            .bind(original.test_lease_token())
            .bind(expired_deadline_epoch_micros)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        changed, "expired",
        "an expired lease must not settle even before another worker reclaims it"
    );
    let status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status, crate::outbox::STATUS_PUBLISHING);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t9c_each_settle_rejects_token_and_deadline_mismatch_independently() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_ids = [
        unique_event_id("t9c-published"),
        unique_event_id("t9c-retry"),
        unique_event_id("t9c-dlx"),
    ];
    for (index, event_id) in event_ids.iter().enumerate() {
        let entry = make_entry(event_id);
        let env = make_test_env(&unique_domain(&format!("t9c-{index}")), "lease.fencing");
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let published_claim = claimed_entry_for_event(&store, &event_ids[0]).await?;
    let retry_claim = claimed_entry_for_event(&store, &event_ids[1]).await?;
    let dlx_claim = claimed_entry_for_event(&store, &event_ids[2]).await?;
    let wrong_token = "00000000-0000-4000-8000-000000000001";

    for (token, deadline, label) in [
        (
            wrong_token,
            published_claim.test_lease_deadline_epoch_micros(),
            "token",
        ),
        (
            published_claim.test_lease_token(),
            published_claim.test_lease_deadline_epoch_micros() + 1,
            "deadline",
        ),
    ] {
        let changed: String =
            sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
                .bind(&event_ids[0])
                .bind(token)
                .bind(deadline)
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(
            changed, "lost_lease",
            "published settle must reject {label} mismatch"
        );
    }

    for (token, deadline, label) in [
        (
            wrong_token,
            retry_claim.test_lease_deadline_epoch_micros(),
            "token",
        ),
        (
            retry_claim.test_lease_token(),
            retry_claim.test_lease_deadline_epoch_micros() + 1,
            "deadline",
        ),
    ] {
        let changed: String =
            sqlx::query_scalar("SELECT rss_outbox_settle_retry($1, $2::uuid, $3)::text")
                .bind(&event_ids[1])
                .bind(token)
                .bind(deadline)
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(
            changed, "lost_lease",
            "retry settle must reject {label} mismatch"
        );
    }

    for (token, deadline, label) in [
        (
            wrong_token,
            dlx_claim.test_lease_deadline_epoch_micros(),
            "token",
        ),
        (
            dlx_claim.test_lease_token(),
            dlx_claim.test_lease_deadline_epoch_micros() + 1,
            "deadline",
        ),
    ] {
        let outcome: String = sqlx::query_scalar(
            "SELECT settlement_outcome::text FROM rss_outbox_mark_dlx($1, $2::uuid, $3)",
        )
        .bind(&event_ids[2])
        .bind(token)
        .bind(deadline)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            outcome, "lost_lease",
            "DLX settle must reject {label} mismatch"
        );
    }

    let states: BTreeMap<String, (String, i32)> = sqlx::query_as::<_, (String, String, i32)>(
        "SELECT event_id, status, retry_count FROM outbox WHERE event_id = ANY($1)",
    )
    .bind(event_ids.to_vec())
    .fetch_all(&store.pool)
    .await?
    .into_iter()
    .map(|(event_id, status, retry_count)| (event_id, (status, retry_count)))
    .collect();
    assert_eq!(
        states,
        BTreeMap::from(
            event_ids
                .map(|event_id| { (event_id, (crate::outbox::STATUS_PUBLISHING.to_string(), 0),) })
        ),
        "all six fencing misses must leave durable state untouched"
    );

    store.shutdown().await?;
    Ok(())
}

/// 三个 settle 都必须等拿到目标行锁后再取结算时钟；等待期间过期的 lease 不得被结算。
#[tokio::test(flavor = "multi_thread")]
async fn t9d_each_settle_takes_expiry_clock_after_row_lock() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_ids = [
        unique_event_id("t9d-lock-published"),
        unique_event_id("t9d-lock-retry"),
        unique_event_id("t9d-lock-dlx"),
    ];
    let mut lease_tokens = Vec::new();
    for (index, event_id) in event_ids.iter().enumerate() {
        let entry = make_entry(event_id);
        let env = make_test_env(
            &unique_domain(&format!("t9d-lock-{index}")),
            "settle.lock.clock",
        );
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        let claim = claimed_entry_for_event(&store, event_id).await?;
        lease_tokens.push(claim.test_lease_token().to_string());
    }

    enum LockedSettleResult {
        Outcome(String),
    }

    for (index, event_id) in event_ids.iter().enumerate() {
        let deadline: i64 = sqlx::query_scalar(
            r#"
            UPDATE outbox
            SET updated_at = clock_timestamp() - interval '1 second',
                lease_until = clock_timestamp() + interval '2 seconds'
            WHERE event_id = $1
            RETURNING (EXTRACT(EPOCH FROM lease_until) * 1000000)::bigint
            "#,
        )
        .bind(event_id)
        .fetch_one(&store.pool)
        .await?;
        let mut settle_conn = store.pool.acquire().await?;
        let waiter_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *settle_conn)
            .await?;
        let mut blocker = store.pool.begin().await?;
        let locked: String =
            sqlx::query_scalar("SELECT event_id FROM outbox WHERE event_id = $1 FOR UPDATE")
                .bind(event_id)
                .fetch_one(&mut *blocker)
                .await?;
        assert_eq!(locked, *event_id);

        let controller = async {
            await_try(std::time::Duration::from_secs(1), async || {
                let blockers = sqlx::query_scalar::<_, Vec<i32>>("SELECT pg_blocking_pids($1)")
                    .bind(waiter_pid)
                    .fetch_one(&store.pool)
                    .await?;
                Ok::<Option<()>, TestError>((!blockers.is_empty()).then_some(()))
            })
            .await
            .map_err(|error| {
                TestError::from(format!("settle session must wait on the row lock: {error}"))
            })?;
            let lease_is_fresh: bool = sqlx::query_scalar(
                "SELECT lease_until > clock_timestamp() FROM outbox WHERE event_id = $1",
            )
            .bind(event_id)
            .fetch_one(&store.pool)
            .await?;
            assert!(
                lease_is_fresh,
                "settle {index} must begin waiting before its lease expires"
            );
            await_delay(std::time::Duration::from_millis(2_100)).await;
            blocker.commit().await?;
            Ok::<(), TestError>(())
        };
        let settle = async {
            match index {
                0 => sqlx::query_scalar::<_, String>(
                    "SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text",
                )
                .bind(event_id)
                .bind(&lease_tokens[index])
                .bind(deadline)
                .fetch_one(&mut *settle_conn)
                .await
                .map(LockedSettleResult::Outcome),
                1 => sqlx::query_scalar::<_, String>(
                    "SELECT rss_outbox_settle_retry($1, $2::uuid, $3)::text",
                )
                .bind(event_id)
                .bind(&lease_tokens[index])
                .bind(deadline)
                .fetch_one(&mut *settle_conn)
                .await
                .map(LockedSettleResult::Outcome),
                _ => sqlx::query_scalar::<_, String>(
                    "SELECT settlement_outcome::text FROM rss_outbox_mark_dlx($1, $2::uuid, $3)",
                )
                .bind(event_id)
                .bind(&lease_tokens[index])
                .bind(deadline)
                .fetch_one(&mut *settle_conn)
                .await
                .map(LockedSettleResult::Outcome),
            }
        };
        let (settle, controller) = tokio::join!(settle, controller);
        controller?;
        match settle? {
            LockedSettleResult::Outcome(outcome) => {
                assert_eq!(
                    outcome, "expired",
                    "settle {index} must classify lock-wait expiry"
                );
            }
        }
    }

    let states: Vec<(String, i32, bool, bool)> = sqlx::query_as(
        "SELECT status, retry_count, published_at IS NULL, dlx_at IS NULL \
         FROM outbox WHERE event_id = ANY($1) ORDER BY event_id",
    )
    .bind(event_ids.to_vec())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(states.len(), 3);
    assert!(
        states.iter().all(|state| {
            state == &(crate::outbox::STATUS_PUBLISHING.to_string(), 0, true, true)
        })
    );

    store.shutdown().await?;
    Ok(())
}

/// relay 已发布后若 settle 被数据库行锁阻塞，typed settle budget 必须返回 Transient；timeout 本身不得
/// 追加 retry/DLX/terminal 写入。释放锁并令原租约过期后，同一 event ID 可重新 claim 并正常收敛。
#[tokio::test(flavor = "multi_thread")]
async fn t9e_relay_settle_timeout_preserves_state_and_same_id_reclaim_converges() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t9e-settle-timeout");
    let domain = unique_domain("t9e-settle-timeout");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "settle.timeout");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let budget = RelayBudget::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_millis(250),
        Duration::from_secs(1),
    )?;
    set_test_relay_budget_policy(&store, budget).await?;
    let (publisher, control) = SettleLockPublisher::new();
    let outbox = make_pg_outbox_for_domain_with_budget(&store, domain.as_str(), publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    let relay_completed = tokio::sync::Notify::new();
    let relay_run = async {
        let result = outbox.relay(claim).await;
        relay_completed.notify_one();
        result
    };
    let lock_controller = async {
        control.first_publish_started.notified().await;
        let mut blocker = store.pool.begin().await?;
        let locked: String =
            sqlx::query_scalar("SELECT event_id FROM outbox WHERE event_id = $1 FOR UPDATE")
                .bind(&event_id)
                .fetch_one(&mut *blocker)
                .await?;
        assert_eq!(locked, event_id);
        control.release_first_publish.notify_one();
        relay_completed.notified().await;

        let durable_while_locked: (String, i32, bool, bool) = sqlx::query_as(
            "SELECT status, retry_count, published_at IS NULL, dlx_at IS NULL \
             FROM outbox WHERE event_id = $1",
        )
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(
            durable_while_locked,
            (crate::outbox::STATUS_PUBLISHING.to_string(), 0, true, true),
            "timeout must not append a terminal or retry state write"
        );
        let dead_letters: i64 =
            sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                .bind(&event_id)
                .fetch_one(&store.pool)
                .await?;
        assert_eq!(dead_letters, 0, "settle timeout must not directly DLX");

        // 在持锁事务内让原 capability 失效；即便被取消的旧 SQL 在解锁后到达，也只能 CAS miss。
        sqlx::query(
            "UPDATE outbox SET updated_at = clock_timestamp() - interval '11 seconds', \
             lease_until = clock_timestamp() - interval '1 second' WHERE event_id = $1",
        )
        .bind(&event_id)
        .execute(&mut *blocker)
        .await?;
        blocker.commit().await?;
        Ok::<(), TestError>(())
    };
    let (first_result, lock_controller_result) = tokio::join!(relay_run, lock_controller);
    lock_controller_result?;
    assert!(
        matches!(first_result, Err(error) if error.kind() == EngineErrorKind::Transient),
        "settle timeout must remain transient"
    );
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);

    let reclaimed = claim_entry_for_relay(&outbox, &event_id).await?;
    assert_eq!(reclaimed.idem_key().as_str(), event_id);
    assert_eq!(outbox.relay(reclaimed).await?, Disposition::Ack);
    assert_eq!(control.calls.load(Ordering::SeqCst), 2);

    let converged: (String, i32, bool, bool) = sqlx::query_as(
        "SELECT status, retry_count, published_at IS NOT NULL, dlx_at IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        converged,
        (crate::outbox::STATUS_PUBLISHED.to_string(), 0, true, true),
        "same-ID reclaim must converge after the timed-out settlement"
    );

    store.shutdown().await?;
    Ok(())
}

/// publish preflight 完成后耗尽唯一连接，证明 settlement 的 pool acquire 与 SQL/lock 共用同一绝对预算。
#[tokio::test(flavor = "multi_thread")]
async fn t9e_published_settle_pool_wait_is_bounded_and_preserves_state() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let event_id = unique_event_id("t9e-settle-pool-wait");
    let domain = unique_domain("t9e-settle-pool-wait");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "settle.pool.wait");
    owner
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let budget = RelayBudget::new(
        Duration::from_secs(10),
        Duration::from_secs(2),
        Duration::from_millis(250),
        Duration::from_secs(1),
    )?;
    set_test_relay_budget_policy(&owner, budget).await?;
    let p = pg.owner_params();
    let single_config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(Duration::from_secs(5));
    let single = PgStore::connect(&single_config).await?;
    let (publisher, control) = SettleLockPublisher::new();
    let outbox = make_pg_outbox_for_domain_with_budget(&single, domain.as_str(), publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    let relay_completed = tokio::sync::Notify::new();
    let relay_run = async {
        let result = outbox.relay(claim).await;
        relay_completed.notify_one();
        result
    };
    let exhaustion = async {
        control.first_publish_started.notified().await;
        let held = single.pool.acquire().await?;
        control.release_first_publish.notify_one();
        relay_completed.notified().await;
        drop(held);
        Ok::<(), TestError>(())
    };
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let (result, exhaustion_result) = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { tokio::join!(relay_run, exhaustion) })
        })
    });
    exhaustion_result?;
    assert!(matches!(result, Err(error) if error.kind() == EngineErrorKind::Transient));
    assert_single_settlement_failure_metric(&metrics_handle.render(), "published", "timeout");

    let durable: (String, i32, bool, bool) = sqlx::query_as(
        "SELECT status, retry_count, published_at IS NULL, dlx_at IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        durable,
        (crate::outbox::STATUS_PUBLISHING.to_owned(), 0, true, true)
    );

    single.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_expired_settlement_preflight_performs_no_pool_io() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let event_id = unique_event_id("settle-preflight-no-io");
    let domain = unique_domain("settle-preflight-no-io");
    let entry = make_entry(&event_id);
    let env = make_test_env(&domain, "settle.preflight.no.io");
    owner
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let budget = RelayBudget::new(
        Duration::from_millis(500),
        Duration::from_millis(100),
        Duration::from_millis(100),
        Duration::from_millis(100),
    )?;
    set_test_relay_budget_policy(&owner, budget).await?;
    let p = pg.owner_params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(Duration::from_secs(5));
    let single = PgStore::connect(&config).await?;
    let (publisher, _) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain_with_budget(&single, &domain, publisher, budget);
    let claim = claim_entry_for_relay(&outbox, &event_id).await?;
    let held = single.pool.acquire().await?;
    await_delay(Duration::from_millis(550)).await;

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let metrics_handle = recorder.handle();
    let outcome = metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(tokio::time::timeout(
                Duration::from_millis(50),
                outbox.test_published_settlement_outcome(&claim),
            ))
        })
    })
    .map_err(|_| "expired preflight attempted pool I/O")??;
    assert_eq!(outcome, "expired");
    assert_single_settlement_failure_metric(&metrics_handle.render(), "published", "expired");
    drop(held);

    let state: String = sqlx::query_scalar("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&owner.pool)
        .await?;
    assert_eq!(state, crate::outbox::STATUS_PUBLISHING);
    single.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_published_settlement_expired_emits_exactly_once() -> TestResult {
    assert_published_settlement_failure_metric(ForcedPublishedSettlementFailure::Expired).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_published_settlement_lost_lease_emits_exactly_once() -> TestResult {
    assert_published_settlement_failure_metric(ForcedPublishedSettlementFailure::LostLease).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_claim_pool_wait_does_not_consume_an_unminted_local_lease() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let (event_id, domain) = seed_timed_out_settle_entry(&owner, TimedOutSettlePath::Retry).await?;
    let budget = claim_clock_test_budget();
    set_test_relay_budget_policy(&owner, budget).await?;

    let p = pg.owner_params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(Duration::from_secs(5));
    let single = PgStore::connect(&config).await?;
    let (publisher, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain_with_budget(&single, &domain, publisher, budget);
    let held = single.pool.acquire().await?;

    let claim = claim_entry_for_relay(&outbox, &event_id);
    let release = async move {
        await_delay(Duration::from_millis(1_200)).await;
        drop(held);
        Ok::<(), TestError>(())
    };
    let (claim, released) = tokio::join!(claim, release);
    released?;
    let claim = claim?;
    assert_eq!(outbox.relay(claim).await?, Disposition::Ack);
    assert_eq!(*calls.lock().unwrap_or_else(|error| error.into_inner()), 1);

    single.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_claim_sql_delay_exhausts_local_budget_before_any_publish_io() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let (event_id, domain) = seed_timed_out_settle_entry(&owner, TimedOutSettlePath::Retry).await?;
    let budget = claim_clock_test_budget();
    set_test_relay_budget_policy(&owner, budget).await?;

    let p = pg.owner_params();
    let config = PgConfig::new(
        p.host.clone(),
        p.port,
        p.database.clone(),
        p.username.clone(),
        PgPassword::new(p.password.clone()),
    )
    .with_ssl_mode(PgSslMode::Prefer)
    .with_max_connections(1)
    .with_acquire_timeout(Duration::from_secs(5));
    let single = PgStore::connect(&config).await?;
    let (publisher, calls) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain_with_budget(&single, &domain, publisher, budget);

    let mut blocker = owner.pool.begin().await?;
    sqlx::query("LOCK TABLE event_delivery_policy IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let claim = claim_entry_for_relay(&outbox, &event_id);
    let release = async move {
        await_delay(Duration::from_millis(1_200)).await;
        blocker.commit().await?;
        Ok::<(), TestError>(())
    };
    let (claim, released) = tokio::join!(claim, release);
    released?;
    let result = outbox.relay(claim?).await;
    assert!(matches!(result, Err(error) if error.kind() == EngineErrorKind::Transient));
    assert_eq!(*calls.lock().unwrap_or_else(|error| error.into_inner()), 0);
    let status: String = sqlx::query_scalar("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&owner.pool)
        .await?;
    assert_eq!(status, crate::outbox::STATUS_PUBLISHING);

    single.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_retry_settle_pool_wait_is_bounded_and_preserves_state() -> TestResult {
    assert_settle_pool_wait_is_bounded(TimedOutSettlePath::Retry).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_ordinary_dlx_settle_pool_wait_is_bounded_and_preserves_state() -> TestResult {
    assert_settle_pool_wait_is_bounded(TimedOutSettlePath::OrdinaryDlx).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_retry_settle_timeout_preserves_state_then_converges_once() -> TestResult {
    assert_relay_settle_timeout_outcome(TimedOutSettlePath::Retry).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_ordinary_dlx_settle_timeout_preserves_state_then_converges_once() -> TestResult {
    assert_relay_settle_timeout_outcome(TimedOutSettlePath::OrdinaryDlx).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_same_id_expiry_settle_timeout_preserves_state_then_converges_once() -> TestResult {
    assert_relay_settle_timeout_outcome(TimedOutSettlePath::SameIdExpiryDlx).await
}

#[tokio::test(flavor = "multi_thread")]
async fn t9e_relay_rejects_lost_lease_before_publish() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_ids = [
        unique_event_id("t9d-publish-ok"),
        unique_event_id("t9d-publish-failed"),
    ];
    let domains = [
        unique_domain("t9e-publish-ok"),
        unique_domain("t9e-publish-failed"),
    ];
    for (event_id, domain) in event_ids.iter().zip(&domains) {
        let entry = make_entry(event_id);
        let env = make_test_env(domain, "lost.lease");
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    let (success_publisher, success_calls) = RecordingPublisher::always_ok();
    let success_relay = make_pg_outbox_for_domain(&store, &domains[0], success_publisher);
    let published_claim = claim_entry_for_relay(&success_relay, &event_ids[0]).await?;

    let (failed_publisher, failed_calls) = RecordingPublisher::always_transient();
    let failed_relay = make_pg_outbox_for_domain(&store, &domains[1], failed_publisher);
    let failed_claim = claim_entry_for_relay(&failed_relay, &event_ids[1]).await?;
    sqlx::query("UPDATE outbox SET lease_token = gen_random_uuid() WHERE event_id = ANY($1)")
        .bind(event_ids.to_vec())
        .execute(&store.pool)
        .await?;

    let Err(success_error) = success_relay.relay(published_claim).await else {
        return Err("lost lease must be rejected before publish".into());
    };
    assert_eq!(success_error.kind(), EngineErrorKind::Transient);

    let Err(failed_error) = failed_relay.relay(failed_claim).await else {
        return Err("lost lease must be rejected before failed publish attempt".into());
    };
    assert_eq!(failed_error.kind(), EngineErrorKind::Transient);

    #[allow(clippy::unwrap_used)]
    {
        assert_eq!(*success_calls.lock().unwrap(), 0);
        assert_eq!(*failed_calls.lock().unwrap(), 0);
    }
    let states: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT event_id, status, retry_count FROM outbox \
         WHERE event_id = ANY($1) ORDER BY event_id",
    )
    .bind(event_ids.to_vec())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(states.len(), 2);
    assert!(states.iter().all(|(_, status, retry_count)| {
        status == crate::outbox::STATUS_PUBLISHING && *retry_count == 0
    }));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn generated_fingerprint_allows_real_claim_settle_and_redrive() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let settled_id = unique_event_id("generated-permission-settle");
    let dlx_id = unique_event_id("generated-permission-redrive");
    for event_id in [&settled_id, &dlx_id] {
        let entry = make_entry(event_id);
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry, &make_test_env("generated_permission", "event"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox_for_domain(
        &store,
        "generated_permission",
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let claims = outbox.claim_batch(10).await?;
    let mut settled_claim = None;
    let mut dlx_claim = None;
    for claim in claims {
        if claim.idem_key().as_str() == settled_id {
            settled_claim = Some(claim);
        } else if claim.idem_key().as_str() == dlx_id {
            dlx_claim = Some(claim);
        }
    }
    let settled_claim = settled_claim.ok_or("missing generated-fingerprint settle claim")?;
    let settled_outcome: String =
        sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
            .bind(&settled_id)
            .bind(settled_claim.test_lease_token())
            .bind(settled_claim.test_lease_deadline_epoch_micros())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(settled_outcome, "settled");

    let dlx_claim = dlx_claim.ok_or("missing generated-fingerprint dlx claim")?;
    let marked: Option<(String,)> =
        sqlx::query_as("SELECT tenant_id FROM rss_outbox_mark_dlx($1, $2::uuid, $3)")
            .bind(&dlx_id)
            .bind(dlx_claim.test_lease_token())
            .bind(dlx_claim.test_lease_deadline_epoch_micros())
            .fetch_optional(&store.pool)
            .await?;
    assert!(
        marked.is_some(),
        "mark DLX must update the generated column row"
    );
    let redriven = direct_outbox_redrive(store.pool.clone(), test_tenant(), dlx_id.clone()).await?;
    assert_eq!(
        redriven, 1,
        "redrive must update exactly one generated column row"
    );

    let states: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT event_id, status, retry_count FROM outbox WHERE event_id = ANY($1) ORDER BY event_id",
    )
    .bind(vec![settled_id, dlx_id])
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(states.len(), 2);
    assert!(states.iter().any(|(_, status, _)| status == "published"));
    assert!(
        states
            .iter()
            .any(|(_, status, retry_count)| status == "pending" && *retry_count == 0)
    );

    store.shutdown().await?;
    Ok(())
}

/// PgEmitter::write 落 durable outbox：恰 1 行 pending，event_id(=EventId)/domain/topic 正确，
/// metadata 含标准 header + opaque subjectId（无完整 PII，FR-020）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——EventTopic/IdemKey parse 已知合法值；函数级 item-level carve-out（error-handling.md §Carve-out）。
async fn t10_pg_emitter_commits_one_pending_with_eventid_and_subject() -> TestResult {
    use eventexec::event::ReviewedEventWriter as _;

    let (_pg, store) = connect_pg().await?;
    // F5(#1194)：仅建表、不全表 DELETE——本用例按 unique `event_id` 隔离断言（`WHERE event_id = $1`），不需
    // 净表起点。#1194 现已全量收口：`setup_outbox` 亦不再全表 DELETE，全部 outbox 用例按 event_id + 专属
    // domain 自隔离（correct-by-construction，并发下亦不互污染）；此处直接 `run_migrations` 与之一致。
    store.run_migrations().await?;

    let event_id = unique_event_id("t10-emit");
    let tenant = test_tenant();
    let event = reviewed_session_event(
        &event_id,
        tenant,
        "subj-opaque-77",
        actor_for(tenant),
        uuid::Uuid::from_u128(0x2001),
    )
    .await?;
    crate::PgEmitter::new(&store, fixed_clock())
        .write(event)
        .await?;

    let row: (
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        serde_json::Value,
    ) = sqlx::query_as(
        "SELECT event_id, domain, topic, contract_id, contract_version, schema_hash, causation_id, status, metadata FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, event_id, "event_id = EventId");
    assert_eq!(row.1, "identity", "domain");
    assert_eq!(row.2, SESSION_CREATED_TOPIC, "topic");
    // contract_id 列 = ContractBinding.contract_id()（#1193 typed 绑定经 adapter 落库的 drift-lock）。
    assert_eq!(row.3, "identity.session-created", "contract_id");
    assert_eq!(row.4, "v1", "contract_version 物理列");
    assert_eq!(
        row.5,
        session_contract().schema_hash(),
        "schema_hash 物理列"
    );
    assert_eq!(row.6, None, "默认 causation_id 为 NULL");
    assert_eq!(row.7, "pending", "新 entry pending 待 relay");
    // metadata 含标准 header + opaque subjectId + actor + sealed 注入的 reserved occurred_at（#1129/#1618）；无完整 PII（FR-020 funnel）。
    assert_eq!(
        row.8.get("subjectId").and_then(serde_json::Value::as_str),
        Some("subj-opaque-77"),
        "metadata 应含 opaque subjectId: {}",
        row.8
    );
    assert_eq!(
        row.8.get("occurredAt").and_then(serde_json::Value::as_i64),
        Some(expected_occurred_at()),
        "metadata 应含 sealed 注入的 occurred_at（unix 秒，来自注入 Clock）: {}",
        row.8
    );
    assert_eq!(
        row.8
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str),
        Some("v1"),
        "metadata 应含 schemaVersion: {}",
        row.8
    );
    assert_eq!(
        row.8.get("schemaHash").and_then(serde_json::Value::as_str),
        Some(session_contract().schema_hash()),
        "metadata 应含 schemaHash: {}",
        row.8
    );
    let Some(actor) = row.8.get("actor") else {
        return Err(
            std::io::Error::other(format!("metadata should include actor: {}", row.8)).into(),
        );
    };
    assert_eq!(
        actor.get("kind").and_then(serde_json::Value::as_str),
        Some("admin"),
        "metadata.actor.kind 应落库: {}",
        row.8
    );
    assert_eq!(
        actor.get("id").and_then(serde_json::Value::as_str),
        Some("pg-integration-actor"),
        "metadata.actor.id 应落库: {}",
        row.8
    );
    let tenant_text = tenant.to_string();
    assert_eq!(
        actor.get("tenantId").and_then(serde_json::Value::as_str),
        Some(tenant_text.as_str()),
        "metadata.actor.tenantId 应落库: {}",
        row.8
    );
    assert_eq!(
        actor.get("scope").and_then(serde_json::Value::as_str),
        Some("tenant"),
        "metadata.actor.scope 应落库: {}",
        row.8
    );
    // 本写入发生在 diagctx scope 外；ambient correlation 必须 fail-open 为省略。
    // trace / principal 仍是尚未接入的 reserved key。
    for reserved in ["trace", "correlation", "principal"] {
        assert!(
            row.8.get(reserved).is_none(),
            "空接缝 reserved key {reserved} 本 PR 不应写入: {}",
            row.8
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// PG-EMITTER-AMBIENT-CORRELATION-01: `PgEmitter` must persist ambient correlation only while
/// the write future is inside the diagnostic scope.
#[tokio::test(flavor = "multi_thread")]
async fn t10c_pg_emitter_persists_only_scoped_ambient_correlation() -> TestResult {
    use eventexec::event::ReviewedEventWriter as _;

    const CORRELATION: &str = "pg-emitter-correlation-1399";

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant = test_tenant();
    let scoped_event_id = unique_event_id("t10c-scoped");
    let unscoped_event_id = unique_event_id("t10c-unscoped");
    let emitter = crate::PgEmitter::new(&store, fixed_clock());
    let scoped_event = reviewed_session_event(
        &scoped_event_id,
        tenant,
        "subject-scoped-correlation",
        actor_for(tenant),
        uuid::Uuid::from_u128(0x2002),
    )
    .await?;
    diagctx::scope(
        diagctx::DiagnosticCtx::new(diagctx::CorrelationId::parse(CORRELATION)?),
        emitter.write(scoped_event),
    )
    .await?;

    let unscoped_event = reviewed_session_event(
        &unscoped_event_id,
        tenant,
        "subject-unscoped-correlation",
        actor_for(tenant),
        uuid::Uuid::from_u128(0x2003),
    )
    .await?;
    emitter.write(unscoped_event).await?;

    let scoped_metadata: serde_json::Value =
        sqlx::query_scalar("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&scoped_event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        scoped_metadata
            .get("correlation")
            .and_then(serde_json::Value::as_str),
        Some(CORRELATION),
        "scoped PgEmitter write must persist the exact ambient correlation: {scoped_metadata}"
    );

    let unscoped_metadata: serde_json::Value =
        sqlx::query_scalar("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&unscoped_event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(
        unscoped_metadata.get("correlation").is_none(),
        "scope completion must not leak correlation into a later PgEmitter write: {unscoped_metadata}"
    );

    store.shutdown().await?;
    Ok(())
}

/// A generated event authored from a verified consumer handler persists the consumed envelope ID
/// as causation. The handler cannot pass that ID to the generated wrapper; the eventexec task-local
/// origin is therefore the only path that can populate this provider column.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
// reason: integration-test handler must return HandleResult rather than TestResult; known-valid
// fixtures and provider writes fail the test immediately through expect.
async fn t10b_pg_emitter_persists_verified_consumer_causation() -> TestResult {
    use eventexec::event::ReviewedEventWriter as _;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let parent_id = unique_event_id("t10-parent");
    let child_id = unique_event_id("t10-child");
    let group = unique_event_id("t10-causation-group");
    let tenant = test_tenant();
    let emitter = Arc::new(crate::PgEmitter::new(&store, fixed_clock()));
    let child_id_for_handler = child_id.clone();
    let handler = move |_message: Message| {
        let emitter = Arc::clone(&emitter);
        let child_id = child_id_for_handler.clone();
        Box::pin(async move {
            let event = reviewed_session_event(
                &child_id,
                tenant,
                "verified-consumer-child",
                actor_for(tenant),
                uuid::Uuid::from_u128(0x2004),
            )
            .await
            .expect("generated child event should encode");
            emitter
                .write(event)
                .await
                .expect("reviewed child event should persist");
            HandleResult::ack()
        }) as futures::future::BoxFuture<'static, HandleResult>
    };

    let (stream, acker) = conf_delivery_stream(&parent_id);
    run_consumer_ackable(
        stream,
        Arc::new(store.inbox()),
        (DynDeadLetterStore::new_box(store.dead_letter(test_dlx_payload_protector()))).as_ref(),
        &(conf_consumer_meta(&group)),
        &(handler),
        conf_lease_cfg(),
    )
    .await;

    assert_eq!(acker.exactly_one_action()?, AckAction::Ack);
    let causation_id: Option<String> =
        sqlx::query_scalar("SELECT causation_id FROM outbox WHERE event_id = $1")
            .bind(&child_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(causation_id.as_deref(), Some(parent_id.as_str()));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn outbox_cdc_emitter_appends_once_without_relay_outbox_fallback() -> TestResult {
    use eventexec::event::ReviewedEventWriter as _;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("outbox-cdc-emit");
    let tenant = test_tenant();
    let session_id = uuid::Uuid::from_u128(0x2005);
    let session_id_wire = session_id.hyphenated().to_string();
    let event = reviewed_session_event(
        &event_id,
        tenant,
        "cdc-subj-opaque-77",
        actor_for(tenant),
        session_id,
    )
    .await?;
    let emitter = crate::PgOutboxCdcEmitter::new(&store, fixed_clock());
    emitter.write(event.clone()).await?;
    emitter.write(event).await?;

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox_log WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(count.0, 1, "CDC emitter should append idempotently once");

    let row: OutboxCdcEmitterRow = sqlx::query_as(
        "SELECT tenant_id::text, aggregate_type, aggregate_id, topic, contract_id, \
                contract_version, schema_hash, payload, metadata, causation_id, \
                occurred_at, trace, correlation_id \
         FROM outbox_log \
         WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    let tenant_text = tenant.to_string();
    assert_eq!(row.0, tenant.to_string(), "tenant_id");
    assert_eq!(row.1, "identity", "aggregate_type");
    assert_eq!(row.2, "cdc-subj-opaque-77", "aggregate_id");
    assert_eq!(row.3, SESSION_CREATED_TOPIC, "topic");
    assert_eq!(row.4, "identity.session-created", "contract_id");
    assert_eq!(row.5, "v1", "contract_version");
    assert_eq!(row.6, session_contract().schema_hash(), "schema_hash");
    let payload: serde_json::Value = serde_json::from_slice(&row.7)?;
    assert_eq!(
        payload.get("sessionId").and_then(serde_json::Value::as_str),
        Some(session_id_wire.as_str())
    );
    assert_eq!(
        row.8.get("tenantId").and_then(serde_json::Value::as_str),
        Some(tenant_text.as_str()),
        "metadata tenantId"
    );
    assert_eq!(
        row.8
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str),
        Some("v1"),
        "metadata schemaVersion"
    );
    assert_eq!(
        row.8.get("schemaHash").and_then(serde_json::Value::as_str),
        Some(session_contract().schema_hash()),
        "metadata schemaHash"
    );
    assert_eq!(row.9, None, "generated event has no causation override");
    let expected_occurred_at_header = expected_occurred_at().to_string();
    assert_eq!(
        row.10.as_deref(),
        Some(expected_occurred_at_header.as_str()),
        "occurred_at generated column"
    );
    assert_eq!(row.11, None, "trace generated column");
    assert_eq!(row.12, None, "correlation_id generated column");

    let relay_count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        relay_count.0, 0,
        "CDC emitter must not fallback to relay outbox"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn outbox_cdc_emitter_rejects_event_id_conflict_with_different_payload() -> TestResult {
    use eventexec::event::ReviewedEventWriter as _;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("outbox-cdc-conflict");
    let tenant = test_tenant();
    let first_session_id = uuid::Uuid::from_u128(0x2006);
    let second_session_id = uuid::Uuid::from_u128(0x2007);
    let first_session_wire = first_session_id.hyphenated().to_string();
    let second_session_wire = second_session_id.hyphenated().to_string();
    let first = reviewed_session_event(
        &event_id,
        tenant,
        "cdc-conflict-subject",
        actor_for(tenant),
        first_session_id,
    )
    .await?;
    let second = reviewed_session_event(
        &event_id,
        tenant,
        "cdc-conflict-subject",
        actor_for(tenant),
        second_session_id,
    )
    .await?;
    let emitter = crate::PgOutboxCdcEmitter::new(&store, fixed_clock());
    emitter.write(first).await?;
    let conflict = emitter.write(second).await;
    let Err(conflict) = conflict else {
        return Err("same event_id with different immutable CDC payload must fail".into());
    };
    assert_eq!(conflict.kind(), OutboxEmitErrorKind::FactConflict);
    let rendered = format!("{conflict:?} {conflict}");
    for secret in [
        first_session_wire.clone(),
        second_session_wire,
        "cdc-conflict-subject".to_owned(),
        "fingerprint".to_owned(),
    ] {
        assert!(
            !rendered.contains(&secret),
            "typed CDC fact conflict must redact `{secret}`: {rendered}"
        );
    }

    let row: (i64, Vec<u8>) =
        sqlx::query_as("SELECT count(*) OVER (), payload FROM outbox_log WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0, 1, "event_id conflict must not append a second row");
    let payload: serde_json::Value = serde_json::from_slice(&row.1)?;
    assert_eq!(
        payload.get("sessionId").and_then(serde_json::Value::as_str),
        Some(first_session_wire.as_str()),
        "event_id conflict must preserve the original immutable row"
    );

    store.shutdown().await?;
    Ok(())
}

/// t24：append 3 行（同 domain，无 partition）→ SELECT seq 严格递增、互异、非空；
/// 尝试 INSERT 显式写 seq 被 GENERATED ALWAYS 拒（应用不可伪造）。
///
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t24_seq_monotonic_and_app_cannot_forge() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t24");
    let ids: Vec<_> = (0..3)
        .map(|i| unique_event_id(&format!("t24-{i}")))
        .collect();

    // append 3 行，无 partition。
    for eid in &ids {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c");
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // SELECT seq 并验证严格递增、互异、非空。
    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM outbox WHERE event_id = ANY($1::text[]) ORDER BY seq ASC",
    )
    .bind(ids.as_slice())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(seqs.len(), 3, "t24: 应有 3 行 seq");
    for w in seqs.windows(2) {
        assert!(
            w[0] < w[1],
            "t24: seq 应严格递增，实际 {} >= {}",
            w[0],
            w[1]
        );
    }

    // GENERATED ALWAYS 拒绝应用显式写入 seq。
    let fake_seq: i64 = 999_999_999;
    let forge_id = unique_event_id("t24-forge");
    let forge_env = make_test_env(&domain, "c");
    let forge_result = sqlx::query(
        "INSERT INTO outbox (
             event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
             payload, metadata, status, seq
         ) VALUES ($1, $2::uuid, $3, 'test.event', 'c', $4, $5, $6, $7::jsonb, 'pending', $8)",
    )
    .bind(&forge_id)
    .bind(forge_env.tenant().to_string())
    .bind(&domain)
    .bind(forge_env.contract_version())
    .bind(forge_env.schema_hash())
    .bind(b"p".as_slice())
    .bind(forge_env.metadata_json())
    .bind(fake_seq)
    .execute(&store.pool)
    .await;
    let Err(forge_err) = forge_result else {
        return Err("t24: GENERATED ALWAYS 应拒绝应用写入 seq（反真空：伪造尝试必须失败）".into());
    };
    let rendered = forge_err.to_string();
    assert!(
        rendered.contains("non-DEFAULT value") || rendered.contains("GENERATED ALWAYS"),
        "t24: 伪造 seq 必须由 GENERATED ALWAYS 拒绝，而不是被其它约束挡住: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// t25：同 (domain, 'p1') partition → `claim_batch` 仅返队头；relay → published → claim → 后继。
///
/// 反真空：S2/S3 在 H 未 published 前缺席（head-of-partition gating 生效）。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t25_partition_serial_in_order() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t25");
    let key = PartitionKey::parse("p1").unwrap();

    let h_id = unique_event_id("t25-H");
    let s2_id = unique_event_id("t25-S2");
    let s3_id = unique_event_id("t25-S3");

    // append H, S2, S3 同 (domain, 'p1')——顺序由 seq 的 IDENTITY 单调递增保证。
    for eid in [&h_id, &s2_id, &s3_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let (pub_ok, _) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain(&store, &domain, pub_ok);

    // claim → 仅 H（S2/S3 被 gate）。
    let entries = outbox.claim_batch(10).await?;
    assert_eq!(entries.len(), 1, "t25: 首轮 claim 应仅返队头 H");
    assert_eq!(
        entries[0].idem_key().as_str(),
        h_id,
        "t25: 首轮 claim 必须是 H"
    );
    // 反真空：S2/S3 确实缺席。
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t25: S2 不应出现（被 gate）"
    );
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s3_id),
        "t25: S3 不应出现（被 gate）"
    );

    // relay H → published。
    let h_entry = entries.into_iter().next().unwrap();
    let disp = outbox.relay(h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t25: relay H 应返 Ack");

    // claim → S2（H 已 published，S2 现在是队头）。
    let entries2 = outbox.claim_batch(10).await?;
    assert_eq!(entries2.len(), 1, "t25: 第二轮 claim 应仅返 S2");
    assert_eq!(
        entries2[0].idem_key().as_str(),
        s2_id,
        "t25: 第二轮 claim 必须是 S2"
    );
    // 反真空：S3 第二轮仍被 gate（与首轮 S3 缺席对称）。
    assert!(
        !entries2.iter().any(|e| e.idem_key().as_str() == s3_id),
        "t25: S3 第二轮仍被 gate 不应出现"
    );

    // relay S2 → published。
    let s2_entry = entries2.into_iter().next().unwrap();
    outbox.relay(s2_entry).await?;

    // claim → S3。
    let entries3 = outbox.claim_batch(10).await?;
    assert_eq!(entries3.len(), 1, "t25: 第三轮 claim 应仅返 S3");
    assert_eq!(
        entries3[0].idem_key().as_str(),
        s3_id,
        "t25: 第三轮 claim 必须是 S3"
    );

    store.shutdown().await?;
    Ok(())
}

/// t26：跨 partition 不互阻 + NULL-partition 无序并行路径不变。
///
/// 同 domain 下：p1-head + p2-head + 2 个 NULL-partition 行 → 一轮 claim 返 4 行。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t26_cross_partition_and_null_parallel() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t26");

    let p1_key = PartitionKey::parse("p1").unwrap();
    let p2_key = PartitionKey::parse("p2").unwrap();

    // p1-head, p2-head, null1, null2。
    let p1_id = unique_event_id("t26-p1");
    let p2_id = unique_event_id("t26-p2");
    let n1_id = unique_event_id("t26-null1");
    let n2_id = unique_event_id("t26-null2");

    // p1-head
    {
        let entry = make_entry(&p1_id);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(p1_key));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    // p2-head
    {
        let entry = make_entry(&p2_id);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(p2_key));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    // null1, null2（无 partition）。
    for nid in [&n1_id, &n2_id] {
        let entry = make_entry(nid);
        let env = make_test_env(&domain, "c");
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let entries = outbox.claim_batch(10).await?;
    assert_eq!(
        entries.len(),
        4,
        "t26: p1-head + p2-head + null1 + null2 = 4 行（跨 partition 不互阻，NULL 不约束）"
    );

    // 验证四个预期 ID 都在返回集合中。
    let ids_in: Vec<&str> = entries.iter().map(|e| e.idem_key().as_str()).collect();
    for expected in [
        p1_id.as_str(),
        p2_id.as_str(),
        n1_id.as_str(),
        n2_id.as_str(),
    ] {
        assert!(
            ids_in.contains(&expected),
            "t26: {expected} 应在 claim 结果中"
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// t27：dlx 队头阻塞 partition，re-drive 后恢复。
///
/// append H, S2 同 partition；强制 H→dlx；claim 该 partition 空；
/// re-drive H → relay → published → claim → S2。
/// 反真空：NULL-partition dlx 行不阻塞任何东西。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t27_dlx_head_blocks_then_unblocks() -> TestResult {
    use consistency::PartitionKey;
    use eventexec::{DlqRedriveOutcome, DlqRedriveRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;

    let domain = unique_domain("t27");
    let key = PartitionKey::parse("part-dlx").unwrap();

    let h_id = unique_event_id("t27-H");
    let s2_id = unique_event_id("t27-S2");

    // append H, S2 同 (domain, 'part-dlx')。
    for eid in [&h_id, &s2_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // 强制 H → dlx（直接 UPDATE status）。
    set_outbox_terminal_for_test(&store, &h_id, "dlx", 0).await?;

    // claim → 该 partition 空（H 在 dlx，S2 被 gate）。
    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let blocked = outbox.claim_batch(10).await?;
    assert!(
        blocked.is_empty(),
        "t27: dlx 队头必须完全阻塞 partition（blocked={blocked:?}）"
    );

    // 反真空：NULL-partition dlx 行不阻塞任何东西。
    let null_dlx_id = unique_event_id("t27-null-dlx");
    let null_live_id = unique_event_id("t27-null-live");
    for eid in [&null_dlx_id, &null_live_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c"); // no partition
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    set_outbox_terminal_for_test(&store, &null_dlx_id, "dlx", 0).await?;

    let after_null_dlx = outbox.claim_batch(10).await?;
    assert!(
        after_null_dlx
            .iter()
            .any(|e| e.idem_key().as_str() == null_live_id),
        "t27: NULL-partition dlx 不阻塞 null_live 行（反真空）"
    );

    // re-drive H：经 DLQ store 固定函数把 H 从 dlx 重置回 pending。
    let dlq = maintenance.dlq_store_without_payload_replay();
    let redrive = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            dlq_authorization(test_tenant()),
            IdemKey::parse(&h_id).unwrap(),
        ))
        .await?;
    assert_eq!(redrive.outcome(), &DlqRedriveOutcome::Redriven);

    // relay H → published。
    let redriven = outbox.claim_batch(10).await?;
    let h_entry = redriven
        .into_iter()
        .find(|e| e.idem_key().as_str() == h_id)
        .expect("t27: re-drive 后 H 应出现在 claim 结果中");
    let disp = outbox.relay(h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t27: relay H 应返 Ack");

    // claim → S2 现在可见。
    let unblocked = outbox.claim_batch(10).await?;
    assert!(
        unblocked.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t27: H published 后 S2 应解除阻塞"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// t27b：跨租户同 `(domain, partition_key)` 不互阻。
///
/// tenant A 队头进 dlx 后，只能阻塞 tenant A 同 partition 后继；tenant B 使用相同业务 key 的行仍可投递。
/// INVARIANT: OUTBOX-TENANT-PARTITION-ORDER-01 { level = "Hard", exec = "native-compile", source = "code", native = "migration 0031 tenant-scopes outbox partition ordering keys" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t27b_outbox_cross_tenant_partition_dlx_does_not_block() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t27b");
    let key = PartitionKey::parse("shared-business-key").unwrap();
    let tenant_a = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B).unwrap();
    let a_head = unique_event_id("t27b-a-head");
    let a_tail = unique_event_id("t27b-a-tail");
    let b_head = unique_event_id("t27b-b-head");

    for (tenant, eid) in [
        (tenant_a, &a_head),
        (tenant_a, &a_tail),
        (tenant_b, &b_head),
    ] {
        let entry = make_entry(eid);
        let env = make_test_env_for_tenant(&domain, "c", tenant)
            .with_partition_key_opt(Some(key.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(tenant, move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    set_outbox_terminal_for_test(&store, &a_head, "dlx", 0).await?;

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );
    let claimed = outbox.claim_batch(10).await?;
    let ids: Vec<&str> = claimed
        .iter()
        .map(|entry| entry.idem_key().as_str())
        .collect();
    assert!(
        ids.contains(&b_head.as_str()),
        "tenant B same partition key must remain claimable; got {ids:?}"
    );
    assert!(
        !ids.contains(&a_tail.as_str()),
        "tenant A tail must stay blocked by tenant A dlx head; got {ids:?}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_terminal_timestamp_checks_reject_invalid_state_combinations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    for (suffix, status) in [
        ("legal-pending", "pending"),
        ("legal-publishing", "publishing"),
        ("legal-published", "published"),
        ("legal-dlx", "dlx"),
    ] {
        let event_id = unique_event_id(suffix);
        let entry = make_entry(&event_id);
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry, &make_test_env("terminal-check", "event"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        set_outbox_terminal_for_test(&store, &event_id, status, 0).await?;
    }

    let invalid = [
        (
            "pending-with-published",
            "pending",
            true,
            false,
            "outbox_published_at_matches_status",
        ),
        (
            "publishing-with-dlx",
            "publishing",
            false,
            true,
            "outbox_dlx_at_matches_status",
        ),
        (
            "published-without-time",
            "published",
            false,
            false,
            "outbox_published_at_matches_status",
        ),
        (
            "published-with-dlx",
            "published",
            true,
            true,
            "outbox_dlx_at_matches_status",
        ),
        (
            "dlx-without-time",
            "dlx",
            false,
            false,
            "outbox_dlx_at_matches_status",
        ),
        (
            "dlx-with-published",
            "dlx",
            true,
            true,
            "outbox_published_at_matches_status",
        ),
    ];
    for (suffix, status, has_published_at, has_dlx_at, constraint) in invalid {
        let event_id = unique_event_id(suffix);
        let entry = make_entry(&event_id);
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                Box::pin(async move {
                    let _outcome =
                        append_outbox(cap, &entry, &make_test_env("terminal-check", "event"))
                            .await
                            .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        let result = sqlx::query(
            r#"
            UPDATE outbox
            SET status = $1,
                lease_token = CASE WHEN $1 = 'publishing' THEN gen_random_uuid() ELSE NULL END,
                lease_until = CASE
                    WHEN $1 = 'publishing' THEN now() + interval '60 seconds'
                    ELSE NULL
                END,
                automatic_retry_deadline = CASE
                    WHEN $1 IN ('publishing', 'published', 'dlx') THEN
                        COALESCE(automatic_retry_deadline, now() + interval '24 hours')
                    ELSE automatic_retry_deadline
                END,
                same_id_redrive_deadline = CASE
                    WHEN $1 = 'dlx' THEN
                        COALESCE(same_id_redrive_deadline, now() + interval '24 hours')
                    ELSE same_id_redrive_deadline
                END,
                published_at = CASE WHEN $2 THEN now() ELSE NULL END,
                dlx_at = CASE WHEN $3 THEN now() ELSE NULL END
            WHERE event_id = $4
            "#,
        )
        .bind(status)
        .bind(has_published_at)
        .bind(has_dlx_at)
        .bind(&event_id)
        .execute(&store.pool)
        .await;
        let Err(error) = result else {
            return Err(
                format!("invalid terminal fixture unexpectedly persisted: {suffix}").into(),
            );
        };
        assert!(
            error.to_string().contains(constraint),
            "unexpected constraint for {suffix}: {error}"
        );
    }

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_terminal_timestamp_and_routine_catalog_match_current_authority() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let indexdef: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_outbox_sweep'",
    )
    .fetch_one(&store.pool)
    .await?;
    let normalized_index = indexdef.to_ascii_lowercase();
    assert!(normalized_index.contains("(published_at)"));
    assert!(normalized_index.contains("where (status = 'published'::text)"));
    assert!(!normalized_index.contains("created_at"));

    let sweep_def: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('rss_sweep_outbox_published(bigint)'::regprocedure)",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(sweep_def.contains("p_retain_seconds <= 0"));
    assert!(sweep_def.contains("published_at <="));
    assert!(!sweep_def.contains("created_at"));

    let observed: Vec<OutboxRoutineObservation> = sqlx::query_as(
        r#"
        SELECT p.oid::regprocedure::text AS signature,
               owner.rolname AS owner,
               owner.rolcanlogin AS owner_can_login,
               p.prosecdef AS security_definer,
               COALESCE(
                   'search_path=public, pg_temp' = ANY(p.proconfig),
                   false
               ) AS fixed_search_path,
               EXISTS (
                   SELECT 1
                   FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                   WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
               ) AS public_execute,
               has_function_privilege('rss_app', p.oid, 'EXECUTE') AS app_execute,
               has_function_privilege(
                   'rss_outbox_maintenance', p.oid, 'EXECUTE'
               ) AS maintenance_execute,
               has_function_privilege(
                   'rss_l2_dr_recovery_owner', p.oid, 'EXECUTE'
               ) AS recovery_execute
        FROM pg_proc p
        JOIN pg_namespace namespace ON namespace.oid = p.pronamespace
        JOIN pg_roles owner ON owner.oid = p.proowner
        WHERE namespace.nspname = 'public'
          AND (
              starts_with(p.proname, 'rss_outbox_')
              OR p.proname = 'rss_sweep_outbox_published'
          )
        ORDER BY p.oid::regprocedure::text
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    validate_outbox_routine_catalog(&observed)?;

    let outcome_type_acl: (String, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT owner.rolname,
               owner.rolcanlogin,
               NOT EXISTS (
                   SELECT 1
                   FROM aclexplode(COALESCE(t.typacl, acldefault('T', t.typowner))) acl
                   WHERE acl.grantee = 0 AND acl.privilege_type = 'USAGE'
               ),
               has_type_privilege('rss_app', t.oid, 'USAGE')
        FROM pg_type AS t
        JOIN pg_namespace AS n ON n.oid = t.typnamespace
        JOIN pg_roles AS owner ON owner.oid = t.typowner
        WHERE n.nspname = 'public' AND t.typname = 'rss_outbox_settlement_outcome'
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(outcome_type_acl.0, "rss_outbox_maintenance");
    assert!(!outcome_type_acl.1, "settlement type owner must be NOLOGIN");
    assert!(outcome_type_acl.2, "PUBLIC type USAGE must be revoked");
    assert!(outcome_type_acl.3, "rss_app type USAGE grant missing");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn event_delivery_policy_constraints_loader_and_acl_fail_closed() -> TestResult {
    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let app = connect_pg_rss_app_role(&pg, &store).await?;

    let privileges: (bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT has_table_privilege('rss_app', 'event_delivery_policy', 'SELECT'),
               has_table_privilege('rss_app', 'event_delivery_policy', 'INSERT'),
               has_table_privilege('rss_app', 'event_delivery_policy', 'UPDATE'),
               has_table_privilege('rss_app', 'event_delivery_policy', 'DELETE'),
               has_function_privilege('rss_app', 'rss_outbox_redrive(text, uuid)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_resolve_expired(text, uuid, text, text, text, text)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_sweep_inbox_receipts()', 'EXECUTE')
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        privileges,
        (false, false, false, false, false, false, true, true)
    );
    let policy_owner: String = sqlx::query_scalar(
        "SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'event_delivery_policy'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(policy_owner, "rss_outbox_maintenance");

    let policy_probe_acl: (String, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT owner.rolname,
               owner.rolcanlogin,
               procedure.prosecdef,
               procedure.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[],
               has_function_privilege('rss_app', procedure.oid, 'EXECUTE'),
               NOT EXISTS (
                   SELECT 1
                   FROM aclexplode(
                       COALESCE(procedure.proacl, acldefault('f', procedure.proowner))
                   ) AS acl
                   WHERE acl.grantee = 0
                     AND acl.privilege_type = 'EXECUTE'
               ),
               has_schema_privilege('rss_app', 'public', 'USAGE'),
               has_schema_privilege('rss_app', 'public', 'CREATE')
        FROM pg_proc AS procedure
        JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        JOIN pg_roles AS owner ON owner.oid = procedure.proowner
        WHERE namespace.nspname = 'public'
          AND procedure.proname = 'rss_load_event_delivery_policy'
          AND pg_get_function_identity_arguments(procedure.oid) = ''
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        policy_probe_acl,
        (
            "rss_outbox_maintenance".to_owned(),
            false,
            true,
            true,
            true,
            true,
            true,
            false,
        ),
        "delivery policy probe must have a NOLOGIN owner, trusted search_path, exact EXECUTE grants and read-only schema access"
    );

    let resolution_acl: (bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT has_table_privilege('rss_app', 'outbox_expired_resolutions', 'SELECT'),
               has_table_privilege('rss_app', 'outbox_expired_resolutions', 'INSERT'),
               has_table_privilege('rss_app', 'outbox_expired_resolutions', 'UPDATE'),
               has_table_privilege('rss_app', 'outbox_expired_resolutions', 'DELETE'),
               has_table_privilege('rss_outbox_maintenance', 'outbox_expired_resolutions', 'SELECT'),
               has_table_privilege('rss_outbox_maintenance', 'outbox_expired_resolutions', 'INSERT'),
               has_table_privilege('rss_outbox_maintenance', 'outbox_expired_resolutions', 'UPDATE'),
               has_table_privilege('rss_outbox_maintenance', 'outbox_expired_resolutions', 'DELETE')
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        resolution_acl,
        (false, false, false, false, true, true, false, false),
        "resolution evidence is maintenance-only append-only data"
    );

    let old_functions: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT to_regprocedure('rss_outbox_lease_can_publish(text,uuid,bigint)')::text, \
                to_regprocedure('rss_sweep_inbox_receipts(bigint)')::text",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(old_functions, (None, None));

    let table_insert =
        sqlx::query_scalar::<_, bool>("SELECT has_table_privilege('rss_app', 'outbox', 'INSERT')")
            .fetch_one(&store.pool)
            .await?;
    assert!(
        !table_insert,
        "rss_app must not retain table-wide outbox INSERT"
    );
    let insert_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.column_privileges
        WHERE table_schema = 'public'
          AND table_name = 'outbox'
          AND grantee = 'rss_app'
          AND privilege_type = 'INSERT'
        ORDER BY column_name
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        insert_columns,
        [
            "causation_id",
            "contract_id",
            "contract_version",
            "domain",
            "event_id",
            "metadata",
            "partition_key",
            "payload",
            "schema_hash",
            "tenant_id",
            "topic",
        ],
        "rss_app may insert only immutable outbox fact inputs"
    );

    let allowed_event_id = unique_event_id("outbox-column-grant-allowed");
    let metadata = serde_json::json!({
        "tenantId": COTX_TENANT_A,
        "schemaVersion": "v1",
        "schemaHash": TEST_SCHEMA_HASH,
    })
    .to_string();
    {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(COTX_TENANT_A)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO outbox (
                event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
                payload, metadata, partition_key, causation_id
            )
            VALUES ($1, $2::uuid, 'test', 'test.event', 'test.contract', 'v1', $3,
                    decode('00', 'hex'), $4::jsonb, NULL, NULL)
            "#,
        )
        .bind(&allowed_event_id)
        .bind(COTX_TENANT_A)
        .bind(TEST_SCHEMA_HASH)
        .bind(&metadata)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    let allowed_state: (String, String, bool, bool) = sqlx::query_as(
        "SELECT status, same_id_delivery_phase, automatic_retry_deadline IS NULL, \
                same_id_redrive_deadline IS NULL FROM outbox WHERE event_id = $1",
    )
    .bind(&allowed_event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        allowed_state,
        ("pending".to_string(), "automatic".to_string(), true, true),
        "fact-only INSERT must obtain the database-owned initial state"
    );

    for (event_id, forged_column, forged_value) in [
        (
            unique_event_id("outbox-forge-automatic-deadline"),
            "automatic_retry_deadline",
            "clock_timestamp() + interval '100 years'",
        ),
        (
            unique_event_id("outbox-forge-redrive-infinity"),
            "same_id_redrive_deadline",
            "timestamptz 'infinity'",
        ),
    ] {
        let mut tx = app.pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(COTX_TENANT_A)
            .execute(&mut *tx)
            .await?;
        let statement = format!(
            r#"
            INSERT INTO outbox (
                event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash,
                payload, metadata, partition_key, causation_id, {forged_column}
            )
            VALUES ($1, $2::uuid, 'test', 'test.event', 'test.contract', 'v1', $3,
                    decode('00', 'hex'), $4::jsonb, NULL, NULL, {forged_value})
            "#
        );
        let forged = sqlx::query(&statement)
            .bind(&event_id)
            .bind(COTX_TENANT_A)
            .bind(TEST_SCHEMA_HASH)
            .bind(&metadata)
            .execute(&mut *tx)
            .await;
        assert!(
            matches!(
                forged,
                Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")
            ),
            "rss_app deadline forgery must fail by column ACL: {forged:?}"
        );
        tx.rollback().await?;
        let inserted: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(
            inserted, 0,
            "rejected deadline forgery must not insert a row"
        );
    }

    for statement in [
        "UPDATE event_delivery_policy SET automatic_retry_window_seconds = 0",
        "UPDATE event_delivery_policy SET same_id_redrive_horizon_seconds = -1",
        "UPDATE event_delivery_policy SET inbox_receipt_retention_seconds = automatic_retry_window_seconds + same_id_redrive_horizon_seconds + safety_margin_seconds",
        "UPDATE event_delivery_policy SET automatic_retry_window_seconds = 9223372036854775807, same_id_redrive_horizon_seconds = 9223372036854775807, safety_margin_seconds = 9223372036854775807, inbox_receipt_retention_seconds = 9223372036854775807",
        "UPDATE event_delivery_policy SET relay_lease_ttl_ms = 0",
        "UPDATE event_delivery_policy SET relay_lease_ttl_ms = 86400001",
        "UPDATE event_delivery_policy SET relay_publish_timeout_ms = relay_lease_ttl_ms - relay_settle_timeout_ms - relay_safety_margin_ms",
        "INSERT INTO event_delivery_policy (singleton, policy_revision, automatic_retry_window_seconds, same_id_redrive_horizon_seconds, safety_margin_seconds, inbox_receipt_retention_seconds, relay_budget_revision, relay_lease_ttl_ms, relay_publish_timeout_ms, relay_settle_timeout_ms, relay_safety_margin_ms) VALUES (true, 'same-id-delivery-v1', 86400, 86400, 86400, 604800, 'relay-budget-v1', 60000, 40000, 5000, 5000)",
    ] {
        let result = sqlx::query(statement).execute(&store.pool).await;
        assert!(
            result.is_err(),
            "policy constraint must reject: {statement}"
        );
    }

    sqlx::query(
        "UPDATE event_delivery_policy SET relay_publish_timeout_ms = relay_publish_timeout_ms - 1",
    )
    .execute(&store.pool)
    .await?;
    let alternate_policy = store.load_event_delivery_policy().await?;
    let alternate_budget = RelayBudget::new(
        Duration::from_secs(60),
        Duration::from_millis(39_999),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?;
    assert!(
        alternate_policy
            .validate_relay_budget(alternate_budget)
            .is_ok()
    );
    assert!(matches!(
        alternate_policy.validate_relay_budget(test_relay_budget()),
        Err(crate::PgError::EventDeliveryPolicyMismatch)
    ));
    sqlx::query(
        "UPDATE event_delivery_policy SET relay_publish_timeout_ms = relay_publish_timeout_ms + 1",
    )
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "UPDATE event_delivery_policy SET automatic_retry_window_seconds = automatic_retry_window_seconds + 1",
    )
    .execute(&store.pool)
    .await?;
    assert!(matches!(
        store.load_event_delivery_policy().await,
        Err(crate::PgError::EventDeliveryPolicyMismatch)
    ));
    sqlx::query("DELETE FROM event_delivery_policy")
        .execute(&store.pool)
        .await?;
    assert!(matches!(
        store.load_event_delivery_policy().await,
        Err(crate::PgError::EventDeliveryPolicyMismatch)
    ));

    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn outbox_same_id_checks_reject_each_invalid_state_without_mutation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let event_id = unique_event_id("outbox-same-id-checks");
    let entry = make_entry(&event_id);
    let env = make_test_env("same_id_check", "test.contract");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    type RowSnapshot = (String, String);
    let snapshot: RowSnapshot = sqlx::query_as(
        "SELECT to_jsonb(o)::text, o.xmin::text FROM outbox AS o WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    let invalid_updates = [
        (
            "phase closed",
            "UPDATE outbox SET same_id_delivery_phase = 'invalid' WHERE event_id = $1",
        ),
        (
            "publishing requires automatic deadline",
            "UPDATE outbox SET status = 'publishing', lease_token = gen_random_uuid(), \
             lease_until = clock_timestamp() + interval '1 hour' WHERE event_id = $1",
        ),
        (
            "published requires automatic deadline",
            "UPDATE outbox SET status = 'published', published_at = clock_timestamp() \
             WHERE event_id = $1",
        ),
        (
            "dlx requires redrive deadline",
            "UPDATE outbox SET status = 'dlx', dlx_at = clock_timestamp(), \
             automatic_retry_deadline = clock_timestamp() + interval '1 hour' \
             WHERE event_id = $1",
        ),
        (
            "redrive phase requires redrive deadline",
            "UPDATE outbox SET same_id_delivery_phase = 'redrive', \
             automatic_retry_deadline = clock_timestamp() + interval '1 hour' \
             WHERE event_id = $1",
        ),
        (
            "redrive deadline requires automatic deadline",
            "UPDATE outbox SET same_id_redrive_deadline = clock_timestamp() + interval '1 hour' \
             WHERE event_id = $1",
        ),
    ];
    for (case, statement) in invalid_updates {
        let rejected = sqlx::query(statement)
            .bind(&event_id)
            .execute(&store.pool)
            .await;
        assert!(
            matches!(
                rejected,
                Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("23514")
            ),
            "{case} must fail by CHECK: {rejected:?}"
        );
        let after: RowSnapshot = sqlx::query_as(
            "SELECT to_jsonb(o)::text, o.xmin::text FROM outbox AS o WHERE event_id = $1",
        )
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
        assert_eq!(after, snapshot, "{case} must leave the row unchanged");
    }

    store.shutdown().await?;
    Ok(())
}

/// 0031 权限面：rss_app 不能直接全域 UPDATE/DELETE outbox，只能 EXECUTE 固定 relay/maintenance 函数。
#[tokio::test(flavor = "multi_thread")]
async fn outbox_rss_app_uses_fixed_functions_not_direct_global_dml() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let event_id = unique_event_id("outbox-rss-app-perm");
    let entry = make_entry(&event_id);
    let env = make_test_env("outbox-perm", "c");
    store
        .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
            let entry = entry.clone();
            Box::pin(async move {
                let _outcome = append_outbox(cap, &entry, &env)
                    .await
                    .map_err(test_append_error)?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let mut tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *tx)
        .await?;
    crate::cotx::set_local_tenant(&mut tx, test_tenant()).await?;
    let direct_update = sqlx::query("UPDATE outbox SET retry_count = -1 WHERE event_id = $1")
        .bind(&event_id)
        .execute(&mut *tx)
        .await;
    assert!(
        direct_update.is_err(),
        "rss_app must not directly forge retry_count"
    );
    tx.rollback().await?;

    let invalid_retry_count = sqlx::query("UPDATE outbox SET retry_count = -1 WHERE event_id = $1")
        .bind(&event_id)
        .execute(&store.pool)
        .await;
    let Err(invalid_retry_count_error) = invalid_retry_count else {
        return Err("negative retry_count must fail the table CHECK".into());
    };
    assert!(
        invalid_retry_count_error
            .to_string()
            .contains("outbox_retry_count_nonnegative"),
        "unexpected retry_count CHECK error: {invalid_retry_count_error}"
    );

    for (limit_sql, expected) in [
        ("NULL::bigint", "limit must be in range"),
        ("0", "limit must be in range"),
        ("10001", "limit must be in range"),
    ] {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        crate::cotx::set_local_tenant(&mut tx, test_tenant()).await?;
        let relay_budget = test_relay_budget();
        let result = sqlx::query(&format!(
            "SELECT * FROM rss_outbox_claim_batch('outbox-perm', {limit_sql}, $1, $2)"
        ))
        .bind(relay_budget.lease_ttl_millis())
        .bind(relay_budget.required_budget_millis())
        .execute(&mut *tx)
        .await;
        let Err(err) = result else {
            return Err("rss_app claim_batch must reject invalid limits".into());
        };
        assert!(
            err.to_string().contains(expected),
            "unexpected claim_batch limit error for {limit_sql}: {err}"
        );
        tx.rollback().await?;
    }

    let mut claim_tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *claim_tx)
        .await?;
    crate::cotx::set_local_tenant(&mut claim_tx, test_tenant()).await?;
    let lease: (String, i64) = sqlx::query_as(
        "SELECT lease_token, deadline_epoch_micros \
         FROM rss_outbox_claim_batch('outbox-perm', 1, $2, $3) WHERE event_id = $1",
    )
    .bind(&event_id)
    .bind(test_relay_budget().lease_ttl_millis())
    .bind(test_relay_budget().required_budget_millis())
    .fetch_one(&mut *claim_tx)
    .await?;
    claim_tx.commit().await?;

    let settle_retry_as_app = |lease_token: String, lease_deadline: i64| {
        let pool = store.pool.clone();
        let event_id = event_id.clone();
        async move {
            let mut tx = pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            crate::cotx::set_local_tenant(&mut tx, test_tenant()).await?;
            let changed = sqlx::query_scalar::<_, String>(
                "SELECT rss_outbox_settle_retry($1, $2::uuid, $3)::text",
            )
            .bind(&event_id)
            .bind(lease_token)
            .bind(lease_deadline)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok::<String, sqlx::Error>(changed)
        }
    };
    assert_eq!(settle_retry_as_app(lease.0, lease.1).await?, "settled");
    let retry_state: (String, i32, i64, bool, bool) = sqlx::query_as(
        "SELECT status, retry_count, EXTRACT(EPOCH FROM (retry_after - updated_at))::bigint, \
                lease_token IS NULL, lease_until IS NULL \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        retry_state,
        (crate::outbox::STATUS_PENDING.to_string(), 1, 1, true, true),
        "first retry must derive an exact one-second backoff from persisted retry_count=0"
    );

    sqlx::query(
        "UPDATE outbox SET retry_count = 9, retry_after = clock_timestamp() - interval '1 second' \
         WHERE event_id = $1",
    )
    .bind(&event_id)
    .execute(&store.pool)
    .await?;
    let mut high_claim_tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *high_claim_tx)
        .await?;
    crate::cotx::set_local_tenant(&mut high_claim_tx, test_tenant()).await?;
    let high_lease: (String, i64) = sqlx::query_as(
        "SELECT lease_token, deadline_epoch_micros \
         FROM rss_outbox_claim_batch('outbox-perm', 1, $2, $3) WHERE event_id = $1",
    )
    .bind(&event_id)
    .bind(test_relay_budget().lease_ttl_millis())
    .bind(test_relay_budget().required_budget_millis())
    .fetch_one(&mut *high_claim_tx)
    .await?;
    high_claim_tx.commit().await?;
    assert_eq!(
        settle_retry_as_app(high_lease.0, high_lease.1).await?,
        "settled"
    );
    let high_retry_state: (i32, i64) = sqlx::query_as(
        "SELECT retry_count, EXTRACT(EPOCH FROM (retry_after - updated_at))::bigint \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        high_retry_state,
        (10, 512),
        "retry must derive exponential backoff from the database row, not caller input"
    );

    set_outbox_terminal_for_test(&store, &event_id, STATUS_PUBLISHED, 0).await?;
    for (invalid_retain, label) in [(Some(0_i64), "0"), (Some(-1_i64), "-1"), (None, "NULL")] {
        let invalid_sweep = sqlx::query("SELECT rss_sweep_outbox_published($1)")
            .bind(invalid_retain)
            .execute(&store.pool)
            .await;
        let Err(invalid_sweep_error) = invalid_sweep else {
            return Err(
                format!("rss_sweep_outbox_published must reject retain seconds {label}").into(),
            );
        };
        assert!(
            invalid_sweep_error
                .to_string()
                .contains("retain seconds must be positive"),
            "unexpected invalid sweep error: {invalid_sweep_error}"
        );
        let remains: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(remains, 1, "invalid retention {label} must not delete rows");
    }

    let can_execute: (bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT has_function_privilege('rss_app', 'rss_outbox_claim_batch(text, bigint, bigint, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_settle_published(text, uuid, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_settle_retry(text, uuid, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_mark_dlx(text, uuid, bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_redrive(text, uuid)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_sweep_outbox_published(bigint)', 'EXECUTE'),
               has_function_privilege('rss_app', 'rss_outbox_sample_backlog(text)', 'EXECUTE')
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        can_execute,
        (true, true, true, true, true, false, true, true),
        "rss_app should only receive the fixed outbox function surface"
    );
    let legacy_present: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT signature
        FROM (VALUES
            ('rss_outbox_poll_pending(text,bigint)'),
            ('rss_outbox_acquire_lease(text)'),
            ('rss_outbox_lease_can_publish(text,uuid,bigint)'),
            ('rss_outbox_claim_batch(text,bigint)'),
            ('rss_outbox_publish_preflight(text,uuid,bigint)'),
            ('rss_outbox_settle_published(text,uuid)'),
            ('rss_outbox_settle_retry(text,integer,bigint,uuid)'),
            ('rss_outbox_settle_retry(text,integer,bigint,uuid,bigint)'),
            ('rss_outbox_settle_retry(text,bigint,uuid,bigint)'),
            ('rss_outbox_mark_dlx(text,integer,uuid)'),
            ('rss_outbox_mark_dlx(text,integer,uuid,bigint)')
        ) AS legacy(signature)
        WHERE to_regprocedure(signature) IS NOT NULL
        ORDER BY signature
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert!(
        legacy_present.is_empty(),
        "legacy relay overloads must be absent: {legacy_present:?}"
    );

    store.shutdown().await?;
    Ok(())
}

/// t28：crash recovery 保持 partition 顺序（stale publishing 头 gate 后继）。
///
/// append H, S2 同 partition；置 H status='publishing', updated_at 很久之前（模拟崩溃）；
/// claim → 仅 H（stale publishing 被重捞，S2 被 gate）；relay H→published → claim → S2。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t28_crash_recovery_preserves_partition_order() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t28");
    let key = PartitionKey::parse("part-crash").unwrap();

    let h_id = unique_event_id("t28-H");
    let s2_id = unique_event_id("t28-S2");

    // append H, S2 同 partition。
    for eid in [&h_id, &s2_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // 模拟 H 崩溃：status=publishing, lease_until 已过期。
    sqlx::query(
        "UPDATE outbox SET status='publishing', lease_token=gen_random_uuid(), \
         automatic_retry_deadline=COALESCE(automatic_retry_deadline, now()+interval '24 hours'), \
         updated_at=now()-make_interval(secs => $1), lease_until=now()-interval '10 seconds' \
         WHERE event_id = $2",
    )
    .bind(test_relay_lease_ttl_seconds() + 10)
    .bind(&h_id)
    .execute(&store.pool)
    .await?;

    let (pub_ok, _) = RecordingPublisher::always_ok();
    let outbox = make_pg_outbox_for_domain(&store, &domain, pub_ok);

    // claim → 仅 H（stale publishing 可捞，S2 被 gate）。
    let entries = outbox.claim_batch(10).await?;
    assert_eq!(entries.len(), 1, "t28: crash recovery 仅应返回 H");
    assert_eq!(entries[0].idem_key().as_str(), h_id, "t28: 返回的必须是 H");
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t28: S2 被 stale-publishing H gate，不应出现"
    );

    // relay H → published。
    let h_entry = entries.into_iter().next().unwrap();
    let disp = outbox.relay(h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t28: relay H 应返 Ack");

    // claim → S2（H published 后解锁）。
    let entries2 = outbox.claim_batch(10).await?;
    assert_eq!(entries2.len(), 1, "t28: 第二轮 claim 应仅返 S2");
    assert_eq!(
        entries2[0].idem_key().as_str(),
        s2_id,
        "t28: 第二轮 claim 必须是 S2"
    );

    store.shutdown().await?;
    Ok(())
}

/// t29：sample_backlog 计入 gated 后继（backlog claim-only by design）。
///
/// H + 3 后继同 partition → `sample_backlog.depth()==4`（gate 不减 depth）；
/// `claim_batch` 返 1（仅队头）。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t29_sample_backlog_counts_gated_successors() -> TestResult {
    use consistency::PartitionKey;
    use eventexec::{DlqRedriveOutcome, DlqRedriveRequest, DlqStore as _};

    let (pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let maintenance = connect_pg_maintenance(&pg).await?;

    let domain = unique_domain("t29");
    let key = PartitionKey::parse("part-backlog").unwrap();

    // append H + 3 后继同 partition。
    let ids: Vec<_> = (0..4)
        .map(|i| unique_event_id(&format!("t29-{i}")))
        .collect();
    for eid in &ids {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox_for_domain(
        &store,
        &domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );

    // sample_backlog depth = 4（全部计入，gate 不减少 backlog 深度）。
    let samples = active_backlog(outbox.sample_backlog(&domain).await?)?;
    assert_eq!(
        samples.len(),
        1,
        "t29: 单 contract backlog 应产生一个 metric sample"
    );
    assert_eq!(
        samples[0].partition_blocked_depth(),
        3,
        "t29: H 后 3 个同 partition 后继必须计入 blocked depth"
    );
    let sample = summarize_backlog(&samples);
    assert_eq!(
        sample.depth(),
        4,
        "t29: backlog depth 应计入所有 4 行（含 gated 后继），实际={}",
        sample.depth()
    );
    assert_eq!(
        sample.oldest_age_seconds(),
        0,
        "t29: fresh rows，gate 不扭曲 age（age 应为 0 秒），实际={}",
        sample.oldest_age_seconds()
    );

    // claim_batch 仅返 1（队头）——反真空：gate 确实生效。
    let claimed = outbox.claim_batch(10).await?;
    assert_eq!(
        claimed.len(),
        1,
        "t29: claim_batch 应仅返队头（1 行），gate 生效"
    );
    assert_eq!(
        claimed[0].idem_key().as_str(),
        ids[0],
        "t29: claim_batch 返回的必须是 H（最小 seq 的队头）"
    );

    let dlx_domain = unique_domain("t29-dlx");
    let dlx_key = PartitionKey::parse("part-backlog-dlx").unwrap();
    let dlx_ids: Vec<_> = (0..3)
        .map(|i| unique_event_id(&format!("t29-dlx-{i}")))
        .collect();
    for eid in &dlx_ids {
        let entry = make_entry(eid);
        let env = make_test_env(&dlx_domain, "c").with_partition_key_opt(Some(dlx_key.clone()));
        store
            .serving_write_fixture::<_, _, sqlx::Error>(test_tenant(), move |cap| {
                let entry = entry.clone();
                Box::pin(async move {
                    let _outcome = append_outbox(cap, &entry, &env)
                        .await
                        .map_err(test_append_error)?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    set_outbox_terminal_for_test(&store, &dlx_ids[0], "dlx", 0).await?;

    let dlx_outbox = make_pg_outbox_for_domain(
        &store,
        &dlx_domain,
        RecordingPublisher {
            result: || Ok(()),
            calls: Arc::new(Mutex::new(0)),
        },
    );

    let dlx_samples = active_backlog(outbox.sample_backlog(&dlx_domain).await?)?;
    assert_eq!(
        dlx_samples[0].partition_blocked_depth(),
        2,
        "t29: DLX 队头后 2 个同 partition 后继必须计入 blocked depth"
    );
    assert_eq!(
        summarize_backlog(&dlx_samples).depth(),
        2,
        "t29: DLX 队头本身不计入 pending backlog depth，后继仍计入"
    );
    assert!(
        dlx_outbox.claim_batch(10).await?.is_empty(),
        "t29: DLX 队头必须阻塞同 partition 后继投递"
    );

    let dlq = maintenance.dlq_store_without_payload_replay();
    let redrive = dlq
        .redrive_outbox(DlqRedriveRequest::new(
            dlq_authorization(test_tenant()),
            IdemKey::parse(&dlx_ids[0]).unwrap(),
        ))
        .await?;
    assert_eq!(redrive.outcome(), &DlqRedriveOutcome::Redriven);

    let redriven_head = dlx_outbox.claim_batch(10).await?;
    assert_eq!(redriven_head.len(), 1, "t29: redrive 后仅队头可投递");
    assert_eq!(redriven_head[0].idem_key().as_str(), dlx_ids[0]);
    let disp = dlx_outbox
        .relay(redriven_head.into_iter().next().unwrap())
        .await?;
    assert_eq!(disp, Disposition::Ack, "t29: redriven 队头应成功发布");

    let unblocked = dlx_outbox.claim_batch(10).await?;
    assert_eq!(unblocked.len(), 1, "t29: 队头发布后仅第一后继可投递");
    assert_eq!(
        unblocked[0].idem_key().as_str(),
        dlx_ids[1],
        "t29: DLX 队头发布后必须按 partition 顺序解除第一后继"
    );

    drop(dlq);
    maintenance.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}
