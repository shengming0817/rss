#![cfg(feature = "integration")]

use std::borrow::Cow;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

const OWNER: &str = "billing";
const CONTRACT_ID: &str = "billing.checkout";
const DEFINITION_VERSION: &str = "v1";
const DEFINITION_SCHEMA_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ACTION_REGISTRY_GENERATION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn migrations_through(max_version: i64) -> sqlx::migrate::Migrator {
    let embedded = sqlx::migrate!("./migrations");
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            embedded
                .iter()
                .filter(|migration| migration.version <= max_version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: embedded.no_tx,
    }
}

async fn connect_fixture() -> Result<(testkit::PgFixture, sqlx::PgPool), TestError> {
    let fixture = testkit::env_or_postgres().await?;
    let params = fixture.params();
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(PgSslMode::Prefer);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    Ok((fixture, pool))
}

async fn set_tenant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn register(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    saga_id: uuid::Uuid,
    start_actor: &str,
    start_audit_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT public.rss_saga_register( \
         $1::uuid, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .bind(DEFINITION_VERSION)
    .bind(DEFINITION_SCHEMA_DIGEST)
    .bind(ACTION_REGISTRY_GENERATION)
    .bind(start_actor)
    .bind(start_audit_id)
    .fetch_one(&mut **tx)
    .await
}

async fn saga_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: uuid::Uuid,
    saga_id: uuid::Uuid,
) -> Result<(String, Option<String>, i64, Option<String>, String), sqlx::Error> {
    sqlx::query_as(
        "SELECT status, lease_token::text, epoch, unresolved_at::text, updated_at::text \
         FROM public.saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant_id.to_string())
    .bind(saga_id.to_string())
    .fetch_one(&mut **tx)
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0087_rejects_live_saga_then_applies_without_partial_state() -> TestResult {
    let (fixture, pool) = connect_fixture().await?;
    migrations_through(86).run(&pool).await?;

    let tenant_id = uuid::Uuid::new_v4();
    let saga_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO public.saga_instances ( \
             tenant_id, saga_id, owner, contract_id, definition_version, \
             definition_schema_digest, action_registry_generation \
         ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)",
    )
    .bind(tenant_id.to_string())
    .bind(saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .bind(DEFINITION_VERSION)
    .bind(DEFINITION_SCHEMA_DIGEST)
    .bind(ACTION_REGISTRY_GENERATION)
    .execute(&pool)
    .await?;

    let failure = match migrations_through(87).run(&pool).await {
        Err(error) => error,
        Ok(()) => {
            return Err(std::io::Error::other(
                "0087 accepted a live Saga instead of failing closed",
            )
            .into());
        }
    };
    let database_error = match &failure {
        sqlx::migrate::MigrateError::ExecuteMigration(
            sqlx::Error::Database(database_error),
            87,
        ) => database_error.as_ref(),
        _ => {
            return Err(std::io::Error::other(format!(
                "0087 failed through an unexpected path: {failure}"
            ))
            .into());
        }
    };
    assert_eq!(database_error.code().as_deref(), Some("55000"));
    assert_eq!(
        database_error.message(),
        "saga_instances must be empty before installing operator lifecycle v2"
    );

    let ledger: (Option<i64>, i64) = sqlx::query_as(
        "SELECT max(version), count(*) FILTER (WHERE version = 87) \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(ledger, (Some(86), 0));

    let partial_objects: i64 = sqlx::query_scalar(
        "SELECT \
             (SELECT count(*) FROM information_schema.columns \
              WHERE table_schema = 'public' AND table_name = 'saga_instances' \
                AND column_name IN ('start_actor', 'start_audit_id', 'unresolved_at')) \
           + (SELECT count(*) FROM information_schema.tables \
              WHERE table_schema = 'public' AND table_name = 'saga_operator_transitions')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(partial_objects, 0, "failed 0087 must roll back completely");

    sqlx::query(
        "DELETE FROM public.saga_instances WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant_id.to_string())
    .bind(saga_id.to_string())
    .execute(&pool)
    .await?;

    pool.close().await;
    let params = fixture.params();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(&params.username)
                .password(&params.password)
                .ssl_mode(PgSslMode::Prefer),
        )
        .await?;
    migrations_through(87).run(&pool).await?;

    let ledger: (Option<i64>, i64, bool) = sqlx::query_as(
        "SELECT max(version), count(*) FILTER (WHERE version = 87), bool_and(success) \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(ledger, (Some(87), 1, true));

    let installed: bool = sqlx::query_scalar(
        r#"
        SELECT
            (SELECT count(*) = 3 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'saga_instances'
               AND column_name IN ('start_actor', 'start_audit_id', 'unresolved_at'))
        AND to_regclass('public.saga_operator_transitions') IS NOT NULL
        AND to_regprocedure('public.rss_saga_retry_compensation(uuid,text,text,bigint,text,integer,bytea,text,text,text,text)') IS NOT NULL
        AND to_regprocedure('public.rss_saga_terminate(uuid,text,text,text,text,text,text)') IS NOT NULL
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert!(installed, "0087 must install the closed operator lifecycle");

    pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn operator_retry_and_terminate_are_fenced_audited_and_time_stable() -> TestResult {
    let (_fixture, pool) = connect_fixture().await?;
    migrations_through(87).run(&pool).await?;

    let tenant_id = uuid::Uuid::new_v4();
    let retry_saga_id = uuid::Uuid::new_v4();
    let terminate_saga_id = uuid::Uuid::new_v4();
    let mut tx = pool.begin().await?;
    set_tenant(&mut tx, tenant_id).await?;

    assert!(register(&mut tx, retry_saga_id, "operator@example", "audit-start-1").await?);
    assert!(
        register(
            &mut tx,
            terminate_saga_id,
            "operator@example",
            "audit-start-2"
        )
        .await?
    );

    let empty_actor = register(&mut tx, uuid::Uuid::new_v4(), "", "audit-start-3").await;
    assert!(empty_actor.is_err(), "empty start actor must fail closed");
    tx.rollback().await?;

    let mut tx = pool.begin().await?;
    set_tenant(&mut tx, tenant_id).await?;
    let empty_audit = register(&mut tx, uuid::Uuid::new_v4(), "operator@example", "").await;
    assert!(
        empty_audit.is_err(),
        "empty start audit id must fail closed"
    );
    tx.rollback().await?;

    // Re-register because the first transaction deliberately rolled back with the negative case.
    let mut tx = pool.begin().await?;
    set_tenant(&mut tx, tenant_id).await?;
    assert!(register(&mut tx, retry_saga_id, "operator@example", "audit-start-1").await?);
    assert!(
        register(
            &mut tx,
            terminate_saga_id,
            "operator@example",
            "audit-start-2"
        )
        .await?
    );

    let (worker_token, worker_epoch): (String, i64) = sqlx::query_as(
        "SELECT lease_token, epoch FROM public.rss_saga_claim( \
             $1::uuid, $2, $3, $4, $5, $6, 'ready', 'worker-1', 60000000::bigint)",
    )
    .bind(retry_saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .bind(DEFINITION_VERSION)
    .bind(DEFINITION_SCHEMA_DIGEST)
    .bind(ACTION_REGISTRY_GENERATION)
    .fetch_one(&mut *tx)
    .await?;
    let worker_token = uuid::Uuid::parse_str(&worker_token)?;
    let moved_to_compensating: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_apply_lifecycle( \
             $1::uuid, $2::uuid, $3::bigint, 'compensating', NULL, 'business_failure', false, \
             ARRAY['running', 'compensating']::text[], false)",
    )
    .bind(retry_saga_id.to_string())
    .bind(worker_token.to_string())
    .bind(worker_epoch)
    .fetch_one(&mut *tx)
    .await?;
    assert!(moved_to_compensating);

    let effect_key = vec![7_u8; 32];
    for (seq, status, error, cause) in [
        (0_i64, "compensation_intent", None, Some("business_failure")),
        (1_i64, "compensation_failed", Some("retryable"), None),
    ] {
        let appended: bool = sqlx::query_scalar(
            "SELECT public.rss_saga_append_journal( \
                 $1::uuid, $2::uuid, $3::bigint, $4::bigint, 'reserve-credit', $5, $6, \
                 1::integer, $7, $8)",
        )
        .bind(retry_saga_id.to_string())
        .bind(worker_token.to_string())
        .bind(worker_epoch)
        .bind(seq)
        .bind(status)
        .bind(error)
        .bind(&effect_key)
        .bind(cause)
        .fetch_one(&mut *tx)
        .await?;
        assert!(appended);
    }
    let blocked: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_apply_lifecycle( \
             $1::uuid, $2::uuid, $3::bigint, 'compensation_failed', NULL, NULL, true, \
             ARRAY['compensating']::text[], true)",
    )
    .bind(retry_saga_id.to_string())
    .bind(worker_token.to_string())
    .bind(worker_epoch)
    .fetch_one(&mut *tx)
    .await?;
    assert!(blocked);

    let (terminal_at, unresolved_at): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT terminal_at::text, unresolved_at::text FROM public.saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant_id.to_string())
    .bind(retry_saga_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    assert!(
        terminal_at.is_none(),
        "compensation failure is blocked, not terminal"
    );
    assert!(unresolved_at.is_some(), "missing unresolved_at");

    let stale_retry: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_retry_compensation( \
             $1::uuid, $2, $3, 1::bigint, 'reserve-credit', 1::integer, $4, \
             'operator@example', 'dependency recovered', 'CHG-1926', 'audit-retry-1')",
    )
    .bind(retry_saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .bind(vec![8_u8; 32])
    .fetch_one(&mut *tx)
    .await?;
    assert!(!stale_retry, "stale failure identity must not transition");

    let wrong_identity_retry: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_retry_compensation( \
             $1::uuid, 'wrong-owner', $2, 1::bigint, 'reserve-credit', 1::integer, $3, \
             'operator@example', 'dependency recovered', 'CHG-1926', 'audit-retry-1')",
    )
    .bind(retry_saga_id.to_string())
    .bind(CONTRACT_ID)
    .bind(&effect_key)
    .fetch_one(&mut *tx)
    .await?;
    assert!(!wrong_identity_retry, "wrong identity must not transition");

    let retried: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_retry_compensation( \
             $1::uuid, $2, $3, 1::bigint, 'reserve-credit', 1::integer, $4, \
             'operator@example', 'dependency recovered', 'CHG-1926', 'audit-retry-1')",
    )
    .bind(retry_saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .bind(&effect_key)
    .fetch_one(&mut *tx)
    .await?;
    assert!(retried);

    let retry_state: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, unresolved_at::text, lease_token::text FROM public.saga_instances \
             WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant_id.to_string())
    .bind(retry_saga_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(retry_state, ("compensating".to_owned(), None, None));

    let wrong_identity_terminated: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_terminate( \
             $1::uuid, 'wrong-owner', $2, \
             'operator@example', 'request withdrawn', 'CHG-1926', 'audit-term-1')",
    )
    .bind(terminate_saga_id.to_string())
    .bind(CONTRACT_ID)
    .fetch_one(&mut *tx)
    .await?;
    assert!(
        !wrong_identity_terminated,
        "wrong identity must not terminate"
    );
    let terminated: bool = sqlx::query_scalar(
        "SELECT public.rss_saga_terminate( \
             $1::uuid, $2, $3, \
             'operator@example', 'request withdrawn', 'CHG-1926', 'audit-term-1')",
    )
    .bind(terminate_saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .fetch_one(&mut *tx)
    .await?;
    assert!(terminated);

    let terminated_state: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, terminal_at::text, unresolved_at::text FROM public.saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant_id.to_string())
    .bind(terminate_saga_id.to_string())
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(terminated_state.0, "terminated");
    assert!(
        terminated_state.1.is_some(),
        "terminated is a true terminal state"
    );
    assert!(terminated_state.2.is_none());

    let transitions: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT transition, from_status, to_status, operator_actor, operator_reason_text, start_audit_id \
         FROM public.saga_operator_transitions \
         WHERE tenant_id = $1::uuid ORDER BY transitioned_at, saga_id",
    )
    .bind(tenant_id.to_string())
    .fetch_all(&mut *tx)
    .await?;
    assert_eq!(transitions.len(), 2);
    assert!(transitions.contains(&(
        "retry_compensation".to_owned(),
        "compensation_failed".to_owned(),
        "compensating".to_owned(),
        "operator@example".to_owned(),
        "dependency recovered".to_owned(),
        "audit-retry-1".to_owned(),
    )));
    assert!(transitions.contains(&(
        "terminate".to_owned(),
        "ready".to_owned(),
        "terminated".to_owned(),
        "operator@example".to_owned(),
        "request withdrawn".to_owned(),
        "audit-term-1".to_owned(),
    )));

    let unresolved: (i64, i64, i64, Option<String>) = sqlx::query_as(
        "SELECT operator_required_count, degraded_count, compensation_failed_count, \
                oldest_unresolved_at::text \
         FROM public.rss_saga_observe_unresolved($1, $2)",
    )
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(unresolved, (0, 0, 0, None));

    tx.commit().await?;
    pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn terminate_rejects_intent_blocked_state_and_invalid_audit_without_mutation() -> TestResult {
    let (_fixture, pool) = connect_fixture().await?;
    migrations_through(87).run(&pool).await?;

    let tenant_id = uuid::Uuid::new_v4();
    let intent_saga_id = uuid::Uuid::new_v4();
    let blocked_saga_id = uuid::Uuid::new_v4();
    let invalid_audit_saga_id = uuid::Uuid::new_v4();
    let mut setup = pool.begin().await?;
    set_tenant(&mut setup, tenant_id).await?;
    for (saga_id, audit_id) in [
        (intent_saga_id, "audit-intent"),
        (blocked_saga_id, "audit-blocked"),
        (invalid_audit_saga_id, "audit-invalid"),
    ] {
        assert!(register(&mut setup, saga_id, "operator@example", audit_id).await?);
    }

    // Seed an intent to prove termination independently rejects any started effect.
    sqlx::query(
        "INSERT INTO public.saga_journal ( \
             tenant_id, saga_id, seq, step_name, status, error_summary, attempt, effect_key, \
             compensation_cause \
         ) VALUES ($1::uuid, $2::uuid, 0, 'reserve-credit', 'forward_intent', NULL, 1, $3, NULL)",
    )
    .bind(tenant_id.to_string())
    .bind(intent_saga_id.to_string())
    .bind(vec![9_u8; 32])
    .execute(&mut *setup)
    .await?;
    sqlx::query(
        "UPDATE public.saga_instances SET status = 'degraded' \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(tenant_id.to_string())
    .bind(blocked_saga_id.to_string())
    .execute(&mut *setup)
    .await?;
    setup.commit().await?;

    let mut rejected = pool.begin().await?;
    set_tenant(&mut rejected, tenant_id).await?;
    let intent_before = saga_state(&mut rejected, tenant_id, intent_saga_id).await?;
    let blocked_before = saga_state(&mut rejected, tenant_id, blocked_saga_id).await?;
    for saga_id in [intent_saga_id, blocked_saga_id] {
        let terminated: bool = sqlx::query_scalar(
            "SELECT public.rss_saga_terminate( \
                 $1::uuid, $2, $3, \
                 'operator@example', 'request withdrawn', 'CHG-1926', 'audit-rejected')",
        )
        .bind(saga_id.to_string())
        .bind(OWNER)
        .bind(CONTRACT_ID)
        .fetch_one(&mut *rejected)
        .await?;
        assert!(!terminated);
    }
    assert_eq!(
        saga_state(&mut rejected, tenant_id, intent_saga_id).await?,
        intent_before
    );
    assert_eq!(
        saga_state(&mut rejected, tenant_id, blocked_saga_id).await?,
        blocked_before
    );
    rejected.commit().await?;

    let mut invalid_audit = pool.begin().await?;
    set_tenant(&mut invalid_audit, tenant_id).await?;
    let audit_before = saga_state(&mut invalid_audit, tenant_id, invalid_audit_saga_id).await?;
    let failure = sqlx::query_scalar::<_, bool>(
        "SELECT public.rss_saga_terminate( \
             $1::uuid, $2, $3, 'operator@example', '', 'CHG-1926', 'audit-invalid')",
    )
    .bind(invalid_audit_saga_id.to_string())
    .bind(OWNER)
    .bind(CONTRACT_ID)
    .fetch_one(&mut *invalid_audit)
    .await
    .expect_err("invalid operator reason text must fail the atomic transition");
    assert_eq!(
        failure
            .as_database_error()
            .and_then(|database| database.code())
            .as_deref(),
        Some("23514")
    );
    invalid_audit.rollback().await?;

    let mut verify = pool.begin().await?;
    set_tenant(&mut verify, tenant_id).await?;
    assert_eq!(
        saga_state(&mut verify, tenant_id, invalid_audit_saga_id).await?,
        audit_before
    );
    let transition_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.saga_operator_transitions WHERE tenant_id = $1::uuid",
    )
    .bind(tenant_id.to_string())
    .fetch_one(&mut *verify)
    .await?;
    assert_eq!(
        transition_count, 0,
        "rejected termination must not append audit"
    );
    verify.rollback().await?;
    pool.close().await;
    Ok(())
}
