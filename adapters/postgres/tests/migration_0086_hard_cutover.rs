use std::borrow::Cow;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

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

#[tokio::test(flavor = "multi_thread")]
async fn migration_0086_rejects_live_aggregate_rolls_back_then_applies_cleanly() -> TestResult {
    let (fixture, pool) = connect_fixture().await?;
    migrations_through(85).run(&pool).await?;

    let tenant_id = uuid::Uuid::new_v4().to_string();
    let saga_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO public.saga_instances ( \
             tenant_id, saga_id, owner, contract_id, definition_version, \
             definition_schema_digest, action_registry_generation \
         ) VALUES ( \
             $1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', \
             'sha256:0000000000000000000000000000000000000000000000000000000000000000', \
             'sha256:1111111111111111111111111111111111111111111111111111111111111111' \
         )",
    )
    .bind(&tenant_id)
    .bind(&saga_id)
    .execute(&pool)
    .await?;

    let failure = match migrations_through(86).run(&pool).await {
        Err(error) => error,
        Ok(()) => {
            return Err(std::io::Error::other(
                "0086 accepted a legal live Saga aggregate instead of failing closed",
            )
            .into());
        }
    };
    let database_error = match &failure {
        sqlx::migrate::MigrateError::ExecuteMigration(
            sqlx::Error::Database(database_error),
            86,
        ) => database_error.as_ref(),
        _ => {
            return Err(std::io::Error::other(format!(
                "0086 failed through an unexpected path: {failure}"
            ))
            .into());
        }
    };
    assert_eq!(
        database_error.code().as_deref(),
        Some("55000"),
        "the live-row cutover gate must expose the documented SQLSTATE"
    );
    assert_eq!(
        database_error.message(),
        "cannot close saga durable recovery while saga durable rows exist"
    );

    let ledger: (Option<i64>, i64) = sqlx::query_as(
        "SELECT max(version), count(*) FILTER (WHERE version = 86) \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(ledger, (Some(85), 0), "failed 0086 must not advance ledger");

    let partial_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' \
           AND ( \
               (table_name = 'saga_instances' \
                    AND column_name IN ('operator_reason', 'compensation_cause')) \
               OR (table_name = 'saga_journal' \
                    AND column_name IN ('attempt', 'effect_key', 'compensation_cause')) \
           )",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        partial_columns, 0,
        "failed 0086 must roll back every new column"
    );

    let old_status_constraint: String = sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_constraintdef(oid) \
         FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'public.saga_instances'::regclass \
           AND conname = 'saga_instances_status_valid'",
    )
    .fetch_one(&pool)
    .await?;
    assert!(old_status_constraint.contains("'failed'::text"));
    assert!(!old_status_constraint.contains("operator_required"));

    sqlx::query(
        "DELETE FROM public.saga_instances \
         WHERE tenant_id = $1::uuid AND saga_id = $2::uuid",
    )
    .bind(&tenant_id)
    .bind(&saga_id)
    .execute(&pool)
    .await?;

    // A failed sqlx migration can leave the session-scoped advisory lock on the pooled
    // connection that executed it. Reconnect before the green retry so the proof exercises the
    // migration again instead of waiting on a lock held by its own idle session.
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
    migrations_through(86).run(&pool).await?;

    let ledger: (Option<i64>, i64, bool) = sqlx::query_as(
        "SELECT max(version), count(*) FILTER (WHERE version = 86), bool_and(success) \
         FROM public._sqlx_migrations",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(ledger, (Some(86), 1, true));

    let exact_columns: bool = sqlx::query_scalar(
        "WITH expected(table_name, column_name, data_type, nullable) AS ( \
             VALUES \
                 ('saga_instances', 'operator_reason', 'text', 'YES'), \
                 ('saga_instances', 'compensation_cause', 'text', 'YES'), \
                 ('saga_journal', 'attempt', 'integer', 'NO'), \
                 ('saga_journal', 'effect_key', 'bytea', 'NO'), \
                 ('saga_journal', 'compensation_cause', 'text', 'YES') \
         ) \
         SELECT count(actual.column_name) = count(*) \
                AND bool_and( \
                    actual.data_type = expected.data_type \
                    AND actual.is_nullable = expected.nullable \
                ) \
         FROM expected \
         LEFT JOIN information_schema.columns AS actual \
           ON actual.table_schema = 'public' \
          AND actual.table_name = expected.table_name \
          AND actual.column_name = expected.column_name",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        exact_columns,
        "successful 0086 must install the exact durable columns"
    );

    let exact_triggers: bool = sqlx::query_scalar(
        "SELECT count(*) = 2 AND bool_and(tgenabled = 'O' AND tgdeferrable AND tginitdeferred) \
         FROM pg_catalog.pg_trigger \
         WHERE tgname IN ( \
             'saga_receipt_requires_completed', \
             'saga_completed_requires_receipt' \
         )",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        exact_triggers,
        "successful 0086 must replace both deferred exact-pair triggers"
    );

    pool.close().await;
    Ok(())
}
