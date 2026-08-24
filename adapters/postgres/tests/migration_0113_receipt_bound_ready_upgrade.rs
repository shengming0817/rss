use std::borrow::Cow;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn migrations_through(last_version: i64) -> sqlx::migrate::Migrator {
    let embedded = sqlx::migrate!("./migrations");
    let migrations = embedded
        .iter()
        .filter(|migration| migration.version <= last_version)
        .cloned()
        .collect();
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: false,
        no_tx: embedded.no_tx,
    }
}

async fn connect(params: &testkit::PgConnParams) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(&params.username)
                .password(&params.password)
                .ssl_mode(PgSslMode::Prefer),
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_installs_the_receipt_bound_ready_function_and_behavioral_oracle() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(112).run(&pool).await?;

    let before: String = sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_functiondef('public.rss_mark_device_certificate_ready(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,bigint,bytea,bigint,bigint,bigint)'::regprocedure)",
    )
    .fetch_one(&pool)
    .await?;
    assert!(!before.contains("durable_authorization_receipt_id"));

    migrations_through(113).run(&pool).await?;
    let after: String = sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_functiondef('public.rss_mark_device_certificate_ready(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bytea,text,bytea,bytea,bytea,text,bigint,bigint,bytea,bigint,bigint,bigint)'::regprocedure)",
    )
    .fetch_one(&pool)
    .await?;
    let normalized = after.split_whitespace().collect::<String>();
    for required in [
        "desired.authorization_receipt_id",
        "artifact.authorization_receipt_id=durable_authorization_receipt_id",
        "payload_json->>'authorizationReceiptId'=durable_authorization_receipt_id::text",
    ] {
        assert!(
            normalized.contains(required),
            "missing live receipt join: {required}"
        );
    }
    assert_ne!(before, after);
    // The integration-level oracle executes this upgraded function with a valid Ready proof,
    // then corrupts the command authorizationReceiptId and proves both false and an atomically
    // unchanged six-condition snapshot. Keep the target name here so the migration-specific
    // release check cannot regress to source-shape evidence alone.
    let behavioral_oracle = include_str!("../src/integration_tests/device_certificate_tests.rs");
    for required in [
        "mismatched_payload[\"authorizationReceiptId\"]",
        "durable command authorization receipt drift must reject an earlier valid proof",
        "rejected recovery proof must leave the complete outage condition set untouched",
    ] {
        assert!(
            behavioral_oracle.contains(required),
            "missing behavioral oracle: {required}"
        );
    }
    Ok(())
}
