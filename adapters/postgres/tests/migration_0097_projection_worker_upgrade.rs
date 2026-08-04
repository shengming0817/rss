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
        // Each test owns one isolated database. Disabling the session advisory lock also lets the
        // same pool retry after an intentionally failed transactional migration without waiting on
        // a lock retained by another idle pooled connection.
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

async fn assert_cutover_rolled_back(pool: &sqlx::PgPool) -> TestResult {
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT pg_catalog.max(version) FROM public._sqlx_migrations")
            .fetch_one(pool)
            .await?;
    assert_eq!(ledger, Some(96));

    let actor_column: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute \
         WHERE attrelid = 'public.settings_projection_dedupe_receipts'::regclass \
           AND attname = 'actor' AND NOT attisdropped)",
    )
    .fetch_one(pool)
    .await?;
    assert!(
        !actor_column,
        "failed 0097 must not leave receipt DDL behind"
    );

    let functions: (bool, bool) = sqlx::query_as(
        "SELECT \
           pg_catalog.to_regprocedure(\
             'public.rss_settings_projection_apply(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)'\
           ) IS NOT NULL, \
           pg_catalog.to_regprocedure(\
             'public.rss_settings_projection_apply_worker(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)'\
           ) IS NULL",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(functions, (true, true));
    Ok(())
}

async fn seed_worker_roles(pool: &sqlx::PgPool) -> TestResult {
    sqlx::query(
        "CREATE ROLE rss_projection_worker \
         NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE ROLE rss_projection_worker_owner \
         NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_backfills_historical_receipts_and_closes_attribution() -> TestResult {
    let fixture = testkit::env_or_postgres().await?;
    let pool = connect(fixture.params()).await?;
    migrations_through(96).run(&pool).await?;

    let tenant = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy-v3', 'v3', \
                   $2, $3, 7)",
    )
    .bind(&tenant)
    .bind("sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103")
    .bind("sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8")
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (\
             tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy-v3', \
                   'historical-event', 7, $2)",
    )
    .bind(&tenant)
    .bind(vec![0x95_u8; 32])
    .execute(&pool)
    .await?;

    migrations_through(97).run(&pool).await?;

    let attribution: (String, String) = sqlx::query_as(
        "SELECT actor, purpose FROM public.settings_projection_dedupe_receipts \
         WHERE tenant_id = $1::uuid AND source_event_id = 'historical-event'",
    )
    .bind(&tenant)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        attribution,
        (
            "rss-projection-replay".to_owned(),
            "operator-replay".to_owned()
        )
    );

    for invalid in [
        "UPDATE public.settings_projection_dedupe_receipts \
         SET actor = 'forged-worker' WHERE source_event_id = 'historical-event'",
        "UPDATE public.settings_projection_dedupe_receipts \
         SET purpose = NULL WHERE source_event_id = 'historical-event'",
    ] {
        let result = sqlx::query(invalid).execute(&pool).await;
        assert!(
            result.is_err(),
            "0097 must reject invalid attribution: {result:?}"
        );
    }

    pool.close().await;
    drop(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn role_drift_aborts_0097_before_the_hard_cut_and_rolls_back() -> TestResult {
    let fixture = testkit::env_or_postgres().await?;
    let pool = connect(fixture.params()).await?;
    migrations_through(96).run(&pool).await?;
    seed_worker_roles(&pool).await?;

    sqlx::query("CREATE ROLE rss_projection_worker_drift_parent NOLOGIN")
        .execute(&pool)
        .await?;
    sqlx::query("GRANT rss_projection_worker_drift_parent TO rss_projection_worker")
        .execute(&pool)
        .await?;
    assert!(migrations_through(97).run(&pool).await.is_err());
    assert_cutover_rolled_back(&pool).await?;
    sqlx::query("REVOKE rss_projection_worker_drift_parent FROM rss_projection_worker")
        .execute(&pool)
        .await?;
    sqlx::query("DROP ROLE rss_projection_worker_drift_parent")
        .execute(&pool)
        .await?;

    sqlx::query("CREATE TABLE public.projection_worker_drift_owner (id bigint)")
        .execute(&pool)
        .await?;
    sqlx::query(
        "ALTER TABLE public.projection_worker_drift_owner OWNER TO rss_projection_worker_owner",
    )
    .execute(&pool)
    .await?;
    assert!(migrations_through(97).run(&pool).await.is_err());
    assert_cutover_rolled_back(&pool).await?;
    sqlx::query("DROP TABLE public.projection_worker_drift_owner")
        .execute(&pool)
        .await?;

    sqlx::query("GRANT SELECT ON TABLE public.projection_events TO rss_projection_worker")
        .execute(&pool)
        .await?;
    assert!(migrations_through(97).run(&pool).await.is_err());
    assert_cutover_rolled_back(&pool).await?;
    sqlx::query("REVOKE SELECT ON TABLE public.projection_events FROM rss_projection_worker")
        .execute(&pool)
        .await?;

    migrations_through(97).run(&pool).await?;
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT pg_catalog.max(version) FROM public._sqlx_migrations")
            .fetch_one(&pool)
            .await?;
    assert_eq!(ledger, Some(97));

    pool.close().await;
    drop(fixture);
    Ok(())
}
