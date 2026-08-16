use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

const MIGRATION: &str = include_str!("../migrations/0109_export_inbox_backlog_samples.sql");

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
async fn reader_role_is_function_only() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    sqlx::raw_sql(
        "CREATE ROLE rss_app LOGIN PASSWORD 'writer';
         CREATE ROLE rss_app_read LOGIN PASSWORD 'reader';
         CREATE ROLE rss_inbox_receipt_maintenance NOLOGIN BYPASSRLS;
         CREATE TABLE public.inbox_receipts (
           tenant_id uuid NOT NULL, event_id text NOT NULL, consumer_group text NOT NULL,
           status text NOT NULL, claimed_at timestamptz NOT NULL, trace text, lease_token uuid
         );
         GRANT SELECT ON public.inbox_receipts TO rss_app_read;
         GRANT SELECT, DELETE ON public.inbox_receipts TO rss_inbox_receipt_maintenance;",
    )
    .execute(&pool)
    .await?;
    sqlx::raw_sql(MIGRATION).execute(&pool).await?;
    sqlx::raw_sql(
        "INSERT INTO public.inbox_receipts VALUES
         ('00000000-0000-4000-8000-000000000001','a','settings.config-version-changed',
          'claimed',now()-interval '120 seconds','secret',
          '00000000-0000-4000-8000-000000000002');",
    )
    .execute(&pool)
    .await?;

    let mut reader = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app_read")
        .execute(&mut *reader)
        .await?;
    let (depth,): (i64,) = sqlx::query_as(
        "SELECT depth FROM public.rss_inbox_sample_backlog(
           ARRAY['settings.config-version-changed'])",
    )
    .fetch_one(&mut *reader)
    .await?;
    assert_eq!(depth, 1);
    assert!(
        sqlx::query("SELECT tenant_id FROM public.inbox_receipts")
            .execute(&mut *reader)
            .await
            .is_err()
    );
    reader.rollback().await?;

    for (case, query) in [
        (
            "null selection",
            "SELECT * FROM public.rss_inbox_sample_backlog(NULL)",
        ),
        (
            "empty selection",
            "SELECT * FROM public.rss_inbox_sample_backlog(ARRAY[]::text[])",
        ),
        (
            "null element",
            "SELECT * FROM public.rss_inbox_sample_backlog(ARRAY['settings.config-version-changed', NULL]::text[])",
        ),
        (
            "duplicate group",
            "SELECT * FROM public.rss_inbox_sample_backlog(ARRAY['settings.config-version-changed', 'settings.config-version-changed'])",
        ),
        (
            "unknown group",
            "SELECT * FROM public.rss_inbox_sample_backlog(ARRAY['forged.consumer-group'])",
        ),
    ] {
        let mut invalid = pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app_read")
            .execute(&mut *invalid)
            .await?;
        let result = sqlx::query(query).execute(&mut *invalid).await;
        let sqlstate = result
            .as_ref()
            .err()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|error| error.code());
        assert_eq!(sqlstate.as_deref(), Some("22023"), "{case}: {result:?}");
        invalid.rollback().await?;
    }

    let mut writer = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *writer)
        .await?;
    assert!(
        sqlx::query(
            "SELECT * FROM public.rss_inbox_sample_backlog(
           ARRAY['settings.config-version-changed'])",
        )
        .execute(&mut *writer)
        .await
        .is_err()
    );
    writer.rollback().await?;
    Ok(())
}
