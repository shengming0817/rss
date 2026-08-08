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

async fn connect_fixture() -> Result<(testkit::OwnedPgFixture, sqlx::PgPool), TestError> {
    let fixture = testkit::owned_postgres().await?;
    let params = fixture.owner_params();
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

/// Restored from `9af7939d^:adapters/postgres/src/integration_tests.rs`
/// (`migration_0067_historical_fixture_is_idempotent`); Cargo `[[test]] required-features`
/// owns eligibility — no harness ignore attribute.
#[tokio::test(flavor = "multi_thread")]
async fn migration_0067_historical_fixture_is_idempotent() -> TestResult {
    let (_fixture, pool) = connect_fixture().await?;
    migrations_through(66).run(&pool).await?;
    sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_app_read') THEN
                CREATE ROLE rss_app_read LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
                    NOREPLICATION NOINHERIT;
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await?;
    let public_large_object: i64 =
        sqlx::query_scalar("SELECT lo_from_bytea(0, decode('7075626c6963', 'hex'))::bigint")
            .fetch_one(&pool)
            .await?;
    let grantable_large_object: i64 =
        sqlx::query_scalar("SELECT lo_from_bytea(0, decode('6772616e7461626c65', 'hex'))::bigint")
            .fetch_one(&pool)
            .await?;
    sqlx::raw_sql(&format!(
        "GRANT SELECT ON LARGE OBJECT {public_large_object} TO PUBLIC; \
         GRANT SELECT ON LARGE OBJECT {grantable_large_object} TO rss_app_read WITH GRANT OPTION; \
         GRANT SET ON PARAMETER work_mem TO PUBLIC; \
         GRANT ALTER SYSTEM ON PARAMETER maintenance_work_mem TO rss_app_read WITH GRANT OPTION; \
         GRANT EXECUTE ON FUNCTION pg_catalog.lo_create(oid) TO rss_app_read"
    ))
    .execute(&pool)
    .await?;
    migrations_through(67).run(&pool).await?;
    migrations_through(67).run(&pool).await?;

    let applied: Vec<(i64, bool)> = sqlx::query_as(
        "SELECT version, success FROM _sqlx_migrations WHERE version >= 66 ORDER BY version",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(applied, vec![(66, true), (67, true)]);
    let reader_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_app_read')")
            .fetch_one(&pool)
            .await?;
    assert!(reader_exists);
    let residual_large_object_acl: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_largeobject_metadata object \
         CROSS JOIN LATERAL aclexplode(object.lomacl) acl \
         WHERE object.oid IN ($1::oid, $2::oid) \
           AND acl.grantee IN (0::oid, (SELECT oid FROM pg_roles WHERE rolname = 'rss_app_read'))",
    )
    .bind(public_large_object)
    .bind(grantable_large_object)
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        residual_large_object_acl, 0,
        "0067 must converge direct/PUBLIC and grantable large-object ACL drift"
    );
    let residual_parameter_acl: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_parameter_acl parameter \
         CROSS JOIN LATERAL aclexplode(parameter.paracl) acl \
         WHERE parameter.parname IN ('work_mem', 'maintenance_work_mem') \
           AND acl.grantee IN (0::oid, (SELECT oid FROM pg_roles WHERE rolname = 'rss_app_read'))",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        residual_parameter_acl, 0,
        "0067 must converge direct/PUBLIC and grantable parameter ACL drift"
    );
    let reader_mutator_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM unnest(ARRAY[
            'pg_catalog.lo_creat(integer)'::regprocedure,
            'pg_catalog.lo_create(oid)'::regprocedure,
            'pg_catalog.lo_from_bytea(oid,bytea)'::regprocedure,
            'pg_catalog.lo_put(oid,bigint,bytea)'::regprocedure,
            'pg_catalog.lo_truncate(integer,integer)'::regprocedure,
            'pg_catalog.lo_truncate64(integer,bigint)'::regprocedure,
            'pg_catalog.lo_unlink(oid)'::regprocedure,
            'pg_catalog.lowrite(integer,bytea)'::regprocedure,
            'pg_catalog.lo_import(text)'::regprocedure,
            'pg_catalog.lo_import(text,oid)'::regprocedure
        ]) AS mutator(oid)
        WHERE has_function_privilege('rss_app_read', mutator.oid, 'EXECUTE')
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        reader_mutator_count, 0,
        "0067 must remove every effective reader large-object mutator EXECUTE path"
    );
    let writer_missing_mutator_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM unnest(ARRAY[
            'pg_catalog.lo_creat(integer)'::regprocedure,
            'pg_catalog.lo_create(oid)'::regprocedure,
            'pg_catalog.lo_from_bytea(oid,bytea)'::regprocedure,
            'pg_catalog.lo_put(oid,bigint,bytea)'::regprocedure,
            'pg_catalog.lo_truncate(integer,integer)'::regprocedure,
            'pg_catalog.lo_truncate64(integer,bigint)'::regprocedure,
            'pg_catalog.lo_unlink(oid)'::regprocedure,
            'pg_catalog.lowrite(integer,bytea)'::regprocedure
        ]) AS mutator(oid)
        WHERE NOT has_function_privilege('rss_app', mutator.oid, 'EXECUTE')
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        writer_missing_mutator_count, 0,
        "0067 must preserve the existing writer large-object behavior explicitly"
    );
    sqlx::query(&format!(
        "SELECT lo_unlink(object_oid::oid) FROM unnest(ARRAY[{public_large_object}, {grantable_large_object}]::bigint[]) object_oid"
    ))
    .execute(&pool)
    .await?;
    pool.close().await;
    Ok(())
}
