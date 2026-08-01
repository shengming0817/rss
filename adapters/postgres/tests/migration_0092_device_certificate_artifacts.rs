const MIGRATION: &str = include_str!("../migrations/0092_persist_device_certificate_artifacts.sql");
const DEVICE_CERTIFICATE_ADAPTER: &str = include_str!("../src/device_certificate.rs");
const DEVICE_CERTIFICATE_PORT: &str =
    include_str!("../../../crates/identity/src/device_certificate/port.rs");

#[test]
fn ready_true_is_opened_and_deletion_state_is_closed() {
    assert!(MIGRATION.contains("DROP CONSTRAINT device_certificate_conditions_ready_not_true"));
    assert!(MIGRATION.contains("ADD COLUMN deletion_requested_at timestamptz"));
    assert!(MIGRATION.contains("ADD COLUMN finalizer_present boolean NOT NULL DEFAULT true"));
    assert!(MIGRATION.contains("CHECK (finalizer_present OR deletion_requested_at IS NOT NULL)"));
    assert!(MIGRATION.contains("same-generation desired update is not a deletion transition"));
}

#[test]
fn artifact_receipts_are_append_only_tenant_authority() {
    assert!(MIGRATION.contains("PRIMARY KEY (tenant_id, device_id, generation)"));
    for digest in [
        "policy_hash",
        "public_key_digest",
        "expected_state_hash",
        "artifact_digest",
    ] {
        assert!(MIGRATION.contains(digest));
    }
    assert!(MIGRATION.contains("ENABLE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("FORCE ROW LEVEL SECURITY"));
    assert!(MIGRATION.contains("CREATE FUNCTION public.rss_append_device_certificate_artifact"));
    assert!(MIGRATION.contains("SECURITY DEFINER"));
    assert!(MIGRATION.contains("OWNER TO rss_device_certificate_funnel_owner"));
    assert!(
        MIGRATION.contains("REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact")
    );
    assert!(
        MIGRATION
            .contains("GRANT EXECUTE ON FUNCTION public.rss_append_device_certificate_artifact")
    );
    assert!(MIGRATION.contains("REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER"));
    assert!(MIGRATION.contains("octet_length(artifact_id) BETWEEN 16 AND 256"));
    assert!(!MIGRATION.contains("CREATE TABLE public.certificate_revocations"));
}

#[test]
fn legacy_observed_condition_authoring_is_absent_from_the_migration_api() {
    let legacy = "rss_write_device_certificate_observed_condition";
    assert!(
        !MIGRATION.contains(&format!("CREATE FUNCTION public.{legacy}")),
        "the hard cut must not install the legacy authoring function"
    );
    assert!(
        !MIGRATION.contains(&format!("GRANT EXECUTE ON FUNCTION public.{legacy}")),
        "the hard cut must not publish a legacy execute capability"
    );
    assert!(
        !DEVICE_CERTIFICATE_ADAPTER.contains(legacy),
        "the postgres adapter must not retain a callable legacy SQL lane"
    );
    assert!(
        !DEVICE_CERTIFICATE_ADAPTER.contains("upsert_condition_states")
            && !DEVICE_CERTIFICATE_PORT.contains("upsert_condition_states"),
        "the hard cut must remove the legacy Rust authoring API from both port and adapter"
    );
}

fn assert_single_revocation_authority<'a>(relations: impl IntoIterator<Item = &'a str>) {
    let authorities = relations
        .into_iter()
        .filter(|relation| relation.contains("certificate_revocation"))
        .collect::<Vec<_>>();
    assert_eq!(
        authorities,
        vec!["certificate_revocations"],
        "certificate_revocations must remain the only durable revocation authority"
    );
}

#[test]
#[should_panic(expected = "only durable revocation authority")]
fn revocation_schema_inventory_guard_rejects_a_synthetic_second_authority() {
    assert_single_revocation_authority([
        "certificate_revocations",
        "device_certificate_revocations",
    ]);
}

#[cfg(feature = "integration")]
mod postgres {
    use std::borrow::Cow;
    use std::time::Duration;

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

    type TestError = Box<dyn std::error::Error + Send + Sync>;
    type TestResult = Result<(), TestError>;

    const MEMBERSHIP_FAILURE: &str =
        "rss_device_certificate_funnel_owner must have no role memberships";

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

    async fn pool_for(fixture: &testkit::PgFixture) -> Result<sqlx::PgPool, TestError> {
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
        Ok(pool)
    }

    async fn connect_fixture() -> Result<(testkit::PgFixture, sqlx::PgPool), TestError> {
        let fixture = testkit::env_or_postgres().await?;
        let pool = pool_for(&fixture).await?;
        Ok((fixture, pool))
    }

    fn migration_database_error(
        failure: &sqlx::migrate::MigrateError,
    ) -> Result<&(dyn sqlx::error::DatabaseError + 'static), TestError> {
        match failure {
            sqlx::migrate::MigrateError::ExecuteMigration(
                sqlx::Error::Database(database_error),
                92,
            ) => Ok(database_error.as_ref()),
            _ => Err(std::io::Error::other(format!(
                "0092 failed through an unexpected path: {failure}"
            ))
            .into()),
        }
    }

    async fn assert_0092_failure(
        pool: &sqlx::PgPool,
        expected_message: &str,
    ) -> Result<(), TestError> {
        let failure = match migrations_through(92).run(pool).await {
            Err(error) => error,
            Ok(()) => {
                return Err(std::io::Error::other(format!(
                    "0092 unexpectedly accepted preflight state: {expected_message}"
                ))
                .into());
            }
        };
        let database_error = migration_database_error(&failure)?;
        assert_eq!(database_error.code().as_deref(), Some("55000"));
        assert_eq!(database_error.message(), expected_message);

        let ledger: (Option<i64>, i64) = sqlx::query_as(
            "SELECT max(version), count(*) FILTER (WHERE version = 92) \
             FROM public._sqlx_migrations",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(ledger, (Some(91), 0));

        let partial_objects: i64 = sqlx::query_scalar(
            "SELECT \
                 (SELECT count(*) FROM information_schema.columns \
                  WHERE table_schema = 'public' \
                    AND table_name = 'device_certificate_desired_states' \
                    AND column_name IN ('deletion_requested_at', 'finalizer_present')) \
               + (SELECT count(*) FROM information_schema.tables \
                  WHERE table_schema = 'public' \
                    AND table_name = 'device_certificate_authorized_artifacts') \
               + (SELECT count(*) FROM pg_catalog.pg_proc \
                  WHERE oid = pg_catalog.to_regprocedure( \
                    'public.rss_append_device_certificate_artifact(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)'))",
        )
        .fetch_one(pool)
        .await?;
        assert_eq!(
            partial_objects, 0,
            "failed 0092 must roll back every DDL carrier"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn migration_0092_rejects_live_authority_and_memberships_then_retries_cleanly()
    -> TestResult {
        let (fixture, mut pool) = connect_fixture().await?;
        migrations_through(91).run(&pool).await?;

        let tenant_id = uuid::Uuid::new_v4().to_string();
        let device_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO public.device_certificate_desired_states ( \
                 tenant_id, device_id, generation, validity_seconds, renew_before_seconds, \
                 client_auth, server_auth, sans \
             ) VALUES ($1::uuid, $2::uuid, 1, 3600, 600, true, false, ARRAY[]::text[])",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&pool)
        .await?;
        let target_id: String = sqlx::query_scalar(
            "INSERT INTO public.reconcile_targets ( \
                 tenant_id, reconciler_id, resource_kind, resource_id \
             ) VALUES ($1::uuid, 'identity.device-certificate', 'device-certificate', $2) \
             RETURNING target_id::text",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .fetch_one(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO public.reconcile_leases ( \
                 tenant_id, target_id, state, lease_token, holder_id, epoch, \
                 acquired_at, expires_at, heartbeat_at \
             ) VALUES ( \
                 $1::uuid, $2::uuid, 'held', gen_random_uuid(), 'legacy-worker', 1, \
                 pg_catalog.transaction_timestamp(), \
                 pg_catalog.transaction_timestamp() + interval '5 minutes', \
                 pg_catalog.transaction_timestamp())",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&pool)
        .await?;

        assert_0092_failure(
            &pool,
            "0092 requires every device-certificate reconcile lease to be free",
        )
        .await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;
        sqlx::query(
            "UPDATE public.reconcile_leases SET \
                 state = 'free', lease_token = NULL, holder_id = NULL, \
                 acquired_at = NULL, expires_at = NULL, heartbeat_at = NULL \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(&tenant_id)
        .bind(&target_id)
        .execute(&pool)
        .await?;

        sqlx::raw_sql(
            "CREATE ROLE rss_device_certificate_funnel_owner \
                 NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOINHERIT; \
             CREATE ROLE rss_0092_membership_attacker LOGIN; \
             CREATE ROLE rss_0092_membership_parent NOLOGIN; \
             GRANT rss_device_certificate_funnel_owner TO rss_0092_membership_attacker;",
        )
        .execute(&pool)
        .await?;
        assert_0092_failure(&pool, MEMBERSHIP_FAILURE).await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        sqlx::raw_sql(
            "REVOKE rss_device_certificate_funnel_owner FROM rss_0092_membership_attacker; \
             GRANT rss_0092_membership_parent TO rss_device_certificate_funnel_owner;",
        )
        .execute(&pool)
        .await?;
        assert_0092_failure(&pool, MEMBERSHIP_FAILURE).await?;
        pool.close().await;
        pool = pool_for(&fixture).await?;

        sqlx::query("REVOKE rss_0092_membership_parent FROM rss_device_certificate_funnel_owner")
            .execute(&pool)
            .await?;
        migrations_through(92).run(&pool).await?;

        let installed: (Option<i64>, i64, bool, bool, bool) = sqlx::query_as(
            "SELECT max(version), count(*) FILTER (WHERE version = 92), bool_and(success), \
                    pg_catalog.to_regclass( \
                        'public.device_certificate_authorized_artifacts') IS NOT NULL, \
                    pg_catalog.to_regprocedure( \
                        'public.rss_append_device_certificate_artifact(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)') IS NOT NULL \
             FROM public._sqlx_migrations",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(installed, (Some(92), 1, true, true, true));
        pool.close().await;
        Ok(())
    }
}
