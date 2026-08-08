//! Postgres integration tests — revocation seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn revocation_facade_rejects_scope_mismatch_before_querying_revocation_table() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let transaction_scope = unique_revocation_scope();
    let mismatched_scope = diport::CertScope::new(
        vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?,
        transaction_scope.device(),
    );
    let serial = revocation_serial(&[0x18, 0x82, 0x01]);
    let scoped =
        crate::cotx::TenantDb::<crate::cotx::ServingWriteLane>::from_unverified_for_test(&app);

    // An ACCESS EXCLUSIVE lock is the SQL-execution sentinel: any query against the revocation
    // table would remain blocked until this transaction is released. A scope mismatch must be
    // rejected by the direct façade before reaching that table.
    let mut table_blocker = owner.pool.begin().await?;
    sqlx::query("LOCK TABLE public.certificate_revocations IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *table_blocker)
        .await?;
    let observed = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        scoped.revocation_write(
            transaction_scope,
            move |mut tx| {
                Box::pin(async move {
                    tx.revocations()
                        .is_certificate_revoked(mismatched_scope, serial)
                        .await
                })
            },
            crate::revocation::storage_error,
        ),
    )
    .await;
    table_blocker.rollback().await?;

    let result = observed.map_err(|_| {
        std::io::Error::other(
            "revocation scope mismatch queried its table instead of failing before façade SQL",
        )
    })?;
    assert!(
        result.is_err(),
        "a direct revocation façade call must fail closed on tenant scope mismatch"
    );

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}
/// PostgreSQL residual: `rss_app` without SET LOCAL tenant observes zero revocation rows.
/// Round-trip / scope / conflict / rotation owned by
/// `revocation_store_satisfies_provider_neutral_conformance` (`assert_revocation_semantics`).
#[tokio::test(flavor = "multi_thread")]
async fn revocation_rss_app_without_tenant_guc_sees_zero_rows() -> TestResult {
    let (fixture, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let store = deps.handle().infra().revocation_store();
    let scope = unique_revocation_scope();
    let serial = revocation_serial(&[0x17, 0x99, 0x01]);
    let expiry = revocation_expiry_after(3_600);

    // Minimal seed so fail-closed is not vacuously true on an empty table.
    store.revoke(serial, scope, expiry).await?;

    let app = PgStore::connect(&runtime_pg_config(
        fixture.owner_params(),
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    ))
    .await?;
    let visible_without_tenant: i64 =
        sqlx::query_scalar("SELECT count(*) FROM certificate_revocations")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(
        visible_without_tenant, 0,
        "rss_app without SET LOCAL tenant must observe no revocation evidence"
    );
    app.shutdown().await?;
    shutdown_runtime_deps(deps).await
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_store_satisfies_provider_neutral_conformance() -> TestResult {
    let (fixture, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let evidence_pool = runtime_assertion_pool(fixture.owner_params()).await?;
    let primary_scope = unique_revocation_scope();
    let other_tenant_scope = diport::CertScope::new(
        vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?,
        primary_scope.device(),
    );
    let other_device_scope = diport::CertScope::new(
        primary_scope.tenant(),
        ids::DeviceId::new(uuid::Uuid::new_v4()),
    );
    let database_now: i64 = sqlx::query_scalar(
        "SELECT pg_catalog.floor(\
             EXTRACT(epoch FROM pg_catalog.clock_timestamp())\
         )::bigint",
    )
    .fetch_one(&evidence_pool)
    .await?;
    let valid_expiry = u64::try_from(database_now + 10)?;
    let harness = PgRevocationConformanceHarness {
        store: deps.handle().infra().revocation_store(),
        evidence_pool: evidence_pool.clone(),
    };
    let cases = testkit::revocation::RevocationCases {
        primary_scope,
        other_tenant_scope,
        other_device_scope,
        primary_serial: revocation_serial(&[0x17, 0x99, 0x30]),
        rotated_serial: revocation_serial(&[0x17, 0x99, 0x31]),
        concurrent_serial: revocation_serial(&[0x17, 0x99, 0x32]),
        concurrent_conflict_serial: revocation_serial(&[0x17, 0x99, 0x33]),
        expired_serial: revocation_serial(&[0x17, 0x99, 0x34]),
        valid_expiry: revocation_expiry_at_unix(valid_expiry),
        conflicting_expiry: revocation_expiry_at_unix(valid_expiry + 60),
        expired_expiry: revocation_expiry_at_unix(1),
    };

    let result = testkit::revocation::assert_revocation_semantics(
        || harness.clone(),
        cases,
        |store, serial, scope, not_after| {
            Box::pin(async move {
                store
                    .store
                    .revoke(serial, scope, not_after)
                    .await
                    .map_err(|error| Box::new(error) as TestError)
            })
        },
        |store, serial, scope| {
            Box::pin(async move {
                store
                    .store
                    .is_revoked(serial, scope)
                    .await
                    .map_err(|error| Box::new(error) as TestError)
            })
        },
        |store, serial, scope| Box::pin(store.evidence(serial, scope)),
        |_| {
            Box::pin(async {
                await_delay(std::time::Duration::from_secs(11)).await;
            })
        },
    )
    .await;

    evidence_pool.close().await;
    shutdown_runtime_deps(deps).await?;
    result?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_store_commit_failure_is_redacted_rolled_back_and_quarantined() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    provision_runtime_logins(&fixture).await?;
    let database = create_isolated_database(&admin, "revocation_commit_failure").await?;
    let owner_config = isolated_database_config(fixture.owner_params(), &database);
    let serving_config = isolated_database_role_config(
        fixture.owner_params(),
        &database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    );
    let tenant_read_config = isolated_tenant_read_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let mutator = PgStore::connect(&owner_config).await?;
        mutator.run_migrations().await?;
        let deps = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await?;
        sqlx::raw_sql(
            r#"
            CREATE SEQUENCE public.revocation_commit_backend_pid;
            CREATE FUNCTION public.reject_revocation_on_commit()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $$
            BEGIN
                PERFORM pg_catalog.setval(
                    'public.revocation_commit_backend_pid'::pg_catalog.regclass,
                    pg_catalog.pg_backend_pid()
                );
                RAISE EXCEPTION 'injected revocation commit secret';
            END;
            $$;
            CREATE CONSTRAINT TRIGGER reject_revocation_on_commit
            AFTER INSERT ON public.certificate_revocations
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION public.reject_revocation_on_commit();
            "#,
        )
        .execute(&mutator.pool)
        .await?;

        let store = deps.handle().infra().revocation_store();
        let scope = unique_revocation_scope();
        let serial = revocation_serial(&[0x17, 0x99, 0x35]);
        let error = store
            .revoke(serial.clone(), scope, revocation_expiry_after(3_600))
            .await
            .expect_err("deferred constraint trigger must reject revocation commit");
        assert_eq!(error.to_string(), "revocation store operation failed");
        assert!(
            !format!("{error:?}").contains("injected revocation commit secret"),
            "provider error detail must remain redacted"
        );

        let rows: i64 = sqlx::query_scalar(
            "SELECT pg_catalog.count(*) FROM public.certificate_revocations \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND serial = $3",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.device().as_uuid().to_string())
        .bind(serial.as_bytes())
        .fetch_one(&mutator.pool)
        .await?;
        assert_eq!(rows, 0, "commit failure must leave no revocation evidence");

        let backend_pid: i32 = sqlx::query_scalar::<_, i64>(
            "SELECT last_value FROM public.revocation_commit_backend_pid",
        )
        .fetch_one(&mutator.pool)
        .await?
        .try_into()?;
        await_try(std::time::Duration::from_secs(6), async || {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity WHERE pid = $1",
            )
            .bind(backend_pid)
            .fetch_one(&mutator.pool)
            .await?;
            Ok::<Option<()>, TestError>((count == 0).then_some(()))
        })
        .await
        .map_err(|error| {
            format!("commit failure backend {backend_pid} must be quarantined: {error}")
        })?;

        shutdown_runtime_deps(deps).await?;
        mutator.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}
#[tokio::test(flavor = "multi_thread")]
async fn revocation_store_survives_full_runtime_pool_rebuild() -> TestResult {
    let (fixture, first) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let scope = unique_revocation_scope();
    let serial = revocation_serial(&[0x17, 0x99, 0x20]);
    first
        .handle()
        .infra()
        .revocation_store()
        .revoke(serial.clone(), scope, revocation_expiry_after(3_600))
        .await?;
    shutdown_runtime_deps(first).await?;

    let p = fixture.owner_params();
    let owner_config = runtime_pg_config(p, &p.username, &p.password);
    let tenant_read_config = crate::pool::PgTenantReadConfig::new(runtime_pg_config(
        p,
        TEST_READ_ROLE,
        TEST_READ_PASSWORD,
    ));
    let rebuilt = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
        &owner_config,
        &runtime_pg_config(p, TEST_APP_ROLE, TEST_APP_PASSWORD),
        &tenant_read_config,
        None,
        EMPTY_PROJECTION_INPUT_GENERATION,
        &[],
    )
    .await?;
    assert!(
        rebuilt
            .handle()
            .infra()
            .revocation_store()
            .is_revoked(serial, scope)
            .await?,
        "revocation evidence must survive closing and rebuilding every runtime pool"
    );
    shutdown_runtime_deps(rebuilt).await
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_store_ignores_search_path_shadow_table_and_function() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    provision_runtime_logins(&fixture).await?;
    let database = create_isolated_database(&admin, "revocation_search_path").await?;
    let owner_config = isolated_database_config(fixture.owner_params(), &database);
    let serving_config = isolated_database_role_config(
        fixture.owner_params(),
        &database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    );
    let tenant_read_config = isolated_tenant_read_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let mutator = PgStore::connect(&owner_config).await?;
        mutator.run_migrations().await?;

        let deps = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await?;
        sqlx::raw_sql(
            r#"
            CREATE SCHEMA rss_app;
            GRANT USAGE ON SCHEMA rss_app TO rss_app;
            CREATE TABLE rss_app.certificate_revocations (
                tenant_id uuid NOT NULL,
                device_id uuid NOT NULL,
                serial bytea NOT NULL,
                revoked_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
                not_after timestamptz NOT NULL,
                PRIMARY KEY (tenant_id, device_id, serial)
            );
            GRANT SELECT ON TABLE rss_app.certificate_revocations TO rss_app;
            GRANT INSERT (tenant_id, device_id, serial, not_after)
                ON TABLE rss_app.certificate_revocations TO rss_app;
            CREATE FUNCTION rss_app.to_timestamp(bigint)
            RETURNS timestamptz
            LANGUAGE sql
            IMMUTABLE
            AS 'SELECT ''2000-01-01 00:00:00+00''::timestamptz';
            GRANT EXECUTE ON FUNCTION rss_app.to_timestamp(bigint) TO rss_app;
            "#,
        )
        .execute(&mutator.pool)
        .await?;
        sqlx::query(&format!(
            "ALTER ROLE rss_app IN DATABASE \"{database}\" \
             SET search_path = rss_app, public, pg_catalog"
        ))
        .execute(&mutator.pool)
        .await?;
        sqlx::query(
            "SELECT pg_catalog.pg_terminate_backend(pid) \
             FROM pg_catalog.pg_stat_activity \
             WHERE datname = $1 AND usename = 'rss_app' \
               AND pid <> pg_catalog.pg_backend_pid()",
        )
        .bind(&database)
        .execute(&mutator.pool)
        .await?;

        let store = deps.handle().infra().revocation_store();
        let scope = unique_revocation_scope();
        let serial = revocation_serial(&[0x17, 0x99, 0x21]);
        store
            .revoke(serial.clone(), scope, revocation_expiry_after(3_600))
            .await?;
        assert!(store.is_revoked(serial, scope).await?);

        let public_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM public.certificate_revocations")
                .fetch_one(&mutator.pool)
                .await?;
        let shadow_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM rss_app.certificate_revocations")
                .fetch_one(&mutator.pool)
                .await?;
        assert_eq!(
            public_rows, 1,
            "revocation evidence must use the gated public table"
        );
        assert_eq!(
            shadow_rows, 0,
            "the default $user search-path entry must not capture revocation evidence"
        );

        shutdown_runtime_deps(deps).await?;
        mutator.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_store_expiry_is_logical_and_retention_is_bounded_with_grace() -> TestResult {
    let (fixture, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let scope = unique_revocation_scope();
    let observer = runtime_assertion_pool(fixture.owner_params()).await?;

    sqlx::query(
        r#"
        INSERT INTO certificate_revocations
            (tenant_id, device_id, serial, revoked_at, not_after)
        SELECT $1::uuid, $2::uuid, pg_catalog.int4send(value),
               pg_catalog.clock_timestamp() - interval '10 minutes',
               pg_catalog.clock_timestamp() - interval '5 minutes 1 second'
        FROM pg_catalog.generate_series(1, 1001) AS value
        "#,
    )
    .bind(scope.tenant().to_string())
    .bind(scope.device().as_uuid().to_string())
    .execute(&observer)
    .await?;
    let grace_serial = revocation_serial(&[0x7f, 0xee]);
    sqlx::query(
        r#"
        INSERT INTO certificate_revocations
            (tenant_id, device_id, serial, revoked_at, not_after)
        VALUES ($1::uuid, $2::uuid, $3,
                pg_catalog.clock_timestamp() - interval '10 minutes',
                pg_catalog.clock_timestamp() - interval '4 minutes')
        "#,
    )
    .bind(scope.tenant().to_string())
    .bind(scope.device().as_uuid().to_string())
    .bind(grace_serial.as_bytes())
    .execute(&observer)
    .await?;

    let store = deps.handle().infra().revocation_store();
    assert!(
        !store
            .is_revoked(revocation_serial(&[0, 0, 0, 1]), scope)
            .await?,
        "expired evidence must stop revocation immediately, before physical retention"
    );
    assert!(!store.is_revoked(grace_serial.clone(), scope).await?);

    let sweeper = deps.handle().infra().revocation_sweeper();
    let first = sweeper
        .sweep_expired(crate::RevocationSweepDeadline::from_timeout(
            std::time::Duration::from_secs(5),
        )?)
        .await?;
    assert_eq!(first.deleted(), 1_000);
    assert_eq!(first.backlog().depth(), 1);

    let second = sweeper
        .sweep_expired(crate::RevocationSweepDeadline::from_timeout(
            std::time::Duration::from_secs(5),
        )?)
        .await?;
    assert_eq!(second.deleted(), 1);
    assert_eq!(second.backlog().depth(), 0);
    assert_eq!(second.backlog().oldest_age_seconds(), 0);

    let third = sweeper
        .sweep_expired(crate::RevocationSweepDeadline::from_timeout(
            std::time::Duration::from_secs(5),
        )?)
        .await?;
    assert_eq!(third.deleted(), 0);
    assert_eq!(third.backlog().depth(), 0);

    let retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM certificate_revocations \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.device().as_uuid().to_string())
    .fetch_one(&observer)
    .await?;
    assert_eq!(
        retained, 1,
        "the five-minute grace row must remain physical"
    );
    let retained_serial: Vec<u8> = sqlx::query_scalar(
        "SELECT serial FROM certificate_revocations \
         WHERE tenant_id = $1::uuid AND device_id = $2::uuid",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.device().as_uuid().to_string())
    .fetch_one(&observer)
    .await?;
    assert_eq!(retained_serial, grace_serial.as_bytes());

    observer.close().await;
    shutdown_runtime_deps(deps).await
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_store_writer_pool_outage_fails_read_and_write_closed() -> TestResult {
    let (_fixture, deps) =
        setup_runtime_deps_with_projection_inputs(EMPTY_PROJECTION_INPUT_GENERATION, &[]).await?;
    let store = deps.handle().infra().revocation_store();
    let scope = unique_revocation_scope();
    let serial = revocation_serial(&[0x17, 0x99, 0x30]);
    let expiry = revocation_expiry_after(3_600);
    shutdown_runtime_deps(deps).await?;

    assert!(
        store.is_revoked(serial.clone(), scope).await.is_err(),
        "closed writer pool must not degrade a security read to false"
    );
    assert!(
        store.revoke(serial, scope, expiry).await.is_err(),
        "closed writer pool must fail revocation writes"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_startup_capability_gate_rejects_rls_acl_role_and_function_drift() -> TestResult
{
    let (fixture, admin) = connect_pg().await?;
    provision_runtime_logins(&fixture).await?;
    let database = create_isolated_database(&admin, "revocation_capability").await?;
    let owner_config = isolated_database_config(fixture.owner_params(), &database);
    let serving_config = isolated_database_role_config(
        fixture.owner_params(),
        &database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    );
    let tenant_read_config = isolated_tenant_read_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let mutator = PgStore::connect(&owner_config).await?;
        mutator.run_migrations().await?;

        sqlx::query(
            "ALTER POLICY tenant_isolation ON certificate_revocations \
             USING (true) WITH CHECK (true)",
        )
        .execute(&mutator.pool)
        .await?;
        let policy_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query(
            "ALTER POLICY tenant_isolation ON certificate_revocations \
             USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) \
             WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
        )
        .execute(&mutator.pool)
        .await?;
        assert!(
            matches!(
                policy_drift,
                Err(crate::PgError::RlsNotEnforced | crate::PgError::RevocationSchema)
            ),
            "tenant policy expression drift must reject startup before a receipt can be minted"
        );

        sqlx::query("ALTER TABLE certificate_revocations DISABLE ROW LEVEL SECURITY")
            .execute(&mutator.pool)
            .await?;
        let rls_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query("ALTER TABLE certificate_revocations ENABLE ROW LEVEL SECURITY")
            .execute(&mutator.pool)
            .await?;
        assert!(
            matches!(rls_drift, Err(crate::PgError::RlsNotEnforced)),
            "revocation RLS drift must reject startup before a receipt can be minted"
        );

        sqlx::query("GRANT UPDATE ON certificate_revocations TO rss_app")
            .execute(&mutator.pool)
            .await?;
        let acl_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query("REVOKE UPDATE ON certificate_revocations FROM rss_app")
            .execute(&mutator.pool)
            .await?;
        assert!(
            matches!(
                acl_drift,
                Err(crate::PgError::RevocationPrivileges | crate::PgError::WriterPrivileges { .. })
            ),
            "widened serving ACL must reject revocation capability startup"
        );

        sqlx::query("ALTER ROLE rss_revocation_maintenance INHERIT")
            .execute(&mutator.pool)
            .await?;
        let role_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query("ALTER ROLE rss_revocation_maintenance NOINHERIT")
            .execute(&mutator.pool)
            .await?;
        assert!(
            matches!(role_drift, Err(crate::PgError::RevocationMaintenanceRole)),
            "maintenance role widening must reject revocation capability startup"
        );

        sqlx::query("GRANT CREATE ON SCHEMA public TO rss_revocation_maintenance")
            .execute(&mutator.pool)
            .await?;
        let schema_acl_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query("REVOKE CREATE ON SCHEMA public FROM rss_revocation_maintenance")
            .execute(&mutator.pool)
            .await?;
        assert!(
            matches!(
                schema_acl_drift,
                Err(crate::PgError::RevocationMaintenanceRole)
            ),
            "maintenance role schema ACL widening must reject startup"
        );

        sqlx::query("CREATE SEQUENCE revocation_maintenance_acl_drift")
            .execute(&mutator.pool)
            .await?;
        sqlx::query(
            "GRANT USAGE ON SEQUENCE revocation_maintenance_acl_drift \
             TO rss_revocation_maintenance",
        )
        .execute(&mutator.pool)
        .await?;
        let extra_relation_acl = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query("DROP SEQUENCE revocation_maintenance_acl_drift")
            .execute(&mutator.pool)
            .await?;
        assert!(
            matches!(
                extra_relation_acl,
                Err(crate::PgError::RevocationMaintenanceRole)
            ),
            "maintenance role ACL on another relation must reject startup"
        );

        sqlx::query(
            "CREATE FUNCTION revocation_maintenance_acl_drift() RETURNS void \
             LANGUAGE sql AS 'SELECT'",
        )
        .execute(&mutator.pool)
        .await?;
        sqlx::query("REVOKE ALL ON FUNCTION revocation_maintenance_acl_drift() FROM PUBLIC")
            .execute(&mutator.pool)
            .await?;
        sqlx::query(
            "GRANT EXECUTE ON FUNCTION revocation_maintenance_acl_drift() \
             TO rss_revocation_maintenance",
        )
        .execute(&mutator.pool)
        .await?;
        let extra_function_acl = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query("DROP FUNCTION revocation_maintenance_acl_drift()")
            .execute(&mutator.pool)
            .await?;
        assert!(
            matches!(
                extra_function_acl,
                Err(crate::PgError::RevocationMaintenanceRole)
            ),
            "maintenance role ACL on another function must reject startup"
        );

        sqlx::query(
            "ALTER FUNCTION rss_sweep_expired_certificate_revocations() \
             SET search_path = public",
        )
        .execute(&mutator.pool)
        .await?;
        let function_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        sqlx::query(
            "ALTER FUNCTION rss_sweep_expired_certificate_revocations() \
             SET search_path = pg_catalog, pg_temp",
        )
        .execute(&mutator.pool)
        .await?;
        assert!(
            matches!(
                function_drift,
                Err(crate::PgError::RevocationMaintenanceFunction)
            ),
            "maintenance function drift must reject revocation capability startup"
        );

        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION public.rss_sweep_expired_certificate_revocations()
            RETURNS bigint
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp
            AS $$ BEGIN RETURN 0; END; $$
            "#,
        )
        .execute(&mutator.pool)
        .await?;
        let function_body_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &owner_config,
            &serving_config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        assert!(
            matches!(
                function_body_drift,
                Err(crate::PgError::RevocationMaintenanceFunction)
            ),
            "maintenance function body drift must reject startup"
        );

        mutator.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_capability_each_catalog_carrier_has_a_real_drift_red() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    provision_runtime_logins(&fixture).await?;
    let database = create_isolated_database(&admin, "revocation_each_carrier").await?;
    let owner_config = isolated_database_config(fixture.owner_params(), &database);
    let serving_config = isolated_database_role_config(
        fixture.owner_params(),
        &database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    );
    let tenant_read_config = isolated_tenant_read_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let mutator = PgStore::connect(&owner_config).await?;
        mutator.run_migrations().await?;

        let cases = [
            RevocationCapabilityDriftCase {
                label: "schema.rls_enabled",
                mutate_sql: "ALTER TABLE public.certificate_revocations DISABLE ROW LEVEL SECURITY",
                restore_sql: "ALTER TABLE public.certificate_revocations ENABLE ROW LEVEL SECURITY",
                expected: RevocationCapabilityDriftKind::RlsOrSchema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.rls_forced",
                mutate_sql: "ALTER TABLE public.certificate_revocations NO FORCE ROW LEVEL SECURITY",
                restore_sql: "ALTER TABLE public.certificate_revocations FORCE ROW LEVEL SECURITY",
                expected: RevocationCapabilityDriftKind::RlsOrSchema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.columns_exact",
                mutate_sql: "ALTER TABLE public.certificate_revocations ADD COLUMN drift boolean",
                restore_sql: "ALTER TABLE public.certificate_revocations DROP COLUMN drift",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.primary_key_exact",
                mutate_sql: "ALTER TABLE public.certificate_revocations DROP CONSTRAINT certificate_revocations_pkey",
                restore_sql: "ALTER TABLE public.certificate_revocations ADD PRIMARY KEY (tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.serial_check_exact",
                mutate_sql: r#"
                    ALTER TABLE public.certificate_revocations
                    DROP CONSTRAINT certificate_revocations_serial_length;
                    ALTER TABLE public.certificate_revocations
                    ADD CONSTRAINT certificate_revocations_serial_length
                    CHECK (pg_catalog.octet_length(serial) <= 20);
                "#,
                restore_sql: r#"
                    ALTER TABLE public.certificate_revocations
                    DROP CONSTRAINT certificate_revocations_serial_length;
                    ALTER TABLE public.certificate_revocations
                    ADD CONSTRAINT certificate_revocations_serial_length
                    CHECK (pg_catalog.octet_length(serial) >= 1
                           AND pg_catalog.octet_length(serial) <= 20);
                "#,
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.time_check_exact",
                mutate_sql: r#"
                    ALTER TABLE public.certificate_revocations
                    DROP CONSTRAINT certificate_revocations_time_order;
                    ALTER TABLE public.certificate_revocations
                    ADD CONSTRAINT certificate_revocations_time_order
                    CHECK (revoked_at <= not_after);
                "#,
                restore_sql: r#"
                    ALTER TABLE public.certificate_revocations
                    DROP CONSTRAINT certificate_revocations_time_order;
                    ALTER TABLE public.certificate_revocations
                    ADD CONSTRAINT certificate_revocations_time_order
                    CHECK (revoked_at < not_after);
                "#,
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.default_exact",
                mutate_sql: "ALTER TABLE public.certificate_revocations ALTER COLUMN revoked_at DROP DEFAULT",
                restore_sql: "ALTER TABLE public.certificate_revocations ALTER COLUMN revoked_at SET DEFAULT pg_catalog.clock_timestamp()",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_present",
                mutate_sql: "DROP INDEX public.certificate_revocations_retention_idx",
                restore_sql: "CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_not_partial",
                mutate_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial) WHERE false",
                restore_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_not_unique",
                mutate_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE UNIQUE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                restore_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_has_no_included_columns",
                mutate_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial) INCLUDE (revoked_at)",
                restore_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_btree",
                mutate_sql: "UPDATE pg_catalog.pg_class SET relam = (SELECT oid FROM pg_catalog.pg_am WHERE amname = 'hash') WHERE oid = 'public.certificate_revocations_retention_idx'::pg_catalog.regclass",
                restore_sql: "UPDATE pg_catalog.pg_class SET relam = (SELECT oid FROM pg_catalog.pg_am WHERE amname = 'btree') WHERE oid = 'public.certificate_revocations_retention_idx'::pg_catalog.regclass",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_default_ordering",
                mutate_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after DESC NULLS FIRST, tenant_id, device_id, serial)",
                restore_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.retention_index_default_opclass_for_column_type",
                mutate_sql: r#"
                    UPDATE pg_catalog.pg_index AS target
                    SET indclass = (
                        SELECT pg_catalog.string_agg(
                            CASE WHEN key_opclass.ordinality = 1 THEN (
                                SELECT opclass.oid::text
                                FROM pg_catalog.pg_opclass AS opclass
                                JOIN pg_catalog.pg_am AS access_method
                                  ON access_method.oid = opclass.opcmethod
                                WHERE access_method.amname = 'btree'
                                  AND opclass.opcname = 'uuid_ops'
                                  AND opclass.opcdefault
                            ) ELSE key_opclass.opclass_oid::text END,
                            ' ' ORDER BY key_opclass.ordinality
                        )::pg_catalog.oidvector
                        FROM pg_catalog.unnest(target.indclass)
                            WITH ORDINALITY AS key_opclass(opclass_oid, ordinality)
                    )
                    WHERE target.indexrelid =
                        'public.certificate_revocations_retention_idx'::pg_catalog.regclass
                "#,
                restore_sql: "DROP INDEX public.certificate_revocations_retention_idx; CREATE INDEX certificate_revocations_retention_idx ON public.certificate_revocations (not_after, tenant_id, device_id, serial)",
                expected: RevocationCapabilityDriftKind::Schema,
            },
            RevocationCapabilityDriftCase {
                label: "schema.tenant_policy_exact",
                mutate_sql: "ALTER POLICY tenant_isolation ON public.certificate_revocations USING (true) WITH CHECK (true)",
                restore_sql: "ALTER POLICY tenant_isolation ON public.certificate_revocations USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
                expected: RevocationCapabilityDriftKind::RlsOrSchema,
            },
            RevocationCapabilityDriftCase {
                label: "acl.no_unexpected_grants",
                mutate_sql: "GRANT UPDATE ON TABLE public.certificate_revocations TO rss_app",
                restore_sql: "REVOKE UPDATE ON TABLE public.certificate_revocations FROM rss_app",
                expected: RevocationCapabilityDriftKind::Privileges,
            },
            RevocationCapabilityDriftCase {
                label: "acl.no_missing_grants",
                mutate_sql: "REVOKE SELECT ON TABLE public.certificate_revocations FROM rss_app_read",
                restore_sql: "GRANT SELECT ON TABLE public.certificate_revocations TO rss_app_read",
                expected: RevocationCapabilityDriftKind::Privileges,
            },
            RevocationCapabilityDriftCase {
                label: "role.attributes_exact",
                mutate_sql: "ALTER ROLE rss_revocation_maintenance INHERIT",
                restore_sql: "ALTER ROLE rss_revocation_maintenance NOINHERIT",
                expected: RevocationCapabilityDriftKind::MaintenanceRole,
            },
            RevocationCapabilityDriftCase {
                label: "role.no_memberships",
                mutate_sql: "GRANT rss_revocation_maintenance TO rss_app",
                restore_sql: "REVOKE rss_revocation_maintenance FROM rss_app",
                expected: RevocationCapabilityDriftKind::MaintenanceRole,
            },
            RevocationCapabilityDriftCase {
                label: "role.namespace_capabilities_exact",
                mutate_sql: "GRANT CREATE ON SCHEMA public TO rss_revocation_maintenance",
                restore_sql: "REVOKE CREATE ON SCHEMA public FROM rss_revocation_maintenance",
                expected: RevocationCapabilityDriftKind::MaintenanceRole,
            },
            RevocationCapabilityDriftCase {
                label: "role.no_extra_relation_capabilities",
                mutate_sql: r#"
                    CREATE SEQUENCE public.revocation_maintenance_relation_drift;
                    REVOKE ALL ON SEQUENCE public.revocation_maintenance_relation_drift FROM PUBLIC;
                    GRANT USAGE ON SEQUENCE public.revocation_maintenance_relation_drift
                        TO rss_revocation_maintenance;
                "#,
                restore_sql: "DROP SEQUENCE public.revocation_maintenance_relation_drift",
                expected: RevocationCapabilityDriftKind::MaintenanceRole,
            },
            RevocationCapabilityDriftCase {
                label: "role.no_extra_function_capabilities",
                mutate_sql: r#"
                    CREATE FUNCTION public.revocation_maintenance_function_drift()
                    RETURNS void LANGUAGE sql AS 'SELECT';
                    REVOKE ALL ON FUNCTION public.revocation_maintenance_function_drift() FROM PUBLIC;
                    GRANT EXECUTE ON FUNCTION public.revocation_maintenance_function_drift()
                        TO rss_revocation_maintenance;
                "#,
                restore_sql: "DROP FUNCTION public.revocation_maintenance_function_drift()",
                expected: RevocationCapabilityDriftKind::MaintenanceRole,
            },
            RevocationCapabilityDriftCase {
                label: "function.security_definer",
                mutate_sql: "ALTER FUNCTION public.rss_sweep_expired_certificate_revocations() SECURITY INVOKER",
                restore_sql: "ALTER FUNCTION public.rss_sweep_expired_certificate_revocations() SECURITY DEFINER",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.owner_exact",
                mutate_sql: "ALTER FUNCTION public.rss_sweep_expired_certificate_revocations() OWNER TO rss_app",
                restore_sql: RESTORE_REVOCATION_SWEEP_FUNCTION_SQL,
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.language_exact",
                mutate_sql: "UPDATE pg_catalog.pg_proc SET prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'sql') WHERE oid = 'public.rss_sweep_expired_certificate_revocations()'::pg_catalog.regprocedure",
                restore_sql: "UPDATE pg_catalog.pg_proc SET prolang = (SELECT oid FROM pg_catalog.pg_language WHERE lanname = 'plpgsql') WHERE oid = 'public.rss_sweep_expired_certificate_revocations()'::pg_catalog.regprocedure",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.signature_exact",
                mutate_sql: "UPDATE pg_catalog.pg_proc SET prorettype = 'pg_catalog.int4'::pg_catalog.regtype WHERE oid = 'public.rss_sweep_expired_certificate_revocations()'::pg_catalog.regprocedure",
                restore_sql: "UPDATE pg_catalog.pg_proc SET prorettype = 'pg_catalog.int8'::pg_catalog.regtype WHERE oid = 'public.rss_sweep_expired_certificate_revocations()'::pg_catalog.regprocedure",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.search_path_exact",
                mutate_sql: "ALTER FUNCTION public.rss_sweep_expired_certificate_revocations() SET search_path = public",
                restore_sql: "ALTER FUNCTION public.rss_sweep_expired_certificate_revocations() SET search_path = pg_catalog, pg_temp",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.body_exact",
                mutate_sql: r#"
                    CREATE OR REPLACE FUNCTION public.rss_sweep_expired_certificate_revocations()
                    RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
                    SET search_path = pg_catalog, pg_temp
                    AS $$ BEGIN RETURN 0; END; $$;
                "#,
                restore_sql: RESTORE_REVOCATION_SWEEP_FUNCTION_SQL,
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.no_unexpected_grants",
                mutate_sql: "GRANT EXECUTE ON FUNCTION public.rss_sweep_expired_certificate_revocations() TO rss_app_read",
                restore_sql: "REVOKE EXECUTE ON FUNCTION public.rss_sweep_expired_certificate_revocations() FROM rss_app_read",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.no_missing_grants",
                mutate_sql: "REVOKE EXECUTE ON FUNCTION public.rss_sweep_expired_certificate_revocations() FROM rss_app",
                restore_sql: "GRANT EXECUTE ON FUNCTION public.rss_sweep_expired_certificate_revocations() TO rss_app",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.backlog_present",
                mutate_sql: "DROP FUNCTION public.rss_certificate_revocation_retention_backlog()",
                restore_sql: RESTORE_REVOCATION_BACKLOG_FUNCTION_SQL,
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.backlog_no_unexpected_grants",
                mutate_sql: "GRANT EXECUTE ON FUNCTION public.rss_certificate_revocation_retention_backlog() TO rss_app_read",
                restore_sql: "REVOKE EXECUTE ON FUNCTION public.rss_certificate_revocation_retention_backlog() FROM rss_app_read",
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
            RevocationCapabilityDriftCase {
                label: "function.backlog_body_exact",
                mutate_sql: r#"
                    CREATE OR REPLACE FUNCTION public.rss_certificate_revocation_retention_backlog()
                    RETURNS TABLE (depth bigint, oldest_age_seconds bigint)
                    LANGUAGE sql SECURITY DEFINER
                    SET search_path = pg_catalog, pg_temp
                    AS $$ SELECT 0::bigint, 0::bigint $$;
                "#,
                restore_sql: RESTORE_REVOCATION_BACKLOG_FUNCTION_SQL,
                expected: RevocationCapabilityDriftKind::MaintenanceFunction,
            },
        ];

        for case in &cases {
            assert_revocation_capability_drift(
                &mutator,
                &owner_config,
                &serving_config,
                &tenant_read_config,
                case,
            )
            .await?;
        }

        mutator.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

#[derive(Clone)]
struct PgRevocationConformanceHarness {
    store: crate::PgRevocationStore,
    evidence_pool: sqlx::PgPool,
}

impl PgRevocationConformanceHarness {
    async fn evidence(
        &self,
        serial: diport::CertSerial,
        scope: diport::CertScope,
    ) -> Result<testkit::revocation::RevocationEvidence<String>, TestError> {
        let (record_count, first_revoked_marker): (i64, Option<String>) = sqlx::query_as(
            r#"
            SELECT pg_catalog.count(*), pg_catalog.min(revoked_at)::text
            FROM public.certificate_revocations
            WHERE tenant_id = $1::uuid
              AND device_id = $2::uuid
              AND serial = $3
            "#,
        )
        .bind(scope.tenant().as_uuid().to_string())
        .bind(scope.device().as_uuid().to_string())
        .bind(serial.as_bytes())
        .fetch_one(&self.evidence_pool)
        .await?;
        let record_count = usize::try_from(record_count)
            .map_err(|_| std::io::Error::other("negative revocation evidence count"))?;
        Ok(testkit::revocation::RevocationEvidence {
            record_count,
            first_revoked_marker,
        })
    }
}

#[derive(Clone, Copy)]
enum RevocationCapabilityDriftKind {
    Schema,
    RlsOrSchema,
    Privileges,
    MaintenanceRole,
    MaintenanceFunction,
}

impl RevocationCapabilityDriftKind {
    fn matches(self, error: &crate::PgError) -> bool {
        match self {
            Self::Schema => matches!(
                error,
                crate::PgError::RevocationSchema | crate::PgError::WriterPrivileges { .. }
            ),
            Self::RlsOrSchema => matches!(
                error,
                crate::PgError::RlsNotEnforced | crate::PgError::RevocationSchema
            ),
            Self::Privileges => matches!(
                error,
                crate::PgError::RevocationPrivileges | crate::PgError::WriterPrivileges { .. }
            ),
            Self::MaintenanceRole => {
                matches!(
                    error,
                    crate::PgError::RevocationMaintenanceRole | crate::PgError::WriterMembership
                )
            }
            Self::MaintenanceFunction => {
                matches!(
                    error,
                    crate::PgError::RevocationMaintenanceFunction
                        | crate::PgError::WriterOwnership
                        | crate::PgError::WriterPrivileges { .. }
                )
            }
        }
    }
}

struct RevocationCapabilityDriftCase {
    label: &'static str,
    mutate_sql: &'static str,
    restore_sql: &'static str,
    expected: RevocationCapabilityDriftKind,
}

async fn assert_revocation_capability_drift(
    mutator: &PgStore,
    owner_config: &PgConfig,
    serving_config: &PgConfig,
    tenant_read_config: &crate::pool::PgTenantReadConfig,
    case: &RevocationCapabilityDriftCase,
) -> TestResult {
    sqlx::raw_sql(case.mutate_sql)
        .execute(&mutator.pool)
        .await?;
    let setup = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
        owner_config,
        serving_config,
        tenant_read_config,
        None,
        EMPTY_PROJECTION_INPUT_GENERATION,
        &[],
    )
    .await;
    let restore = sqlx::raw_sql(case.restore_sql).execute(&mutator.pool).await;

    match setup {
        Ok(deps) => {
            shutdown_runtime_deps(deps).await?;
            restore?;
            panic!(
                "revocation capability drift '{}' unexpectedly minted a runtime receipt",
                case.label
            );
        }
        Err(error) => {
            restore?;
            assert!(
                case.expected.matches(&error),
                "revocation capability drift '{}' returned an unrelated error: {error}",
                case.label
            );
        }
    }
    Ok(())
}

const RESTORE_REVOCATION_SWEEP_FUNCTION_SQL: &str = r#"
CREATE OR REPLACE FUNCTION public.rss_sweep_expired_certificate_revocations()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT tenant_id, device_id, serial
        FROM public.certificate_revocations
        WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
        ORDER BY not_after, tenant_id, device_id, serial
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.certificate_revocations AS revocation
    USING expired
    WHERE revocation.tenant_id = expired.tenant_id
      AND revocation.device_id = expired.device_id
      AND revocation.serial = expired.serial;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;
ALTER FUNCTION public.rss_sweep_expired_certificate_revocations()
    OWNER TO rss_revocation_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_expired_certificate_revocations()
    FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_sweep_expired_certificate_revocations() TO rss_app;
"#;

const RESTORE_REVOCATION_BACKLOG_FUNCTION_SQL: &str = r#"
CREATE OR REPLACE FUNCTION public.rss_certificate_revocation_retention_backlog()
RETURNS TABLE (depth bigint, oldest_age_seconds bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT pg_catalog.count(*)::bigint AS depth,
           COALESCE(
               pg_catalog.floor(
                   EXTRACT(
                       EPOCH FROM pg_catalog.clock_timestamp()
                           - (pg_catalog.min(not_after) + interval '5 minutes')
                   )
               )::bigint,
               0::bigint
           ) AS oldest_age_seconds
    FROM public.certificate_revocations
    WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
$$;
ALTER FUNCTION public.rss_certificate_revocation_retention_backlog()
    OWNER TO rss_revocation_maintenance;
REVOKE ALL ON FUNCTION public.rss_certificate_revocation_retention_backlog()
    FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_certificate_revocation_retention_backlog() TO rss_app;
"#;
