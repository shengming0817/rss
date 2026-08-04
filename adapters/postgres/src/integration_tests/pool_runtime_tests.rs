//! Postgres integration tests — pool_runtime seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn private_ca_tls_carries_all_fixed_runtime_role_gates() -> TestResult {
    const ARCHIVER_PASSWORD: &str = "rss_dlx_archiver_test_pw";
    const VERIFIER_PASSWORD: &str = "rss_dlx_verifier_test_pw";
    const PURGER_PASSWORD: &str = "rss_dlx_purger_test_pw";

    let network = testkit::bridge_network("rss-pg-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::postgres_tls(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: &dns_name,
    })
    .await?;
    let ca_file = TestCaFile::write("private-ca", fixture.ca_pem())?;
    let wrong_ca_file = TestCaFile::write("wrong-ca", fixture.wrong_ca_pem())?;
    let params = fixture.params();

    let owner = PgStore::connect(&private_ca_pg_config(
        params,
        &params.username,
        &params.password,
        &ca_file,
    ))
    .await?;
    owner.run_migrations().await?;
    testkit::provision_postgres_test_logins_with_private_ca(
        params,
        fixture.ca_pem().as_bytes(),
        &[
            testkit::PostgresTestLogin::new(TEST_APP_ROLE, TEST_APP_PASSWORD),
            testkit::PostgresTestLogin::new(TEST_READ_ROLE, TEST_READ_PASSWORD),
            testkit::PostgresTestLogin::new("rss_dlx_archiver", ARCHIVER_PASSWORD),
            testkit::PostgresTestLogin::new("rss_dlx_verifier", VERIFIER_PASSWORD),
            testkit::PostgresTestLogin::new("rss_dlx_purger", PURGER_PASSWORD),
        ],
    )
    .await?;

    let wrong_ca = private_ca_pg_config(params, TEST_APP_ROLE, TEST_APP_PASSWORD, &wrong_ca_file);
    let rejected = PgStore::connect(&wrong_ca).await;
    assert!(
        matches!(rejected, Err(PgError::Connect { .. })),
        "an untrusted private CA must fail during PostgreSQL connection"
    );

    let writer = PgStore::connect_verified_writer(&private_ca_pg_config(
        params,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
        &ca_file,
    ))
    .await?;
    let reader = PgStore::connect_verified_read(&crate::pool::PgTenantReadConfig::new(
        private_ca_pg_config(params, TEST_READ_ROLE, TEST_READ_PASSWORD, &ca_file),
    ))
    .await?;
    let archiver = private_ca_pg_config(params, "rss_dlx_archiver", ARCHIVER_PASSWORD, &ca_file);
    let verifier = private_ca_pg_config(params, "rss_dlx_verifier", VERIFIER_PASSWORD, &ca_file);
    let purger = private_ca_pg_config(params, "rss_dlx_purger", PURGER_PASSWORD, &ca_file);
    crate::PgDlxLifecycleRuntime::preflight_identities(&archiver, &verifier, &purger).await?;
    let dlx_runtime = crate::PgDlxLifecycleRuntime::setup(
        &archiver,
        &verifier,
        &purger,
        test_dlx_payload_protector(),
    )
    .await?;

    dlx_runtime.shutdown().await?;
    reader.store_arc().shutdown().await?;
    writer.store_arc().shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_gate_rejects_every_real_postgres_ledger_drift_before_runtime() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    provision_runtime_logins(fixture.params()).await?;
    let database = create_isolated_database(&admin, "serving_ledger_fence").await?;
    let owner_config = isolated_database_config(fixture.params(), &database);
    let serving_config = isolated_database_role_config(
        fixture.params(),
        &database,
        TEST_APP_ROLE,
        TEST_APP_PASSWORD,
    );
    let verdict: TestResult = async {
        let owner = PgStore::connect(&owner_config).await?;
        owner.run_migrations().await?;
        let exact = PgStore::connect_verified_writer(&serving_config).await?;
        exact.store_arc().shutdown().await?;

        sqlx::query("ALTER TABLE public._sqlx_migrations RENAME TO _sqlx_migrations_missing")
            .execute(&owner.pool)
            .await?;
        assert_serving_ledger_rejected(&serving_config, "missing").await?;
        sqlx::query("ALTER TABLE public._sqlx_migrations_missing RENAME TO _sqlx_migrations")
            .execute(&owner.pool)
            .await?;

        let head = postgres_migration_inventory::migrations()
            .last()
            .ok_or("typed migration inventory is empty")?;
        let row: (String, String, bool, Vec<u8>, i64) = sqlx::query_as(
            "DELETE FROM public._sqlx_migrations WHERE version = $1 \
             RETURNING description, installed_on::text, success, checksum, execution_time",
        )
        .bind(head.version)
        .fetch_one(&owner.pool)
        .await?;
        assert_serving_ledger_rejected(&serving_config, "stale").await?;
        sqlx::query(
            "INSERT INTO public._sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES ($1, $2, $3::timestamptz, $4, $5, $6)",
        )
        .bind(head.version)
        .bind(&row.0)
        .bind(row.1)
        .bind(row.2)
        .bind(&row.3)
        .bind(row.4)
        .execute(&owner.pool)
        .await?;

        sqlx::query(
            "INSERT INTO public._sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
             VALUES ($1, 'synthetic ahead', now(), true, $2, 0)",
        )
        .bind(head.version + 1)
        .bind(head.checksum.as_slice())
        .execute(&owner.pool)
        .await?;
        assert_serving_ledger_rejected(&serving_config, "ahead").await?;
        sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = $1")
            .bind(head.version + 1)
            .execute(&owner.pool)
            .await?;

        sqlx::query("UPDATE public._sqlx_migrations SET success = false WHERE version = $1")
            .bind(head.version)
            .execute(&owner.pool)
            .await?;
        assert_serving_ledger_rejected(&serving_config, "failed").await?;
        sqlx::query("UPDATE public._sqlx_migrations SET success = true WHERE version = $1")
            .bind(head.version)
            .execute(&owner.pool)
            .await?;

        sqlx::query(
            "UPDATE public._sqlx_migrations \
             SET checksum = decode(repeat('00', 48), 'hex') WHERE version = $1",
        )
        .bind(head.version)
        .execute(&owner.pool)
        .await?;
        assert_serving_ledger_rejected(&serving_config, "checksum").await?;
        owner.shutdown().await?;
        Ok(())
    }
    .await;
    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

#[tokio::test(flavor = "multi_thread")]
async fn serving_requires_exact_projection_generation_and_allows_other_generations() -> TestResult {
    type CatalogRow<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, &'a str);

    static GLOBAL_INPUTS: &[vocab::ProjectionInputBinding] = &[
        vocab::ProjectionInputBinding::from_static(
            "test-projection-a",
            "test",
            "projection.bound-a",
            "v1",
            TEST_SCHEMA_HASH,
            "test.event-a",
        ),
        vocab::ProjectionInputBinding::from_static(
            "test-projection-b",
            "test",
            "projection.bound-b",
            "v1",
            TEST_SCHEMA_HASH,
            "test.event-b",
        ),
    ];
    static OTHER_GENERATION_INPUTS: &[vocab::ProjectionInputBinding] =
        &[vocab::ProjectionInputBinding::from_static(
            "test-projection-unrelated",
            "test",
            "projection.unrelated",
            "v1",
            TEST_SCHEMA_HASH,
            "test.unrelated",
        )];
    let (fixture, owner) = connect_pg().await?;
    provision_runtime_logins(fixture.params()).await?;
    owner.run_migrations().await?;
    let generation: &'static str = Box::leak(
        crate::projection_events::projection_input_generation(GLOBAL_INPUTS).into_boxed_str(),
    );
    let exact = [
        (
            "test-projection-a",
            "test",
            "projection.bound-a",
            "v1",
            TEST_SCHEMA_HASH,
            "test.event-a",
        ),
        (
            "test-projection-b",
            "test",
            "projection.bound-b",
            "v1",
            TEST_SCHEMA_HASH,
            "test.event-b",
        ),
    ];
    replace_test_projection_generation(&owner, generation, &exact).await?;
    let exact_runtime =
        connect_test_projection_runtime(fixture.params(), generation, GLOBAL_INPUTS).await?;
    shutdown_runtime_deps(exact_runtime).await?;

    let other_generation: &'static str = Box::leak(
        crate::projection_events::projection_input_generation(OTHER_GENERATION_INPUTS)
            .into_boxed_str(),
    );
    replace_test_projection_generation(
        &owner,
        other_generation,
        &[(
            "test-projection-unrelated",
            "test",
            "projection.unrelated",
            "v1",
            TEST_SCHEMA_HASH,
            "test.unrelated",
        )],
    )
    .await?;
    let coexisting_runtime =
        connect_test_projection_runtime(fixture.params(), generation, GLOBAL_INPUTS).await?;
    shutdown_runtime_deps(coexisting_runtime).await?;

    let mismatched_catalogs: [(&str, &[CatalogRow<'_>]); 3] = [
        (
            "missing-global-binding",
            &[(
                "test-projection-a",
                "test",
                "projection.bound-a",
                "v1",
                TEST_SCHEMA_HASH,
                "test.event-a",
            )],
        ),
        (
            "additional-same-generation-binding",
            &[
                (
                    "test-projection-a",
                    "test",
                    "projection.bound-a",
                    "v1",
                    TEST_SCHEMA_HASH,
                    "test.event-a",
                ),
                (
                    "test-projection-b",
                    "test",
                    "projection.bound-b",
                    "v1",
                    TEST_SCHEMA_HASH,
                    "test.event-b",
                ),
                (
                    "test-projection-unexpected",
                    "test",
                    "projection.unexpected",
                    "v1",
                    TEST_SCHEMA_HASH,
                    "test.unexpected",
                ),
            ],
        ),
        (
            "mutated-same-generation-binding",
            &[
                (
                    "test-projection-a",
                    "test",
                    "projection.bound-a",
                    "v1",
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "test.event-a",
                ),
                (
                    "test-projection-b",
                    "test",
                    "projection.bound-b",
                    "v1",
                    TEST_SCHEMA_HASH,
                    "test.event-b",
                ),
            ],
        ),
    ];
    for (label, rows) in mismatched_catalogs {
        replace_test_projection_generation(&owner, generation, rows).await?;
        assert!(
            matches!(
                connect_test_projection_runtime(fixture.params(), generation, GLOBAL_INPUTS).await,
                Err(PgError::ProjectionBindings(_))
            ),
            "serving must reject {label}"
        );
    }
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_connects_and_shuts_down() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    assert_eq!(store.name(), "postgres");
    store.shutdown().await?;
    Ok(())
}
