//! Postgres integration tests — migrations seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn migration_0018_pins_session_audit_resource_to_event_uuid_v4() -> TestResult {
    let (_pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;

    let constraint: Option<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) \
         FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'public.audit_entries'::regclass \
           AND conname = 'audit_entries_session_event_resource_check'",
    )
    .fetch_optional(&owner.pool)
    .await?;
    let constraint = constraint.expect("0018 must install the session EventId CHECK");
    assert!(constraint.contains("identity:login"));
    assert!(constraint.contains("event:"));

    let tenant = uuid::Uuid::new_v4();
    for invalid_resource in [
        "22222222-3333-4444-8555-666666666666",
        "event:33333333-4444-1555-8666-777777777777",
        "event:33333333-4444-4555-7666-777777777777",
        "event:33333333-4444-4555-c666-777777777777",
        "event:33333333-4444-4555-e666-777777777777",
        "event:33333333-4444-4555-8666-77777777777A",
    ] {
        let insert = sqlx::query(
            "INSERT INTO audit_entries \
             (tenant_id, seq, prev_hash, entry_hash, actor, actor_kind, action, resource_kind, \
              resource_id, outcome, recorded_at_secs, recorded_at_nanos, key_id) \
             VALUES ($1::uuid, 0, $2, $2, $3::uuid, 'user', 'identity:login', 'session', $4, \
                     'success', 0, 0, 1)",
        )
        .bind(tenant.to_string())
        .bind(vec![0u8; 32])
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(invalid_resource)
        .execute(&owner.pool)
        .await;
        assert!(
            insert.is_err(),
            "0018 must reject invalid session audit resource {invalid_resource:?}"
        );
    }

    sqlx::query(
        "INSERT INTO audit_entries \
         (tenant_id, seq, prev_hash, entry_hash, actor, actor_kind, action, resource_kind, \
          resource_id, outcome, recorded_at_secs, recorded_at_nanos, key_id) \
         VALUES ($1::uuid, 0, $2, $2, $3::uuid, 'user', 'identity:login', 'session', \
                 'event:33333333-4444-4555-8666-777777777777', 'success', 0, 0, 1)",
    )
    .bind(tenant.to_string())
    .bind(vec![0u8; 32])
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&owner.pool)
    .await?;

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0083_rejects_every_legacy_saga_durable_row() -> TestResult {
    let (_pg, owner) = connect_pg().await?;
    migrations_through(82).run(&owner.pool).await?;
    let tenant = uuid::Uuid::new_v4();
    let saga_id = uuid::Uuid::new_v4();
    let mut tx = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO saga_instances \
             (tenant_id, saga_id, owner, contract_id, definition_version, \
              definition_schema_digest, action_registry_generation) \
         VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout', 'v1', $3, $4)",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .bind(generated::saga::billing_v1::CONTRACT.schema_hash())
    .bind(generated::saga::billing_v1::ACTION_REGISTRY_GENERATION)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let failure = sqlx::migrate!("./migrations")
        .run(&owner.pool)
        .await
        .expect_err("0083 must refuse legacy saga rows instead of guessing receipts");
    assert!(
        failure
            .to_string()
            .contains("cannot install saga receipts while saga durable rows exist"),
        "unexpected 0083 cutover failure: {failure}"
    );
    let table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public.saga_step_receipts') IS NOT NULL")
            .fetch_one(&owner.pool)
            .await?;
    assert!(
        !table_exists,
        "failed 0083 must roll back the entire cutover"
    );

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0085_rejects_unknown_registry_without_partial_cutover() -> TestResult {
    let (_pg, owner) = connect_pg().await?;
    migrations_through(84).run(&owner.pool).await?;
    let generation = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    sqlx::query(
        "INSERT INTO public.projection_input_bindings \
         (generation, contract_id, contract_version, schema_hash, topic) \
         VALUES ($1, 'projection.bound', 'v1', $2, 'test.event')",
    )
    .bind(generation)
    .bind(TEST_SCHEMA_HASH)
    .execute(&owner.pool)
    .await?;

    let failure = sqlx::migrate!("./migrations")
        .run(&owner.pool)
        .await
        .expect_err("0085 must reject an unknown legacy Projection registry");
    assert!(
        failure.to_string().contains(
            "projection_input_bindings does not match the exact predecessor generated set"
        ),
        "unexpected 0085 cutover failure: {failure}"
    );
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations")
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(ledger, Some(84));
    let projection_id_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM pg_catalog.pg_attribute AS attribute \
             WHERE attribute.attrelid = 'public.projection_input_bindings'::regclass \
               AND attribute.attname = 'projection_id' AND NOT attribute.attisdropped\
         )",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(
        !projection_id_exists,
        "failed 0085 must roll back every table-shape mutation"
    );
    let functions: (bool, bool, bool) = sqlx::query_as(
        "SELECT \
             to_regprocedure('public.rss_read_projection_events(bigint,integer)') IS NOT NULL, \
             to_regprocedure('public.rss_register_projection_input_binding(text,text,text,text,text)') IS NOT NULL, \
             to_regprocedure('public.rss_read_projection_events_scoped(uuid,text,text,text,text,bigint,integer)') IS NULL",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(functions, (true, true, true));
    let retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.projection_input_bindings WHERE generation = $1",
    )
    .bind(generation)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(retained, 1, "failed 0085 must preserve the unknown row");

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0085_lock_wait_is_bounded_and_rolls_back() -> TestResult {
    let (_pg, owner) = connect_pg().await?;
    migrations_through(84).run(&owner.pool).await?;
    let mut blocker = owner.pool.begin().await?;
    sqlx::query("LOCK TABLE public.projection_input_bindings IN SHARE MODE")
        .execute(&mut *blocker)
        .await?;
    let started = std::time::Instant::now();
    let failure = sqlx::migrate!("./migrations")
        .run(&owner.pool)
        .await
        .expect_err("0085 must time out while a conflicting registry lock is held");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(15),
        "0085 lock wait exceeded the bounded retry window"
    );
    let rendered = failure.to_string();
    assert!(
        rendered.contains("lock timeout") || rendered.contains("canceling statement"),
        "unexpected 0085 lock failure: {rendered}"
    );
    blocker.rollback().await?;
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations")
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(ledger, Some(84));
    let projection_id_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM pg_catalog.pg_attribute AS attribute \
             WHERE attribute.attrelid = 'public.projection_input_bindings'::regclass \
               AND attribute.attname = 'projection_id' AND NOT attribute.attisdropped\
         )",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert!(!projection_id_exists);

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0085_retires_only_the_exact_predecessor_generated_registry() -> TestResult {
    let (_pg, owner) = connect_pg().await?;
    migrations_through(84).run(&owner.pool).await?;
    sqlx::query(
        "INSERT INTO public.projection_input_bindings \
         (generation, contract_id, contract_version, schema_hash, topic) VALUES \
         ('sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895', \
          'identity.session-created', 'v1', \
          'sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516', \
          'identity.session-created'), \
         ('sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895', \
          'settings.config-version-changed', 'v1', \
          'sha256:b74288de6fd13213cb6676431f4833a7c921ec9ffe2825ad244cad49c52d17e4', \
          'settings.config-version-changed')",
    )
    .execute(&owner.pool)
    .await?;

    migrations_through(85).run(&owner.pool).await?;
    let ledger: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations")
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(ledger, Some(85));
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM projection_input_bindings")
        .fetch_one(&owner.pool)
        .await?;
    assert_eq!(retained, 0, "derived predecessor rows must be retired");
    let definition_identity_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_attribute \
         WHERE attrelid = 'public.projection_input_bindings'::regclass \
           AND attname IN ('projection_id', 'projection_definition_version', \
                           'projection_definition_schema_digest', 'source_domain') \
           AND NOT attisdropped",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(definition_identity_columns, 4);

    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migrator_applies_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?; // 应用 0001 占位
    store.run_migrations().await?; // 再跑：checksum 命中 → 幂等 no-op
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0069_backfills_every_existing_credential_exactly_once() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    run_migrations_through(&store, 68).await?;

    let tenant_id = uuid::Uuid::new_v4().to_string();
    let user_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO public.credentials \
         (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'pre-0069-user', 'phc-before-cutover', 1)",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .execute(&store.pool)
    .await?;
    let table_before: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.account_security_states')::text")
            .fetch_one(&store.pool)
            .await?;
    assert!(
        table_before.is_none(),
        "upgrade proof must begin on the exact 0068 schema"
    );

    store.run_migrations().await?;

    let row: (String, i64, i64, bool) = sqlx::query_as(
        "SELECT status, authn_epoch, version, status_changed_at = updated_at \
         FROM public.account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row, ("active".to_string(), 0, 1, true));

    let (credentials, states, missing, duplicate): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM public.credentials), \
           (SELECT count(*) FROM public.account_security_states), \
           (SELECT count(*) FROM public.credentials AS c \
              LEFT JOIN public.account_security_states AS s \
                USING (tenant_id, user_id) \
             WHERE s.user_id IS NULL), \
           (SELECT count(*) FROM ( \
                SELECT tenant_id, user_id \
                  FROM public.account_security_states \
                 GROUP BY tenant_id, user_id \
                HAVING count(*) <> 1 \
           ) AS invalid)",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(states, credentials, "every credential must have one state");
    assert_eq!(
        missing, 0,
        "backfill must leave no credential without state"
    );
    assert_eq!(
        duplicate, 0,
        "composite primary key must preclude duplicates"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0069_enforces_closed_state_and_strict_one_to_one() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_id = uuid::Uuid::new_v4().to_string();
    let user_id = uuid::Uuid::new_v4().to_string();
    let login = "account-security-constraints";

    let orphan_state = sqlx::query(
        "INSERT INTO public.account_security_states \
         (tenant_id, user_id, status, authn_epoch, version, status_changed_at, updated_at) \
         VALUES ($1::uuid, $2::uuid, 'active', 0, 1, now(), now())",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .execute(&store.pool)
    .await;
    assert!(
        orphan_state.is_err(),
        "security row without credential must be rejected"
    );

    let mut credential_only = store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO public.credentials \
         (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, $3, 'phc', 1)",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .bind(login)
    .execute(&mut *credential_only)
    .await?;
    assert!(
        credential_only.commit().await.is_err(),
        "deferred reverse FK must reject a credential-only commit"
    );

    insert_account_security_pair(&store, &tenant_id, &user_id, login).await?;

    for (column, invalid_value) in [
        ("status", "'unknown'"),
        ("authn_epoch", "-1"),
        ("version", "0"),
        ("updated_at", "status_changed_at - interval '1 second'"),
    ] {
        let sql = format!(
            "UPDATE public.account_security_states SET {column} = {invalid_value} \
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid"
        );
        let result = sqlx::query(&sql)
            .bind(&tenant_id)
            .bind(&user_id)
            .execute(&store.pool)
            .await;
        assert!(
            result.is_err(),
            "0069 CHECK must reject invalid {column}={invalid_value}"
        );
    }

    let rebound_user = uuid::Uuid::new_v4().to_string();
    let rebind = sqlx::query(
        "UPDATE public.credentials SET user_id = $3::uuid \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .bind(&rebound_user)
    .execute(&store.pool)
    .await;
    assert!(rebind.is_err(), "credential user rebind must be rejected");

    let state_only_delete = sqlx::query(
        "DELETE FROM public.account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .execute(&store.pool)
    .await;
    assert!(
        state_only_delete.is_err(),
        "reverse FK must reject deleting state while credential exists"
    );

    sqlx::query(
        "DELETE FROM public.credentials \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .execute(&store.pool)
    .await?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        remaining, 0,
        "credential deletion must cascade to its state"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0069_forces_canonical_rls_and_minimal_acl() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;

    let acl: (bool, bool, bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
           has_table_privilege('rss_app', 'public.account_security_states', 'SELECT'), \
           has_table_privilege('rss_app', 'public.account_security_states', 'INSERT'), \
           has_table_privilege('rss_app', 'public.account_security_states', 'UPDATE'), \
           has_table_privilege('rss_app', 'public.account_security_states', 'DELETE'), \
           has_table_privilege('rss_app_read', 'public.account_security_states', 'SELECT'), \
           has_table_privilege('rss_app_read', 'public.account_security_states', 'INSERT'), \
           has_table_privilege('rss_app_read', 'public.account_security_states', 'UPDATE'), \
           has_table_privilege('rss_app_read', 'public.account_security_states', 'DELETE'), \
           (SELECT relrowsecurity FROM pg_catalog.pg_class \
             WHERE oid = 'public.account_security_states'::regclass), \
           (SELECT relforcerowsecurity FROM pg_catalog.pg_class \
             WHERE oid = 'public.account_security_states'::regclass)",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        acl,
        (
            true, true, true, false, true, false, false, false, true, true
        ),
        "writer/reader ACL and ENABLE/FORCE RLS must be exact"
    );

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let user_a = uuid::Uuid::new_v4().to_string();
    let user_b = uuid::Uuid::new_v4().to_string();
    insert_account_security_pair(&owner, &tenant_a, &user_a, "rls-security-a").await?;
    insert_account_security_pair(&owner, &tenant_b, &user_b, "rls-security-b").await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&owner.pool)
        .await?;

    let mut tenant_a_tx = owner.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *tenant_a_tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant_a)
        .execute(&mut *tenant_a_tx)
        .await?;
    let visible_a: i64 = sqlx::query_scalar("SELECT count(*) FROM public.account_security_states")
        .fetch_one(&mut *tenant_a_tx)
        .await?;
    assert_eq!(visible_a, 1, "writer must see only its bound tenant");
    let cross_tenant_update = sqlx::query(
        "UPDATE public.account_security_states SET tenant_id = $1::uuid \
         WHERE tenant_id = $2::uuid AND user_id = $3::uuid",
    )
    .bind(&tenant_b)
    .bind(&tenant_a)
    .bind(&user_a)
    .execute(&mut *tenant_a_tx)
    .await;
    assert!(
        cross_tenant_update.is_err(),
        "WITH CHECK must reject a cross-tenant update"
    );
    tenant_a_tx.rollback().await?;

    let mut empty_scope_tx = owner.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *empty_scope_tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', '', true)")
        .execute(&mut *empty_scope_tx)
        .await?;
    let empty_visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.account_security_states")
            .fetch_one(&mut *empty_scope_tx)
            .await?;
    assert_eq!(
        empty_visible, 0,
        "empty tenant setting must fail closed without a uuid cast error"
    );
    empty_scope_tx.rollback().await?;

    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let unset_visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.account_security_states")
            .fetch_one(&app.pool)
            .await?;
    assert_eq!(unset_visible, 0, "unset tenant setting must fail closed");
    let direct_delete = sqlx::query("DELETE FROM public.account_security_states")
        .execute(&app.pool)
        .await;
    assert!(
        direct_delete.is_err(),
        "writer role must have no direct state deletion capability"
    );

    let reader = connect_pg_rss_app_read_role(&pg, &owner).await?;
    let mut reader_tx = reader.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant_b)
        .execute(&mut *reader_tx)
        .await?;
    let reader_visible: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.account_security_states")
            .fetch_one(&mut *reader_tx)
            .await?;
    assert_eq!(
        reader_visible, 1,
        "reader must see only its tenant through SELECT"
    );
    reader_tx.rollback().await?;

    reader.shutdown().await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0070_destroys_legacy_session_and_refresh_world_without_compatibility_shape()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    run_migrations_through(&store, 69).await?;

    let tenant = uuid::Uuid::new_v4().to_string();
    let old_session = format!("legacy-session-{}", uuid::Uuid::new_v4());
    let old_refresh = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sessions \
         (session_id, subject, tenant_id, expires_at, created_at, revoked) \
         VALUES ($1, 'legacy-subject', $2::uuid, now() + interval '1 hour', now(), false)",
    )
    .bind(&old_session)
    .bind(&tenant)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (id, tenant_id, subject, kind, token_hash, parent_id, lineage_id, status, \
          issued_at, expires_at, authn_epoch_at_issue) \
         VALUES ($1::uuid, $2::uuid, 'legacy-subject', 'user', $3, NULL, $1::uuid, \
                 'active', now(), now() + interval '1 hour', 0)",
    )
    .bind(&old_refresh)
    .bind(&tenant)
    .bind([0x70_u8; 32].as_slice())
    .execute(&store.pool)
    .await?;

    store.run_migrations().await?;

    let shape: (bool, bool, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT \
           to_regclass('public.sessions') IS NULL, \
           to_regclass('public.auth_grants') IS NOT NULL, \
           (SELECT count(*) FROM refresh_tokens), \
           (SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'refresh_tokens' \
               AND column_name IN ('subject', 'kind')), \
           (SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'refresh_tokens' \
               AND column_name IN ('auth_grant_id', 'user_id', 'auth_grant_status') \
               AND is_nullable = 'NO'), \
           EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 70 AND success)",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        shape,
        (true, true, 0, 0, 3, true),
        "0070 must erase legacy capabilities and expose only strict AuthGrant bindings"
    );
    let operational_cutover: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
           to_regprocedure('rss_sweep_expired_sessions()') IS NULL, \
           to_regprocedure('rss_sweep_expired_auth_grants()') IS NOT NULL, \
           NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_session_maintenance'), \
           EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_auth_grant_maintenance')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(operational_cutover, (true, true, true, true));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn public_setup_funnels_reject_missing_and_drifted_delivery_policy() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    let database = create_isolated_database(&admin, "delivery_policy_startup").await?;
    let config = isolated_database_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let mutator = PgStore::connect(&config).await?;
        mutator.run_migrations().await?;
        sqlx::query("DELETE FROM event_delivery_policy")
            .execute(&mutator.pool)
            .await?;
        mutator.shutdown().await?;

        let tenant_read_config = crate::pool::PgTenantReadConfig::new(config.clone());
        let runtime_missing = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &config,
            &config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        assert!(matches!(
            runtime_missing,
            Err(crate::PgError::EventDeliveryPolicyMismatch)
        ));
        let maintenance_missing = PgRuntimeDeps::connect_maintenance(&config).await;
        assert!(matches!(
            maintenance_missing,
            Err(crate::PgError::EventDeliveryPolicyMismatch)
        ));

        let mutator = PgStore::connect(&config).await?;
        sqlx::query(
            r#"
            INSERT INTO event_delivery_policy (
                singleton, policy_revision, automatic_retry_window_seconds,
                same_id_redrive_horizon_seconds, safety_margin_seconds,
                inbox_receipt_retention_seconds, relay_budget_revision,
                relay_lease_ttl_ms, relay_publish_timeout_ms,
                relay_settle_timeout_ms, relay_safety_margin_ms
            )
            VALUES (true, 'same-id-delivery-v1', 86401, 86400, 86400, 604800,
                    'relay-budget-v1', 60000, 40000, 5000, 5000)
            "#,
        )
        .execute(&mutator.pool)
        .await?;
        mutator.shutdown().await?;

        let runtime_drift = PgRuntimeDeps::setup_owned_test_fixture_with_projection_bindings(
            &config,
            &config,
            &tenant_read_config,
            None,
            EMPTY_PROJECTION_INPUT_GENERATION,
            &[],
        )
        .await;
        assert!(matches!(
            runtime_drift,
            Err(crate::PgError::EventDeliveryPolicyMismatch)
        ));
        let maintenance_drift = PgRuntimeDeps::connect_maintenance(&config).await;
        assert!(matches!(
            maintenance_drift,
            Err(crate::PgError::EventDeliveryPolicyMismatch)
        ));
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

#[tokio::test(flavor = "multi_thread")]
async fn maintenance_connect_cannot_apply_pending_migrations() -> TestResult {
    let (fixture, admin) = connect_pg().await?;
    let database = create_isolated_database(&admin, "maintenance_connect_only").await?;
    let config = isolated_database_config(fixture.owner_params(), &database);

    let verdict: TestResult = async {
        let result = PgRuntimeDeps::connect_maintenance(&config).await;
        assert!(
            result.is_err(),
            "empty schema must fail instead of being migrated"
        );

        let observer = PgStore::connect(&config).await?;
        let migrations_absent: bool =
            sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NULL")
                .fetch_one(&observer.pool)
                .await?;
        assert!(
            migrations_absent,
            "maintenance connect must never create migration ledger"
        );
        observer.shutdown().await?;
        Ok(())
    }
    .await;

    let cleanup = drop_isolated_database(&admin, &database).await;
    admin.shutdown().await?;
    cleanup?;
    verdict
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0028_rejects_non_empty_dead_letter() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::query(
        r#"
        CREATE TABLE dead_letter (
            tenant_id uuid NOT NULL,
            message_id text NOT NULL,
            original_entry jsonb NOT NULL
        )
        "#,
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO dead_letter (tenant_id, message_id, original_entry)
        VALUES ($1::uuid, 'legacy-dlx-row', '{"bytes":[1,2,3]}'::jsonb)
        "#,
    )
    .bind(COTX_TENANT_A)
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0028_encrypt_dead_letter_original_entry.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err(std::io::Error::other("0028 must reject non-empty dead_letter").into());
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("dead_letter must be empty before enabling encrypted original_entry"),
        "unexpected migration error: {rendered}"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0068_rejects_active_legacy_replay_rows_without_partial_cutover() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(67).run(&store.pool).await?;
    sqlx::query(
        "INSERT INTO service_token_replay_nonces (nonce, expires_at) \
         VALUES ('active-legacy-fixture', clock_timestamp() + interval '1 hour')",
    )
    .execute(&store.pool)
    .await?;

    let verdict = sqlx::migrate!("./migrations").run(&store.pool).await;
    assert!(
        verdict.is_err(),
        "active legacy evidence must fail the cutover"
    );
    let latest: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(latest, 67, "failed 0068 must leave the ledger unchanged");
    let tables: (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('public.service_token_replay_nonces') IS NOT NULL, \
                to_regclass('public.service_token_replay_keys') IS NOT NULL",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        tables,
        (true, false),
        "failed cutover must roll back both old-table drop and new-table create"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn migration_0068_rejects_preexisting_owner_membership_before_ownership_transfer()
-> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(67).run(&store.pool).await?;
    sqlx::raw_sql(
        "CREATE ROLE rss_service_token_replay_owner NOLOGIN; \
         GRANT rss_service_token_replay_owner TO rss_app",
    )
    .execute(&store.pool)
    .await?;

    let error = sqlx::migrate!("./migrations")
        .run(&store.pool)
        .await
        .expect_err("owner membership must reject 0068");
    assert!(
        error
            .to_string()
            .contains("rss_service_token_replay_owner must have no role memberships")
    );
    store.shutdown().await?;
    Ok(())
}

// ── reconcile target/attempt/action/lease schema (#1629) ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn migration_0084_initializes_legacy_attempt_snapshots_without_inference() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    run_migrations_through(&store, 83).await?;
    let tenant = uuid::Uuid::new_v4().to_string();
    let target_id: String = sqlx::query_scalar(
        "INSERT INTO reconcile_targets \
            (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'legacy-reconciler', 'device', $2) \
         RETURNING target_id::text",
    )
    .bind(&tenant)
    .bind(format!("legacy-device-{}", uuid::Uuid::new_v4()))
    .fetch_one(&store.pool)
    .await?;
    let attempt_id: String = sqlx::query_scalar(
        "INSERT INTO reconcile_attempts \
            (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind) \
         VALUES ($1::uuid, $2::uuid, gen_random_uuid(), 1, 'legacy-holder', 'resync') \
         RETURNING attempt_id::text",
    )
    .bind(&tenant)
    .bind(&target_id)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO reconcile_attempt_results \
            (tenant_id, attempt_id, target_id, result_label, error_kind) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'transient', 'transient')",
    )
    .bind(&tenant)
    .bind(&attempt_id)
    .bind(&target_id)
    .execute(&store.pool)
    .await?;

    store.run_migrations().await?;
    let migrated: (i64, Option<String>, i64, i64, i64) = sqlx::query_as(
        "SELECT target.failure_streak, target.last_result, target.wake_version, \
                attempt.claimed_failure_streak, attempt.claimed_wake_version \
         FROM reconcile_targets target \
         JOIN reconcile_attempts attempt USING (tenant_id, target_id) \
         WHERE target.tenant_id = $1::uuid AND target.target_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&target_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        migrated,
        (0, None, 0, 0, 0),
        "0084 must not infer retry/result/wake state from legacy ledgers"
    );
    let missing_snapshot = sqlx::query(
        "INSERT INTO reconcile_attempts \
            (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind) \
         VALUES ($1::uuid, $2::uuid, gen_random_uuid(), 2, 'new-holder', 'resync')",
    )
    .bind(&tenant)
    .bind(&target_id)
    .execute(&store.pool)
    .await;
    assert!(
        missing_snapshot.is_err(),
        "post-0084 attempts must explicitly capture streak and wake version"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0084_rejects_held_reconcile_lease_before_schema_changes() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    run_migrations_through(&store, 83).await?;
    let tenant = uuid::Uuid::new_v4().to_string();
    let target_id: String = sqlx::query_scalar(
        "INSERT INTO reconcile_targets \
            (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'cutover-reconciler', 'device', $2) \
         RETURNING target_id::text",
    )
    .bind(&tenant)
    .bind(format!("cutover-device-{}", uuid::Uuid::new_v4()))
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO reconcile_leases \
            (tenant_id, target_id, state, lease_token, holder_id, epoch, acquired_at, \
             expires_at, heartbeat_at) \
         VALUES ($1::uuid, $2::uuid, 'held', gen_random_uuid(), 'old-worker', 1, \
                 now(), now() + interval '1 hour', now())",
    )
    .bind(&tenant)
    .bind(&target_id)
    .execute(&store.pool)
    .await?;

    assert!(
        store.run_migrations().await.is_err(),
        "0084 must fail closed while an old-world worker owns a lease"
    );
    let ledger: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ledger, 83);
    let wake_column_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'reconcile_targets' \
           AND column_name = 'wake_version')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(!wake_column_exists, "failed cutover must be transactional");

    sqlx::query(
        "UPDATE reconcile_leases SET state = 'free', lease_token = NULL, holder_id = NULL, \
         acquired_at = NULL, expires_at = NULL, heartbeat_at = NULL \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(&tenant)
    .bind(&target_id)
    .execute(&store.pool)
    .await?;
    store.run_migrations().await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0084_live_guard_freezes_target_identity_and_wake_regression() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let key = ReconcileTargetKey::parse(
        "guard-reconciler",
        "device",
        &format!("guard-device-{}", uuid::Uuid::new_v4()),
    )?;
    let target = store.reconcile().upsert_target(tenant, &key).await?;

    let mut increment = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *increment)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *increment)
        .await?;
    sqlx::query(
        "UPDATE reconcile_targets SET wake_version = wake_version + 1 \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&mut *increment)
    .await?;
    increment.commit().await?;

    let before: String = sqlx::query_scalar(
        "SELECT to_jsonb(target)::text FROM reconcile_targets AS target \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .fetch_one(&store.pool)
    .await?;

    let replacement_uuid = uuid::Uuid::new_v4().to_string();
    let mutations = [
        (
            "tenant_id",
            "UPDATE reconcile_targets SET tenant_id = $3::uuid \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
            replacement_uuid.as_str(),
        ),
        (
            "target_id",
            "UPDATE reconcile_targets SET target_id = $3::uuid \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
            replacement_uuid.as_str(),
        ),
        (
            "reconciler_id",
            "UPDATE reconcile_targets SET reconciler_id = $3 \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
            "other-reconciler",
        ),
        (
            "resource_kind",
            "UPDATE reconcile_targets SET resource_kind = $3 \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
            "other-kind",
        ),
        (
            "resource_id",
            "UPDATE reconcile_targets SET resource_id = $3 \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
            "other-resource",
        ),
    ];
    for (column, statement, replacement) in mutations {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(statement)
            .bind(tenant.to_string())
            .bind(target.target_id())
            .bind(replacement)
            .execute(&mut *tx)
            .await
            .expect_err("target identity mutation must fail closed");
        assert!(
            error
                .as_database_error()
                .is_some_and(|database| database.code().as_deref() == Some("23514")),
            "{column} mutation failed through the wrong SQLSTATE: {error}"
        );
        tx.rollback().await?;
    }

    let mut regression = store.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE rss_app")
        .execute(&mut *regression)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *regression)
        .await?;
    let error = sqlx::query(
        "UPDATE reconcile_targets SET wake_version = wake_version - 1 \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .execute(&mut *regression)
    .await
    .expect_err("wake regression must fail closed");
    assert!(
        error
            .as_database_error()
            .is_some_and(|database| database.code().as_deref() == Some("23514")),
        "wake regression failed through the wrong SQLSTATE: {error}"
    );
    regression.rollback().await?;

    let after: String = sqlx::query_scalar(
        "SELECT to_jsonb(target)::text FROM reconcile_targets AS target \
         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(target.target_id())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(after, before, "rejected guard writes must preserve the row");

    let carrier: (String, Vec<String>, bool, bool) = sqlx::query_as(
        "SELECT trigger.tgenabled::text, function.proconfig, \
                has_function_privilege('rss_app', function.oid, 'EXECUTE'), \
                EXISTS ( \
                    SELECT 1 FROM pg_catalog.aclexplode( \
                        COALESCE(function.proacl, \
                                 pg_catalog.acldefault('f', function.proowner)) \
                    ) AS acl \
                    WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE' \
                ) \
         FROM pg_catalog.pg_trigger AS trigger \
         JOIN pg_catalog.pg_proc AS function ON function.oid = trigger.tgfoid \
         WHERE trigger.tgrelid = 'public.reconcile_targets'::regclass \
           AND trigger.tgname = 'reconcile_target_wake_monotonic' \
           AND NOT trigger.tgisinternal",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(carrier.0, "O");
    assert_eq!(carrier.1, vec!["search_path=pg_catalog, pg_temp"]);
    assert!(!carrier.2, "rss_app must not execute the guard directly");
    assert!(!carrier.3, "PUBLIC must not execute the guard directly");

    store.shutdown().await?;
    Ok(())
}

/// 0031：tenant_id backfill 必须 fail-closed 拒绝缺失 metadata.tenantId 的历史 outbox 行。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0031_rejects_outbox_rows_missing_tenant_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'test.event', 'contract-1', $2, '{}'::jsonb, 'pending')",
    )
    .bind(unique_event_id("bad-outbox-tenant"))
    .bind(b"payload".as_slice())
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0031_harden_outbox_tenant_scope.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err("0031 must reject outbox rows without metadata tenantId".into());
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox tenant_id backfill requires metadata.tenantId"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0040：旧 projection_events 行不做 backfill，必须 fail-fast。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0040_rejects_non_empty_legacy_projection_events() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0013_create_projection_events.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO projection_events (domain, aggregate_id, event_type, payload) \
         VALUES ('test', 'agg-1', 'test.event', $1)",
    )
    .bind(b"payload".as_slice())
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0040_projection_events_funnel_and_projection_dlx.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err("0040 must reject non-empty legacy projection_events".into());
    };
    let rendered = err.to_string();
    assert!(
        rendered
            .contains("projection_events must be empty before enabling projection writer funnel"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0055_backfills_legacy_mutable_outbox_with_rust_parity() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    create_rss_app_role_for_migration_test(&store).await?;
    sqlx::raw_sql(
        "CREATE TABLE outbox ( \
             event_id text NOT NULL, tenant_id uuid NOT NULL, domain text NOT NULL, \
             topic text NOT NULL, contract_id text NOT NULL, contract_version text NOT NULL, \
             schema_hash text NOT NULL, payload bytea NOT NULL, metadata jsonb NOT NULL, \
             partition_key text NULL, causation_id text NULL \
         ); \
         CREATE TABLE outbox_log ( \
             event_id text NOT NULL, tenant_id uuid NOT NULL, aggregate_type text NOT NULL, \
             topic text NOT NULL, contract_id text NOT NULL, contract_version text NOT NULL, \
             schema_hash text NOT NULL, payload bytea NOT NULL, metadata jsonb NOT NULL, \
             causation_id text NULL \
         ); \
         CREATE TABLE reconcile_targets ( \
             target_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), \
             status text NOT NULL DEFAULT 'active' \
         )",
    )
    .execute(&store.pool)
    .await?;
    let tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let schema_hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let metadata = serde_json::json!({
        "actor": {"kind": "user", "id": "legacy-actor"},
        "occurredAt": 17,
        "subjectId": "legacy-subject"
    });
    sqlx::query(
        "INSERT INTO outbox ( \
             event_id, tenant_id, domain, topic, contract_id, contract_version, schema_hash, \
             payload, metadata, partition_key, causation_id \
         ) VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)",
    )
    .bind("legacy-mutable-event")
    .bind(tenant)
    .bind("identity")
    .bind("identity.session-created")
    .bind("identity.session-created")
    .bind("v1")
    .bind(schema_hash)
    .bind(b"legacy-payload".as_slice())
    .bind(metadata.to_string())
    .bind("legacy-partition")
    .bind("legacy-cause")
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../../migrations/0055_outbox_fact_fingerprint.sql"
    ))
    .execute(&store.pool)
    .await?;

    let stored = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT fact_fingerprint FROM outbox WHERE event_id = 'legacy-mutable-event'",
    )
    .fetch_one(&store.pool)
    .await?;
    let rust = OutboxFactIdentity::new(
        "legacy-mutable-event",
        tenant,
        "identity",
        "identity.session-created",
        "identity.session-created",
        "v1",
        schema_hash,
        b"legacy-payload",
        Some("legacy-partition"),
        Some("legacy-cause"),
        &metadata,
    )
    .fingerprint();
    assert_eq!(stored.len(), 32);
    assert_eq!(stored.as_slice(), rust.as_bytes());

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0055_rejects_non_empty_legacy_outbox_log() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(
        "CREATE TABLE outbox_log (event_id text NOT NULL); \
         INSERT INTO outbox_log (event_id) VALUES ('legacy-cdc-event')",
    )
    .execute(&store.pool)
    .await?;

    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0055_outbox_fact_fingerprint.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(error) = result else {
        return Err("0055 must reject non-empty legacy outbox_log".into());
    };
    assert!(
        error
            .to_string()
            .contains("outbox_log must be empty before canonical fact fingerprint migration")
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0056_backfills_terminal_timestamps_from_updated_at() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    create_rss_app_role_for_migration_test(&store).await?;
    sqlx::raw_sql(
        r#"
        CREATE TABLE outbox (
            event_id text PRIMARY KEY,
            tenant_id uuid NOT NULL,
            domain text NOT NULL,
            topic text NOT NULL,
            contract_id text NOT NULL,
            contract_version text NOT NULL,
            schema_hash text NOT NULL,
            payload bytea NOT NULL,
            metadata jsonb NOT NULL,
            status text NOT NULL,
            retry_count int NOT NULL DEFAULT 0,
            retry_after timestamptz,
            lease_token uuid,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL
        );
        CREATE INDEX idx_outbox_sweep ON outbox (status, created_at);
        INSERT INTO outbox (
            event_id, tenant_id, domain, topic, contract_id, contract_version,
            schema_hash, payload, metadata, status, created_at, updated_at
        )
        SELECT status,
               '11111111-1111-1111-1111-111111111111'::uuid,
               'migration', 'migration.event', 'migration.contract', 'v1',
               'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
               'payload'::bytea, '{}'::jsonb, status,
               TIMESTAMPTZ '2024-01-01 00:00:00+00',
               TIMESTAMPTZ '2024-01-02 00:00:00+00' + ordinal * INTERVAL '1 hour'
        FROM (VALUES
            ('pending', 1), ('publishing', 2), ('published', 3), ('dlx', 4)
        ) AS states(status, ordinal);
        "#,
    )
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../../migrations/0056_add_outbox_terminal_timestamps.sql"
    ))
    .execute(&store.pool)
    .await?;

    let rows: Vec<(String, bool, bool, bool, bool)> = sqlx::query_as(
        r#"
        SELECT status,
               published_at IS NULL,
               dlx_at IS NULL,
               published_at IS NOT DISTINCT FROM updated_at,
               dlx_at IS NOT DISTINCT FROM updated_at
        FROM outbox
        ORDER BY status
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        rows,
        vec![
            ("dlx".to_string(), true, false, false, true),
            ("pending".to_string(), true, true, false, false),
            ("published".to_string(), false, true, true, false),
            ("publishing".to_string(), true, true, false, false),
        ]
    );

    store.shutdown().await?;
    Ok(())
}

/// 0045：legacy reconcile_actions 的 terminal result 必须先 backfill 到 reconcile_attempt_results。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0045_backfills_legacy_reconcile_action_results() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    create_rss_app_role_for_migration_test(&store).await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0041_create_reconcile_schema.sql"
    ))
    .execute(&store.pool)
    .await?;

    let tenant = vocab::TenantId::parse("11111111-1111-1111-1111-111111111111")?;
    let target_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_targets (tenant_id, reconciler_id, resource_kind, resource_id) \
         VALUES ($1::uuid, 'migration-reconciler', 'device', 'migration-device') \
         RETURNING target_id::text",
    )
    .bind(tenant.to_string())
    .fetch_one(&store.pool)
    .await?;
    let attempt_id: (String,) = sqlx::query_as(
        "INSERT INTO reconcile_attempts \
         (tenant_id, target_id, lease_token, epoch, holder_id, trigger_kind) \
         VALUES ($1::uuid, $2::uuid, gen_random_uuid(), 1, 'holder-a', 'resync') \
         RETURNING attempt_id::text",
    )
    .bind(tenant.to_string())
    .bind(&target_id.0)
    .fetch_one(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO reconcile_actions \
         (tenant_id, attempt_id, target_id, action_kind, result_label, requeue_after_ms, error_kind) \
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'update', 'transient', NULL, NULL)",
    )
    .bind(tenant.to_string())
    .bind(&attempt_id.0)
    .bind(&target_id.0)
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../../migrations/0044_create_reconcile_attempt_results.sql"
    ))
    .execute(&store.pool)
    .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0045_reconcile_actions_recorded_label.sql"
    ))
    .execute(&store.pool)
    .await?;

    let result: (String, Option<String>) = sqlx::query_as(
        "SELECT result_label, error_kind \
         FROM reconcile_attempt_results \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&attempt_id.0)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        result,
        ("transient".to_string(), Some("transient".to_string())),
        "0045 must preserve legacy terminal result before action rows become recorded"
    );

    let action: (String, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT result_label, requeue_after_ms, error_kind \
         FROM reconcile_actions \
         WHERE tenant_id = $1::uuid AND attempt_id = $2::uuid",
    )
    .bind(tenant.to_string())
    .bind(&attempt_id.0)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(action, ("recorded".to_string(), None, None));

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0080_rejects_unpinned_legacy_saga_instances() -> TestResult {
    let (_pg, owner) = connect_pg().await?;
    migrations_through(79).run(&owner.pool).await?;
    let tenant = uuid::Uuid::new_v4();
    let saga_id = uuid::Uuid::new_v4();
    let mut tx = owner.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO saga_instances (tenant_id, saga_id, owner, contract_id) \
         VALUES ($1::uuid, $2::uuid, 'billing', 'billing.checkout')",
    )
    .bind(tenant.to_string())
    .bind(saga_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let error = match sqlx::migrate!("./migrations").run(&owner.pool).await {
        Ok(()) => {
            return Err(std::io::Error::other(
                "legacy rows without exact identity passed migration 0080",
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("cannot pin exact saga definition identity"),
        "unexpected migration failure: {error}"
    );
    let identity_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'saga_instances' \
           AND column_name IN ('definition_version', 'definition_schema_digest', \
                               'action_registry_generation')",
    )
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        identity_columns, 0,
        "failed migration must roll back every new column"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0079_upgrades_live_sweeper_and_sweeps_preexisting_family() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    migrations_through(78).run(&owner.pool).await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let case = RefreshProducerCase::new(tenant);
    case.seed(&app, &owner).await?;
    sqlx::query(
        "UPDATE auth_grants SET expires_at = clock_timestamp() - interval '1 second' \
         WHERE tenant_id = $1::uuid AND grant_id = $2",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(case.grant.id().as_str())
    .execute(&owner.pool)
    .await?;

    let predecessor: (i64, String, i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT max(version) FROM _sqlx_migrations), \
         pg_get_functiondef('rss_sweep_expired_auth_grants()'::regprocedure), \
         (SELECT count(*) FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND auth_grant_id = $2)",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(case.grant.id().as_str())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(predecessor.0, 78);
    assert!(predecessor.1.contains("FOR UPDATE SKIP LOCKED"));
    assert_eq!((predecessor.2, predecessor.3), (1, 1));

    migrations_through(79).run(&owner.pool).await?;

    let ledger: (i64, i64, bool) =
        sqlx::query_as("SELECT max(version), count(*), bool_and(success) FROM _sqlx_migrations")
            .fetch_one(&owner.pool)
            .await?;
    assert_eq!(ledger, (79, 79, true));

    let function: (String, String, bool, bool, Vec<String>) = sqlx::query_as(
        "SELECT \
         pg_get_functiondef(p.oid), \
         pg_get_userbyid(p.proowner), \
         p.prosecdef, \
         p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[], \
         ARRAY( \
             SELECT COALESCE(grantee.rolname, 'PUBLIC') \
             FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl \
             LEFT JOIN pg_roles grantee ON grantee.oid = acl.grantee \
             WHERE acl.privilege_type = 'EXECUTE' \
             ORDER BY COALESCE(grantee.rolname, 'PUBLIC') \
         ) \
         FROM pg_proc p \
         WHERE p.oid = 'rss_sweep_expired_auth_grants()'::regprocedure",
    )
    .fetch_one(&owner.pool)
    .await?;
    let normalized_function = function.0.split_whitespace().collect::<Vec<_>>().join(" ");
    let family_lock = normalized_function
        .find("FROM public.refresh_tokens AS refresh")
        .ok_or("upgraded sweeper must lock the refresh family")?;
    let family_delete = normalized_function
        .find("DELETE FROM public.refresh_tokens AS refresh")
        .ok_or("upgraded sweeper must explicitly delete refresh children")?;
    let root_delete = normalized_function
        .find("DELETE FROM public.auth_grants AS root")
        .ok_or("upgraded sweeper must delete the AuthGrant root")?;
    assert!(family_lock < family_delete && family_delete < root_delete);
    assert!(normalized_function.contains("ORDER BY refresh.id FOR UPDATE"));
    assert!(!normalized_function.contains("FOR UPDATE SKIP LOCKED"));
    assert_eq!(function.1, "rss_auth_grant_maintenance");
    assert!(function.2, "upgraded sweeper must remain SECURITY DEFINER");
    assert!(function.3, "upgraded sweeper search_path must remain exact");
    assert_eq!(
        function.4,
        ["rss_app", "rss_auth_grant_maintenance"],
        "upgraded function must preserve its exact EXECUTE ACL"
    );

    let table_privileges: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT relation.relname, ARRAY( \
             SELECT acl.privilege_type \
             FROM aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) acl \
             JOIN pg_roles grantee ON grantee.oid = acl.grantee \
             WHERE grantee.rolname = 'rss_auth_grant_maintenance' \
             ORDER BY acl.privilege_type \
         ) \
         FROM pg_class relation \
         WHERE relation.oid IN ('public.auth_grants'::regclass, 'public.refresh_tokens'::regclass) \
         ORDER BY relation.relname",
    )
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        table_privileges,
        [
            (
                "auth_grants".to_owned(),
                vec![
                    "DELETE".to_owned(),
                    "SELECT".to_owned(),
                    "UPDATE".to_owned()
                ],
            ),
            (
                "refresh_tokens".to_owned(),
                vec![
                    "DELETE".to_owned(),
                    "SELECT".to_owned(),
                    "UPDATE".to_owned()
                ],
            ),
        ],
        "0079 must leave only the exact family-before-root maintenance capabilities"
    );

    let retained_before_sweep: (i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND auth_grant_id = $2)",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(case.grant.id().as_str())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(retained_before_sweep, (1, 1));
    let swept: i64 = sqlx::query_scalar("SELECT rss_sweep_expired_auth_grants()::bigint")
        .fetch_one(&app.pool)
        .await?;
    assert_eq!(swept, 1);
    let remaining: (i64, i64) = sqlx::query_as(
        "SELECT \
         (SELECT count(*) FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2), \
         (SELECT count(*) FROM refresh_tokens WHERE tenant_id = $1::uuid AND auth_grant_id = $2)",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(case.grant.id().as_str())
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(remaining, (0, 0));

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0076_drops_unconsumed_credential_security_target_mapping() -> TestResult {
    let (_fixture, store) = connect_pg().await?;
    migrations_through(75).run(&store.pool).await?;

    let before: Option<String> = sqlx::query_scalar(
        "SELECT to_regclass('public.credential_security_target_mappings')::text",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        before.as_deref(),
        Some("credential_security_target_mappings")
    );

    sqlx::query(
        "INSERT INTO credential_security_target_mappings \
         (target_ref, tenant_id, target_kind, user_id) \
         VALUES ($1::uuid, $2::uuid, 'subject', $3::uuid)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&store.pool)
    .await?;

    migrations_through(79).run(&store.pool).await?;

    let after: Option<String> = sqlx::query_scalar(
        "SELECT to_regclass('public.credential_security_target_mappings')::text",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after, None,
        "0076 must remove both the relation and its rows"
    );
    let ledger: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ledger, 79);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0075_replaces_legacy_session_permission_without_expanding_authority()
-> TestResult {
    let (_fixture, store) = connect_pg().await?;
    migrations_through(74).run(&store.pool).await?;
    let tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let resource = "11111111-2222-4333-8444-555555555555";

    sqlx::query(
        "INSERT INTO roles (tenant_id, id, name, permissions) VALUES \
         ($1::uuid, 'legacy-logout', 'legacy logout', \
          ARRAY['identity:profile:read', 'identity:session:write', \
                'identity:session:logout-current']::text[])",
    )
    .bind(tenant)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO abac_policies \
         (tenant_id, id, contract_id, permission, effective_from, rules) VALUES \
         ($1::uuid, 'legacy-logout', 'identity.logout@v1', \
          'identity:session:write', to_timestamp(1), '{\"rules\":[]}'::jsonb)",
    )
    .bind(tenant)
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "INSERT INTO resource_attributes \
         (tenant_id, contract_id, permission, resource_id, attribute_key, attribute_value, effective_from) \
         VALUES ($1::uuid, 'identity.logout@v1', 'identity:session:write', $2::uuid, \
                 'resource.owner', 'alice', to_timestamp(1))",
    )
    .bind(tenant)
    .bind(resource)
    .execute(&store.pool)
    .await?;

    migrations_through(79).run(&store.pool).await?;

    let permissions: Vec<String> =
        sqlx::query_scalar("SELECT permissions FROM roles WHERE id = 'legacy-logout'")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        permissions,
        ["identity:profile:read", "identity:session:logout-current"]
    );
    let remaining_legacy: i64 = sqlx::query_scalar(
        "SELECT \
           (SELECT count(*) FROM roles WHERE 'identity:session:write' = ANY(permissions)) + \
           (SELECT count(*) FROM abac_policies WHERE permission = 'identity:session:write') + \
           (SELECT count(*) FROM resource_attributes WHERE permission = 'identity:session:write')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(remaining_legacy, 0);
    let current_rows: (i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM abac_policies WHERE permission = 'identity:session:logout-current'), \
           (SELECT count(*) FROM resource_attributes WHERE permission = 'identity:session:logout-current')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(current_rows, (1, 1));
    let expanded: i64 = sqlx::query_scalar(
        "SELECT \
           (SELECT count(*) FROM roles WHERE 'identity:session:logout-all' = ANY(permissions)) + \
           (SELECT count(*) FROM abac_policies WHERE permission = 'identity:session:logout-all') + \
           (SELECT count(*) FROM resource_attributes WHERE permission = 'identity:session:logout-all')",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(expanded, 0, "migration must never grant logout-all");
    let ledger: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ledger, 79);
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0075_resource_scope_collision_fails_closed_and_rolls_back() -> TestResult {
    let (_fixture, store) = connect_pg().await?;
    migrations_through(74).run(&store.pool).await?;
    let tenant = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let resource = "11111111-2222-4333-8444-555555555555";
    for permission in ["identity:session:write", "identity:session:logout-current"] {
        sqlx::query(
            "INSERT INTO resource_attributes \
             (tenant_id, contract_id, permission, resource_id, attribute_key, attribute_value, effective_from) \
             VALUES ($1::uuid, 'identity.logout@v1', $2, $3::uuid, \
                     'resource.owner', 'alice', to_timestamp(1))",
        )
        .bind(tenant)
        .bind(permission)
        .bind(resource)
        .execute(&store.pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO abac_policies \
         (tenant_id, id, contract_id, permission, effective_from, rules) VALUES \
         ($1::uuid, 'rollback-proof', 'identity.logout@v1', \
          'identity:session:write', to_timestamp(1), '{\"rules\":[]}'::jsonb)",
    )
    .bind(tenant)
    .execute(&store.pool)
    .await?;

    let error = sqlx::migrate!("./migrations")
        .run(&store.pool)
        .await
        .expect_err("colliding resource scope must abort migration");
    assert!(error.to_string().contains("duplicate key"), "{error}");
    let legacy_policy: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM abac_policies WHERE permission = 'identity:session:write'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(legacy_policy, 1, "the whole migration must roll back");
    let legacy_resource: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM resource_attributes WHERE permission = 'identity:session:write'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(legacy_resource, 1);
    let ledger: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ledger, 74, "failed migration must not advance the ledger");
    store.shutdown().await?;
    Ok(())
}

/// 0066 is a non-rolling return-contract cutover: upgrading the real 0065 ledger preserves rows,
/// removes the legacy result shapes, and makes the new typed settlement usable atomically.
#[tokio::test(flavor = "multi_thread")]
async fn migration_0066_upgrades_0065_without_mutating_claimed_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(65).run(&store.pool).await?;

    let event_id = unique_event_id("0066-upgrade");
    let entry = make_entry(&event_id);
    let env = make_test_env("migration_0066_upgrade", "migration.settlement");
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
    let before: (String, String) = sqlx::query_as(
        "SELECT to_jsonb(o)::text, o.xmin::text FROM outbox AS o WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;

    let legacy_results: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT pg_get_function_result(p.oid)
        FROM pg_proc AS p
        WHERE p.oid IN (
            'rss_outbox_settle_published(text, uuid, bigint)'::regprocedure,
            'rss_outbox_settle_retry(text, uuid, bigint)'::regprocedure,
            'rss_outbox_mark_dlx(text, uuid, bigint)'::regprocedure
        )
        ORDER BY p.oid::regprocedure::text
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        legacy_results
            .iter()
            .filter(|result| *result == "bigint")
            .count(),
        2
    );
    assert!(
        legacy_results
            .iter()
            .any(|result| result.starts_with("TABLE(tenant_id text"))
    );

    sqlx::migrate!("./migrations").run(&store.pool).await?;
    let after_migration: (String, String) = sqlx::query_as(
        "SELECT to_jsonb(o)::text, o.xmin::text FROM outbox AS o WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after_migration, before,
        "0066 DDL must not rewrite claimed rows"
    );

    let typed_results: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT pg_get_function_result(p.oid)
        FROM pg_proc AS p
        WHERE p.oid IN (
            'rss_outbox_settle_published(text, uuid, bigint)'::regprocedure,
            'rss_outbox_settle_retry(text, uuid, bigint)'::regprocedure,
            'rss_outbox_mark_dlx(text, uuid, bigint)'::regprocedure
        )
        ORDER BY p.oid::regprocedure::text
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        typed_results
            .iter()
            .filter(|result| *result == "rss_outbox_settlement_outcome")
            .count(),
        2
    );
    assert!(typed_results.iter().any(|result| {
        result.starts_with("TABLE(settlement_outcome rss_outbox_settlement_outcome")
    }));

    let mut probe = store.pool.begin().await?;
    let outcome: String =
        sqlx::query_scalar("SELECT rss_outbox_settle_published($1, $2::uuid, $3)::text")
            .bind(&event_id)
            .bind(claim.test_lease_token())
            .bind(claim.test_lease_deadline_epoch_micros())
            .fetch_one(&mut *probe)
            .await?;
    assert_eq!(outcome, "settled");
    probe.rollback().await?;
    let after_probe: (String, String) = sqlx::query_as(
        "SELECT to_jsonb(o)::text, o.xmin::text FROM outbox AS o WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        after_probe, before,
        "rollback verification must preserve the claim"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0062_rejects_nonempty_v2_without_destructive_escape() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(61).run(&store.pool).await?;

    let message_id = unique_event_id("0062-nonempty");
    sqlx::query(
        r#"
        INSERT INTO dead_letter (
            tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic,
            consumer_group, original_entry, original_entry_key_ref,
            original_entry_payload_len, original_entry_encoding, error_summary,
            num_attempts, source_kind, metadata
        ) VALUES (
            $1::uuid, $2, 'identity', 'audit', 'contract-v2', 'migration.v2',
            'migration-consumer', '{"ciphertext":[]}'::jsonb, 'old-key:1',
            0, 'key-provider-v2', 'safe summary', 1, 'consumer', '{}'::jsonb
        )
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&message_id)
    .execute(&store.pool)
    .await?;

    let result = sqlx::migrate!("./migrations").run(&store.pool).await;
    let Err(error) = result else {
        return Err("0062 must reject nonempty dead_letter".into());
    };
    assert!(
        error
            .to_string()
            .contains("legacy dead_letter must be empty before DLX v3"),
        "unexpected 0062 fail-fast error: {error}"
    );
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dead_letter WHERE message_id = $1")
            .bind(&message_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        retained, 1,
        "failed cutover must leave the v2 row untouched"
    );

    let escape_surfaces: (bool, bool) = sqlx::query_as(
        r#"
        SELECT to_regprocedure(
                   'public.rss_cutover_legacy_dead_letter(bytea,bigint,text,text)'
               ) IS NULL,
               to_regclass('public.dead_letter_legacy_cutover_audit') IS NULL
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        escape_surfaces,
        (true, true),
        "0062 must not install digest-authorized disposal or a deletion audit surrogate"
    );

    // Test-only cleanup models completion of the separately reviewed export/restore migration.
    // No production migration or runtime capability receives this destructive authority.
    sqlx::query("TRUNCATE TABLE public.dead_letter")
        .execute(&store.pool)
        .await?;

    // sqlx 0.8 leaves its session advisory lock on the pooled connection when a migration body
    // fails. All calls above are sequential and reuse that sole connection; explicitly release
    // only test-owned session locks before proving the forward retry.
    sqlx::query("SELECT pg_catalog.pg_advisory_unlock_all()")
        .execute(&store.pool)
        .await?;
    sqlx::migrate!("./migrations").run(&store.pool).await?;
    let lifecycle_installed: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('public.rss_dlx_claim_archive_candidates()') IS NOT NULL",
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(lifecycle_installed);
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0063_rejects_bidirectional_and_owner_role_escalation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(61).run(&store.pool).await?;
    sqlx::raw_sql(
        r#"
        CREATE ROLE rss_dlx_archiver NOLOGIN NOBYPASSRLS NOSUPERUSER
            NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
        CREATE ROLE rss_dlx_forbidden_parent NOLOGIN NOSUPERUSER;
        GRANT rss_dlx_forbidden_parent TO rss_dlx_archiver;
        "#,
    )
    .execute(&store.pool)
    .await?;

    let result = sqlx::migrate!("./migrations").run(&store.pool).await;
    let Err(error) = result else {
        return Err("0063 must reject archiver SET ROLE membership".into());
    };
    assert!(
        error
            .to_string()
            .contains("DLX workload roles must have no role memberships"),
        "unexpected 0063 role-membership error: {error}"
    );
    sqlx::raw_sql(
        r#"
        REVOKE rss_dlx_forbidden_parent FROM rss_dlx_archiver;
        DROP ROLE rss_dlx_forbidden_parent;
        CREATE ROLE rss_dlx_forbidden_child NOLOGIN NOSUPERUSER;
        GRANT rss_dlx_archiver TO rss_dlx_forbidden_child;
        "#,
    )
    .execute(&store.pool)
    .await?;

    sqlx::query("SELECT pg_catalog.pg_advisory_unlock_all()")
        .execute(&store.pool)
        .await?;
    let result = sqlx::migrate!("./migrations").run(&store.pool).await;
    let Err(error) = result else {
        return Err("0063 must reject roles inheriting the archiver".into());
    };
    assert!(
        error
            .to_string()
            .contains("DLX workload roles must have no role memberships"),
        "unexpected incoming role-membership error: {error}"
    );
    sqlx::raw_sql(
        r#"
        REVOKE rss_dlx_archiver FROM rss_dlx_forbidden_child;
        DROP ROLE rss_dlx_forbidden_child;
        DROP ROLE rss_dlx_archiver;
        CREATE ROLE rss_dlx_lifecycle_owner LOGIN BYPASSRLS NOSUPERUSER;
        "#,
    )
    .execute(&store.pool)
    .await?;

    sqlx::query("SELECT pg_catalog.pg_advisory_unlock_all()")
        .execute(&store.pool)
        .await?;
    let result = sqlx::migrate!("./migrations").run(&store.pool).await;
    let Err(error) = result else {
        return Err("0063 must reject a pre-existing unsafe lifecycle owner".into());
    };
    assert!(
        error
            .to_string()
            .contains("pre-existing rss_dlx_lifecycle_owner has forbidden role attributes"),
        "unexpected lifecycle-owner error: {error}"
    );
    sqlx::query("DROP ROLE rss_dlx_lifecycle_owner")
        .execute(&store.pool)
        .await?;
    store.shutdown().await?;
    Ok(())
}

/// 0060 upgrades the real 0059 ledger, backfills every historical state to one expired cutover,
/// and removes all free-horizon function surfaces.
#[tokio::test(flavor = "multi_thread")]
async fn migration_0060_upgrades_0059_and_expires_all_historical_same_id_paths() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(59).run(&store.pool).await?;

    let fixtures = [
        (unique_event_id("0060-pending"), "pending"),
        (unique_event_id("0060-publishing"), "publishing"),
        (unique_event_id("0060-published"), "published"),
        (unique_event_id("0060-dlx"), "dlx"),
    ];
    for (event_id, _) in &fixtures {
        let entry = make_entry(event_id);
        let env = make_test_env("migration_0060_upgrade", "migration.same-id");
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
    for (event_id, status) in &fixtures {
        sqlx::query(
            r#"
            UPDATE outbox
            SET status = $1,
                lease_token = CASE WHEN $1 = 'publishing' THEN gen_random_uuid() ELSE NULL END,
                lease_until = CASE WHEN $1 = 'publishing' THEN clock_timestamp() + interval '1 hour' ELSE NULL END,
                published_at = CASE WHEN $1 = 'published' THEN clock_timestamp() ELSE NULL END,
                dlx_at = CASE WHEN $1 = 'dlx' THEN clock_timestamp() ELSE NULL END,
                updated_at = clock_timestamp()
            WHERE event_id = $2
            "#,
        )
        .bind(status)
        .bind(event_id)
        .execute(&store.pool)
        .await?;
    }

    sqlx::migrate!("./migrations").run(&store.pool).await?;
    type HistoricalState = (String, String, bool, bool, bool);
    let states: Vec<HistoricalState> = sqlx::query_as(
        "SELECT event_id, same_id_delivery_phase, \
                automatic_retry_deadline = same_id_redrive_deadline, \
                automatic_retry_deadline <= clock_timestamp(), \
                same_id_redrive_deadline <= clock_timestamp() \
         FROM outbox WHERE event_id = ANY($1) ORDER BY event_id",
    )
    .bind(
        fixtures
            .iter()
            .map(|fixture| fixture.0.clone())
            .collect::<Vec<_>>(),
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(states.len(), 4);
    assert!(
        states
            .iter()
            .all(|state| { state.1 == "automatic" && state.2 && state.3 && state.4 })
    );

    let pending_claim = claimed_entry_for_event(&store, &fixtures[0].0).await?;
    let relay_budget = test_relay_budget();
    let preflight: i16 =
        sqlx::query_scalar("SELECT rss_outbox_publish_preflight($1, $2::uuid, $3, $4, $5)")
            .bind(&fixtures[0].0)
            .bind(pending_claim.test_lease_token())
            .bind(pending_claim.test_lease_deadline_epoch_micros())
            .bind(relay_budget.lease_ttl_millis())
            .bind(relay_budget.required_budget_millis())
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        preflight, 2,
        "historical pending claim must expire before broker I/O"
    );

    let redrive =
        direct_outbox_redrive(store.pool.clone(), test_tenant(), fixtures[3].0.clone()).await?;
    assert_eq!(redrive, -1, "historical DLX must be immediately Expired");
    let legacy_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM (VALUES
            ('rss_outbox_lease_can_publish(text,uuid,bigint)'),
            ('rss_sweep_inbox_receipts(bigint)')
        ) AS legacy(signature)
        WHERE to_regprocedure(signature) IS NOT NULL
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(legacy_count, 0);

    let validated: (i64, bool) = sqlx::query_as(
        "SELECT count(*)::bigint, bool_and(convalidated) \
         FROM pg_constraint \
         WHERE conrelid = 'outbox'::regclass AND conname = 'outbox_same_id_state_valid'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        validated,
        (1, true),
        "0061 must validate one composite state scan"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0057 必须能由 SQLx 的真实迁移账本从 0056 升级，且保留/回填所有既有状态。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0057_upgrades_real_through_0056_database() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(56).run(&store.pool).await?;

    let fixtures = [
        (unique_event_id("0057-pending"), "pending"),
        (unique_event_id("0057-publishing"), "publishing"),
        (unique_event_id("0057-published"), "published"),
        (unique_event_id("0057-dlx"), "dlx"),
    ];
    for (event_id, _) in &fixtures {
        let entry = make_entry(event_id);
        let env = make_test_env("migration_0057_upgrade", "migration.outbox");
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

    for (ordinal, (event_id, status)) in fixtures.iter().enumerate() {
        sqlx::query(
            r#"
            UPDATE outbox
            SET status = $1,
                retry_count = $2,
                lease_token = gen_random_uuid(),
                retry_after = CASE WHEN $1 = 'pending'
                                   THEN TIMESTAMPTZ '2024-02-01 00:00:00+00'
                                   ELSE NULL END,
                published_at = CASE WHEN $1 = 'published'
                                    THEN TIMESTAMPTZ '2024-01-03 00:00:00+00'
                                    ELSE NULL END,
                dlx_at = CASE WHEN $1 = 'dlx'
                              THEN TIMESTAMPTZ '2024-01-04 00:00:00+00'
                              ELSE NULL END,
                updated_at = TIMESTAMPTZ '2024-01-01 00:00:00+00'
                             + $2 * INTERVAL '1 hour'
            WHERE event_id = $3
            "#,
        )
        .bind(status)
        .bind(i32::try_from(ordinal)?)
        .bind(event_id)
        .execute(&store.pool)
        .await?;
    }

    migrations_through(57).run(&store.pool).await?;

    type UpgradeState = (String, String, i32, bool, bool, Option<i64>, bool, bool);
    let states: BTreeMap<String, UpgradeState> = sqlx::query_as::<_, UpgradeState>(
        r#"
        SELECT event_id,
               status,
               retry_count,
               lease_token IS NULL,
               lease_until IS NULL,
               EXTRACT(EPOCH FROM (lease_until - updated_at))::bigint,
               published_at IS NOT DISTINCT FROM TIMESTAMPTZ '2024-01-03 00:00:00+00',
               dlx_at IS NOT DISTINCT FROM TIMESTAMPTZ '2024-01-04 00:00:00+00'
        FROM outbox
        WHERE event_id = ANY($1)
        "#,
    )
    .bind(
        fixtures
            .iter()
            .map(|(event_id, _)| event_id.clone())
            .collect::<Vec<_>>(),
    )
    .fetch_all(&store.pool)
    .await?
    .into_iter()
    .map(|row| (row.0.clone(), row))
    .collect();
    assert_eq!(states.len(), 4);
    for (event_id, status) in &fixtures {
        let row = states.get(event_id).ok_or("missing upgraded fixture")?;
        assert_eq!(row.1.as_str(), *status);
        if *status == "publishing" {
            assert!(!row.3, "publishing token must survive the upgrade");
            assert!(!row.4, "publishing deadline must be backfilled");
            assert_eq!(row.5, Some(60));
        } else {
            assert!(row.3 && row.4, "non-publishing leases must be cleared");
        }
        assert_eq!(row.6, *status == "published");
        assert_eq!(row.7, *status == "dlx");
    }

    for (sql, constraint) in [
        (
            "UPDATE outbox SET retry_count = -1 WHERE event_id = $1",
            "outbox_retry_count_nonnegative",
        ),
        (
            "UPDATE outbox SET lease_token = gen_random_uuid() WHERE event_id = $1",
            "outbox_lease_token_matches_status",
        ),
    ] {
        let result = sqlx::query(sql)
            .bind(&fixtures[0].0)
            .execute(&store.pool)
            .await;
        let Err(error) = result else {
            return Err(format!("0057 constraint {constraint} must reject invalid state").into());
        };
        assert!(
            error.to_string().contains(constraint),
            "unexpected 0057 constraint error: {error}"
        );
    }

    type UpgradedSettleFunction = (String, String, String, bool, bool, bool, bool, bool);
    let settle_definitions: Vec<UpgradedSettleFunction> = sqlx::query_as(
        r#"
        SELECT p.oid::regprocedure::text,
               pg_get_functiondef(p.oid),
               owner.rolname,
               owner.rolcanlogin,
               p.prosecdef,
               COALESCE('search_path=public, pg_temp' = ANY(p.proconfig), false),
               NOT EXISTS (
                   SELECT 1
                   FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                   WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
               ),
               has_function_privilege('rss_app', p.oid, 'EXECUTE')
        FROM pg_proc AS p
        JOIN pg_roles AS owner ON owner.oid = p.proowner
        WHERE p.oid IN (
            'rss_outbox_settle_published(text, uuid, bigint)'::regprocedure,
            'rss_outbox_settle_retry(text, uuid, bigint)'::regprocedure,
            'rss_outbox_mark_dlx(text, uuid, bigint)'::regprocedure
        )
        ORDER BY p.oid::regprocedure::text
        "#,
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(settle_definitions.len(), 3);
    for (
        signature,
        definition,
        owner,
        owner_can_login,
        security_definer,
        fixed_path,
        no_public,
        app_execute,
    ) in settle_definitions
    {
        assert!(
            definition.to_ascii_lowercase().contains("for update"),
            "upgraded settle function must lock before taking its clock: {signature}"
        );
        assert_eq!(owner, "rss_outbox_maintenance", "owner drift: {signature}");
        assert!(!owner_can_login, "owner must remain NOLOGIN: {signature}");
        assert!(security_definer, "SECURITY DEFINER drift: {signature}");
        assert!(fixed_path, "fixed search_path drift: {signature}");
        assert!(no_public, "PUBLIC execute must be revoked: {signature}");
        assert!(app_execute, "rss_app execute grant missing: {signature}");
    }

    type UpgradedPreflightFunction = (String, String, bool, bool, bool, bool, bool);
    let preflight: UpgradedPreflightFunction = sqlx::query_as(
        r#"
        SELECT pg_get_functiondef(p.oid),
               owner.rolname,
               owner.rolcanlogin,
               p.prosecdef,
               COALESCE('search_path=public, pg_temp' = ANY(p.proconfig), false),
               NOT EXISTS (
                   SELECT 1
                   FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                   WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
               ),
               has_function_privilege('rss_app', p.oid, 'EXECUTE')
        FROM pg_proc AS p
        JOIN pg_roles AS owner ON owner.oid = p.proowner
        WHERE p.oid = 'rss_outbox_lease_can_publish(text, uuid, bigint)'::regprocedure
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert!(
        preflight.0.contains("interval '50 seconds'"),
        "upgraded publish preflight must reserve the authoritative lease budget"
    );
    assert_eq!(preflight.1, "rss_outbox_maintenance");
    assert!(!preflight.2, "preflight owner must remain NOLOGIN");
    assert!(preflight.3, "preflight must remain SECURITY DEFINER");
    assert!(preflight.4, "preflight fixed search_path drift");
    assert!(preflight.5, "preflight PUBLIC execute must be revoked");
    assert!(preflight.6, "preflight rss_app execute grant missing");

    let legacy_overloads: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*)
        FROM (VALUES
            ('rss_outbox_settle_published(text,uuid)'),
            ('rss_outbox_settle_retry(text,integer,bigint,uuid)'),
            ('rss_outbox_mark_dlx(text,integer,uuid)')
        ) AS legacy(signature)
        WHERE to_regprocedure(signature) IS NOT NULL
        "#,
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(legacy_overloads, 0, "0057 must remove legacy overloads");

    store.shutdown().await?;
    Ok(())
}

/// 0057 的 fail-fast 前置条件也必须由真实 SQLx 升级路径验证，而非只匹配迁移文本。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0057_rejects_0056_publishing_row_without_token() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    migrations_through(56).run(&store.pool).await?;

    let event_id = unique_event_id("0057-missing-token");
    let entry = make_entry(&event_id);
    let env = make_test_env("migration_0057_reject", "migration.outbox");
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
    sqlx::query("UPDATE outbox SET status = 'publishing', lease_token = NULL WHERE event_id = $1")
        .bind(&event_id)
        .execute(&store.pool)
        .await?;

    let result = sqlx::migrate!("./migrations").run(&store.pool).await;
    let Err(error) = result else {
        return Err("0057 must reject publishing rows without a lease token".into());
    };
    assert!(
        error
            .to_string()
            .contains("publishing outbox rows must have lease_token"),
        "unexpected 0057 fail-fast error: {error}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0036：已知 legacy contract 行按 0035 同源 map 回填物理列；legacy causation 为 NULL。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_backfills_known_legacy_contract_columns() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    let event_id = unique_event_id("known-0036");
    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'identity.session-created', 'identity.session-created', $2, $3::jsonb, 'pending')",
    )
    .bind(&event_id)
    .bind(b"payload".as_slice())
    .bind(serde_json::json!({ "tenantId": COTX_TENANT_A }).to_string())
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await?;

    let row: (String, String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT contract_version, schema_hash, causation_id, metadata->>'schemaVersion', metadata->>'schemaHash' \
         FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, "v1");
    assert_eq!(
        row.1,
        "sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516"
    );
    assert_eq!(row.2, None, "legacy row causation_id 应为 NULL");
    assert_eq!(row.3.as_deref(), Some(row.0.as_str()));
    assert_eq!(row.4.as_deref(), Some(row.1.as_str()));

    store.shutdown().await?;
    Ok(())
}

/// 0036：未知 legacy contract 且缺 schema header 时 fail-fast，不写 `unknown` 兼容值。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_rejects_unknown_legacy_schema_headers() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'unknown', 'unknown.event', 'unknown.contract', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("unknown-0036"))
    .bind(b"payload".as_slice())
    .bind(serde_json::json!({ "tenantId": COTX_TENANT_A }).to_string())
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err("0036 must reject unknown legacy outbox schema headers".into());
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox schema column backfill requires generated known contract map"),
        "unexpected migration error: {rendered}"
    );
    assert!(
        rendered.contains("bad_rows=1") && rendered.contains("domain=unknown"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0036：未知 legacy contract 即便带格式合法 schema headers 也 fail-fast；不信任 metadata 自证契约。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_rejects_unknown_legacy_even_with_valid_schema_headers() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'unknown', 'unknown.event', 'unknown.contract', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("unknown-valid-0036"))
    .bind(b"payload".as_slice())
    .bind(
        serde_json::json!({
            "tenantId": COTX_TENANT_A,
            "schemaVersion": "v1",
            "schemaHash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })
        .to_string(),
    )
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err(
            "0036 must reject unknown legacy rows even with valid metadata schema headers".into(),
        );
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox schema column backfill requires generated known contract map"),
        "unexpected migration error: {rendered}"
    );
    assert!(
        rendered.contains("bad_rows=1") && rendered.contains("domain=unknown"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0036：已知 legacy contract 的 schema metadata 必须匹配 generated map，不能被历史 metadata 覆盖。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0036_rejects_known_contract_schema_metadata_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;

    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'identity.session-created', 'identity.session-created', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("known-mismatch-0036"))
    .bind(b"payload".as_slice())
    .bind(
        serde_json::json!({
            "tenantId": COTX_TENANT_A,
            "schemaVersion": "v2",
            "schemaHash": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        })
        .to_string(),
    )
    .execute(&store.pool)
    .await?;

    apply_outbox_legacy_prereqs_through_0031(&store).await?;
    let result = sqlx::raw_sql(include_str!(
        "../../migrations/0036_add_outbox_schema_columns.sql"
    ))
    .execute(&store.pool)
    .await;
    let Err(err) = result else {
        return Err(
            "0036 must reject known contract metadata that mismatches generated map".into(),
        );
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("outbox known contract schema headers mismatch generated map"),
        "unexpected migration error: {rendered}"
    );
    assert!(
        rendered.contains("bad_rows=1") && rendered.contains("identity.session-created"),
        "unexpected migration error: {rendered}"
    );

    store.shutdown().await?;
    Ok(())
}

/// 0031：tenant_id backfill 接受 typed TenantId 契约允许的 canonical UUIDv7。
#[tokio::test(flavor = "multi_thread")]
async fn migration_0031_accepts_canonical_uuid_v7_tenant_metadata() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    sqlx::raw_sql(include_str!("../../migrations/0003_create_outbox.sql"))
        .execute(&store.pool)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0016_add_seq_and_partition_to_outbox.sql"
    ))
    .execute(&store.pool)
    .await?;
    sqlx::raw_sql(
        r#"
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
                CREATE ROLE rss_app NOLOGIN NOBYPASSRLS;
            END IF;
        END
        $$;
        GRANT USAGE ON SCHEMA public TO rss_app;
        "#,
    )
    .execute(&store.pool)
    .await?;

    let tenant_v7 = "01890f9d-7bb3-7cc0-98c4-dc0c0c07398f";
    assert!(
        vocab::TenantId::parse(tenant_v7).is_ok(),
        "anti-vacuity: fixture must be a valid typed TenantId"
    );
    sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status) \
         VALUES ($1, 'identity', 'test.event', 'contract-1', $2, $3::jsonb, 'pending')",
    )
    .bind(unique_event_id("uuid-v7-outbox-tenant"))
    .bind(b"payload".as_slice())
    .bind(serde_json::json!({ "tenantId": tenant_v7 }).to_string())
    .execute(&store.pool)
    .await?;

    sqlx::raw_sql(include_str!(
        "../../migrations/0031_harden_outbox_tenant_scope.sql"
    ))
    .execute(&store.pool)
    .await?;

    let row: (String,) =
        sqlx::query_as("SELECT tenant_id::text FROM outbox WHERE metadata->>'tenantId' = $1")
            .bind(tenant_v7)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0, tenant_v7);

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_0081_upgrades_0080_and_creates_only_certificate_state_tables() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    run_migrations_through(&store, 80).await?;
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM pg_catalog.pg_class AS c \
         JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname LIKE 'device_certificate_%'",
    )
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(before, 0, "0080 must not contain #1896 state relations");

    run_migrations_through(&store, 81).await?;
    let relations: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_catalog.pg_class AS c \
         JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'r' \
           AND c.relname LIKE 'device_certificate_%' ORDER BY c.relname",
    )
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(
        relations,
        vec![
            "device_certificate_conditions".to_owned(),
            "device_certificate_desired_states".to_owned(),
            "device_certificate_reported_states".to_owned(),
        ],
        "0081 must not pre-create target, command, receipt, operation, or wake state"
    );
    store.shutdown().await?;
    Ok(())
}
