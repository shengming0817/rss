use std::borrow::Cow;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OLD_GENERATION: &str =
    "sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801";
const CURRENT_GENERATION: &str = generated::event::PROJECTION_INPUT_GENERATION;
const DEFINITION_DIGEST: &str =
    "sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8";
const SCHEMA_HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

struct FunctionContract {
    signature: &'static str,
    owner: &'static str,
    app_read: bool,
    worker: bool,
    operator: bool,
}

const PINNED_FUNCTIONS: &[FunctionContract] = &[
    FunctionContract {
        signature: "public.rss_settings_projection_apply_current(text,text,uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)",
        owner: "rss_projection_operator_owner",
        app_read: false,
        worker: false,
        operator: false,
    },
    FunctionContract {
        signature: "public.rss_settings_projection_worker_plan_is_current(text,text,text,text)",
        owner: "rss_projection_worker_owner",
        app_read: false,
        worker: false,
        operator: false,
    },
    FunctionContract {
        signature: "public.rss_settings_projection_apply_operator(uuid,text,text,text,text,text,text,bigint,text,text,bigint,bigint,bytea)",
        owner: "rss_projection_operator_owner",
        app_read: false,
        worker: false,
        operator: true,
    },
    FunctionContract {
        signature: "public.rss_settings_projection_resolve_active()",
        owner: "rss_projection_serving_owner",
        app_read: true,
        worker: true,
        operator: false,
    },
    FunctionContract {
        signature: "public.rss_projection_operator_status_active(uuid)",
        owner: "rss_projection_operator_owner",
        app_read: false,
        worker: false,
        operator: true,
    },
    FunctionContract {
        signature: "public.rss_projection_operator_swap_active(uuid,text,text,bigint,text,text,text)",
        owner: "rss_projection_operator_owner",
        app_read: false,
        worker: false,
        operator: true,
    },
];

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

async fn assert_pinned_function_catalog(pool: &sqlx::PgPool) -> TestResult {
    for expected in PINNED_FUNCTIONS {
        let (
            owner,
            security_definer,
            fixed_search_path,
            definition,
            public,
            app,
            app_read,
            projection_reader,
            worker,
            operator,
        ): (
            String,
            bool,
            bool,
            String,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
        ) = sqlx::query_as(
            "SELECT owner.rolname, function.prosecdef, \
                    function.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[], \
                    pg_catalog.pg_get_functiondef(function.oid), \
                    COALESCE(pg_catalog.array_to_string(function.proacl, ','), '') ~ '(^|,)=X/', \
                    pg_catalog.has_function_privilege('rss_app', function.oid, 'EXECUTE'), \
                    pg_catalog.has_function_privilege('rss_app_read', function.oid, 'EXECUTE'), \
                    pg_catalog.has_function_privilege('rss_projection_reader', function.oid, 'EXECUTE'), \
                    pg_catalog.has_function_privilege('rss_projection_worker', function.oid, 'EXECUTE'), \
                    pg_catalog.has_function_privilege('rss_projection_operator', function.oid, 'EXECUTE') \
             FROM pg_catalog.pg_proc AS function \
             JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner \
             WHERE function.oid = pg_catalog.to_regprocedure($1)",
        )
        .bind(expected.signature)
        .fetch_one(pool)
        .await?;

        assert_eq!(owner, expected.owner, "owner drift: {}", expected.signature);
        assert!(
            security_definer,
            "SECURITY DEFINER drift: {}",
            expected.signature
        );
        assert!(
            fixed_search_path,
            "search_path drift: {}",
            expected.signature
        );
        assert!(
            !definition.contains(OLD_GENERATION),
            "old pin remains: {}",
            expected.signature
        );
        assert!(
            definition.contains(CURRENT_GENERATION),
            "current pin missing: {}",
            expected.signature
        );
        assert!(!public, "PUBLIC execute leaked: {}", expected.signature);
        assert!(!app, "rss_app execute leaked: {}", expected.signature);
        assert_eq!(
            app_read, expected.app_read,
            "rss_app_read ACL drift: {}",
            expected.signature
        );
        assert!(
            !projection_reader,
            "rss_projection_reader execute leaked: {}",
            expected.signature
        );
        assert_eq!(
            worker, expected.worker,
            "worker ACL drift: {}",
            expected.signature
        );
        assert_eq!(
            operator, expected.operator,
            "operator ACL drift: {}",
            expected.signature
        );
    }
    Ok(())
}

async fn assert_legacy_pinned_generation(pool: &sqlx::PgPool) -> TestResult {
    for function in PINNED_FUNCTIONS {
        let definition: String = sqlx::query_scalar(
            "SELECT pg_catalog.pg_get_functiondef(pg_catalog.to_regprocedure($1))",
        )
        .bind(function.signature)
        .fetch_one(pool)
        .await?;
        assert!(
            definition.contains(OLD_GENERATION),
            "old pin missing before upgrade: {}",
            function.signature
        );
        assert!(
            !definition.contains(CURRENT_GENERATION),
            "current pin present before upgrade: {}",
            function.signature
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_replaces_pinned_identity_and_discards_only_derived_settings_state() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(104).run(&pool).await?;

    let tenant = uuid::Uuid::new_v4();
    let unrelated_tenant = uuid::Uuid::new_v4();
    let source_event_id = uuid::Uuid::new_v4().hyphenated().to_string();
    sqlx::query(
        "INSERT INTO public.projection_input_bindings (\
             generation, projection_id, projection_definition_version, \
             projection_definition_schema_digest, source_domain, contract_id, \
             contract_version, schema_hash, topic\
         ) VALUES ($1, 'settings.config-projection', 'v3', $2, 'settings', \
                   'settings.config-version-changed', 'v1', $3, \
                   'settings.config-version-changed')",
    )
    .bind(OLD_GENERATION)
    .bind(DEFINITION_DIGEST)
    .bind(SCHEMA_HASH)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_events (\
             event_id, domain, aggregate_id, event_type, payload, correlation_id, \
             contract_id, contract_version, schema_hash, metadata, partition_key, causation_id\
         ) VALUES ($1, 'settings', 'fixture-config', 'settings.config-version-changed', \
                   decode('01', 'hex'), NULL, 'settings.config-version-changed', 'v1', $2, \
                   pg_catalog.jsonb_build_object('tenantId', $3), NULL, NULL)",
    )
    .bind(&source_event_id)
    .bind(SCHEMA_HASH)
    .bind(tenant.hyphenated().to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy', 'v3', \
                   $2, $3, 1)",
    )
    .bind(tenant.to_string())
    .bind(DEFINITION_DIGEST)
    .bind(OLD_GENERATION)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_config_projection_rows (\
             tenant_id, projection_id, generation, config_key, config_version, change_kind, \
             source_event_id, source_lsn, source_occurred_at_secs\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy', 'fixture', 1, \
                   'published', $2, 1, 1)",
    )
    .bind(tenant.to_string())
    .bind(&source_event_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (\
             tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest, \
             actor, purpose\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy', $2, 1, \
                   decode(repeat('ab', 32), 'hex'), 'rss-projection-worker', 'background-worker')",
    )
    .bind(tenant.to_string())
    .bind(&source_event_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_worker_tenant_quarantine (\
             tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy', 'quarantined', 'conflict', 1), \
                  ($2::uuid, 'unrelated.projection', 'legacy', 'quarantined', 'conflict', 2)",
    )
    .bind(tenant.to_string())
    .bind(unrelated_tenant.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version) VALUES \
             ($1, 'settings.config-projection@legacy:shadow', 1, 1), \
             ('unrelated-owner', 'unrelated-projection', 2, 1)",
    )
    .bind(format!("projection:{tenant}"))
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_active_pointer (\
             tenant_id, projection_id, generation, promoted_high_water_lsn, token\
         ) VALUES ($1::uuid, 'settings.config-projection', 'legacy', 1, 1)",
    )
    .bind(tenant.to_string())
    .execute(&pool)
    .await?;

    assert_legacy_pinned_generation(&pool).await?;
    let legacy_generations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.settings_projection_generations \
         WHERE projection_id = 'settings.config-projection'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        legacy_generations, 1,
        "upgrade fixture must carry stale derived state"
    );
    migrations_through(105).run(&pool).await?;

    assert_pinned_function_catalog(&pool).await?;

    for table in [
        "settings_projection_active_pointer",
        "settings_projection_generations",
        "settings_projection_dedupe_receipts",
        "settings_config_projection_rows",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{table}"))
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 0, "0105 must hard-cut stale derived rows in {table}");
    }

    let matching_checkpoints: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.checkpoint \
         WHERE owner LIKE 'projection:%' \
           AND checkpoint_id LIKE 'settings.config-projection@%:shadow'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(matching_checkpoints, 0);
    let matching_quarantine: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.projection_worker_tenant_quarantine \
         WHERE projection_id = 'settings.config-projection'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(matching_quarantine, 0);
    let retained_checkpoint: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.checkpoint \
         WHERE owner = 'unrelated-owner' AND checkpoint_id = 'unrelated-projection'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(retained_checkpoint, 1);
    let retained_quarantine: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.projection_worker_tenant_quarantine \
         WHERE tenant_scope_id = $1::uuid AND projection_id = 'unrelated.projection'",
    )
    .bind(unrelated_tenant.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(retained_quarantine, 1);
    let retained_source: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.projection_events WHERE event_id = $1")
            .bind(&source_event_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(retained_source, 1);
    let retained_binding: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.projection_input_bindings \
         WHERE generation = $1 AND projection_id = 'settings.config-projection'",
    )
    .bind(OLD_GENERATION)
    .fetch_one(&pool)
    .await?;
    assert_eq!(retained_binding, 1);

    pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_database_installs_the_exact_0105_function_catalog() -> TestResult {
    let fixture = testkit::owned_postgres().await?;
    let pool = connect(fixture.owner_params()).await?;
    migrations_through(105).run(&pool).await?;

    assert_pinned_function_catalog(&pool).await?;

    let head: i64 = sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations")
        .fetch_one(&pool)
        .await?;
    assert_eq!(head, 105);
    pool.close().await;
    Ok(())
}
