use std::borrow::Cow;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GENERATED_PROJECTION: &str = include_str!("../../../generated/src/projection/settings_v3.rs");
const GENERATED_INPUTS: &str =
    include_str!("../../../crates/postgres-migration-inventory/src/projection_inputs.rs");
const READER_PASSWORD: &str = "rss_app_read_upgrade_test_pw";
const OPERATOR_PASSWORD: &str = "rss_projection_operator_upgrade_test_pw";

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct UpgradeSwapRow {
    outcome: String,
    reason: Option<String>,
    previous_generation: Option<String>,
    active_generation: Option<String>,
    result_token: Option<i64>,
    promoted_high_water_lsn: Option<i64>,
}

fn first_sha256_after<'a>(source: &'a str, marker: &str) -> &'a str {
    let (_, tail) = source
        .split_once(marker)
        .unwrap_or_else(|| panic!("generated source omits `{marker}`"));
    let start = tail
        .find("sha256:")
        .unwrap_or_else(|| panic!("generated source has no digest after `{marker}`"));
    &tail[start..start + "sha256:".len() + 64]
}

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
    connect_as(params, &params.username, &params.password).await
}

async fn connect_as(
    params: &testkit::PgConnParams,
    username: &str,
    password: &str,
) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username(username)
                .password(password)
                .ssl_mode(PgSslMode::Prefer),
        )
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_hard_cuts_legacy_settings_state_without_touching_sources_or_generic_cas()
-> TestResult {
    let fixture = testkit::env_or_postgres().await?;
    let pool = connect(fixture.params()).await?;
    migrations_through(97).run(&pool).await?;

    let tenant = uuid::Uuid::new_v4();
    let definition_digest = first_sha256_after(GENERATED_PROJECTION, "settings.config-projection");
    let input_generation = first_sha256_after(GENERATED_INPUTS, "PROJECTION_INPUT_GENERATION");
    let checkpoint_owner = format!("projection:{tenant}");
    let checkpoint_id = "settings.config-projection@v3:shadow";
    let unrelated_checkpoint_owner = format!("projection:{}", uuid::Uuid::new_v4());
    let unrelated_checkpoint_id = "other.projection@v1:shadow";

    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version, \
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'v3', $2, $3, 11)",
    )
    .bind(tenant.to_string())
    .bind(definition_digest)
    .bind(input_generation)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_config_projection_rows (\
             tenant_id, projection_id, generation, config_key, config_version, change_kind,\
             source_event_id, source_lsn, source_occurred_at_secs\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'legacy-key', 1, 'published',\
                   'legacy-event', 11, 1)",
    )
    .bind(tenant.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (\
             tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest,\
             actor, purpose\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'legacy-event', 11, $2,\
                   'rss-projection-worker', 'background-shadow')",
    )
    .bind(tenant.to_string())
    .bind(vec![0x98_u8; 32])
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version)\
         VALUES ($1, $2, 11, 1)",
    )
    .bind(&checkpoint_owner)
    .bind(checkpoint_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version)\
         VALUES ($1, $2, 17, 2)",
    )
    .bind(&unrelated_checkpoint_owner)
    .bind(unrelated_checkpoint_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_worker_tenant_quarantine (\
             tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'quarantined',\
                   'provider_permanent', 11)",
    )
    .bind(tenant.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_worker_tenant_quarantine (\
             tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn\
         ) VALUES ($1::uuid, 'other.projection', 'v1', 'quarantined',\
                   'provider_permanent', 17)",
    )
    .bind(tenant.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.distributed_cas (cas_key, value, token) VALUES\
         ($1, $2, 4), ('unrelated/runtime-state', $3, 7)",
    )
    .bind(format!(
        "projection-active/{tenant}/settings.config-projection"
    ))
    .bind(br#"{"version":"v3"}"#.as_slice())
    .bind(b"unrelated-value".as_slice())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.projection_events (\
             domain, aggregate_id, event_type, payload, correlation_id, event_id, contract_id,\
             contract_version, schema_hash, metadata, partition_key, causation_id\
         ) VALUES ('settings', 'legacy-key', 'settings.config-version-changed', $1, NULL,\
                   'source-survives-0098', 'settings.config-version-changed', 'v1', $2,\
                   jsonb_build_object('tenantId', $3::text), 'legacy-key', NULL)",
    )
    .bind(b"source-payload".as_slice())
    .bind("sha256:b74288de6fd13213cb6676431f4833a7c921ec9ffe2825ad244cad49c52d17e4")
    .bind(tenant.to_string())
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.dead_letter (\
             tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic,\
             consumer_group, replay_capsule, replay_capsule_key_ref, payload_len,\
             replay_capsule_encoding, metadata_digest, error_summary, num_attempts, source_kind\
         ) VALUES\
         ($1::uuid, 'settings-dlq-survives-0098', 'settings', 'settings',\
          'settings.config-version-changed', 'settings.config-version-changed',\
          'settings.config-projection@v3:shadow',\
          jsonb_build_object('ciphertext', 'settings-ciphertext'), 'key-v3', 17,\
          'key-provider-v3', $2, 'settings projection failure', 1, 'projection'),\
         ($1::uuid, 'unrelated-dlq-survives-0098', 'identity', 'consumer',\
          'identity.session-created', 'identity.session-created', 'unrelated-consumer',\
          jsonb_build_object('ciphertext', 'unrelated-ciphertext'), 'key-v3', 19,\
          'key-provider-v3', $3, 'unrelated failure', 1, 'consumer')",
    )
    .bind(tenant.to_string())
    .bind(vec![0x71_u8; 32])
    .bind(vec![0x72_u8; 32])
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.auth_audit_events (\
             occurred_at_secs, occurred_at_nanos, principal_id, principal_kind,\
             tenant_context, resource_kind, resource_id, action, outcome\
         ) VALUES\
         (1, 0, 'settings-operator', 'service', $1::uuid, 'projection',\
          'settings.config-projection@v3', 'swap', 'success'),\
         (1, 0, 'unrelated-service', 'service', $1::uuid, 'runtime',\
          'unrelated', 'observe', 'success')",
    )
    .bind(tenant.to_string())
    .execute(&pool)
    .await?;
    migrations_through(98).run(&pool).await?;
    testkit::provision_postgres_test_logins(
        fixture.params(),
        &[
            testkit::PostgresTestLogin::new("rss_app_read", READER_PASSWORD),
            testkit::PostgresTestLogin::new("rss_projection_operator", OPERATOR_PASSWORD),
        ],
    )
    .await?;

    let removed: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM public.settings_projection_generations \
            WHERE tenant_id = $1::uuid), \
           (SELECT count(*) FROM public.settings_config_projection_rows \
            WHERE tenant_id = $1::uuid), \
           (SELECT count(*) FROM public.settings_projection_dedupe_receipts \
            WHERE tenant_id = $1::uuid), \
           (SELECT count(*) FROM public.checkpoint \
            WHERE owner = $2 AND checkpoint_id = $3), \
           (SELECT count(*) FROM public.projection_worker_tenant_quarantine \
            WHERE tenant_scope_id = $1::uuid AND projection_id = 'settings.config-projection'), \
           (SELECT count(*) FROM public.distributed_cas \
            WHERE cas_key LIKE 'projection-active/%')",
    )
    .bind(tenant.to_string())
    .bind(&checkpoint_owner)
    .bind(checkpoint_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(removed, (0, 0, 0, 0, 0, 0));

    let preserved: (Vec<u8>, i64, Vec<u8>, i64) = sqlx::query_as(
        "SELECT cas.value, cas.token, event.payload, event.id \
         FROM public.distributed_cas AS cas \
         CROSS JOIN public.projection_events AS event \
         WHERE cas.cas_key = 'unrelated/runtime-state' \
           AND event.event_id = 'source-survives-0098'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(preserved.0, b"unrelated-value");
    assert_eq!(preserved.1, 7);
    assert_eq!(preserved.2, b"source-payload");
    assert!(preserved.3 > 0);

    let preserved_sentinels: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM public.checkpoint \
            WHERE owner = $1 AND checkpoint_id = $2 AND offset_lsn = 17 AND version = 2), \
           (SELECT count(*) FROM public.projection_worker_tenant_quarantine \
            WHERE tenant_scope_id = $3::uuid AND projection_id = 'other.projection' \
              AND target_generation = 'v1' AND state = 'quarantined'), \
           (SELECT count(*) FROM public.dead_letter \
            WHERE message_id IN ('settings-dlq-survives-0098', 'unrelated-dlq-survives-0098')), \
           (SELECT count(*) FROM public.auth_audit_events \
            WHERE principal_id IN ('settings-operator', 'unrelated-service'))",
    )
    .bind(&unrelated_checkpoint_owner)
    .bind(unrelated_checkpoint_id)
    .bind(tenant.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        preserved_sentinels,
        (1, 1, 2, 2),
        "hard cut must preserve non-target checkpoints/quarantine and both target-adjacent and unrelated DLQ/audit evidence"
    );

    let legacy_functions: (bool, bool) = sqlx::query_as(
        "SELECT \
           pg_catalog.to_regprocedure( \
             'public.rss_projection_operator_read_active_pointer(uuid,text)' \
           ) IS NULL, \
           pg_catalog.to_regprocedure( \
             'public.rss_projection_operator_cas_active_pointer(uuid,text,bytea,bytea,bigint)' \
           ) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(legacy_functions, (true, true));

    let reserved = sqlx::query(
        "INSERT INTO public.distributed_cas (cas_key, value, token)\
         VALUES ('projection-active/forged/settings.config-projection', $1, 1)",
    )
    .bind(b"forged".as_slice())
    .execute(&pool)
    .await;
    assert!(
        reserved.is_err(),
        "generic distributed CAS must reject the retired pointer namespace"
    );

    sqlx::query(
        "SELECT public.rss_register_projection_input_binding(\
             $1, 'settings.config-projection', 'v3', $2, 'settings', \
             'settings.config-version-changed', 'v1', $3, \
             'settings.config-version-changed'\
         )",
    )
    .bind(input_generation)
    .bind(definition_digest)
    .bind("sha256:b74288de6fd13213cb6676431f4833a7c921ec9ffe2825ad244cad49c52d17e4")
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version,\
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'upgrade-smoke', 'v3', $2, $3, $4)",
    )
    .bind(tenant.to_string())
    .bind(definition_digest)
    .bind(input_generation)
    .bind(preserved.3)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version)\
         VALUES ($1, 'settings.config-projection@upgrade-smoke:shadow', $2, 1)",
    )
    .bind(&checkpoint_owner)
    .bind(preserved.3)
    .execute(&pool)
    .await?;

    let operator = connect_as(
        fixture.params(),
        "rss_projection_operator",
        OPERATOR_PASSWORD,
    )
    .await?;
    let swapped: UpgradeSwapRow = sqlx::query_as(
        "SELECT outcome, reason, previous_generation, active_generation, \
                    result_token, promoted_high_water_lsn \
             FROM public.rss_projection_operator_swap_active(\
                 $1::uuid, 'upgrade-smoke', NULL::text, NULL::bigint, 'v3', $2, $3\
             )",
    )
    .bind(tenant.to_string())
    .bind(definition_digest)
    .bind(input_generation)
    .fetch_one(&operator)
    .await?;
    assert_eq!(
        swapped,
        UpgradeSwapRow {
            outcome: "applied".to_owned(),
            reason: None,
            previous_generation: None,
            active_generation: Some("upgrade-smoke".to_owned()),
            result_token: Some(1),
            promoted_high_water_lsn: Some(preserved.3),
        }
    );

    let reader = connect_as(fixture.params(), "rss_app_read", READER_PASSWORD).await?;
    let mut reader_tx = reader.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('rss.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *reader_tx)
        .await?;
    let resolved: (String, i64, i64) = sqlx::query_as(
        "SELECT generation, promoted_high_water_lsn, token \
         FROM public.rss_settings_projection_resolve_active()",
    )
    .fetch_one(&mut *reader_tx)
    .await?;
    assert_eq!(resolved, ("upgrade-smoke".to_owned(), preserved.3, 1));
    let raw_pointer = sqlx::query("SELECT * FROM public.settings_projection_active_pointer")
        .execute(&mut *reader_tx)
        .await;
    assert!(
        matches!(raw_pointer, Err(sqlx::Error::Database(ref error)) if error.code().as_deref() == Some("42501")),
        "post-upgrade reader must remain function-only: {raw_pointer:?}"
    );
    reader_tx.rollback().await?;
    let reader_acl: (bool, bool, bool) = sqlx::query_as(
        "SELECT \
           NOT has_table_privilege('rss_app_read', \
               'public.settings_projection_active_pointer', 'SELECT'), \
           has_function_privilege('rss_app_read', \
               'public.rss_settings_projection_resolve_active()', 'EXECUTE'), \
           NOT has_function_privilege('public', \
               'public.rss_settings_projection_resolve_active()', 'EXECUTE')",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(reader_acl, (true, true, true));
    operator.close().await;
    reader.close().await;

    sqlx::query(
        "INSERT INTO public.settings_projection_generations (\
             tenant_id, projection_id, generation, definition_version,\
             definition_schema_digest, input_generation, high_water_lsn\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'v3', $2, $3, 12)",
    )
    .bind(tenant.to_string())
    .bind(definition_digest)
    .bind(input_generation)
    .execute(&pool)
    .await?;
    let legacy_purpose = sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (\
             tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest,\
             actor, purpose\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'old-purpose', 12, $2,\
                   'rss-projection-worker', 'background-shadow')",
    )
    .bind(tenant.to_string())
    .bind(vec![0x97_u8; 32])
    .execute(&pool)
    .await;
    assert!(
        legacy_purpose.is_err(),
        "old worker purpose must be rejected"
    );

    sqlx::query(
        "INSERT INTO public.settings_projection_dedupe_receipts (\
             tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest,\
             actor, purpose\
         ) VALUES ($1::uuid, 'settings.config-projection', 'v3', 'new-purpose', 12, $2,\
                   'rss-projection-worker', 'background-worker')",
    )
    .bind(tenant.to_string())
    .bind(vec![0x96_u8; 32])
    .execute(&pool)
    .await?;

    pool.close().await;
    drop(fixture);
    Ok(())
}
