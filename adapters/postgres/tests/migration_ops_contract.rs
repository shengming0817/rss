//! Migration / ops carrier 对账。
//!
//! 只锁可执行 carrier：SQL migration、provisioning、capacity-gate 脚本，以及 runbook 中可复制执行的
//! SQL probe。面向人的说明散文不做 `contains` 断言——要求散文包含某句话不增加 enforcement 强度，
//! 见 `docs/rules/README.md` §红线一。

const SECRET_REFS_HARDENING: &str =
    include_str!("../migrations/0058_harden_secret_refs_append_only.sql");
const DLX_CUTOVER: &str = include_str!("../migrations/0062_prepare_dead_letter_cutover.sql");
const DLX_LIFECYCLE: &str = include_str!("../migrations/0063_dead_letter_lifecycle.sql");
const LOCALONLY_READ_ROLE: &str = include_str!("../migrations/0067_localonly_read_role.sql");
const SERVICE_TOKEN_REPLAY_MIGRATION: &str =
    include_str!("../migrations/0068_replace_service_token_replay_store.sql");
const ACCOUNT_SECURITY_MIGRATION: &str =
    include_str!("../migrations/0069_create_account_security_states.sql");
const AUTH_GRANT_MIGRATION: &str = include_str!("../migrations/0070_create_auth_grants.sql");
const DELIVERY_POLICY_PROBE: &str =
    include_str!("../migrations/0077_expose_event_delivery_policy_probe.sql");
const PROJECTION_INPUT_PROBE: &str =
    include_str!("../migrations/0078_expose_projection_input_generation_probe.sql");
const AUTH_GRANT_SWEEPER_LOCK_ORDER: &str =
    include_str!("../migrations/0079_align_auth_grant_sweeper_lock_order.sql");
const SAGA_RECEIPT_MIGRATION: &str =
    include_str!("../migrations/0083_create_saga_step_receipts.sql");
const SAGA_DURABLE_RECOVERY_MIGRATION: &str =
    include_str!("../migrations/0086_close_saga_durable_recovery.sql");
const SAGA_OPERATOR_LIFECYCLE_MIGRATION: &str =
    include_str!("../migrations/0089_install_saga_operator_lifecycle.sql");
const PROJECTION_PRIVILEGE_BOUNDARY: &str =
    include_str!("../migrations/0085_projection_privilege_boundaries.sql");
const PROJECTION_SCOPED_HIGH_WATER: &str =
    include_str!("../migrations/0088_projection_scoped_high_water.sql");
const SETTINGS_METADATA_PROJECTION: &str =
    include_str!("../migrations/0091_create_settings_metadata_projection.sql");
const SETTINGS_PROJECTION_APPLY_FUNNEL: &str =
    include_str!("../migrations/0093_install_settings_projection_apply_funnel.sql");
const MIGRATION_RUNBOOK: &str = include_str!("../migrations/README.md");
const ACCOUNT_SECURITY_CAPACITY_GATE: &str =
    include_str!("../../../docs/ops/0069-account-security-capacity-gate.sh");
const ACCOUNT_SECURITY_CAPACITY_SELFTEST: &str =
    include_str!("../../../docs/ops/0069-account-security-capacity-gate.selftest.sh");
const SERVICE_TOKEN_REPLAY_ADAPTER: &str = include_str!("../src/service_token_replay.rs");
const READER_PROVISIONING: &str =
    include_str!("../../../deploy/postgres-upgrade/provision-reader-role.sh");
const PROJECTION_ROLE_PROVISIONING: &str =
    include_str!("../../../deploy/postgres-upgrade/provision-projection-roles.sh");
const SAGA_OPERATOR_ROLE_PROVISIONING: &str =
    include_str!("../../../deploy/postgres-upgrade/provision-saga-operator-role.sh");
const L2_DR_RECOVERY_MIGRATION: &str =
    include_str!("../migrations/0100_install_l2_dr_recovery.sql");
const L2_DR_RECOVERY_ROLE_PROVISIONING: &str =
    include_str!("../../../deploy/postgres-upgrade/provision-l2-dr-recovery-roles.sh");
const PROJECTION_CORRECTNESS_RESIDUALS_MIGRATION: &str =
    include_str!("../migrations/0101_projection_correctness_residuals.sql");
const READER_UPGRADE_SMOKE: &str =
    include_str!("../../../deploy/postgres-upgrade/smoke-retained-volume.sh");
const POSTGRES_ROLE_INIT: &str =
    include_str!("../../../deploy/postgres-init/001-create-app-role.sh");

const SETTINGS_PROJECTION_GENERATION_COLUMNS: &[&str] = &[
    "tenant_id",
    "projection_id",
    "generation",
    "definition_version",
    "definition_schema_digest",
    "input_generation",
    "high_water_lsn",
    "created_at",
    "updated_at",
];
const SETTINGS_CONFIG_PROJECTION_ROW_COLUMNS: &[&str] = &[
    "tenant_id",
    "projection_id",
    "generation",
    "config_key",
    "config_version",
    "change_kind",
    "source_event_id",
    "source_lsn",
    "source_occurred_at_secs",
    "created_at",
    "updated_at",
];
const SETTINGS_PROJECTION_RECEIPT_COLUMNS: &[&str] = &[
    "tenant_id",
    "projection_id",
    "generation",
    "source_event_id",
    "source_lsn",
    "fact_digest",
    "applied_at",
];

fn create_table_body<'a>(sql: &'a str, table: &str) -> Result<&'a str, String> {
    let marker = format!("CREATE TABLE public.{table}");
    let marker_offset = sql
        .find(&marker)
        .ok_or_else(|| format!("missing exact table `{table}`"))?;
    let tail = &sql[marker_offset + marker.len()..];
    let open = tail
        .find('(')
        .ok_or_else(|| format!("table `{table}` has no column list"))?;
    let mut depth = 0_u32;
    for (offset, byte) in tail[open..].bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("table `{table}` has unbalanced parentheses"))?;
                if depth == 0 {
                    return Ok(&tail[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    Err(format!("table `{table}` has an unterminated column list"))
}

fn top_level_table_items(body: &str) -> Result<Vec<&str>, String> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut depth = 0_u32;
    for (offset, byte) in body.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "unbalanced table item parentheses".to_owned())?;
            }
            b',' if depth == 0 => {
                items.push(body[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unterminated table item parentheses".to_owned());
    }
    items.push(body[start..].trim());
    Ok(items)
}

fn projection_table_columns(sql: &str, table: &str) -> Result<Vec<String>, String> {
    let body = create_table_body(sql, table)?;
    let mut columns = Vec::new();
    for item in top_level_table_items(body)? {
        let Some(first) = item.split_whitespace().next() else {
            return Err(format!("table `{table}` contains an empty item"));
        };
        if matches!(
            first,
            "CONSTRAINT" | "PRIMARY" | "FOREIGN" | "UNIQUE" | "CHECK"
        ) {
            continue;
        }
        let lowered = item.to_ascii_lowercase();
        if lowered
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| matches!(token, "json" | "jsonb"))
        {
            return Err(format!("table `{table}` contains a JSON column `{item}`"));
        }
        columns.push(first.trim_matches('"').to_ascii_lowercase());
    }
    if columns.is_empty() {
        return Err(format!("table `{table}` has no parsed columns"));
    }
    Ok(columns)
}

fn validate_settings_projection_column_allowlist(sql: &str) -> Result<(), String> {
    for (table, expected) in [
        (
            "settings_projection_generations",
            SETTINGS_PROJECTION_GENERATION_COLUMNS,
        ),
        (
            "settings_config_projection_rows",
            SETTINGS_CONFIG_PROJECTION_ROW_COLUMNS,
        ),
        (
            "settings_projection_dedupe_receipts",
            SETTINGS_PROJECTION_RECEIPT_COLUMNS,
        ),
    ] {
        let actual = projection_table_columns(sql, table)?;
        let expected = expected
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();
        if actual != expected {
            return Err(format!(
                "table `{table}` columns differ: expected {expected:?}, got {actual:?}"
            ));
        }
        for forbidden in ["value", "payload", "secret", "token", "source_version"] {
            if actual.iter().any(|column| column.contains(forbidden)) {
                return Err(format!(
                    "table `{table}` contains forbidden metadata column `{forbidden}`"
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn settings_metadata_projection_schema_is_exact_rls_scoped_and_least_privilege()
-> Result<(), String> {
    validate_settings_projection_column_allowlist(SETTINGS_METADATA_PROJECTION)?;

    let normalized = SETTINGS_METADATA_PROJECTION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "PRIMARY KEY (tenant_id, projection_id, generation)",
        "PRIMARY KEY (tenant_id, projection_id, generation, config_key)",
        "PRIMARY KEY (tenant_id, projection_id, generation, source_event_id)",
        "FOREIGN KEY (tenant_id, projection_id, generation) REFERENCES public.settings_projection_generations (tenant_id, projection_id, generation)",
        "CONSTRAINT settings_projection_dedupe_receipts_source_lsn_unique UNIQUE (tenant_id, projection_id, generation, source_lsn)",
        "CHECK (projection_id = 'settings.config-projection')",
        "CHECK (generation ~ '^[a-z0-9][a-z0-9._-]*$')",
        "CHECK (pg_catalog.octet_length(generation) BETWEEN 1 AND 256)",
        "CHECK (definition_schema_digest ~ '^sha256:[0-9a-f]{64}$')",
        "CHECK (input_generation ~ '^sha256:[0-9a-f]{64}$')",
        "CHECK (high_water_lsn IS NULL OR high_water_lsn >= 0)",
        "CHECK (config_version > 0)",
        "CHECK (change_kind IN ('published', 'rolledBack', 'deleted'))",
        "CHECK (source_lsn >= 0)",
        "CHECK (source_occurred_at_secs >= 0)",
        "CHECK (pg_catalog.octet_length(fact_digest) = 32)",
        "ALTER TABLE public.settings_projection_generations ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.settings_projection_generations FORCE ROW LEVEL SECURITY",
        "ALTER TABLE public.settings_config_projection_rows ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.settings_config_projection_rows FORCE ROW LEVEL SECURITY",
        "ALTER TABLE public.settings_projection_dedupe_receipts ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.settings_projection_dedupe_receipts FORCE ROW LEVEL SECURITY",
        "tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
        "REVOKE ALL ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts FROM PUBLIC",
        "GRANT SELECT ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts TO rss_app_read",
        "GRANT SELECT ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts TO rss_app",
        "GRANT UPDATE (high_water_lsn, updated_at) ON public.settings_projection_generations TO rss_app",
        "GRANT UPDATE ( config_version, change_kind, source_event_id, source_lsn, source_occurred_at_secs, updated_at ) ON public.settings_config_projection_rows TO rss_app",
        ") ON public.settings_projection_dedupe_receipts TO rss_app",
        "REVOKE UPDATE ON TABLE public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read",
        "REVOKE DELETE, TRUNCATE ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read",
    ] {
        assert!(
            normalized.contains(required),
            "0091 omits Settings projection invariant `{required}`"
        );
    }

    assert_eq!(
        normalized
            .matches("CREATE POLICY tenant_isolation ON public.settings_projection_")
            .count()
            + normalized
                .matches("CREATE POLICY tenant_isolation ON public.settings_config_projection_rows")
                .count(),
        3,
        "0091 must install exactly one canonical tenant policy on each projection table"
    );
    assert_eq!(
        normalized
            .matches("CHECK (pg_catalog.octet_length(generation) BETWEEN 1 AND 256)")
            .count(),
        3,
        "0091 must bound generation bytes independently on every projection table"
    );
    for forbidden in [
        " ON DELETE CASCADE",
        "GRANT DELETE",
        "GRANT UPDATE ON TABLE public.settings_projection_dedupe_receipts",
        "GRANT UPDATE (tenant_id",
        "GRANT UPDATE (projection_id",
        "GRANT UPDATE (generation",
        "GRANT UPDATE (definition_version",
        "GRANT UPDATE (definition_schema_digest",
        "GRANT UPDATE (input_generation",
        "GRANT UPDATE (config_key",
        "GRANT INSERT ON TABLE public.settings_projection_dedupe_receipts TO rss_app_read",
        "GRANT SELECT, INSERT, UPDATE ON TABLE public.settings_projection_dedupe_receipts",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0091 exposes forbidden Settings projection surface `{forbidden}`"
        );
    }
    Ok(())
}

#[test]
fn settings_metadata_projection_allowlist_rejects_synthetic_payload_column() -> Result<(), String> {
    let bad_schema = SETTINGS_METADATA_PROJECTION.replace(
        "    updated_at",
        "    payload jsonb NOT NULL,\n    updated_at",
    );
    let error = validate_settings_projection_column_allowlist(&bad_schema)
        .err()
        .ok_or_else(|| {
            "synthetic payload/jsonb column must fail the exact allow-list".to_owned()
        })?;
    assert!(
        error.contains("JSON column") || error.contains("columns differ"),
        "synthetic negative must fail for the injected payload column: {error}"
    );
    Ok(())
}

#[test]
fn settings_projection_apply_is_one_metadata_only_function_with_exact_acl() {
    let normalized = SETTINGS_PROJECTION_APPLY_FUNNEL
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "CREATE FUNCTION public.rss_settings_projection_apply(",
        ") RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp",
        "pg_catalog.current_setting('rss.tenant_id', true)",
        "v_session_tenant IS NULL OR v_session_tenant = '' OR v_session_tenant::uuid <> p_tenant_id",
        "p_definition_version <> 'v3'",
        "p_definition_schema_digest <> 'sha256:3504a1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa'",
        "p_input_generation <> 'sha256:f0c8804d298ce326e5e22b6f8585dbce7cbe794546305cfecd2613985fbeb43e'",
        "SELECT fact_digest",
        "RETURN 'duplicate'",
        "p_source_lsn < v_high_water_lsn",
        "INSERT INTO public.settings_config_projection_rows",
        "INSERT INTO public.settings_projection_dedupe_receipts",
        "UPDATE public.settings_projection_generations SET high_water_lsn",
        ") OWNER TO rss_projection_operator_owner",
        "ALTER ROLE rss_projection_operator_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_dead_letter_source_kind() TO rss_projection_operator_owner",
        "GRANT SELECT ON TABLE public.dead_letter TO rss_projection_operator_owner",
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.settings_projection_generations, public.settings_config_projection_rows, public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read, rss_projection_operator",
        ") FROM PUBLIC, rss_app_read, rss_projection_reader, rss_projection_operator, rss_app",
        ") TO rss_app, rss_projection_operator",
        "CASE WHEN EXISTS",
        "THEN event.payload ELSE ''::bytea END",
        "candidate_binding.contract_id = event.contract_id",
    ] {
        assert!(
            normalized.contains(required),
            "0093 omits Settings apply invariant `{required}`"
        );
    }
    assert_eq!(
        normalized
            .matches("CREATE FUNCTION public.rss_settings_projection_apply(")
            .count(),
        1,
        "0093 must install exactly one mutation funnel"
    );
    for forbidden in [
        "p_payload",
        "p_raw_payload",
        "p_config_value",
        "GRANT INSERT ON TABLE public.settings_projection_generations TO rss_app",
        "GRANT UPDATE ON TABLE public.settings_config_projection_rows TO rss_app",
        "GRANT EXECUTE ON FUNCTION public.rss_settings_projection_apply( uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea ) TO PUBLIC",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0093 exposes forbidden Settings apply surface `{forbidden}`"
        );
    }
}

#[test]
fn settings_projection_apply_guard_rejects_synthetic_raw_payload_parameter() {
    let bad = SETTINGS_PROJECTION_APPLY_FUNNEL.replace(
        "p_fact_digest bytea",
        "p_raw_payload jsonb, p_fact_digest bytea",
    );
    assert!(
        bad.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("p_raw_payload"),
        "synthetic fixture must introduce the forbidden payload parameter"
    );
    assert!(
        !SETTINGS_PROJECTION_APPLY_FUNNEL.contains("p_raw_payload"),
        "canonical funnel must remain metadata-only"
    );
}

#[test]
fn settings_projection_apply_guard_rejects_synthetic_definition_wildcard() {
    let weakened = SETTINGS_PROJECTION_APPLY_FUNNEL.replace(
        "OR p_definition_version <> 'v3'",
        "OR false /* synthetic wildcard */",
    );
    assert!(weakened.contains("synthetic wildcard"));
    assert!(
        SETTINGS_PROJECTION_APPLY_FUNNEL.contains("OR p_definition_version <> 'v3'"),
        "canonical funnel must pin the generated Settings definition identity"
    );
}

#[test]
fn settings_projection_uses_only_typed_settlement_metrics() {
    let source = include_str!("../src/settings_projection.rs");
    assert!(
        !source.contains("settings_projection_apply_failure_total"),
        "Settings target must not create a parallel failure counter outside typed settlement"
    );
}

#[test]
fn projection_privilege_boundary_is_breaking_scoped_and_function_only() {
    let normalized = PROJECTION_PRIVILEGE_BOUNDARY
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for required in [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '5min'",
        "LOCK TABLE public.projection_input_bindings IN ACCESS EXCLUSIVE MODE",
        "IF EXISTS (SELECT 1 FROM public.projection_input_bindings LIMIT 1) THEN",
        "IF (SELECT count(*) FROM public.projection_input_bindings) <> 2",
        "WHERE generation = 'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895' AND contract_id = 'identity.session-created' AND contract_version = 'v1' AND schema_hash = 'sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516' AND topic = 'identity.session-created'",
        "WHERE generation = 'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895' AND contract_id = 'settings.config-version-changed' AND contract_version = 'v1' AND schema_hash = 'sha256:b74288de6fd13213cb6676431f4833a7c921ec9ffe2825ad244cad49c52d17e4' AND topic = 'settings.config-version-changed'",
        "projection_input_bindings does not match the exact predecessor generated set",
        "DELETE FROM public.projection_input_bindings WHERE generation = 'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895'",
        "ADD COLUMN projection_id text NOT NULL",
        "ADD COLUMN projection_definition_version text NOT NULL",
        "ADD COLUMN projection_definition_schema_digest text NOT NULL",
        "DROP FUNCTION public.rss_read_projection_events(bigint, integer)",
        "CREATE FUNCTION public.rss_read_projection_events_scoped(",
        "p_tenant_id uuid",
        "p_projection_id text",
        "p_definition_version text",
        "p_definition_schema_digest text",
        "p_input_generation text",
        "SECURITY DEFINER SET search_path = pg_catalog, pg_temp",
        "GRANT EXECUTE ON FUNCTION public.rss_read_projection_events_scoped(",
        "TO rss_projection_reader",
        "REVOKE ALL ON FUNCTION public.rss_read_projection_events_scoped(",
        "FROM PUBLIC, rss_app, rss_app_read, rss_projection_operator",
        "ALTER FUNCTION public.rss_append_projection_event(",
        "OWNER TO rss_projection_event_writer_owner",
        "CREATE ROLE rss_projection_source_reader_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "CREATE ROLE rss_projection_operator_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "ALTER ROLE rss_projection_source_reader_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "ALTER ROLE rss_projection_operator_owner NOLOGIN NOSUPERUSER NOBYPASSRLS",
        "ALTER ROLE rss_projection_reader SET default_transaction_read_only = on",
        "ALTER ROLE rss_projection_reader SET search_path = pg_catalog, public",
        "ALTER ROLE rss_projection_operator SET search_path = pg_catalog, public",
        "CREATE FUNCTION public.rss_projection_operator_record_audit(",
        "CREATE FUNCTION public.rss_projection_operator_get_checkpoint(",
        "CREATE FUNCTION public.rss_projection_operator_save_checkpoint(",
        "CREATE FUNCTION public.rss_projection_operator_read_active_pointer(",
        "CREATE FUNCTION public.rss_projection_operator_cas_active_pointer(",
        "IF p_expected_value IS NOT NULL OR p_expected_token IS NOT NULL THEN",
        "IF p_expected_token IS DISTINCT FROM stored_token THEN",
        "CREATE FUNCTION public.rss_projection_operator_insert_dead_letter(",
        "OWNER TO rss_projection_operator_owner",
        "REVOKE ALL ON TABLE public.auth_audit_events, public.checkpoint, public.distributed_cas, public.dead_letter FROM rss_projection_operator",
        "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC",
        "GRANT SELECT ON TABLE public._sqlx_migrations TO rss_projection_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_record_audit(",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_get_checkpoint(uuid, text, text) TO rss_projection_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_save_checkpoint(",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_read_active_pointer(uuid, text) TO rss_projection_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_cas_active_pointer(",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_insert_dead_letter(",
        "PERFORM pg_catalog.pg_advisory_xact_lock( pg_catalog.hashtextextended('rss.projection_events.append', 0) )",
        "DROP ROLE rss_projection_events_runtime",
    ] {
        assert!(
            normalized.contains(required),
            "0085 omits Projection capability invariant `{required}`"
        );
    }

    for forbidden in [
        "CREATE VIEW public.rss_read_projection_events",
        "CREATE FUNCTION public.rss_read_projection_events(p_after bigint",
        "GRANT EXECUTE ON FUNCTION public.rss_read_projection_events_scoped( uuid, text, text, text, text, bigint, integer ) TO rss_app",
        " BYPASSRLS ",
        "SET search_path = public",
        "GRANT SELECT ON TABLE public.projection_events TO rss_projection_reader;",
        "GRANT SELECT ON TABLE public.projection_input_bindings TO rss_projection_reader;",
        "GRANT SELECT ON TABLE public.checkpoint TO rss_projection_operator;",
        "GRANT INSERT ON TABLE public.auth_audit_events TO rss_projection_operator;",
        "GRANT SELECT, INSERT, UPDATE ON TABLE public.distributed_cas TO rss_projection_operator;",
        "GRANT INSERT ON TABLE public.dead_letter TO rss_projection_operator;",
        "p_expected_token IS NOT NULL AND p_expected_token < stored_token",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0085 retains forbidden Projection compatibility/privilege surface `{forbidden}`"
        );
    }

    let registry_lock =
        normalized.find("LOCK TABLE public.projection_input_bindings IN ACCESS EXCLUSIVE MODE");
    let predecessor_guard =
        normalized.find("IF EXISTS (SELECT 1 FROM public.projection_input_bindings LIMIT 1) THEN");
    assert!(
        matches!(
            (registry_lock, predecessor_guard),
            (Some(lock), Some(guard)) if lock < guard
        ),
        "0085 must lock the registry before accepting empty or exact-predecessor state"
    );

    let commit_order_lock = normalized
        .find("PERFORM pg_catalog.pg_advisory_xact_lock( pg_catalog.hashtextextended('rss.projection_events.append', 0) )");
    let projection_event_insert = normalized.find("INSERT INTO public.projection_events (");
    assert!(
        matches!(
            (commit_order_lock, projection_event_insert),
            (Some(lock), Some(insert)) if lock < insert
        ),
        "0085 must acquire the transaction-scoped commit-order lock before appending"
    );

    for required in [
        "rss-postgres-projection-source-reader",
        "deploy/postgres-upgrade/provision-projection-roles.sh",
        "WHEN proc.proname = 'rss_service_token_replay_check_and_record'",
        "THEN 'rss_service_token_replay_owner'",
        "NOT owner_role.rolcanlogin",
        "NOT owner_role.rolsuper",
        "NOT owner_role.rolbypassrls",
    ] {
        assert!(
            MIGRATION_RUNBOOK.contains(required),
            "0085 runbook postflight/provision carrier omits `{required}`"
        );
    }
    assert!(
        !MIGRATION_RUNBOOK.contains("'rss-postgres-projection-source',"),
        "0085 runbook must use the exact source-reader application name"
    );
}

#[test]
fn projection_scoped_high_water_is_exact_indexed_and_function_only() {
    let normalized = PROJECTION_SCOPED_HIGH_WATER
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for required in [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '5min'",
        "ALTER ROLE rss_projection_reader RESET default_transaction_read_only",
        "DROP FUNCTION public.rss_read_projection_events_scoped( uuid, text, text, text, text, bigint, integer )",
        "CREATE INDEX idx_projection_events_scoped_tail ON public.projection_events ( domain, contract_id, contract_version, schema_hash, event_type, (metadata ->> 'tenantId'), id DESC )",
        "CREATE TABLE public.projection_source_capabilities",
        "capability_digest bytea PRIMARY KEY",
        "scope_tenant_id uuid NOT NULL",
        "expires_at timestamp with time zone NOT NULL",
        "CHECK (pg_catalog.octet_length(capability_digest) = 32)",
        "CREATE INDEX idx_projection_source_capabilities_expiry ON public.projection_source_capabilities (expires_at, capability_digest)",
        "GRANT SELECT, INSERT, DELETE ON TABLE public.projection_source_capabilities TO rss_projection_operator_owner",
        "CREATE FUNCTION public.rss_assert_projection_source_scope(",
        "p_require_capability boolean",
        "CREATE FUNCTION public.rss_projection_operator_issue_source_capability(",
        "CREATE FUNCTION public.rss_read_projection_events_scoped(",
        "CREATE FUNCTION public.rss_projection_source_high_water_scoped(",
        "p_capability_first uuid",
        "p_capability_second uuid",
        "p_tenant_id uuid",
        "p_projection_id text",
        "p_definition_version text",
        "p_definition_schema_digest text",
        "p_input_generation text",
        "RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp",
        "SET plan_cache_mode = force_custom_plan",
        "DELETE FROM public.projection_source_capabilities AS capability",
        "capability.expires_at > pg_catalog.clock_timestamp()",
        "RETURNING capability.capability_digest INTO consumed_digest",
        "RAISE EXCEPTION 'invalid projection source scope' USING ERRCODE = '22023'",
        "issued_first uuid := pg_catalog.gen_random_uuid()",
        "issued_second uuid := pg_catalog.gen_random_uuid()",
        "CREATE FUNCTION public.rss_projection_operator_sweep_source_capabilities()",
        "WHERE capability.expires_at <= pg_catalog.clock_timestamp() ORDER BY capability.expires_at, capability.capability_digest LIMIT 1000",
        "PERFORM public.rss_projection_operator_sweep_source_capabilities()",
        "PERFORM public.rss_assert_projection_source_scope( false, NULL, NULL, p_tenant_id, p_projection_id, p_definition_version, p_definition_schema_digest, p_input_generation )",
        "INSERT INTO public.projection_source_capabilities",
        "pg_catalog.clock_timestamp() + interval '30 seconds'",
        "PERFORM public.rss_assert_projection_source_scope( true, p_capability_first, p_capability_second, p_tenant_id, p_projection_id, p_definition_version, p_definition_schema_digest, p_input_generation )",
        "WHERE binding.generation = p_input_generation AND binding.projection_id = p_projection_id AND binding.projection_definition_version = p_definition_version AND binding.projection_definition_schema_digest = p_definition_schema_digest",
        "FOR binding_row IN SELECT binding.source_domain, binding.contract_id, binding.contract_version, binding.schema_hash, binding.topic FROM public.projection_input_bindings AS binding",
        "SELECT event.id INTO binding_high_water FROM public.projection_events AS event WHERE event.metadata ->> 'tenantId' = p_tenant_id::text AND event.domain = binding_row.source_domain AND event.contract_id = binding_row.contract_id AND event.contract_version = binding_row.contract_version AND event.schema_hash = binding_row.schema_hash AND event.event_type = binding_row.topic",
        "ORDER BY event.domain, event.contract_id, event.contract_version, event.schema_hash, event.event_type, event.metadata ->> 'tenantId', event.id DESC LIMIT 1",
        "binding_high_water IS NOT NULL AND (high_water IS NULL OR binding_high_water > high_water)",
        "ALTER FUNCTION public.rss_projection_source_high_water_scoped( uuid, uuid, uuid, text, text, text, text ) OWNER TO rss_projection_source_reader_owner",
        "REVOKE ALL ON FUNCTION public.rss_assert_projection_source_scope( boolean, uuid, uuid, uuid, text, text, text, text ) FROM PUBLIC, rss_projection_reader, rss_projection_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_assert_projection_source_scope( boolean, uuid, uuid, uuid, text, text, text, text ) TO rss_projection_operator_owner",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_issue_source_capability( uuid, text, text, text, text ) TO rss_projection_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_sweep_source_capabilities() TO rss_projection_operator",
        "GRANT EXECUTE ON FUNCTION public.rss_read_projection_events_scoped( uuid, uuid, uuid, text, text, text, text, bigint, integer ) TO rss_projection_reader",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_source_high_water_scoped( uuid, uuid, uuid, text, text, text, text ) TO rss_projection_reader",
        "pg_catalog.int8send(",
        "ORDER BY pg_catalog.convert_to(binding.projection_id, 'UTF8')",
        "actual_input_generation IS DISTINCT FROM p_input_generation",
    ] {
        assert!(
            normalized.contains(required),
            "0088 omits scoped high-water invariant `{required}`"
        );
    }

    assert_eq!(
        normalized
            .matches("DELETE FROM public.projection_source_capabilities AS capability")
            .count(),
        2,
        "0088 must delete capabilities only through the shared consumer and bounded sweeper"
    );
    assert_eq!(
        normalized
            .matches("SET plan_cache_mode = force_custom_plan")
            .count(),
        1,
        "0088 must pin custom planning only on the high-water function"
    );
    assert_projection_generation_receipts(&normalized);

    let high_water_body = normalized
        .split_once("CREATE FUNCTION public.rss_projection_source_high_water_scoped(")
        .map_or("", |(_, tail)| tail)
        .split_once("ALTER FUNCTION public.rss_assert_projection_source_scope(")
        .map_or("", |(body, _)| body);
    assert!(
        !high_water_body.is_empty(),
        "0088 must carry a bounded high-water function body"
    );
    assert!(
        !high_water_body.contains("payload"),
        "0088 high-water function must not read or release payload"
    );
    assert!(
        high_water_body.contains("SET plan_cache_mode = force_custom_plan"),
        "0088 high-water function must retain custom planning after statement-cache warm-up"
    );
    assert_projection_high_water_uses_static_composite_tail(high_water_body);

    for forbidden in [
        "CREATE OR REPLACE FUNCTION public.rss_append_projection_event(",
        "GRANT SELECT ON TABLE public.projection_events TO rss_projection_reader",
        "GRANT SELECT ON TABLE public.projection_input_bindings TO rss_projection_reader",
        "GRANT SELECT ON TABLE public.projection_source_capabilities TO rss_projection_reader",
        "GRANT INSERT ON TABLE public.projection_source_capabilities TO rss_projection_operator;",
        "interval '31 seconds'",
        "p_ttl",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_issue_source_capability( uuid, text, text, text, text ) TO rss_projection_reader",
        "CREATE OR REPLACE FUNCTION public.rss_read_projection_events_scoped(",
        "SET search_path = public",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0088 retains forbidden Projection capability `{forbidden}`"
        );
    }

    let index = normalized.find("CREATE INDEX idx_projection_events_scoped_tail");
    let high_water =
        normalized.find("CREATE FUNCTION public.rss_projection_source_high_water_scoped(");
    assert!(
        matches!((index, high_water), (Some(index), Some(function)) if index < function),
        "0088 must install the scoped-tail index before exposing the high-water function"
    );

    let prior_append_lock = PROJECTION_PRIVILEGE_BOUNDARY
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        prior_append_lock.contains(
            "PERFORM pg_catalog.pg_advisory_xact_lock( pg_catalog.hashtextextended('rss.projection_events.append', 0) )"
        ),
        "0088 depends on the transaction-scoped append commit-order guard"
    );
}

fn assert_projection_generation_receipts(normalized: &str) {
    assert_eq!(
        normalized
            .matches("actual_input_generation IS DISTINCT FROM p_input_generation")
            .count(),
        1,
        "0088 must authenticate the complete generation once in the shared validator"
    );
    assert_eq!(
        normalized.matches("pg_catalog.int8send(").count(),
        8,
        "0088 must length-prefix all eight UTF-8 fields in the canonical receipt"
    );

    let validator_body = normalized
        .split_once("CREATE FUNCTION public.rss_assert_projection_source_scope(")
        .map_or("", |(_, tail)| tail)
        .split_once("CREATE FUNCTION public.rss_projection_operator_issue_source_capability(")
        .map_or("", |(body, _)| body);
    assert!(
        validator_body
            .find("actual_input_generation IS DISTINCT FROM p_input_generation")
            .zip(validator_body.find("END; $$"))
            .is_some_and(|(receipt, end)| receipt < end),
        "0088 must authenticate the complete generation inside the shared validator"
    );
    assert_eq!(
        normalized
            .matches("PERFORM public.rss_assert_projection_source_scope(")
            .count(),
        3,
        "0088 issuer, read and high-water paths must share one validator"
    );
}

fn assert_projection_high_water_uses_static_composite_tail(high_water_body: &str) {
    let tail_seek = high_water_body
        .split_once("SELECT event.id INTO binding_high_water")
        .map_or("", |(_, tail)| tail)
        .split_once("END LOOP")
        .map_or("", |(body, _)| body);
    assert!(
        tail_seek.contains(
            "ORDER BY event.domain, event.contract_id, event.contract_version, event.schema_hash, event.event_type, event.metadata ->> 'tenantId', event.id DESC LIMIT 1"
        ),
        "0088 must align each static binding tail seek with the complete composite index order"
    );
    assert!(
        !tail_seek.contains("EXECUTE")
            && !tail_seek.contains("pg_catalog.format")
            && !tail_seek.contains("||"),
        "0088 tail seek must remain a cacheable static query"
    );
    for forbidden in ["enable_seqscan", "pg_hint_plan"] {
        assert!(
            !high_water_body.contains(forbidden),
            "0088 must fix the tail plan without planner override `{forbidden}`"
        );
    }
}

#[test]
fn saga_receipts_have_one_atomic_protected_retention_funnel() {
    for required in [
        "cannot install saga receipts while saga durable rows exist",
        "CREATE TABLE public.saga_step_receipts",
        "DEFERRABLE INITIALLY DEFERRED",
        "CREATE CONSTRAINT TRIGGER saga_receipt_requires_completed",
        "CREATE CONSTRAINT TRIGGER saga_completed_requires_receipt",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "REVOKE INSERT (committed_at) ON public.saga_step_receipts",
        "CREATE FUNCTION public.rss_sweep_terminal_sagas()",
        "status IN ('succeeded', 'compensated', 'failed')",
        "interval '30 days'",
        "LIMIT 1000",
        "ON DELETE CASCADE",
        "GRANT EXECUTE ON FUNCTION public.rss_sweep_terminal_sagas() TO rss_app",
    ] {
        assert!(
            SAGA_RECEIPT_MIGRATION.contains(required),
            "0083 omits Saga receipt invariant `{required}`"
        );
    }
    for forbidden in [
        "p_retain_seconds",
        "p_limit",
        "GRANT DELETE ON public.saga_step_receipts TO rss_app",
        "GRANT DELETE ON public.saga_instances TO rss_app",
        "payload json",
        "payload jsonb",
        "payload text",
    ] {
        assert!(
            !SAGA_RECEIPT_MIGRATION.contains(forbidden),
            "0083 exposes forbidden compatibility/plaintext surface `{forbidden}`"
        );
    }
}

#[test]
fn saga_durable_recovery_cutover_is_strict_atomic_and_least_privilege() {
    for required in [
        "LOCK TABLE public.saga_instances, public.saga_journal, public.saga_step_receipts",
        "cannot close saga durable recovery while saga durable rows exist",
        "ADD COLUMN operator_reason text",
        "ADD COLUMN compensation_cause text",
        "ADD COLUMN attempt integer NOT NULL",
        "ADD COLUMN effect_key bytea NOT NULL",
        "'forward_intent', 'forward_completed', 'forward_not_applied'",
        "'compensation_intent', 'compensation_completed', 'compensation_not_applied'",
        "journal.attempt = NEW.successful_attempt",
        "journal.effect_key = NEW.effect_key",
        "receipt.successful_attempt = NEW.attempt",
        "receipt.effect_key = NEW.effect_key",
        "intent.status = 'forward_intent'",
        "ELSE 'compensation_intent'",
        "intent.seq + 1 = NEW.seq",
        "NEW.attempt <> 1 + (",
        "prior.status = NEW.status",
        "duplicate.attempt = NEW.attempt",
        "NEW.compensation_cause = instance.compensation_cause",
        "intent.attempt = NEW.attempt",
        "intent.effect_key = NEW.effect_key",
        "intent.compensation_cause = instance.compensation_cause",
        "DEFERRABLE INITIALLY DEFERRED",
        "REVOKE ALL ON TABLE public.saga_instances, public.saga_journal",
        "CREATE ROLE rss_saga_writer",
        "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS",
        "CREATE FUNCTION public.rss_saga_register(",
        "CREATE FUNCTION public.rss_saga_claim(",
        "CREATE FUNCTION public.rss_saga_apply_lifecycle(",
        "CREATE FUNCTION public.rss_saga_append_journal(",
        "CREATE FUNCTION public.rss_saga_record_operator_decision(",
        "CREATE FUNCTION public.rss_saga_insert_receipt(",
        "CREATE FUNCTION public.rss_saga_candidate_tenants(",
        "CREATE FUNCTION public.rss_saga_observe_unresolved(",
        "CREATE OR REPLACE FUNCTION public.rss_saga_worker_tenant_index_refresh()",
        "instance.status IN ('ready', 'running', 'compensating')",
        "instance.status IN ('operator_required', 'degraded')",
        "CREATE INDEX saga_instances_worker_candidate_idx",
        "CREATE INDEX saga_instances_unresolved_observation_idx",
        "start_audit_id text NOT NULL",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
        "OWNER TO rss_saga_writer",
        "GRANT SELECT ON TABLE public.saga_instances, public.saga_journal",
    ] {
        assert!(
            SAGA_DURABLE_RECOVERY_MIGRATION.contains(required),
            "0086 omits closed durable Saga invariant `{required}`"
        );
    }
    assert_eq!(
        SAGA_DURABLE_RECOVERY_MIGRATION
            .matches("ADD COLUMN compensation_cause text")
            .count(),
        2,
        "0086 must persist compensation cause on both instance and journal intent rows"
    );
    for forbidden in [
        "GRANT UPDATE ON TABLE public.saga_instances TO rss_app",
        "GRANT INSERT ON TABLE public.saga_journal TO rss_app",
        "GRANT UPDATE ON TABLE public.saga_journal TO rss_app",
        "GRANT INSERT (",
        "GRANT UPDATE (",
        "GRANT SELECT, INSERT ON TABLE public.saga_operator_decisions TO rss_app",
        "GRANT DELETE ON TABLE public.saga_instances TO rss_app",
        "GRANT DELETE ON TABLE public.saga_journal TO rss_app",
        "'executing'",
        "'completed'",
        "'compensating' AS",
    ] {
        assert!(
            !SAGA_DURABLE_RECOVERY_MIGRATION.contains(forbidden),
            "0086 retains forbidden mutable/legacy surface `{forbidden}`"
        );
    }
}

#[test]
fn saga_operator_lifecycle_is_fenced_audited_and_observable() {
    let normalized = SAGA_OPERATOR_LIFECYCLE_MIGRATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "LOCK TABLE public.saga_instances IN ACCESS EXCLUSIVE MODE",
        "saga_instances must be empty before installing operator lifecycle v2",
        "ADD COLUMN start_actor text NOT NULL",
        "ADD COLUMN start_audit_id text NOT NULL",
        "ADD COLUMN unresolved_at timestamptz",
        "'compensation_failed', 'operator_required', 'degraded', 'terminated'",
        "status IN ('succeeded', 'compensated', 'expired', 'terminated')",
        "status IN ('operator_required', 'degraded', 'compensation_failed')",
        "NEW.unresolved_at := OLD.unresolved_at",
        "CREATE INDEX saga_instances_unresolved_observation_idx",
        "INCLUDE (status)",
        "RETURNS TABLE ( deleted bigint, backlog_depth bigint, oldest_expired_age_seconds bigint )",
        "LIMIT 1000 FOR UPDATE SKIP LOCKED",
        "pg_catalog.count(*)",
        "extract(epoch FROM observed_at - pg_catalog.min(instance.terminal_at))",
        "DROP FUNCTION public.rss_saga_observe_unresolved(text, text)",
        "operator_required_count bigint",
        "degraded_count bigint",
        "compensation_failed_count bigint",
        "oldest_unresolved_at timestamptz",
        "CREATE TABLE public.saga_operator_transitions",
        "ADD COLUMN operator_reason_text text NOT NULL",
        "pg_catalog.octet_length(operator_reason_text) BETWEEN 1 AND 512",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON public.saga_operator_transitions",
        "rss_saga_record_operator_decision.start_audit_id",
        "CREATE FUNCTION public.rss_saga_retry_compensation(",
        "failure.status = 'compensation_failed'",
        "later.seq > failure.seq",
        "failure.effect_key = p_failure_effect_key",
        "CREATE FUNCTION public.rss_saga_terminate(",
        "instance.status = 'ready'",
        "instance.unresolved_at IS NULL",
        "AND NOT EXISTS",
        "intent.status IN ('forward_intent', 'compensation_intent')",
        "INSERT INTO public.saga_operator_transitions",
        "GRANT SELECT, INSERT ON TABLE public.saga_operator_transitions TO rss_saga_writer",
        "GRANT SELECT ON TABLE public.saga_operator_transitions TO rss_app, rss_app_read",
        "GRANT EXECUTE ON FUNCTION public.rss_saga_retry_compensation(",
        "GRANT EXECUTE ON FUNCTION public.rss_saga_terminate(",
    ] {
        assert!(
            normalized.contains(required),
            "0089 omits Saga operator lifecycle invariant `{required}`"
        );
    }

    for forbidden in [
        "RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN IF p_owner",
        "GRANT UPDATE ON TABLE public.saga_operator_transitions",
        "GRANT DELETE ON TABLE public.saga_operator_transitions",
        "GRANT EXECUTE ON FUNCTION public.rss_saga_register(uuid, text, text, text, text, text) TO rss_app",
        "p_expected_status IN ('running', 'compensating'",
        "p_expected_status IN ('ready', 'operator_required', 'degraded', 'compensation_failed')",
        "CREATE FUNCTION public.rss_saga_terminate( p_saga_id uuid, p_lease_token uuid, p_epoch bigint, p_expected_status text",
        "CREATE FUNCTION public.rss_saga_claim_operator_transition(",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0089 retains forbidden Saga operator surface `{forbidden}`"
        );
    }
}

#[test]
fn saga_receipt_cutover_runbook_carries_executable_pre_and_postflight_probes() {
    for required in [
        "SELECT max(version) = 82 AS exact_pre_0083_ledger",
        "(SELECT count(*) FROM public.saga_instances) = 0 AS saga_instances_empty",
        "(SELECT count(*) FROM public.saga_journal) = 0 AS saga_journal_empty",
        "SELECT count(*) = 0 AS all_saga_lanes_drained",
        "'rss-postgres-migrator'",
        "SELECT max(version) = 83 AS exact_post_0083_ledger",
        "relation.relrowsecurity AS rls_enabled",
        "relation.relforcerowsecurity AS rls_forced",
        "has_column_privilege('rss_app', 'public.saga_step_receipts', 'tenant_id', 'INSERT')",
        "NOT has_column_privilege('rss_app', 'public.saga_step_receipts', 'committed_at', 'INSERT')",
        "NOT has_table_privilege('rss_app', 'public.saga_step_receipts', 'DELETE')",
        "trigger.tgdeferrable AS deferred",
        "trigger.tginitdeferred AS initially_deferred",
        "pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_receipt_maintenance'",
        "proc.prosecdef AS security_definer",
        "proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]",
        "has_function_privilege('rss_app', proc.oid, 'EXECUTE')",
        "acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'",
        "pg_catalog.pg_get_functiondef(proc.oid) LIKE '%interval ''30 days''%'",
    ] {
        assert!(
            MIGRATION_RUNBOOK.contains(required),
            "0083 runbook omits executable cutover probe `{required}`"
        );
    }
}

#[test]
fn saga_durable_recovery_runbook_carries_executable_hard_cutover_probes() {
    let section = MIGRATION_RUNBOOK
        .split_once("### 0086 Saga durable recovery")
        .map_or(MIGRATION_RUNBOOK, |(_, section)| section);

    for required in [
        "SELECT max(version) = 85 AS exact_pre_0086_ledger",
        "(SELECT count(*) FROM public.saga_instances) = 0 AS saga_instances_empty",
        "(SELECT count(*) FROM public.saga_journal) = 0 AS saga_journal_empty",
        "(SELECT count(*) FROM public.saga_step_receipts) = 0 AS saga_step_receipts_empty",
        "SELECT count(*) = 0 AS all_saga_lanes_drained",
        "'rss-postgres-writer'",
        "'rss-postgres-reader'",
        "'rss-postgres-audit-admin'",
        "'rss-postgres-maintenance'",
        "'rss-postgres-migrator'",
        "SELECT count(*) = 0 AS no_conflicting_saga_locks",
        "'public.saga_step_receipts'::regclass",
        "rss postgres migrate-all",
        "SELECT max(version) = 86 AS exact_post_0086_ledger",
        "('saga_instances', 'operator_reason', 'text', 'YES')",
        "('saga_journal', 'attempt', 'integer', 'NO')",
        "('saga_journal', 'effect_key', 'bytea', 'NO')",
        "('saga_instances', 'saga_instances_resolution_shape')",
        "('saga_journal', 'saga_journal_attempt_positive')",
        "('saga_journal', 'saga_journal_effect_key_width')",
        "('saga_receipt_requires_completed', 'saga_step_receipts', true, true)",
        "('saga_completed_requires_receipt', 'saga_journal', true, true)",
        "trigger.tgdeferrable = expected.deferred",
        "trigger.tginitdeferred = expected.initially_deferred",
        "NOT has_table_privilege('rss_app', relation.oid, 'INSERT')",
        "NOT has_table_privilege('rss_app', relation.oid, 'UPDATE')",
        "NOT has_table_privilege('rss_app', relation.oid, 'DELETE')",
        "has_table_privilege('rss_app_read', relation.oid, 'SELECT')",
        "pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_writer'",
        "proc.proname IN ('rss_saga_register', 'rss_saga_claim'",
        "'public.saga_instances_worker_candidate_idx'::regclass",
        "'public.rss_saga_candidate_tenants(text,text,uuid,bigint)'::regprocedure",
        "'public.rss_saga_observe_unresolved(text,text)'::regprocedure",
        "AS exact_observation_or_keyset_order",
        "pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_receipt_maintenance'",
        "proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]",
        "has_function_privilege('rss_app', proc.oid, 'EXECUTE')",
        "pg_catalog.pg_get_functiondef(proc.oid) LIKE '%LIMIT 1000%'",
        "SELECT max(version) = 85 AS failed_0086_ledger_unchanged",
        ") AS failed_0086_has_no_partial_columns",
        "AS old_instance_status_constraint_intact",
        "AS old_journal_status_constraint_intact",
    ] {
        assert!(
            section.contains(required),
            "0086 runbook omits executable hard-cutover probe `{required}`"
        );
    }

    assert!(
        !section.contains("DELETE FROM public.saga_"),
        "0086 runbook must not turn empty-table preflight into an unaudited disposal path"
    );
}

#[test]
fn security_definer_probes_trust_only_pg_catalog_and_pg_temp() {
    for (migration, sql) in [
        ("0077", DELIVERY_POLICY_PROBE),
        ("0078", PROJECTION_INPUT_PROBE),
        ("0079", AUTH_GRANT_SWEEPER_LOCK_ORDER),
    ] {
        assert!(
            sql.contains("SECURITY DEFINER\nSET search_path = pg_catalog, pg_temp"),
            "{migration} must exclude writable schemas from SECURITY DEFINER search_path"
        );
        assert!(
            !sql.contains("SET search_path = pg_catalog, public"),
            "{migration} must not trust public"
        );
    }
}

#[test]
fn auth_grant_sweeper_replacement_locks_and_deletes_family_before_root() -> Result<(), &'static str>
{
    let normalized = AUTH_GRANT_SWEEPER_LOCK_ORDER
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let family_lock = normalized
        .find("FROM public.refresh_tokens AS refresh WHERE refresh.tenant_id = candidate.tenant_id")
        .ok_or("0079 must lock the exact refresh family")?;
    let family_delete = normalized
        .find("DELETE FROM public.refresh_tokens AS refresh")
        .ok_or("0079 must explicitly delete refresh children")?;
    let root_delete = normalized
        .find("DELETE FROM public.auth_grants AS root")
        .ok_or("0079 must delete the AuthGrant only after its family")?;

    assert!(family_lock < family_delete && family_delete < root_delete);
    assert!(normalized.contains("ORDER BY refresh.id FOR UPDATE"));
    assert!(
        normalized.contains("CREATE OR REPLACE FUNCTION public.rss_sweep_expired_auth_grants()")
    );
    assert!(!normalized.contains("FOR UPDATE SKIP LOCKED"));
    Ok(())
}

#[test]
fn postgres_role_init_keeps_file_passwords_out_of_psql_argv_and_unsets_them() {
    for forbidden in [
        "--set app_password=",
        "--set read_password=",
        "--set projection_reader_password=",
        "--set projection_operator_password=",
        "--set dlx_archiver_password=",
        "--set dlx_verifier_password=",
        "--set dlx_purger_password=",
    ] {
        assert!(
            !POSTGRES_ROLE_INIT.contains(forbidden),
            "argv secret: {forbidden}"
        );
    }
    for required in [
        "\\getenv app_password RSS_INIT_APP_PASSWORD",
        "\\getenv read_password RSS_INIT_READ_PASSWORD",
        "\\getenv projection_reader_password RSS_INIT_PROJECTION_READER_PASSWORD",
        "\\getenv projection_operator_password RSS_INIT_PROJECTION_OPERATOR_PASSWORD",
        "\\getenv dlx_archiver_password RSS_INIT_DLX_ARCHIVER_PASSWORD",
        "\\getenv dlx_verifier_password RSS_INIT_DLX_VERIFIER_PASSWORD",
        "\\getenv dlx_purger_password RSS_INIT_DLX_PURGER_PASSWORD",
        "trap clear_init_passwords EXIT",
        "clear_init_passwords\ntrap - EXIT",
        "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_reader LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
    ] {
        assert!(
            POSTGRES_ROLE_INIT.contains(required),
            "missing secret cleanup: {required}"
        );
    }
}

#[test]
fn auth_grant_cutover_is_strict_atomic_and_least_privilege() {
    let normalized = AUTH_GRANT_MIGRATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for required in [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '5min'",
        "LOCK TABLE public.sessions IN SHARE ROW EXCLUSIVE MODE",
        "LOCK TABLE public.refresh_tokens IN SHARE ROW EXCLUSIVE MODE",
        "DELETE FROM public.refresh_tokens",
        "DROP FUNCTION public.rss_sweep_expired_sessions()",
        "DROP TABLE public.sessions",
        "DROP ROLE rss_session_maintenance",
        "CREATE TABLE public.auth_grants",
        "PRIMARY KEY (tenant_id, grant_id)",
        "user_id uuid NOT NULL",
        "authn_epoch_at_issue bigint NOT NULL",
        "CHECK (authn_epoch_at_issue >= 0)",
        "status = 'active' AND closed_at IS NULL AND close_reason IS NULL",
        "status = 'compromised' AND closed_at IS NOT NULL AND close_reason = 'refresh_reuse_detected'",
        "ADD COLUMN auth_grant_id text NOT NULL",
        "ADD COLUMN user_id uuid NOT NULL",
        "ADD COLUMN auth_grant_status text NOT NULL",
        "CHECK (auth_grant_status = 'active' OR status = 'revoked')",
        "FOREIGN KEY ( tenant_id, auth_grant_id, user_id, authn_epoch_at_issue, auth_grant_status )",
        "ON UPDATE CASCADE ON DELETE CASCADE",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "REVOKE UPDATE ON TABLE public.auth_grants FROM rss_app, rss_app_read",
        "GRANT UPDATE (status, closed_at, close_reason) ON TABLE public.auth_grants TO rss_app",
        "REVOKE DELETE ON TABLE public.auth_grants FROM rss_app, rss_app_read",
        "REVOKE UPDATE ON TABLE public.refresh_tokens FROM rss_app, rss_app_read",
        "GRANT UPDATE (status) ON TABLE public.refresh_tokens TO rss_app",
        "REVOKE DELETE ON TABLE public.refresh_tokens FROM rss_app, rss_app_read",
        "CREATE FUNCTION public.rss_sweep_expired_auth_grants()",
        "LIMIT 1000",
        "FOR UPDATE SKIP LOCKED",
        "OWNER TO rss_auth_grant_maintenance",
        "GRANT SELECT, UPDATE, DELETE ON TABLE public.auth_grants TO rss_auth_grant_maintenance",
        "GRANT DELETE ON TABLE public.refresh_tokens TO rss_auth_grant_maintenance",
    ] {
        assert!(
            normalized.contains(required),
            "0070 omits AuthGrant hard-cutover constraint: {required}"
        );
    }

    for forbidden in [
        "CREATE VIEW public.sessions",
        "CREATE TABLE public.sessions",
        "CREATE TRIGGER",
        "DELETE FROM public.sessions",
        "ADD COLUMN auth_grant_id text",
        "ADD COLUMN user_id uuid",
        "ADD COLUMN auth_grant_status text",
        "GRANT SELECT, INSERT, UPDATE ON TABLE public.auth_grants TO rss_app",
        "GRANT UPDATE ON TABLE public.auth_grants TO rss_app",
        "GRANT UPDATE ON TABLE public.refresh_tokens TO rss_app",
        "GRANT DELETE ON TABLE public.auth_grants TO rss_app",
        "GRANT DELETE ON TABLE public.refresh_tokens TO rss_app",
        "rss_sweep_expired_sessions() TO rss_app",
    ] {
        let forbidden_is_nullable_column = matches!(
            forbidden,
            "ADD COLUMN auth_grant_id text"
                | "ADD COLUMN user_id uuid"
                | "ADD COLUMN auth_grant_status text"
        );
        let present = if forbidden_is_nullable_column {
            normalized.contains(forbidden) && !normalized.contains(&format!("{forbidden} NOT NULL"))
        } else {
            normalized.contains(forbidden)
        };
        assert!(
            !present,
            "0070 contains compatibility or excess-privilege path: {forbidden}"
        );
    }
}

#[test]
fn account_security_migration_is_strict_closed_and_least_privilege() {
    let normalized = ACCOUNT_SECURITY_MIGRATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "CREATE TABLE public.account_security_states",
        "PRIMARY KEY (tenant_id, user_id)",
        "REFERENCES public.credentials (tenant_id, user_id) ON DELETE CASCADE",
        "CHECK (status IN ('active', 'suspended', 'locked', 'deactivated'))",
        "CHECK (authn_epoch >= 0)",
        "CHECK (version >= 1)",
        "CHECK (status_changed_at <= updated_at)",
        "INSERT INTO public.account_security_states",
        "'active', 0, 1",
        "ALTER TABLE public.credentials",
        "DEFERRABLE INITIALLY DEFERRED",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
        "WHERE status = 'active'",
        "DELETE FROM public.refresh_tokens",
        "ADD COLUMN authn_epoch_at_issue bigint NOT NULL",
        "CHECK (authn_epoch_at_issue >= 0)",
        "GRANT SELECT, INSERT, UPDATE ON TABLE public.account_security_states TO rss_app",
        "GRANT SELECT ON TABLE public.account_security_states TO rss_app_read",
    ] {
        assert!(
            normalized.contains(required),
            "0069 omits account-security hard constraint: {required}"
        );
    }

    for forbidden in [
        "GRANT DELETE ON TABLE public.account_security_states",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.account_security_states",
        "CREATE POLICY account_security_tenant_isolation ON public.account_security_states USING ( tenant_id = current_setting",
        "ON CONFLICT",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0069 contains compatibility or excess-privilege path: {forbidden}"
        );
    }
}

#[test]
fn account_security_cutover_has_bounded_locking_and_executable_capacity_gate() {
    for required in [
        "SET LOCAL lock_timeout = '5s'",
        "SET LOCAL statement_timeout = '5min'",
    ] {
        assert!(
            ACCOUNT_SECURITY_MIGRATION.contains(required),
            "0069 omits bounded migration timeout: {required}"
        );
    }

    for required in [
        "set -eu",
        "SELECT count(*) FROM public.credentials",
        "pg_total_relation_size('public.credentials'::regclass)",
        "DATA_BUDGET",
        "WAL_BUDGET",
        "ARCHIVE_BUDGET",
        "SELECT count(*) FROM pg_stat_replication",
        "sample.byte_lag = 0",
        "sample.reply_time >= sample.checked_at - interval '60 seconds'",
        "pg_switch_wal()",
        "archive_target_present",
        "MINIMUM_WINDOW_SECONDS=480",
    ] {
        assert!(
            ACCOUNT_SECURITY_CAPACITY_GATE.contains(required),
            "0069 capacity gate omits fail-closed carrier: {required}"
        );
    }
    for required in [
        "short maintenance window must fail closed",
        "credential row overflow must fail closed",
        "credential byte overflow must fail closed",
        "replica inventory mismatch must fail closed",
        "unhealthy replica must fail closed",
        "archive failure-count change must fail closed",
    ] {
        assert!(
            ACCOUNT_SECURITY_CAPACITY_SELFTEST.contains(required),
            "0069 capacity selftest omits red case: {required}"
        );
    }
}

#[test]
fn service_token_replay_store_is_async_fixed_shape_and_least_privilege() {
    for forbidden in [
        "block_in_place",
        "Handle::block_on",
        "service_token_replay_nonces",
        "DELETE FROM service_token_replay",
    ] {
        assert!(
            !SERVICE_TOKEN_REPLAY_ADAPTER.contains(forbidden),
            "replay adapter contains blocking, legacy, or hot-path cleanup token: {forbidden}"
        );
    }

    let consume_function = SERVICE_TOKEN_REPLAY_MIGRATION
        .split_once("CREATE FUNCTION public.rss_service_token_replay_sweep_expired()")
        .map_or(SERVICE_TOKEN_REPLAY_MIGRATION, |(consume, _)| consume);
    for required in [
        "active legacy service-token replay entries prevent scoped-store cutover",
        "DROP TABLE public.service_token_replay_nonces",
        "key_digest bytea PRIMARY KEY",
        "pg_catalog.octet_length(key_digest) = 32",
        "INSERT INTO public.service_token_replay_keys",
        "ON CONFLICT (key_digest) DO NOTHING",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
        "REVOKE ALL ON TABLE public.service_token_replay_keys FROM PUBLIC, rss_app",
        "GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record",
    ] {
        assert!(
            SERVICE_TOKEN_REPLAY_MIGRATION.contains(required),
            "0068 omits replay-store contract token: {required}"
        );
    }
    assert!(
        !consume_function.contains("DELETE FROM public.service_token_replay_keys"),
        "authentication consume function must never perform retention cleanup"
    );
    for required in [
        ".run(async",
        ".server_timeout_millis()",
        "pool.begin()",
        "set_config('statement_timeout'",
        "set_config('lock_timeout'",
        ".commit()",
    ] {
        assert!(
            SERVICE_TOKEN_REPLAY_ADAPTER.contains(required),
            "replay adapter omits the single absolute deadline transaction funnel: {required}"
        );
    }
    assert!(
        !SERVICE_TOKEN_REPLAY_ADAPTER.contains(".fetch_one(&self.pool)"),
        "replay SQL must not bypass the deadline-owned transaction"
    );
    for required in [
        "LIMIT 1000",
        "FOR UPDATE SKIP LOCKED",
        "interval '5 minutes'",
    ] {
        assert!(
            SERVICE_TOKEN_REPLAY_MIGRATION.contains(required),
            "bounded replay retention function omits: {required}"
        );
    }
}

#[test]
fn reader_provisioning_disables_inherited_xtrace_before_secret_expansion() {
    assert!(
        matches!(
            (
                READER_PROVISIONING.find("set +x"),
                READER_PROVISIONING.find("${RSS_PG_")
            ),
            (Some(disable_xtrace), Some(first_secret_expansion))
                if disable_xtrace < first_secret_expansion
        ),
        "set +x must exist and execute before any credential-bearing shell expansion"
    );
    assert!(!READER_PROVISIONING.contains("set -x"));
    for required in [
        "ALTER ROLE rss_app_read SET default_transaction_read_only = 'on'",
        "ALTER ROLE rss_app_read SET search_path = pg_catalog, public",
        "current_setting('lo_compat_privileges')",
        "rss_app_read:on:pg_catalog, public:off",
    ] {
        assert!(
            READER_PROVISIONING.contains(required),
            "reader credential provisioning must preserve the startup-gate role settings: {required}"
        );
    }
}

#[test]
fn projection_role_provisioning_is_file_only_atomic_and_exact() {
    assert!(
        matches!(
            (
                PROJECTION_ROLE_PROVISIONING.find("set +x"),
                PROJECTION_ROLE_PROVISIONING.find("${RSS_PG_")
            ),
            (Some(disable_xtrace), Some(first_secret_expansion))
                if disable_xtrace < first_secret_expansion
        ),
        "set +x must precede every credential-bearing shell expansion"
    );
    for forbidden in [
        "--set projection_reader_password=",
        "--set projection_operator_password=",
        "set -x",
        "GRANT rss_projection_reader",
        "GRANT rss_projection_operator",
    ] {
        assert!(
            !PROJECTION_ROLE_PROVISIONING.contains(forbidden),
            "projection provisioning exposes a forbidden surface: {forbidden}"
        );
    }
    for required in [
        "\\getenv projection_reader_password RSS_PROVISION_PROJECTION_READER_PASSWORD",
        "\\getenv projection_operator_password RSS_PROVISION_PROJECTION_OPERATOR_PASSWORD",
        "BEGIN;",
        "COMMIT;",
        "ALTER ROLE rss_projection_reader LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_reader SET default_transaction_read_only = 'on'",
        "ALTER ROLE rss_projection_reader SET search_path = pg_catalog, public",
        "ALTER ROLE rss_projection_operator SET search_path = pg_catalog, public",
        "current_setting('lo_compat_privileges')",
        "rss_projection_reader:on:pg_catalog, public:off",
        "rss_projection_operator:off:pg_catalog, public:off",
    ] {
        assert!(
            PROJECTION_ROLE_PROVISIONING.contains(required),
            "projection credential provisioning omits exact gate state: {required}"
        );
    }
}

#[test]
fn saga_operator_role_provisioning_is_file_only_atomic_and_exact() {
    assert!(
        matches!(
            (
                SAGA_OPERATOR_ROLE_PROVISIONING.find("set +x"),
                SAGA_OPERATOR_ROLE_PROVISIONING.find("${RSS_PG_")
            ),
            (Some(disable_xtrace), Some(first_secret_expansion))
                if disable_xtrace < first_secret_expansion
        ),
        "set +x must precede every Saga credential-bearing shell expansion"
    );
    for forbidden in [
        "--set saga_operator_password=",
        "set -x",
        "GRANT rss_saga_operator",
    ] {
        assert!(
            !SAGA_OPERATOR_ROLE_PROVISIONING.contains(forbidden),
            "Saga operator provisioning exposes a forbidden surface: {forbidden}"
        );
    }
    for required in [
        "\\getenv saga_operator_password RSS_PROVISION_SAGA_OPERATOR_PASSWORD",
        "BEGIN;",
        "COMMIT;",
        "ALTER ROLE rss_saga_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_saga_operator SET search_path = pg_catalog, public",
        "current_setting('lo_compat_privileges')",
        "rss_saga_operator:off:pg_catalog, public:off",
    ] {
        assert!(
            SAGA_OPERATOR_ROLE_PROVISIONING.contains(required),
            "Saga operator credential provisioning omits exact gate state: {required}"
        );
    }

    for required in [
        "RSS_PG_SAGA_OPERATOR_USERNAME",
        "RSS_PG_SAGA_OPERATOR_PASSWORD_FILE",
        "CREATE ROLE rss_saga_operator LOGIN PASSWORD %L",
        "ALTER ROLE rss_saga_operator LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "GRANT CONNECT ON DATABASE %I TO rss_saga_operator",
    ] {
        assert!(
            POSTGRES_ROLE_INIT.contains(required),
            "fresh-install Saga operator provisioning omits `{required}`"
        );
    }
    assert!(
        READER_UPGRADE_SMOKE.contains("provision-saga-operator-role.sh"),
        "retained-volume smoke must execute Saga operator credential provisioning"
    );
}

#[test]
fn l2_dr_recovery_migration_isolates_start_proof_and_acl() {
    let normalized = L2_DR_RECOVERY_MIGRATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "CREATE ROLE rss_l2_dr_recovery_owner",
        "NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "CREATE TABLE public.event_l2_dr_recovery_start_proof",
        "ALTER TABLE public.event_l2_dr_recovery_start_proof ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.event_l2_dr_recovery_start_proof FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON public.event_l2_dr_recovery_start_proof",
        "ALTER TABLE public.event_l2_dr_recovery_start_proof OWNER TO rss_l2_dr_recovery_owner",
        "REVOKE ALL ON TABLE public.event_l2_dr_recovery_start_proof FROM PUBLIC, rss_app",
        "GRANT SELECT, INSERT ON TABLE public.event_l2_dr_recovery_start_proof TO rss_l2_dr_recovery_owner",
        "INSERT INTO public.event_l2_dr_recovery_start_proof",
        "FROM public.event_l2_dr_recovery_start_proof AS proof",
        "CREATE TABLE public.event_l2_dr_recovery_receipt",
        "ALTER TABLE public.event_l2_dr_recovery_receipt OWNER TO rss_l2_dr_recovery_owner",
        "REVOKE ALL ON TABLE public.event_l2_dr_recovery_receipt FROM PUBLIC, rss_app",
        "GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_record_start_audit(",
        "GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_apply(",
        "TO rss_l2_dr_recovery_auditor",
        "TO rss_l2_dr_recovery_executor",
        // Broker-ahead is an intentional no-op receipt; do not require outbox rows.
        "Broker-ahead / database-earlier intentionally does not require the planned event IDs to exist",
        "v_outcome := 'normal_consume_resume'",
    ] {
        assert!(
            normalized.contains(required) || L2_DR_RECOVERY_MIGRATION.contains(required),
            "0098 omits L2 DR recovery invariant `{required}`"
        );
    }
    for forbidden in [
        "FROM public.auth_audit_events AS audit\n        WHERE audit.principal_id = p_operator_subject\n          AND audit.principal_kind = 'service'\n          AND audit.tenant_context = p_tenant_id\n          AND audit.resource_kind = 'eventing.l2-dr-recovery'\n          AND audit.resource_id = p_epoch_id::text\n          AND audit.action = 'eventing.l2-dr-recovery.apply.start'",
        "GRANT SELECT, INSERT ON TABLE public.event_l2_dr_recovery_start_proof TO rss_app",
        "GRANT INSERT ON TABLE public.event_l2_dr_recovery_start_proof TO rss_app",
        "GRANT ALL ON TABLE public.event_l2_dr_recovery_start_proof TO rss_app",
        "CREATE ROLE rss_l2_dr_recovery_operator",
    ] {
        assert!(
            !L2_DR_RECOVERY_MIGRATION.contains(forbidden),
            "0098 retains forbidden L2 DR surface `{forbidden}`"
        );
    }
}

#[test]
fn l2_dr_recovery_role_provisioning_is_file_only_fail_closed_and_exact() {
    assert!(
        matches!(
            (
                L2_DR_RECOVERY_ROLE_PROVISIONING.find("set +x"),
                L2_DR_RECOVERY_ROLE_PROVISIONING.find("${RSS_PG_")
            ),
            (Some(disable_xtrace), Some(first_secret_expansion))
                if disable_xtrace < first_secret_expansion
        ),
        "set +x must precede every L2 DR credential-bearing shell expansion"
    );
    for forbidden in [
        "--set l2_dr_recovery_",
        "set -x",
        "GRANT rss_l2_dr_recovery_auditor",
        "GRANT rss_l2_dr_recovery_executor",
        "ALTER ROLE rss_l2_dr_recovery_owner LOGIN",
        "--set l2_dr_auditor_password=",
    ] {
        assert!(
            !L2_DR_RECOVERY_ROLE_PROVISIONING.contains(forbidden),
            "L2 DR provisioning exposes a forbidden surface: {forbidden}"
        );
    }
    for required in [
        "\\getenv l2_dr_recovery_auditor_password RSS_PROVISION_L2_DR_RECOVERY_AUDITOR_PASSWORD",
        "\\getenv l2_dr_recovery_executor_password RSS_PROVISION_L2_DR_RECOVERY_EXECUTOR_PASSWORD",
        "BEGIN;",
        "COMMIT;",
        "is absent; apply migration 0100 before provisioning credentials",
        "has role membership; refuse credential provisioning",
        "ALTER ROLE rss_l2_dr_recovery_auditor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_l2_dr_recovery_executor LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "expected=\"${verify_role_name}:${verify_role_name}:true:false:false:false:false:false:false:off:pg_catalog, public:off\"",
        "verify_role rss_l2_dr_recovery_auditor",
        "verify_role rss_l2_dr_recovery_executor",
    ] {
        assert!(
            L2_DR_RECOVERY_ROLE_PROVISIONING.contains(required),
            "L2 DR credential provisioning omits exact gate state: {required}"
        );
    }
    assert!(
        READER_UPGRADE_SMOKE.contains("provision-l2-dr-recovery-roles.sh"),
        "retained-volume smoke must execute L2 DR credential provisioning"
    );
    for required in [
        "rss_l2_dr_recovery_owner:false:true",
        "provision must fail when 0098 L2 DR roles are absent",
        "provision must fail when L2 DR role membership has drifted",
        "rss_l2_dr_recovery_auditor_absent",
        "GRANT rss_app TO rss_l2_dr_recovery_auditor",
    ] {
        assert!(
            READER_UPGRADE_SMOKE.contains(required),
            "retained-volume smoke omits L2 DR fail-closed/owner gate `{required}`"
        );
    }
}
#[test]
fn localonly_reader_migration_is_exact_and_has_no_future_grant_fallback() {
    for required in [
        "CREATE ROLE rss_app_read",
        "LOGIN",
        "NOSUPERUSER",
        "NOBYPASSRLS",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOREPLICATION",
        "NOINHERIT",
        "default_transaction_read_only = 'on'",
        "search_path = pg_catalog, public",
        "refuse implicit normalization",
        "REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC",
        "GRANT TEMPORARY ON DATABASE %I TO rss_app",
        "GRANT CONNECT ON DATABASE %I TO rss_app_read",
        "FOR application_schema IN",
        "n.nspname <> 'information_schema'",
        "n.nspname !~ '^pg_'",
        "REVOKE ALL PRIVILEGES ON SCHEMA %I FROM rss_app_read",
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I FROM rss_app_read",
        "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I FROM rss_app_read",
        "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA %I FROM rss_app_read",
        "a.attacl IS NOT NULL",
        "REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM rss_app_read",
        "pg_largeobject_metadata",
        "REVOKE ALL PRIVILEGES ON LARGE OBJECT %s FROM %s",
        "pg_parameter_acl",
        "REVOKE ALL PRIVILEGES ON PARAMETER %I FROM %s",
        "acl.grantee IN (0::oid, reader.oid)",
        "pg_catalog.lo_from_bytea(oid, bytea)",
        "pg_catalog.lo_put(oid, bigint, bytea)",
        "pg_catalog.lo_unlink(oid)",
        "FROM PUBLIC, rss_app_read",
        "TO rss_app",
        "CREATE POLICY saga_worker_tenant_index_tenant_isolation",
        "AS RESTRICTIVE",
        "USING (false)",
        "GRANT SELECT ON TABLE %I.%I TO rss_app_read",
        "a.attname = 'tenant_id'",
        "c.relkind IN ('r', 'p')",
    ] {
        assert!(
            LOCALONLY_READ_ROLE.contains(required),
            "0067 omits the exact tenant-reader contract: {required}"
        );
    }
    for forbidden in [
        "ALTER DEFAULT PRIVILEGES",
        "GRANT INSERT",
        "GRANT UPDATE",
        "GRANT DELETE",
        "GRANT TRUNCATE",
        "GRANT USAGE ON ALL SEQUENCES",
        "GRANT TEMPORARY ON DATABASE %I TO rss_app_read",
        "PASSWORD",
    ] {
        assert!(
            !LOCALONLY_READ_ROLE.contains(forbidden),
            "0067 exposes a forbidden reader capability or fallback: {forbidden}"
        );
    }
}

#[test]
fn reader_upgrade_smoke_uses_real_sqlx_ledger_and_forward_only_cli_with_bounded_startup() {
    for required in [
        "rev-list --topo-order HEAD",
        "0084_persist_reconcile_wake_and_device_policy_operations.sql",
        "0085_projection_privilege_boundaries.sql",
        "git clone --quiet --shared --no-checkout",
        "checkout --quiet --detach",
        "predecessor_registry=",
        "84:true:48:84",
        "RSS_PG_DATABASE_URL_FILE=",
        "RSS_PG_MIGRATOR_PASSWORD_FILE=",
        "postgres migrate-all",
        "SELECT max(version)",
        "docker inspect",
        "deadline=",
    ] {
        assert!(
            READER_UPGRADE_SMOKE.contains(required),
            "retained-volume smoke omits release-path evidence: {required}"
        );
    }
    for forbidden in [
        "sed -n",
        "0067_localonly_read_role.sql",
        "for migration in",
        "until owner_psql",
        "bootstrap_reader_upgrade_smoke_predecessor",
    ] {
        assert!(
            !READER_UPGRADE_SMOKE.contains(forbidden),
            "retained-volume smoke must not replay migration SQL or wait forever: {forbidden}"
        );
    }
}

#[test]
fn secret_refs_repair_must_finish_before_sqlx_reaches_0058() {
    for token in [
        "reviewed out-of-band preflight/repair",
        "before deploying the binary that contains 0058",
    ] {
        assert!(
            SECRET_REFS_HARDENING.contains(token),
            "0058 recovery hint omits the deployment-order contract: {token}"
        );
    }
    for misleading in ["explicit forward data migration", "forward data migration"] {
        assert!(
            !SECRET_REFS_HARDENING.contains(misleading),
            "failed 0058 must not claim that a later forward migration can repair it: {misleading}"
        );
    }
}

#[test]
fn dlx_lifecycle_migration_is_fixed_shape_and_archive_before_purge() {
    let dlx_only = DLX_LIFECYCLE
        .split_once("-- Keep published outbox retention")
        .map_or(DLX_LIFECYCLE, |(dlx, _)| dlx);
    for required in [
        "dead_letter must be empty before enabling DLX lifecycle v3",
        "ALTER COLUMN tenant_id SET NOT NULL",
        "dead_letter_archive_receipts",
        "object_version_id text NOT NULL",
        "reconcile_after timestamptz NOT NULL",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "CREATE ROLE rss_dlx_archiver NOLOGIN NOBYPASSRLS NOSUPERUSER",
        "rss_dlx_claim_archive_candidates()",
        "rss_dlx_archive_backlog()",
        "LIMIT 100",
        "rss_dlx_record_archive_receipt",
        "rss_dlx_purge_verified()",
        "LIMIT 1000",
        "rss_dlx_reconcile_expired_receipts()",
        "rss_dlx_delete_missing_archive_receipt",
        "object_lock_mode = 'COMPLIANCE'",
        "object_lock_retain_until > now()",
        "p_object_lock_retain_until <= verified_at + interval '30 days'",
        "object_lock_retain_until > verified_at + interval '30 days'",
        "last_attempt_at <= now() - interval '30 days'",
        "SET search_path = pg_catalog, pg_temp",
        "DLX workload roles must have no role memberships",
        "rss_dlx_lifecycle_owner must have no role memberships",
        "SET reconcile_after = now() + interval '1 day'",
        "DROP FUNCTION IF EXISTS public.rss_sweep_dead_letter(bigint)",
        "replay_capsule_encoding = 'key-provider-v3'",
    ] {
        assert!(
            DLX_LIFECYCLE.contains(required),
            "0063 omits the fixed DLX lifecycle contract: {required}"
        );
    }

    for forbidden in [
        "GRANT EXECUTE ON FUNCTION rss_dlx_claim_archive_candidates() TO rss_app",
        "TO rss_app; -- rss_dlx_record_archive_receipt",
        "GRANT EXECUTE ON FUNCTION rss_dlx_purge_verified() TO rss_app",
        "GRANT DELETE ON dead_letter",
        "p_retain_seconds",
        "p_limit",
        "SET search_path = public, pg_temp",
        "FROM dead_letter AS",
        "FROM dead_letter_archive_receipts AS",
        "DELETE FROM dead_letter AS",
        "DELETE FROM dead_letter_archive_receipts AS",
    ] {
        assert!(
            !dlx_only.contains(forbidden),
            "0063 exposes a forbidden compatibility or variable policy surface: {forbidden}"
        );
    }
}

#[test]
fn dlx_lifecycle_roles_and_claims_are_separated_and_durable() {
    let migration = include_str!("../migrations/0063_dead_letter_lifecycle.sql");
    for required in [
        "CREATE ROLE rss_dlx_verifier NOLOGIN NOBYPASSRLS NOSUPERUSER",
        "CREATE ROLE rss_dlx_purger NOLOGIN NOBYPASSRLS NOSUPERUSER",
        "archive_claim_token uuid",
        "archive_lease_until timestamptz",
        "archive_next_attempt_at timestamptz NOT NULL",
        "archive_failure_count int NOT NULL",
        "archive_quarantined_at timestamptz",
        "UPDATE public.dead_letter AS d",
        "archive_claim_token = gen_random_uuid()",
        "FOR UPDATE OF d SKIP LOCKED",
        "rss_dlx_settle_archive_retry",
        "rss_dlx_quarantine_archive_candidate",
        "TO rss_dlx_verifier",
        "TO rss_dlx_purger",
    ] {
        assert!(
            migration.contains(required),
            "0063 must carry durable separated DLX lifecycle token `{required}`"
        );
    }
    for forbidden in [
        "rss_dlx_record_archive_receipt(uuid, uuid, text, text, bytea, text, text, timestamptz, timestamptz)\n    TO rss_dlx_archiver",
        "GRANT EXECUTE ON FUNCTION public.rss_dlx_purge_verified() TO rss_dlx_archiver",
    ] {
        assert!(
            !migration.contains(forbidden),
            "archiver must not mint or consume purge proof: {forbidden}"
        );
    }
}

#[test]
fn legacy_cutover_has_no_digest_authorized_delete_escape() {
    let cutover = include_str!("../migrations/0062_prepare_dead_letter_cutover.sql");
    assert!(
        !cutover.contains("DELETE FROM public.dead_letter"),
        "an inventory digest is not a recoverable export proof"
    );
    assert!(
        !cutover.contains("CREATE FUNCTION public.rss_cutover_legacy_dead_letter"),
        "0062 must not install an owner-only destructive escape hatch"
    );
}

#[test]
fn dlx_cutover_is_fail_closed_and_never_disposes_legacy_rows() {
    for required in [
        "LOCK TABLE public.dead_letter IN ACCESS EXCLUSIVE MODE",
        "legacy dead_letter must be empty before DLX v3",
        "automatic disposal is forbidden",
        "separately reviewed export/restore migration is required",
        "complete encrypted row bytes",
        "restore drill",
    ] {
        assert!(
            DLX_CUTOVER.contains(required),
            "0062 omits audited cutover contract: {required}"
        );
    }
    for forbidden in [
        "CREATE FUNCTION",
        "DELETE FROM public.dead_letter",
        "dead_letter_legacy_cutover_audit",
        "rss_cutover_legacy_dead_letter",
        "source_inventory_sha256",
        "RSS_DEAD_LETTER_RETAIN_SECONDS",
        "p_retain_seconds",
    ] {
        assert!(
            !DLX_CUTOVER.contains(forbidden),
            "0062 exposes a reusable or policy-bearing cutover surface: {forbidden}"
        );
    }
    assert!(
        !DLX_LIFECYCLE.contains("rss_cutover_legacy_dead_letter"),
        "0063 must not retain or remove a reusable destructive cutover function"
    );
}

#[test]
fn projection_correctness_residuals_hard_cut_audit_and_worker_observe() {
    let normalized = PROJECTION_CORRECTNESS_RESIDUALS_MIGRATION
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    for required in [
        "DROP FUNCTION public.rss_projection_operator_record_audit( bigint, integer, text, text, text, text, text )",
        "CREATE FUNCTION public.rss_projection_operator_record_audit(",
        "p_request_id text",
        "p_correlation_id text",
        "public.rss_is_canonical_non_nil_uuid(p_request_id)",
        "public.rss_is_canonical_non_nil_uuid(p_correlation_id)",
        "GRANT EXECUTE ON FUNCTION public.rss_is_canonical_non_nil_uuid(text) TO rss_projection_operator_owner",
        "ERRCODE = '22023'",
        "p_request_id, p_correlation_id",
        "OWNER TO rss_projection_operator_owner",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_record_audit( bigint, integer, text, text, text, text, text, text, text ) TO rss_projection_operator",
        "CREATE FUNCTION public.rss_projection_worker_observe_tenant(",
        "source_high_water bigint",
        "checkpoint_offset_lsn bigint",
        "checkpoint_updated_at_epoch_micros bigint",
        "projection_dlq_backlog bigint",
        "public.rss_settings_projection_worker_tenant_scope_is_active(",
        "public.rss_projection_worker_source_high_water(",
        "public.rss_projection_dead_letter_source_kind()",
        "p_projection_id || '@' || p_target_generation || ':shadow'",
        "OWNER TO rss_projection_worker_owner",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_worker_observe_tenant(",
        "TO rss_projection_worker",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
    ] {
        assert!(
            normalized.contains(required),
            "0101 omits projection correctness residual invariant `{required}`"
        );
    }

    for forbidden in [
        "CREATE OR REPLACE FUNCTION public.rss_projection_operator_record_audit( p_occurred_at_secs bigint, p_occurred_at_nanos integer, p_operator_subject text, p_resource_id text, p_action text, p_outcome text, p_failure_reason text )",
        "NULL, NULL",
        "GRANT EXECUTE ON FUNCTION public.rss_projection_operator_record_audit( bigint, integer, text, text, text, text, text ) TO",
        "GRANT SELECT ON TABLE public.checkpoint TO rss_projection_worker",
        "GRANT SELECT ON TABLE public.dead_letter TO rss_projection_worker",
        "GRANT SELECT ON TABLE public.projection_events TO rss_projection_worker",
        "ALTER FUNCTION public.rss_projection_operator_record_audit( bigint, integer, text, text, text, text, text )",
    ] {
        assert!(
            !normalized.contains(forbidden),
            "0101 retains forbidden dual-path or privilege expansion `{forbidden}`"
        );
    }

    assert!(
        !PROJECTION_PRIVILEGE_BOUNDARY.contains("p_request_id text"),
        "0085 must remain unchanged; audit correlation hard-cut belongs in 0101"
    );
    assert!(
        !PROJECTION_PRIVILEGE_BOUNDARY.contains("rss_projection_worker_observe_tenant"),
        "0085 must remain unchanged; worker observation belongs in 0101"
    );
}
