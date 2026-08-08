const MIGRATION: &str = include_str!("../migrations/0097_install_projection_worker_lifecycle.sql");

const WORKER_FUNCTIONS: &[&str] = &[
    "rss_projection_worker_list_tenants",
    "rss_projection_worker_quarantine_tenant",
    "rss_projection_worker_has_quarantined_tenants",
    "rss_projection_worker_read_events",
    "rss_projection_worker_source_high_water",
    "rss_projection_worker_get_checkpoint",
    "rss_projection_worker_save_checkpoint",
    "rss_projection_worker_insert_dead_letter",
    "rss_settings_projection_apply_worker",
];

const OPERATOR_OR_READER_FUNCTIONS: &[&str] = &[
    "rss_projection_operator_record_audit",
    "rss_projection_operator_get_checkpoint",
    "rss_projection_operator_save_checkpoint",
    "rss_projection_operator_read_active_pointer",
    "rss_projection_operator_cas_active_pointer",
    "rss_projection_operator_sweep_source_capabilities",
    "rss_projection_operator_issue_source_capability",
    "rss_projection_operator_insert_dead_letter",
    "rss_projection_operator_recover_tenant",
    "rss_read_projection_events_scoped",
    "rss_projection_source_high_water_scoped",
];

#[test]
fn tenant_fatal_quarantine_is_durable_closed_and_operator_recoverable() -> Result<(), String> {
    let sql = normalized();
    for required in [
        "CREATE TABLE public.projection_worker_tenant_quarantine",
        "state text NOT NULL CHECK (state IN ('quarantined', 'released'))",
        "reason text NOT NULL CHECK (reason IN ( 'target_definition_drift', 'input_binding_drift', 'tenant_drift', 'payload_malformed', 'payload_value_invalid', 'version_regression', 'provider_invariant', 'provider_permanent', 'conflict', 'apply_out_of_order', 'rollback_failed', 'source_out_of_order' ))",
        "failed_lsn bigint NOT NULL CHECK (failed_lsn >= 0)",
        "CREATE FUNCTION public.rss_projection_worker_quarantine_tenant(",
        "CREATE FUNCTION public.rss_projection_operator_recover_tenant(",
    ] {
        assert!(
            sql.contains(required),
            "0097 omits quarantine guard `{required}`"
        );
    }

    let candidates = function_section(&sql, "rss_projection_worker_list_tenants")?;
    assert!(
        candidates.contains("projection_worker_tenant_quarantine")
            && candidates.contains("quarantine.state = 'quarantined'")
            && candidates
                .contains("quarantine.tenant_scope_id = (event.metadata ->> 'tenantId')::uuid"),
        "worker discovery must exclude only durably quarantined tenants"
    );

    let quarantine = function_section(&sql, "rss_projection_worker_quarantine_tenant")?;
    assert!(
        quarantine
            .contains("ON CONFLICT (tenant_scope_id, projection_id, target_generation) DO UPDATE")
            && quarantine.contains("state = 'quarantined'")
            && quarantine.contains("failed_lsn = EXCLUDED.failed_lsn"),
        "tenant fatal quarantine must be idempotent and durable across worker restarts"
    );
    let recover = function_section(&sql, "rss_projection_operator_recover_tenant")?;
    assert!(
        recover.contains("state = 'released'")
            && recover.contains("failed_lsn = p_expected_failed_lsn")
            && recover.contains("state = 'quarantined'"),
        "operator recovery must be an expected-LSN guarded state transition"
    );
    assert_executable_only_by(
        &sql,
        "rss_projection_worker_quarantine_tenant",
        "rss_projection_worker",
    );
    assert_executable_only_by(
        &sql,
        "rss_projection_operator_recover_tenant",
        "rss_projection_operator",
    );
    Ok(())
}

const DENIED_LOGIN_ROLES: &[&str] = &[
    "PUBLIC",
    "rss_app",
    "rss_app_read",
    "rss_projection_reader",
    "rss_projection_operator",
    "rss_projection_worker",
];

const DEFINITION_DIGEST: &str =
    "sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103";
const INPUT_GENERATION: &str =
    "sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8";

fn normalized() -> String {
    MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn function_section<'a>(sql: &'a str, name: &str) -> Result<&'a str, String> {
    let marker = format!("CREATE FUNCTION public.{name}(");
    let (_, tail) = sql
        .split_once(&marker)
        .ok_or_else(|| format!("0097 must create `{name}`"))?;
    Ok(tail
        .split_once("$function$;")
        .map_or(tail, |(section, _)| section))
}

fn statements_containing<'a>(sql: &'a str, marker: &str) -> Vec<&'a str> {
    sql.split(';')
        .map(str::trim)
        .filter(|statement| statement.contains(marker))
        .collect()
}

fn assert_executable_only_by(sql: &str, function: &str, role: &str) {
    let marker = format!("ON FUNCTION public.{function}(");
    let grants = statements_containing(sql, &format!("GRANT EXECUTE {marker}"));
    assert_eq!(
        grants.len(),
        1,
        "0097 must have one EXECUTE grant for `{function}`"
    );
    assert!(
        grants[0].ends_with(&format!(") TO {role}")),
        "`{function}` must be executable only by `{role}`: {}",
        grants[0]
    );

    let revokes = statements_containing(sql, &format!("REVOKE ALL {marker}"));
    assert_eq!(
        revokes.len(),
        1,
        "0097 must have one fail-closed revoke for `{function}`"
    );
    let denied = revokes[0]
        .split_once(" FROM ")
        .map(|(_, roles)| roles.split(',').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(
        denied, DENIED_LOGIN_ROLES,
        "`{function}` revoke set must be the exact login-role closure"
    );
}

#[test]
fn hard_cut_replaces_ambiguous_apply_with_fixed_purpose_entrypoints() -> Result<(), String> {
    let sql = normalized();
    let legacy_signature = "public.rss_settings_projection_apply( uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea )";
    assert!(
        sql.contains(&format!("DROP FUNCTION {legacy_signature}")),
        "0097 must hard-drop the ambiguous apply function"
    );
    assert!(
        !sql.contains("CREATE FUNCTION public.rss_settings_projection_apply("),
        "0097 must not recreate the ambiguous apply function"
    );
    assert!(
        !sql.contains(&format!("GRANT EXECUTE ON FUNCTION {legacy_signature}")),
        "the dropped apply function must not retain an ACL carrier"
    );

    for (function, actor, purpose, role) in [
        (
            "rss_settings_projection_apply_worker",
            "rss-projection-worker",
            "background-shadow",
            "rss_projection_worker",
        ),
        (
            "rss_settings_projection_apply_operator",
            "rss-projection-replay",
            "operator-replay",
            "rss_projection_operator",
        ),
    ] {
        let section = function_section(&sql, function)?;
        let signature = section
            .split_once(") RETURNS text")
            .map_or(section, |(signature, _)| signature);
        assert_eq!(
            signature.matches("p_").count(),
            13,
            "`{function}` must retain the metadata-only 13-argument apply signature"
        );
        assert!(
            !signature.contains("actor") && !signature.contains("purpose"),
            "`{function}` must not accept caller-selected actor or purpose"
        );
        assert!(
            section.contains(&format!("'{actor}'")) && section.contains(&format!("'{purpose}'")),
            "`{function}` must stamp its fixed actor/purpose pair"
        );
        assert!(
            section.contains("INSERT INTO public.settings_projection_dedupe_receipts")
                && section.contains("actor")
                && section.contains("purpose"),
            "`{function}` must persist its attribution in the durable receipt"
        );
        assert!(
            section.contains("SELECT fact_digest, actor, purpose"),
            "`{function}` must authenticate duplicate receipts against attribution"
        );
        assert_executable_only_by(&sql, function, role);
    }
    Ok(())
}

#[test]
fn receipt_attribution_is_backfilled_before_a_closed_pair_constraint() -> Result<(), String> {
    let sql = normalized();
    let add_actor = sql
        .find("ADD COLUMN actor text")
        .ok_or_else(|| "0097 must add receipt actor".to_owned())?;
    let add_purpose = sql
        .find("ADD COLUMN purpose text")
        .ok_or_else(|| "0097 must add receipt purpose".to_owned())?;
    let backfill = sql
        .find("UPDATE public.settings_projection_dedupe_receipts SET actor = 'rss-projection-replay', purpose = 'operator-replay'")
        .ok_or_else(|| "0097 must attribute all historical receipts to operator replay".to_owned())?;
    let actor_not_null = sql
        .find("ALTER COLUMN actor SET NOT NULL")
        .ok_or_else(|| "0097 must close nullable actor state".to_owned())?;
    let purpose_not_null = sql
        .find("ALTER COLUMN purpose SET NOT NULL")
        .ok_or_else(|| "0097 must close nullable purpose state".to_owned())?;
    let pair_constraint = sql
        .find("CHECK ( (actor = 'rss-projection-worker' AND purpose = 'background-shadow') OR (actor = 'rss-projection-replay' AND purpose = 'operator-replay') )")
        .ok_or_else(|| "0097 must constrain receipts to the two reviewed attribution pairs".to_owned())?;

    assert!(
        add_actor < backfill
            && add_purpose < backfill
            && backfill < actor_not_null
            && backfill < purpose_not_null
            && actor_not_null < pair_constraint
            && purpose_not_null < pair_constraint,
        "0097 must add, backfill, close, then constrain receipt attribution"
    );
    for forbidden in [
        "actor text DEFAULT",
        "purpose text DEFAULT",
        "ALTER COLUMN actor SET DEFAULT",
        "ALTER COLUMN purpose SET DEFAULT",
    ] {
        assert!(
            !sql.contains(forbidden),
            "receipt attribution must not use ambient defaults: `{forbidden}`"
        );
    }
    Ok(())
}

#[test]
fn worker_role_has_an_exact_function_only_capability_closure() {
    let sql = normalized();
    for required in [
        "CREATE ROLE rss_projection_worker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "CREATE ROLE rss_projection_worker_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_worker NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_worker_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_worker SET search_path = pg_catalog, public",
        "GRANT USAGE ON SCHEMA public TO rss_projection_worker",
    ] {
        assert!(
            sql.contains(required),
            "0097 omits worker role guard `{required}`"
        );
    }

    for function in WORKER_FUNCTIONS {
        assert_executable_only_by(&sql, function, "rss_projection_worker");
        let owner_statements =
            statements_containing(&sql, &format!("ALTER FUNCTION public.{function}("));
        assert_eq!(
            owner_statements.len(),
            1,
            "`{function}` must have one explicit owner assignment"
        );
        assert!(
            owner_statements[0].ends_with(") OWNER TO rss_projection_worker_owner"),
            "`{function}` must be owned by the non-login worker owner"
        );
    }
    assert_executable_only_by(
        &sql,
        "rss_settings_projection_apply_operator",
        "rss_projection_operator",
    );

    for role in ["rss_projection_worker", "rss_projection_operator"] {
        for statement in sql.split(';').map(str::trim).filter(|statement| {
            statement.starts_with("GRANT ")
                && statement.rsplit_once(" TO ").is_some_and(|(_, roles)| {
                    roles.split(',').map(str::trim).any(|target| target == role)
                })
        }) {
            assert!(
                statement.contains(" ON FUNCTION ") || statement.contains(" ON SCHEMA "),
                "login role `{role}` must have no raw relation or membership grant: {statement}"
            );
        }
    }

    for table in [
        "projection_events",
        "projection_input_bindings",
        "projection_source_capabilities",
        "checkpoint",
        "dead_letter",
        "settings_projection_generations",
        "settings_config_projection_rows",
        "settings_projection_dedupe_receipts",
        "projection_worker_tenant_quarantine",
    ] {
        assert!(
            sql.split(';').any(|statement| {
                statement.contains("REVOKE ALL ON TABLE")
                    && statement.contains(&format!("public.{table}"))
                    && statement.contains("rss_projection_worker")
                    && statement.contains("rss_projection_operator")
            }),
            "0097 must explicitly revoke worker/operator table access to `{table}`"
        );
    }

    for function in OPERATOR_OR_READER_FUNCTIONS {
        assert!(
            sql.split(';').any(|statement| {
                statement.contains("REVOKE ALL ON FUNCTION")
                    && statement.contains(&format!("public.{function}("))
                    && statement
                        .split_once(" FROM ")
                        .is_some_and(|(_, roles)| roles.contains("rss_projection_worker"))
            }),
            "0097 must explicitly exclude the worker from `{function}`"
        );
    }
}

#[test]
fn destructive_cutover_has_a_worker_role_drift_preflight() -> Result<(), String> {
    let sql = normalized();
    let preflight = sql
        .find("projection worker preflight")
        .ok_or_else(|| "0097 must label the worker role preflight".to_owned())?;
    let receipt_alter = sql
        .find("ALTER TABLE public.settings_projection_dedupe_receipts")
        .ok_or_else(|| "0097 must alter historical receipts".to_owned())?;
    let legacy_drop = sql
        .find("DROP FUNCTION public.rss_settings_projection_apply")
        .ok_or_else(|| "0097 must hard-drop the legacy apply function".to_owned())?;
    assert!(
        preflight < receipt_alter && preflight < legacy_drop,
        "role drift must fail before any destructive hard-cut action"
    );
    for required in [
        "pg_catalog.pg_auth_members",
        "membership.member = checked_role OR membership.roleid = checked_role",
        "pg_catalog.pg_shdepend",
        "dependency.deptype = 'o'",
        "dependency.deptype = 'a'",
        "projection worker roles must have no memberships",
        "projection worker roles must own no database objects",
        "projection worker roles must have no pre-existing privileges",
    ] {
        assert!(
            sql.contains(required),
            "0097 worker preflight omits `{required}`"
        );
    }
    Ok(())
}

#[test]
fn worker_apply_and_source_read_are_exactly_plan_bound() -> Result<(), String> {
    let normalized = normalized();
    let apply = function_section(&normalized, "rss_settings_projection_apply_worker")?.to_owned();
    assert!(
        apply.contains("p_generation <> 'v3'"),
        "worker apply must reject a target generation outside the sealed v3 plan"
    );

    let read = function_section(&normalized, "rss_projection_worker_read_events")?.to_owned();
    assert!(
        read.contains("candidate_binding.contract_version = event.contract_version")
            && read.contains("candidate_binding.schema_hash = event.schema_hash"),
        "worker source read must require the exact generated version and schema"
    );
    assert!(
        !read.contains("CASE WHEN EXISTS"),
        "worker source read must not return metadata for a non-exact event while blanking only payload"
    );
    Ok(())
}

#[test]
fn worker_source_checkpoint_and_dlq_seams_validate_scope_directly() -> Result<(), String> {
    let sql = normalized();
    for function in WORKER_FUNCTIONS {
        let section = function_section(&sql, function)?;
        for required in [
            "LANGUAGE plpgsql",
            "SECURITY DEFINER",
            "SET search_path = pg_catalog, pg_temp",
            "session_user <> 'rss_projection_worker'",
            "'settings.config-projection'",
            "'v3'",
            DEFINITION_DIGEST,
            INPUT_GENERATION,
        ] {
            assert!(
                section.contains(required),
                "worker seam `{function}` omits fail-closed guard `{required}`"
            );
        }
    }

    for function in [
        "rss_projection_worker_read_events",
        "rss_projection_worker_source_high_water",
        "rss_projection_worker_get_checkpoint",
        "rss_projection_worker_save_checkpoint",
        "rss_projection_worker_insert_dead_letter",
        "rss_settings_projection_apply_worker",
    ] {
        let section = function_section(&sql, function)?;
        assert!(
            section.contains("pg_catalog.current_setting('rss.tenant_id', true)")
                && section.contains("p_tenant_id"),
            "tenant-scoped worker seam `{function}` must reject missing/mismatched tenant context"
        );
    }

    let candidates = function_section(&sql, "rss_projection_worker_list_tenants")?;
    let events = function_section(&sql, "rss_projection_worker_read_events")?;
    let high_water = function_section(&sql, "rss_projection_worker_source_high_water")?;
    for (name, section) in [
        ("list_tenants", candidates),
        ("read_events", events),
        ("source_high_water", high_water),
    ] {
        assert!(
            section.contains("public.projection_events")
                && section.contains("public.projection_input_bindings"),
            "worker source seam `{name}` must derive candidates from the reviewed binding closure"
        );
    }

    let checkpoint = function_section(&sql, "rss_projection_worker_get_checkpoint")?;
    let save_checkpoint = function_section(&sql, "rss_projection_worker_save_checkpoint")?;
    for section in [checkpoint, save_checkpoint] {
        assert!(
            section.contains("'projection:' || p_tenant_id::text") && section.contains("':shadow'"),
            "worker checkpoint seam must stay in the tenant shadow namespace"
        );
    }
    assert!(
        function_section(&sql, "rss_projection_worker_insert_dead_letter")?
            .contains("public.rss_projection_dead_letter_source_kind()"),
        "worker DLQ seam must use the projection-only source kind"
    );

    for forbidden in [
        "rss_projection_operator_issue_source_capability",
        "rss_assert_projection_source_scope",
        "rss_read_projection_events_scoped",
        "rss_projection_source_high_water_scoped",
    ] {
        for function in WORKER_FUNCTIONS {
            assert!(
                !function_section(&sql, function)?.contains(forbidden),
                "worker seam `{function}` must not reuse operator/source-reader capability `{forbidden}`"
            );
        }
        assert!(
            !sql.split(';').any(|statement| {
                statement.contains(&format!("GRANT EXECUTE ON FUNCTION public.{forbidden}("))
                    && statement
                        .split_once(" TO ")
                        .is_some_and(|(_, roles)| roles.contains("rss_projection_worker"))
            }),
            "worker role must not receive operator/source-reader capability `{forbidden}`"
        );
    }
    Ok(())
}
