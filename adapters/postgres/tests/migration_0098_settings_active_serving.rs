const MIGRATION: &str = include_str!("../migrations/0098_activate_settings_projection_serving.sql");
const ACTIVATED_DEFINITION_DIGEST: &str =
    "sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8";
const ACTIVATED_INPUT_GENERATION: &str =
    "sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801";

#[path = "support/migration_contract.rs"]
mod migration_contract;

use migration_contract::{RoutineIdentity, routine_definition_slice};

const DENIED_LOGIN_ROLES: &[&str] = &[
    "PUBLIC",
    "rss_app",
    "rss_app_read",
    "rss_projection_reader",
    "rss_projection_operator",
    "rss_projection_worker",
];

fn normalized(source: &str) -> String {
    migration_contract::normalize_sql(source)
}

fn function_section<'a>(sql: &'a str, name: &str) -> Result<&'a str, String> {
    let identity = match name {
        "rss_settings_projection_resolve_active" => RoutineIdentity::public(name, &[]),
        "rss_projection_operator_status_active" => RoutineIdentity::public(name, &["uuid"]),
        "rss_projection_operator_swap_active" => RoutineIdentity::public(
            name,
            &["uuid", "text", "text", "bigint", "text", "text", "text"],
        ),
        "rss_settings_projection_apply_worker" | "rss_settings_projection_apply_operator" => {
            RoutineIdentity::public(
                name,
                &[
                    "uuid", "text", "text", "text", "text", "text", "text", "bigint", "text",
                    "text", "bigint", "bigint", "bytea",
                ],
            )
        }
        "rss_settings_projection_worker_tenant_scope_is_active" => {
            RoutineIdentity::public(name, &["uuid", "text", "text", "text", "text", "text"])
        }
        "rss_projection_worker_list_tenants" => {
            RoutineIdentity::public(name, &["text", "text", "text", "text", "uuid", "integer"])
        }
        _ => return Err(format!("0098 has no typed routine identity for `{name}`")),
    };
    routine_definition_slice(sql, identity)
}

fn statements_containing<'a>(sql: &'a str, marker: &str) -> Vec<&'a str> {
    sql.split(';')
        .map(str::trim)
        .filter(|statement| statement.contains(marker))
        .collect()
}

fn assert_function_only_grants(sql: &str, function: &str, expected_roles: &[&str]) {
    let grants = statements_containing(
        sql,
        &format!("GRANT EXECUTE ON FUNCTION public.{function}("),
    );
    assert_eq!(
        grants.len(),
        1,
        "`{function}` must have exactly one explicit EXECUTE grant"
    );
    let granted = grants[0]
        .split_once(" TO ")
        .map(|(_, roles)| roles.split(',').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(granted, expected_roles, "`{function}` has capability drift");

    let revokes = statements_containing(sql, &format!("REVOKE ALL ON FUNCTION public.{function}("));
    assert_eq!(
        revokes.len(),
        1,
        "`{function}` must have exactly one fail-closed revoke"
    );
    let denied = revokes[0]
        .split_once(" FROM ")
        .map(|(_, roles)| roles.split(',').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(
        denied, DENIED_LOGIN_ROLES,
        "`{function}` revoke set must close every login role before the exact grant"
    );
}

#[test]
fn active_pointer_is_typed_fixed_tenant_safe_and_generation_bound() {
    let sql = normalized(MIGRATION);
    for required in [
        "CREATE TABLE public.settings_projection_active_pointer",
        "tenant_id uuid NOT NULL",
        "projection_id text NOT NULL",
        "generation text NOT NULL",
        "promoted_high_water_lsn bigint NOT NULL",
        "token bigint NOT NULL",
        "PRIMARY KEY (tenant_id, projection_id)",
        "CHECK (projection_id = 'settings.config-projection')",
        "CHECK (promoted_high_water_lsn >= 0)",
        "CHECK (token >= 1)",
        "FOREIGN KEY (tenant_id, projection_id, generation)",
        "REFERENCES public.settings_projection_generations (tenant_id, projection_id, generation)",
        "ALTER TABLE public.settings_projection_active_pointer ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE public.settings_projection_active_pointer FORCE ROW LEVEL SECURITY",
        "CREATE POLICY tenant_isolation ON public.settings_projection_active_pointer",
    ] {
        assert!(
            sql.contains(required),
            "0098 omits pointer invariant `{required}`"
        );
    }

    assert!(
        sql.contains(
            "tenant_id = NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid"
        ) || sql.contains("tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid"),
        "active pointer RLS must derive tenant scope from the authenticated transaction"
    );
    assert!(
        sql.contains("ON DELETE RESTRICT") || sql.contains("ON DELETE NO ACTION"),
        "an active generation must not be deletable through its pointer FK"
    );
}

#[test]
fn serving_owner_and_login_roles_have_an_exact_function_only_closure() {
    let sql = normalized(MIGRATION);
    for required in [
        "CREATE ROLE rss_projection_serving_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER ROLE rss_projection_serving_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT",
        "ALTER TABLE public.settings_projection_active_pointer OWNER TO rss_projection_serving_owner",
        "REVOKE ALL ON TABLE public.settings_projection_active_pointer FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker",
    ] {
        assert!(
            sql.contains(required),
            "0098 omits serving ACL guard `{required}`"
        );
    }
    assert!(
        !sql.contains(
            "GRANT SELECT ON TABLE public.settings_projection_active_pointer TO rss_app_read"
        ),
        "rss_app_read must resolve through the fixed function and own zero raw pointer privileges"
    );

    assert_function_only_grants(
        &sql,
        "rss_settings_projection_resolve_active",
        &["rss_app_read", "rss_projection_worker"],
    );
    assert_function_only_grants(
        &sql,
        "rss_projection_worker_tenant_is_quarantined",
        &["rss_projection_worker"],
    );
    assert_function_only_grants(
        &sql,
        "rss_projection_operator_status_active",
        &["rss_projection_operator"],
    );
    assert_function_only_grants(
        &sql,
        "rss_projection_operator_swap_active",
        &["rss_projection_operator"],
    );

    for role in [
        "rss_app_read",
        "rss_projection_worker",
        "rss_projection_operator",
    ] {
        for statement in sql.split(';').map(str::trim).filter(|statement| {
            statement.starts_with("GRANT ")
                && statement.rsplit_once(" TO ").is_some_and(|(_, roles)| {
                    roles.split(',').map(str::trim).any(|target| target == role)
                })
        }) {
            assert!(
                statement.contains(" ON FUNCTION ") || statement.contains(" ON SCHEMA "),
                "login role `{role}` must remain function-only: {statement}"
            );
        }
    }
}

#[test]
fn resolver_status_and_swap_are_fixed_security_definer_carriers() -> Result<(), String> {
    let sql = normalized(MIGRATION);
    for function in [
        "rss_settings_projection_resolve_active",
        "rss_projection_operator_status_active",
        "rss_projection_operator_swap_active",
    ] {
        let section = function_section(&sql, function)?;
        for required in [
            "LANGUAGE plpgsql",
            "SECURITY DEFINER",
            "SET search_path = pg_catalog, pg_temp",
            "'settings.config-projection'",
        ] {
            assert!(
                section.contains(required),
                "fixed carrier `{function}` omits `{required}`"
            );
        }
    }

    let resolver = function_section(&sql, "rss_settings_projection_resolve_active")?;
    assert!(
        resolver.contains("RETURNS TABLE")
            && resolver.contains("generation")
            && resolver.contains("definition_version")
            && resolver.contains("definition_schema_digest")
            && resolver.contains("input_generation")
            && resolver.contains("promoted_high_water_lsn")
            && resolver.contains("token")
            && resolver.contains("pg_catalog.current_setting('rss.tenant_id', true)")
            && resolver.contains("settings_projection_active_pointer")
            && resolver.contains("settings_projection_generations"),
        "resolver must return a typed snapshot, authenticate tenant context, and validate the pointed generation"
    );

    let swap = function_section(&sql, "rss_projection_operator_swap_active")?;
    for required in [
        "pg_catalog.pg_advisory_xact_lock",
        "rss.projection_events.append",
        "projection_input_bindings",
        "settings_projection_generations",
        "projection_worker_tenant_quarantine",
        "checkpoint",
        "projection_events",
        "settings_projection_active_pointer",
    ] {
        assert!(swap.contains(required), "atomic swap omits `{required}`");
    }
    assert!(
        swap.contains("'applied'")
            && swap.contains("'rejected'")
            && swap.contains("'conflict'")
            && swap.contains("'fenced'"),
        "swap must expose a closed result vocabulary"
    );
    for reason in [
        "source_missing",
        "checkpoint_missing",
        "checkpoint_stale",
        "checkpoint_ahead",
        "generation_missing",
        "definition_mismatch",
        "input_generation_mismatch",
        "generation_high_water_mismatch",
        "target_quarantined",
    ] {
        assert!(swap.contains(reason), "swap omits rejection `{reason}`");
    }
    Ok(())
}

#[test]
fn legacy_json_pointer_functions_are_hard_dropped_and_reserved_namespace_is_closed() {
    let sql = normalized(MIGRATION);
    for signature in [
        "public.rss_projection_operator_read_active_pointer(uuid, text)",
        "public.rss_projection_operator_cas_active_pointer(uuid, text, bytea, bytea, bigint)",
    ] {
        assert!(
            sql.contains(&format!("DROP FUNCTION {signature}")),
            "0098 must hard-drop `{signature}`"
        );
        assert!(
            !sql.contains(&format!("CREATE FUNCTION {signature}")),
            "0098 must not recreate `{signature}`"
        );
    }

    assert!(
        sql.contains("ALTER TABLE public.distributed_cas") && sql.contains("projection-active/"),
        "generic distributed CAS must receive a database-enforced reserved-prefix guard"
    );
    assert!(
        sql.contains("DELETE FROM public.distributed_cas")
            && sql.contains("LIKE 'projection-active/%'"),
        "0098 must remove the pre-GA legacy pointer namespace before sealing it"
    );
}

#[test]
fn worker_apply_is_hard_cut_to_activated_identity_and_purpose() -> Result<(), String> {
    let sql = normalized(MIGRATION);

    assert!(
        sql.contains(ACTIVATED_DEFINITION_DIGEST),
        "0098 must bind worker/operator/resolver SQL to its activated Settings v3 definition"
    );
    assert!(
        sql.contains(ACTIVATED_INPUT_GENERATION),
        "0098 must bind worker/operator/resolver SQL to its activated projection input generation"
    );
    assert!(
        sql.contains("background-worker"),
        "worker receipt purpose must be the active-safe `background-worker` closed value"
    );
    assert!(
        sql.contains("DROP CONSTRAINT settings_projection_dedupe_receipts_execution_pair")
            && sql.contains("ADD CONSTRAINT settings_projection_dedupe_receipts_execution_pair")
            && sql.contains("actor = 'rss-projection-worker' AND purpose = 'background-worker'"),
        "receipt attribution constraint must be replaced, not relaxed"
    );

    let worker = function_section(&sql, "rss_settings_projection_apply_worker")?;
    assert!(worker.contains("'background-worker'"));
    assert!(!worker.contains("'background-shadow'"));
    assert!(
        worker.contains("rss_settings_projection_worker_tenant_scope_is_active"),
        "worker apply must prove the requested generation is the tenant active pointer"
    );

    let operator = function_section(&sql, "rss_settings_projection_apply_operator")?;
    assert!(operator.contains("'operator-replay'"));
    assert!(operator.contains(&format!(
        "p_definition_schema_digest <> '{ACTIVATED_DEFINITION_DIGEST}'"
    )));
    assert!(operator.contains(&format!(
        "p_input_generation <> '{ACTIVATED_INPUT_GENERATION}'"
    )));
    Ok(())
}

#[test]
fn worker_scope_and_discovery_are_active_generation_closed() -> Result<(), String> {
    let sql = normalized(MIGRATION);
    let active_scope = function_section(
        &sql,
        "rss_settings_projection_worker_tenant_scope_is_active",
    )?;
    for required in [
        "settings_projection_active_pointer",
        "settings_projection_generations",
        "pointer.generation = p_target_generation",
        "target.definition_version = p_definition_version",
        "target.definition_schema_digest = p_definition_schema_digest",
        "target.input_generation = p_input_generation",
    ] {
        assert!(
            active_scope.contains(required),
            "tenant active worker scope omits `{required}`"
        );
    }

    let tenants = function_section(&sql, "rss_projection_worker_list_tenants")?;
    assert!(
        !tenants.contains("p_target_generation")
            && !tenants.contains("projection_worker_tenant_quarantine"),
        "tenant discovery must be generation-neutral; each tenant quantum resolves and fences its active generation separately"
    );
    Ok(())
}
