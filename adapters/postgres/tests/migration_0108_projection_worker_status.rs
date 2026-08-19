const MIGRATION: &str = include_str!("../migrations/0108_expose_projection_worker_status.sql");

#[path = "support/migration_contract.rs"]
mod migration_contract;

use migration_contract::{RoutineIdentity, routine_definition_slice};

fn normalized() -> String {
    migration_contract::normalize_sql(MIGRATION)
}

fn function_section<'a>(sql: &'a str, name: &str) -> Result<&'a str, String> {
    routine_definition_slice(
        sql,
        RoutineIdentity::public(name, &["uuid", "text", "text", "text", "text", "text"]),
    )
}

fn assert_worker_observation_contract(sql: &str) -> Result<(), String> {
    let observation = function_section(sql, "rss_projection_worker_observe_tenant")?;
    for required in [
        "quarantine_reason text",
        "LEFT JOIN public.projection_worker_tenant_quarantine AS quarantine",
        "quarantine.tenant_scope_id = p_tenant_id",
        "quarantine.projection_id = p_projection_id",
        "quarantine.target_generation = p_target_generation",
        "quarantine.state = 'quarantined'",
        "quarantine.reason",
    ] {
        if !observation.contains(required) {
            return Err(format!(
                "rss_projection_worker_observe_tenant omits durable restart guard `{required}`"
            ));
        }
    }
    assert!(
        !observation.contains("projection_worker_tenant_is_quarantined"),
        "restart posture must recover the durable closed reason, not collapse it to a boolean"
    );
    Ok(())
}

#[test]
fn worker_observation_restores_durable_quarantine_reason_after_restart() -> Result<(), String> {
    assert_worker_observation_contract(&normalized())
}

#[test]
fn worker_observation_rejects_neighbor_quarantine_bait() -> Result<(), String> {
    let target = "CREATE FUNCTION public.rss_projection_worker_observe_tenant(uuid,text,text,text,text,text) RETURNS text AS $$ SELECT 'neutral' $$ LANGUAGE sql;";
    let neighbor = "CREATE FUNCTION public.neighbor() RETURNS text AS $$ SELECT quarantine.reason FROM public.projection_worker_tenant_quarantine AS quarantine $$ LANGUAGE sql;";
    let sql = migration_contract::normalize_sql(&format!("{target}\n{neighbor}"));
    let Err(error) = assert_worker_observation_contract(&sql) else {
        return Err(
            "neighboring routine satisfied the exact worker observation contract".to_owned(),
        );
    };
    assert!(error.contains("rss_projection_worker_observe_tenant"));
    Ok(())
}

#[test]
fn worker_observation_preserves_exact_security_definer_capability() {
    let sql = normalized();
    let signature =
        "public.rss_projection_worker_observe_tenant( uuid, text, text, text, text, text )";
    for required in [
        "SECURITY DEFINER SET search_path = pg_catalog, pg_temp",
        &format!("ALTER FUNCTION {signature} OWNER TO rss_projection_worker_owner"),
        &format!(
            "REVOKE ALL ON FUNCTION {signature} FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker"
        ),
        &format!("GRANT EXECUTE ON FUNCTION {signature} TO rss_projection_worker"),
    ] {
        assert!(
            sql.contains(required),
            "0107 capability drift: `{required}`"
        );
    }
    let grants = sql
        .split(';')
        .filter(|statement| {
            statement
                .contains("GRANT EXECUTE ON FUNCTION public.rss_projection_worker_observe_tenant(")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        grants.len(),
        1,
        "worker observation must have one identity-scoped execute grant"
    );
}
