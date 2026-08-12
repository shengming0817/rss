const MIGRATION: &str = include_str!("../migrations/0108_expose_projection_worker_status.sql");

fn normalized() -> String {
    MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn function_section<'a>(sql: &'a str, name: &str) -> Result<&'a str, String> {
    let marker = format!("CREATE FUNCTION public.{name}(");
    let (_, tail) = sql
        .split_once(&marker)
        .ok_or_else(|| format!("0107 must replace fixed function `{name}`"))?;
    Ok(tail
        .split_once("$function$;")
        .map_or(tail, |(section, _)| section))
}

#[test]
fn worker_observation_restores_durable_quarantine_reason_after_restart() -> Result<(), String> {
    let sql = normalized();
    let observation = function_section(&sql, "rss_projection_worker_observe_tenant")?;
    for required in [
        "quarantine_reason text",
        "LEFT JOIN public.projection_worker_tenant_quarantine AS quarantine",
        "quarantine.tenant_scope_id = p_tenant_id",
        "quarantine.projection_id = p_projection_id",
        "quarantine.target_generation = p_target_generation",
        "quarantine.state = 'quarantined'",
        "quarantine.reason",
    ] {
        assert!(
            sql.contains(required) || observation.contains(required),
            "0107 omits durable restart observation guard `{required}`"
        );
    }
    assert!(
        !observation.contains("projection_worker_tenant_is_quarantined"),
        "restart posture must recover the durable closed reason, not collapse it to a boolean"
    );
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
    assert_eq!(
        sql.matches("GRANT EXECUTE ON FUNCTION public.rss_projection_worker_observe_tenant(")
            .count(),
        1,
        "worker observation must have one exact execute grant"
    );
}
