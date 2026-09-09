use super::*;

const TENANT_EXPR: &str = "tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid";

pub(super) async fn drift(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let mut accepted = Vec::new();
    let mut cases = Vec::new();
    for (object, privilege) in [
        ("SCHEMA rss_saga", "USAGE"),
        ("rss_saga.instances", "SELECT"),
        ("rss_saga.journal", "SELECT"),
        ("rss_saga.step_receipts", "SELECT"),
        ("rss_saga.instances", "SELECT(revision)"),
        ("rss_saga.journal", "SELECT(tenant_id)"),
        ("rss_saga.step_receipts", "SELECT(tenant_id)"),
    ] {
        cases.push((
            format!("F1 PUBLIC {object} {privilege}"),
            format!("GRANT {privilege} ON {object} TO PUBLIC"),
            format!("REVOKE {privilege} ON {object} FROM PUBLIC"),
        ));
    }
    policy_cases(&mut cases);
    for table in ["instances", "journal", "step_receipts"] {
        for event in ["INSERT", "UPDATE"] {
            cases.push((
                format!("F3 {table} {event} rule"),
                format!(
                    "CREATE RULE suppress AS ON {event} TO rss_saga.{table} DO INSTEAD NOTHING"
                ),
                format!("DROP RULE suppress ON rss_saga.{table}"),
            ));
        }
    }
    function_cases(owner, &mut cases).await?;
    let count = cases.len();
    for (label, change, restore) in cases {
        PgStore::new(pool.clone(), control).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(change))
            .execute(owner)
            .await?;
        let rejected = PgStore::new(pool.clone(), control).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
            .execute(owner)
            .await?;
        PgStore::new(pool.clone(), control).await?;
        if !matches!(rejected, Err(e) if e.kind()==ErrorKind::StorageContract) {
            eprintln!("accepted noncanonical storage: {label}");
            accepted.push(label);
        }
    }
    anyhow::ensure!(accepted.is_empty(), "admission accepted: {accepted:?}");
    eprintln!("verified {count} isolated Saga admission drift cases");
    Ok(())
}

type Case = (String, String, String);
fn policy_cases(cases: &mut Vec<Case>) {
    for table in ["instances", "journal", "step_receipts"] {
        let create = format!(
            "CREATE POLICY tenant ON rss_saga.{table} USING ({TENANT_EXPR}) WITH CHECK ({TENANT_EXPR})"
        );
        let drop = format!("DROP POLICY tenant ON rss_saga.{table}");
        cases.push((format!("F2 {table} missing"), drop.clone(), create.clone()));
        cases.push((
            format!("F2 {table} wrong name"),
            format!("ALTER POLICY tenant ON rss_saga.{table} RENAME TO extra"),
            format!("ALTER POLICY extra ON rss_saga.{table} RENAME TO tenant"),
        ));
        let expression = TENANT_EXPR.replace("rss.tenant_id", "rss.tenant_id ");
        cases.push((
            format!("F2 {table} changed literal"),
            format!("ALTER POLICY tenant ON rss_saga.{table} USING ({expression}) WITH CHECK ({expression})"),
            format!("{drop}; {create}"),
        ));
        for clause in ["AS RESTRICTIVE", "FOR UPDATE", "TO saga_runtime"] {
            cases.push((
                format!("F2 {table} {clause}"),
                format!("{drop}; CREATE POLICY tenant ON rss_saga.{table} {clause} USING ({TENANT_EXPR}) WITH CHECK ({TENANT_EXPR})"),
                format!("{drop}; {create}"),
            ));
        }
    }
    cases.push((
        "F2 missing policy masked by policy on another table".into(),
        format!("DROP POLICY tenant ON rss_saga.instances; CREATE POLICY extra ON rss_saga.journal USING ({TENANT_EXPR}) WITH CHECK ({TENANT_EXPR})"),
        format!("DROP POLICY extra ON rss_saga.journal; CREATE POLICY tenant ON rss_saga.instances USING ({TENANT_EXPR}) WITH CHECK ({TENANT_EXPR})"),
    ));
}

async fn function_cases(owner: &PgPool, cases: &mut Vec<Case>) -> anyhow::Result<()> {
    let lease: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('rss_saga.lease(uuid,uuid,bigint,bigint)'::regprocedure)",
    )
    .fetch_one(owner)
    .await?;
    let claim: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('rss_saga.claim(uuid,uuid,bigint)'::regprocedure)",
    )
    .fetch_one(owner)
    .await?;
    let drop = "DROP FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint)";
    let restore = format!(
        "SET ROLE saga_owner; {lease}; REVOKE ALL ON FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) FROM PUBLIC; GRANT EXECUTE ON FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) TO saga_runtime; RESET ROLE"
    );
    let overload = claim.replacen("p_ttl bigint)", "p_ttl bigint, extra bigint)", 1);
    cases.push((
        "F4 missing lease masked by claim overload".into(),
        format!("SET ROLE saga_owner; {drop}; {overload}; REVOKE ALL ON FUNCTION rss_saga.claim(uuid,uuid,bigint,bigint) FROM PUBLIC; GRANT EXECUTE ON FUNCTION rss_saga.claim(uuid,uuid,bigint,bigint) TO saga_runtime; RESET ROLE"),
        format!("DROP FUNCTION rss_saga.claim(uuid,uuid,bigint,bigint); {restore}"),
    ));
    cases.push((
        "F4 lease input type".into(),
        format!("SET ROLE saga_owner; {drop}; {}; REVOKE ALL ON FUNCTION rss_saga.lease(uuid,uuid,bigint,numeric) FROM PUBLIC; GRANT EXECUTE ON FUNCTION rss_saga.lease(uuid,uuid,bigint,numeric) TO saga_runtime; RESET ROLE", lease.replacen("p_ttl bigint)", "p_ttl numeric)", 1)),
        format!("DROP FUNCTION rss_saga.lease(uuid,uuid,bigint,numeric); {restore}"),
    ));
    // A second PL/pgSQL handler language keeps the canonical body valid while changing prolang.
    cases.push((
        "F4 lease language".into(),
        format!("CREATE TRUSTED LANGUAGE saga_plpgsql HANDLER plpgsql_call_handler INLINE plpgsql_inline_handler VALIDATOR plpgsql_validator; SET ROLE saga_owner; {drop}; {}; REVOKE ALL ON FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) FROM PUBLIC; GRANT EXECUTE ON FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) TO saga_runtime; RESET ROLE", lease.replacen("LANGUAGE plpgsql", "LANGUAGE saga_plpgsql", 1)),
        format!("{drop}; DROP LANGUAGE saga_plpgsql; {restore}"),
    ));
    for (attribute, original) in [
        ("STRICT", "CALLED ON NULL INPUT"),
        ("STABLE", "VOLATILE"),
        ("PARALLEL SAFE", "PARALLEL UNSAFE"),
        ("LEAKPROOF", "NOT LEAKPROOF"),
    ] {
        cases.push((
            format!("F4 lease {attribute}"),
            format!("ALTER FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) {attribute}"),
            format!("ALTER FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) {original}"),
        ));
    }
    for (label, from, to) in [
        ("argument name", "p_ttl bigint)", "other bigint)"),
        (
            "default argument",
            "p_ttl bigint)",
            "p_ttl bigint DEFAULT 1000)",
        ),
        ("return type", "RETURNS void", "RETURNS bigint"),
        ("set return", "RETURNS void", "RETURNS SETOF void"),
    ] {
        cases.push((
            format!("F4 lease {label}"),
            format!("SET ROLE saga_owner; {drop}; {}; REVOKE ALL ON FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) FROM PUBLIC; GRANT EXECUTE ON FUNCTION rss_saga.lease(uuid,uuid,bigint,bigint) TO saga_runtime; RESET ROLE", lease.replacen(from, to, 1)),
            format!("{drop}; {restore}"),
        ));
    }
    Ok(())
}
