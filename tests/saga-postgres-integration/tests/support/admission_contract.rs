use super::*;

const TENANT_EXPR: &str = "tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid";

pub(super) async fn drift(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let mut cases = Vec::new();
    for (object, privilege) in [
        ("SCHEMA rss_saga", "USAGE"),
        ("rss_saga.definitions", "SELECT"),
        ("rss_saga.instances", "SELECT"),
        ("rss_saga.journal", "SELECT"),
        ("rss_saga.instances", "SELECT(revision)"),
        ("rss_saga.journal", "SELECT(tenant_id)"),
    ] {
        cases.push((
            format!("F1 PUBLIC {object} {privilege}"),
            format!("GRANT {privilege} ON {object} TO PUBLIC"),
            format!("REVOKE {privilege} ON {object} FROM PUBLIC"),
        ));
    }
    for (object, privilege) in [
        ("SCHEMA rss_saga", "USAGE"),
        ("rss_saga.definitions", "SELECT"),
        ("rss_saga.instances", "SELECT"),
        ("rss_saga.journal", "SELECT"),
        ("FUNCTION rss_saga.register(uuid,jsonb,jsonb)", "EXECUTE"),
        (
            "FUNCTION rss_saga.extend_history(uuid,uuid,bigint,bigint,jsonb,jsonb)",
            "EXECUTE",
        ),
        (
            "FUNCTION rss_saga.commit_event(uuid,uuid,bigint,jsonb,bytea,jsonb,jsonb)",
            "EXECUTE",
        ),
        (
            "FUNCTION rss_saga.runnable(jsonb,jsonb,bigint,bigint,bigint,bigint)",
            "EXECUTE",
        ),
    ] {
        cases.push((
            format!("missing required {object} {privilege}"),
            format!("REVOKE {privilege} ON {object} FROM saga_runtime"),
            format!("GRANT {privilege} ON {object} TO saga_runtime"),
        ));
    }
    definition_cases(&mut cases);
    history_cases(&mut cases);
    policy_cases(&mut cases);
    for table in ["definitions", "instances", "journal"] {
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
    check_drift_cases(pool, owner, control, cases).await
}

async fn check_drift_cases(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
    cases: Vec<Case>,
) -> anyhow::Result<()> {
    let mut accepted = Vec::new();
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
fn definition_cases(cases: &mut Vec<Case>) {
    for (label, change, restore) in [
        (
            "inherited relation",
            "CREATE TABLE public.saga_fixture_child () INHERITS (rss_saga.definitions)",
            "DROP TABLE public.saga_fixture_child",
        ),
        (
            "external validator",
            "CREATE FUNCTION public.valid_definition(jsonb) RETURNS boolean LANGUAGE sql AS 'SELECT rss_saga.valid_definition($1)'; ALTER TABLE rss_saga.definitions DROP CONSTRAINT saga_definition, ADD CONSTRAINT saga_definition CHECK(public.valid_definition(definition))",
            "ALTER TABLE rss_saga.definitions DROP CONSTRAINT saga_definition, ADD CONSTRAINT saga_definition CHECK(rss_saga.valid_definition(definition)); DROP FUNCTION public.valid_definition(jsonb)",
        ),
        (
            "unexpected foreign key",
            "CREATE TABLE public.saga_fixture_tenants(id uuid PRIMARY KEY); ALTER TABLE rss_saga.definitions ADD FOREIGN KEY(tenant_id) REFERENCES public.saga_fixture_tenants(id) ON UPDATE CASCADE NOT VALID",
            "DROP TABLE public.saga_fixture_tenants CASCADE",
        ),
        (
            "cross-tenant unique index",
            "CREATE UNIQUE INDEX global_version ON rss_saga.definitions(contract,version) WHERE version='v99'",
            "DROP INDEX rss_saga.global_version",
        ),
        (
            "definition body writable",
            "GRANT UPDATE(definition) ON rss_saga.definitions TO saga_runtime",
            "REVOKE UPDATE(definition) ON rss_saga.definitions FROM saga_runtime",
        ),
        (
            "nullable instance binding",
            "ALTER TABLE rss_saga.instances ALTER COLUMN version DROP NOT NULL",
            "ALTER TABLE rss_saga.instances ALTER COLUMN version SET NOT NULL",
        ),
        (
            "missing definition reference",
            "ALTER TABLE rss_saga.instances DROP CONSTRAINT instance_definition",
            "ALTER TABLE rss_saga.instances ADD CONSTRAINT instance_definition FOREIGN KEY(tenant_id,contract,version) REFERENCES rss_saga.definitions",
        ),
    ] {
        cases.push((label.into(), change.into(), restore.into()));
    }
}

fn history_cases(cases: &mut Vec<Case>) {
    for (table, name, expr) in [
        (
            "definitions",
            "saga_definition",
            "rss_saga.valid_definition(definition)",
        ),
        (
            "instances",
            "saga_history_instance",
            "rss_saga.valid_instance(progress,revision,history_encoded_bytes,history_entry_limit,history_byte_limit)",
        ),
        (
            "journal",
            "saga_history_journal",
            "rss_saga.valid_journal(kind,seq,attempt,effect_key,protected,encoded_bytes)",
        ),
    ] {
        cases.push((format!("history {name} weakened"), format!("ALTER TABLE rss_saga.{table} DROP CONSTRAINT {name}; ALTER TABLE rss_saga.{table} ADD CONSTRAINT {name} CHECK(true)"), format!("ALTER TABLE rss_saga.{table} DROP CONSTRAINT {name}; ALTER TABLE rss_saga.{table} ADD CONSTRAINT {name} CHECK({expr})")));
    }
    for (name, columns) in [
        ("saga_forward_step", "tenant_id,saga_id,step"),
        ("saga_forward_effect", "tenant_id,effect_key"),
    ] {
        cases.push((format!("history {name} nonunique"), format!("DROP INDEX rss_saga.{name}; CREATE INDEX {name} ON rss_saga.journal({columns}) WHERE kind='ForwardApplied'"), format!("DROP INDEX rss_saga.{name}; CREATE UNIQUE INDEX {name} ON rss_saga.journal({columns}) WHERE kind='ForwardApplied'")));
    }
}

fn policy_cases(cases: &mut Vec<Case>) {
    for table in ["definitions", "instances", "journal"] {
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
