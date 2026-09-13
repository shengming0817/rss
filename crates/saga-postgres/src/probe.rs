//! Verify the executable storage boundary, not only a schema marker.
mod functions;
use crate::{Error, sql_error};
use sqlx::{PgConnection, PgPool, Row as _};
pub(super) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let mut connection = pool.acquire().await.map_err(sql_error)?;
    let conn = &mut *connection;
    let ok: Option<bool> = sqlx::query_scalar(
        r#"
WITH reachable AS (
    SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')
)
SELECT current_user=session_user AND NOT o.rolsuper AND NOT o.rolbypassrls
    AND NOT pg_has_role(current_user,n.nspowner,'MEMBER')
    AND NOT EXISTS(SELECT FROM reachable WHERE rolsuper OR rolbypassrls OR rolcreaterole)
    AND NOT EXISTS(SELECT FROM reachable r
        WHERE r.oid=n.nspowner OR has_schema_privilege(r.oid,n.oid,'CREATE'))
    AND NOT EXISTS(SELECT FROM aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
        WHERE a.grantee=0)
    AND obj_description(n.oid,'pg_namespace')='rss-saga-postgres:2'
FROM pg_namespace n JOIN pg_roles o ON o.oid=n.nspowner WHERE n.nspname='rss_saga'
"#,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(sql_error)?
    .flatten();
    if ok != Some(true) {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    tables(conn).await?;
    functions::validate(conn).await?;
    constraints(conn).await?;
    triggers(conn).await
}
async fn tables(conn: &mut PgConnection) -> Result<(), Error> {
    let rows=sqlx::query(r#"
WITH reachable AS (
    SELECT * FROM pg_roles WHERE rolname=current_user OR pg_has_role(current_user,oid,'SET')
)
SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner=n.nspowner AS owned,
    c.relpersistence='p'
        AND NOT EXISTS(SELECT FROM pg_rewrite WHERE ev_class=c.oid)
        AND NOT EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
            WHERE a.grantee=0)
        AND NOT EXISTS(SELECT FROM pg_attribute col,
            LATERAL aclexplode(coalesce(col.attacl,acldefault('c',c.relowner))) a
            WHERE col.attrelid=c.oid AND NOT col.attisdropped AND a.grantee=0) AS canonical,
    EXISTS(SELECT FROM reachable r WHERE c.relowner=r.oid
        OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
        OR EXISTS(SELECT FROM aclexplode(c.relacl) a WHERE a.privilege_type='MAINTAIN'
            AND CASE WHEN a.grantee=0 THEN true ELSE pg_has_role(r.oid,a.grantee,'USAGE') END)) AS writes
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='rss_saga' AND c.relkind='r' ORDER BY c.relname
"#).fetch_all(&mut *conn).await.map_err(sql_error)?;
    if rows.len() != 2 {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    for (row, name) in rows.iter().zip(["instances", "journal"]) {
        if row.try_get::<String, _>("relname").map_err(sql_error)? != name
            || !row
                .try_get::<bool, _>("relrowsecurity")
                .map_err(sql_error)?
            || !row
                .try_get::<bool, _>("relforcerowsecurity")
                .map_err(sql_error)?
            || !row.try_get::<bool, _>("owned").map_err(sql_error)?
            || !row.try_get::<bool, _>("canonical").map_err(sql_error)?
            || row.try_get::<bool, _>("writes").map_err(sql_error)?
        {
            return Err(Error::new(rss_saga::ErrorKind::Integrity));
        }
    }
    let policies: Vec<Option<bool>> = sqlx::query_scalar(
        r#"
WITH tenant_predicate(value) AS (VALUES ($predicate$(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)$predicate$)),
expected AS (
    SELECT to_regclass('rss_saga.' || name) AS relation FROM
        unnest(ARRAY['instances','journal']) AS name
), actual AS (
    SELECT p.* FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga'
)
SELECT p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
    AND e.relation IS NOT NULL
    AND pg_get_expr(p.polqual,p.polrelid)=(SELECT value FROM tenant_predicate)
    AND pg_get_expr(p.polwithcheck,p.polrelid)=(SELECT value FROM tenant_predicate)
FROM expected e FULL JOIN actual p ON p.polrelid=e.relation AND p.polname='tenant'
"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(sql_error)?;
    if policies.len() != 2 || policies.iter().any(|valid| *valid != Some(true)) {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    Ok(())
}
async fn triggers(conn: &mut PgConnection) -> Result<(), Error> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga' AND NOT t.tgisinternal").fetch_one(conn).await.map_err(sql_error)?;
    if count != 0 {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    Ok(())
}

async fn constraints(conn: &mut PgConnection) -> Result<(), Error> {
    for (table, name, expression) in [
        (
            "instances",
            "saga_history_instance",
            "valid_instance(definition, progress, revision, history_encoded_bytes, history_entry_limit, history_byte_limit)",
        ),
        (
            "journal",
            "saga_history_journal",
            "valid_journal(kind, seq, attempt, effect_key, protected, encoded_bytes)",
        ),
    ] {
        let actual: Option<String> = sqlx::query_scalar("SELECT pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE conrelid=to_regclass('rss_saga.'||$1) AND conname=$2 AND contype='c' AND convalidated AND NOT connoinherit")
            .bind(table).bind(name).fetch_optional(&mut *conn).await.map_err(sql_error)?;
        if actual
            .as_deref()
            .is_none_or(|value| value.strip_prefix("rss_saga.").unwrap_or(value) != expression)
        {
            return Err(rss_saga::ErrorKind::StorageContract.into());
        }
    }
    for (table, name, definition) in [
        (
            "instances",
            "instances_pkey",
            "PRIMARY KEY (tenant_id, saga_id)",
        ),
        (
            "journal",
            "journal_pkey",
            "PRIMARY KEY (tenant_id, saga_id, seq)",
        ),
        (
            "journal",
            "journal_tenant_id_saga_id_fkey",
            "FOREIGN KEY (tenant_id, saga_id) REFERENCES rss_saga.instances(tenant_id, saga_id)",
        ),
    ] {
        let actual: Option<String> = sqlx::query_scalar("SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_index i ON i.indexrelid=c.conindid WHERE c.conrelid=to_regclass('rss_saga.'||$1) AND c.conname=$2 AND c.convalidated AND i.indisvalid AND i.indisready")
            .bind(table).bind(name).fetch_optional(&mut *conn).await.map_err(sql_error)?;
        if actual.as_deref() != Some(definition) {
            return Err(rss_saga::ErrorKind::StorageContract.into());
        }
    }
    for (name, columns) in [
        ("saga_forward_step", "tenant_id, saga_id, step"),
        ("saga_forward_effect", "tenant_id, effect_key"),
    ] {
        let actual: Option<String> = sqlx::query_scalar("SELECT pg_get_indexdef(indexrelid) FROM pg_index WHERE indexrelid=to_regclass('rss_saga.'||$1) AND indisvalid AND indisready AND indisunique")
            .bind(name).fetch_optional(&mut *conn).await.map_err(sql_error)?;
        let expected = format!(
            "CREATE UNIQUE INDEX {name} ON rss_saga.journal USING btree ({columns}) WHERE (kind = 'ForwardApplied'::text)"
        );
        if actual.as_deref() != Some(expected.as_str()) {
            return Err(rss_saga::ErrorKind::StorageContract.into());
        }
    }
    Ok(())
}
