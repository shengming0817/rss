//! Validate the dedicated schema and reachable role posture on the actual connection.
use rss_reconcile::{Error, ErrorKind};
use sqlx::{PgConnection, PgPool, Row};
const PROBE: &str = r#"
WITH reachable AS (
    SELECT * FROM pg_roles WHERE rolname = current_user OR pg_has_role(current_user, oid, 'SET')
), relations AS (
    SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='rss_reconcile' AND c.relname IN ('targets')
)
SELECT
    session_user = current_user
    AND (SELECT count(*)=1 AND bool_and(relrowsecurity AND relforcerowsecurity) FROM relations)
    AND NOT EXISTS (
        SELECT FROM reachable r WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
    )
    AND NOT EXISTS (
        SELECT FROM reachable r CROSS JOIN relations c
        WHERE c.relowner=r.oid
           OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
    )
    AND NOT EXISTS (
        SELECT FROM reachable r JOIN pg_namespace n ON n.nspname='rss_reconcile'
        WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')
    )
    AND NOT EXISTS (
        SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_roles owner ON owner.oid=p.proowner
        WHERE n.nspname='rss_reconcile' AND
            ((p.prosecdef AND (owner.rolsuper OR owner.rolbypassrls)) OR p.proowner IN (SELECT oid FROM reachable))
    )
    AND NOT EXISTS (
        SELECT FROM relations c CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE a.privilege_type='MAINTAIN' AND
            CASE WHEN a.grantee=0 THEN true ELSE
                EXISTS(SELECT FROM reachable r WHERE r.oid=a.grantee OR pg_has_role(r.oid,a.grantee,'USAGE')) END
    )
    AND (SELECT array_agg(attname::text ORDER BY attnum) = ARRAY['tenant_id','reconciler','entity','wake_version','epoch','token','lease_until','next_run','failures','result']
         AND array_agg(format_type(atttypid,atttypmod) ORDER BY attnum)=ARRAY['uuid','text','text','bigint','bigint','uuid','timestamp with time zone','timestamp with time zone','bigint','text']
         AND array_agg(attnotnull ORDER BY attnum)=ARRAY[true,true,true,true,true,false,false,false,true,true]
         FROM pg_attribute WHERE attrelid='rss_reconcile.targets'::regclass AND attnum>0 AND NOT attisdropped)
    AND (SELECT count(*)=1 AND bool_and(pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, reconciler, entity)') FROM pg_constraint WHERE conrelid='rss_reconcile.targets'::regclass AND contype='p')
    AND (SELECT count(*)=8 AND bool_and(convalidated) FROM pg_constraint WHERE conrelid='rss_reconcile.targets'::regclass AND contype='c')
    AND (SELECT count(*)=1 AND bool_and(polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid]
         AND pg_get_expr(polqual,polrelid)=pg_get_expr(polwithcheck,polrelid)
         AND pg_get_expr(polqual,polrelid) = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)')
         FROM pg_policy WHERE polrelid='rss_reconcile.targets'::regclass)
    AND NOT EXISTS (SELECT FROM pg_trigger WHERE tgrelid='rss_reconcile.targets'::regclass AND NOT tgisinternal)
    AND (SELECT obj_description(oid,'pg_namespace')='rss-reconcile-postgres:1'
         FROM pg_namespace WHERE nspname='rss_reconcile')
"#;
pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let mut conn = pool.acquire().await.map_err(crate::transaction::map_sql)?;
    validate_connection(&mut conn).await
}
pub(crate) async fn validate_connection(conn: &mut PgConnection) -> Result<(), Error> {
    let safe = sqlx::query_scalar::<_, Option<bool>>(PROBE)
        .fetch_one(&mut *conn)
        .await
        .map_err(crate::transaction::map_sql)?;
    if safe == Some(true) {
        functions(conn).await
    } else {
        Err(Error::new(ErrorKind::StorageContract))
    }
}
// The shipped SQL is the sole function definition source, compared with the actual provider.
async fn functions(conn: &mut PgConnection) -> Result<(), Error> {
    let rows=sqlx::query("SELECT proname,prosrc,prosecdef,proconfig,pg_get_function_identity_arguments(p.oid) AS args,has_function_privilege(p.oid,'EXECUTE') AS executable,EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_reconcile'").fetch_all(conn).await.map_err(crate::transaction::map_sql)?;
    let definitions: Vec<_> = crate::MIGRATION_SQL
        .split("CREATE FUNCTION rss_reconcile.")
        .skip(1)
        .collect();
    if rows.len() != definitions.len() {
        return Err(Error::new(ErrorKind::StorageContract));
    }
    for definition in definitions {
        let (name, rest) = definition
            .split_once('(')
            .ok_or_else(|| Error::new(ErrorKind::Invariant))?;
        let row = rows
            .iter()
            .find(|row| row.try_get::<String, _>("proname").is_ok_and(|n| n == name))
            .ok_or_else(|| Error::new(ErrorKind::StorageContract))?;
        let expected_args = rest
            .split_once(')')
            .ok_or_else(|| Error::new(ErrorKind::Invariant))?
            .0;
        let actual_args: String = row.try_get("args").map_err(crate::transaction::map_sql)?;
        if actual_args.split_whitespace().collect::<String>()
            != expected_args.split_whitespace().collect::<String>()
        {
            return Err(Error::new(ErrorKind::StorageContract));
        }
        let body = rest
            .split_once("AS $$")
            .and_then(|(_, s)| s.split_once("$$;"))
            .map(|(body, _)| body)
            .ok_or_else(|| Error::new(ErrorKind::Invariant))?;
        let config: Vec<String> = row
            .try_get("proconfig")
            .map_err(crate::transaction::map_sql)?;
        if row
            .try_get::<String, _>("prosrc")
            .map_err(crate::transaction::map_sql)?
            != body
            || row
                .try_get::<bool, _>("prosecdef")
                .map_err(crate::transaction::map_sql)?
                != (name != "assert_tenant")
            || config != ["search_path=pg_catalog, rss_reconcile"]
            || !row
                .try_get::<bool, _>("executable")
                .map_err(crate::transaction::map_sql)?
            || row
                .try_get::<bool, _>("public_execute")
                .map_err(crate::transaction::map_sql)?
        {
            return Err(Error::new(ErrorKind::StorageContract));
        }
    }
    Ok(())
}
