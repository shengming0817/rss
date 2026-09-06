//! Verify the executable storage boundary, not only a schema marker.
use crate::{Error, MIGRATION_SQL, sql_error};
use sqlx::{PgPool, Row as _};
pub(super) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let ok:bool=sqlx::query_scalar("SELECT current_user=session_user AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT o.rolsuper AND NOT o.rolbypassrls AND NOT pg_has_role(current_user,n.nspowner,'MEMBER') AND obj_description(n.oid,'pg_namespace')='rss-saga-postgres:1' FROM pg_roles r CROSS JOIN pg_namespace n JOIN pg_roles o ON o.oid=n.nspowner WHERE r.rolname=current_user AND n.nspname='rss_saga'").fetch_one(pool).await.map_err(sql_error)?;
    if !ok {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    tables(pool).await?;
    functions(pool).await?;
    triggers(pool).await
}
async fn tables(pool: &PgPool) -> Result<(), Error> {
    let rows=sqlx::query("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner=n.nspowner AS owned,(has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')) AS writes FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga' AND c.relkind='r' ORDER BY c.relname").fetch_all(pool).await.map_err(sql_error)?;
    if rows.len() != 3 {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    for (row, name) in rows.iter().zip(["instances", "journal", "step_receipts"]) {
        if row.try_get::<String, _>("relname").map_err(sql_error)? != name
            || !row
                .try_get::<bool, _>("relrowsecurity")
                .map_err(sql_error)?
            || !row
                .try_get::<bool, _>("relforcerowsecurity")
                .map_err(sql_error)?
            || !row.try_get::<bool, _>("owned").map_err(sql_error)?
            || row.try_get::<bool, _>("writes").map_err(sql_error)?
        {
            return Err(Error::new(rss_saga::ErrorKind::Integrity));
        }
    }
    let policies=sqlx::query("SELECT p.polcmd,p.polpermissive,pg_get_expr(p.polqual,p.polrelid) AS qual,pg_get_expr(p.polwithcheck,p.polrelid) AS checked FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga'").fetch_all(pool).await.map_err(sql_error)?;
    if policies.len() != 3 {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    for policy in policies {
        for column in ["qual", "checked"] {
            let expression = policy.try_get::<String, _>(column).map_err(sql_error)?;
            let normalized = expression
                .replace("::text", "")
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '(' && *c != ')')
                .collect::<String>();
            if normalized != "tenant_id=NULLIFcurrent_setting'rss.tenant_id',true,''::uuid" {
                return Err(Error::new(rss_saga::ErrorKind::Integrity));
            }
        }
    }
    Ok(())
}
async fn functions(pool: &PgPool) -> Result<(), Error> {
    let rows=sqlx::query("SELECT p.proname,p.prosrc,p.prosecdef,p.proconfig,p.proowner=n.nspowner AS owned,EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_saga'").fetch_all(pool).await.map_err(sql_error)?;
    if rows.len() != 6 {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    for row in rows {
        let name = row.try_get::<String, _>("proname").map_err(sql_error)?;
        let marker = format!("CREATE FUNCTION rss_saga.{name}(");
        let body = MIGRATION_SQL
            .split_once(&marker)
            .and_then(|(_, s)| s.split_once("AS $$"))
            .and_then(|(_, s)| s.split_once("$$;"))
            .map(|(body, _)| body.trim())
            .ok_or(Error::new(rss_saga::ErrorKind::Integrity))?;
        if row
            .try_get::<String, _>("prosrc")
            .map_err(sql_error)?
            .trim()
            != body
            || !row.try_get::<bool, _>("owned").map_err(sql_error)?
            || row
                .try_get::<bool, _>("public_execute")
                .map_err(sql_error)?
            || row.try_get::<bool, _>("prosecdef").map_err(sql_error)?
                != (name != "assert_receipt_pair")
        {
            return Err(Error::new(rss_saga::ErrorKind::Integrity));
        }
        let config = row
            .try_get::<Vec<String>, _>("proconfig")
            .map_err(sql_error)?;
        if config != ["search_path=pg_catalog, rss_saga"] {
            return Err(Error::new(rss_saga::ErrorKind::Integrity));
        }
    }
    Ok(())
}
async fn triggers(pool: &PgPool) -> Result<(), Error> {
    let rows=sqlx::query("SELECT c.relname,t.tgname,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgtype,t.tgfoid='rss_saga.assert_receipt_pair()'::regprocedure AS correct_function FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname").fetch_all(pool).await.map_err(sql_error)?;
    if rows.len() != 2 {
        return Err(Error::new(rss_saga::ErrorKind::Integrity));
    }
    for (row, (table, name)) in rows.iter().zip([
        ("journal", "receipt_pair"),
        ("step_receipts", "journal_pair"),
    ]) {
        let valid = row.try_get::<String, _>("relname").map_err(sql_error)? == table
            && row.try_get::<String, _>("tgname").map_err(sql_error)? == name
            && row.try_get::<i8, _>("tgenabled").map_err(sql_error)? == b'O' as i8
            && row.try_get::<bool, _>("tgdeferrable").map_err(sql_error)?
            && row
                .try_get::<bool, _>("tginitdeferred")
                .map_err(sql_error)?
            && row.try_get::<i16, _>("tgtype").map_err(sql_error)? == 5
            && row
                .try_get::<bool, _>("correct_function")
                .map_err(sql_error)?;
        if !valid {
            return Err(Error::new(rss_saga::ErrorKind::Integrity));
        }
    }
    Ok(())
}
