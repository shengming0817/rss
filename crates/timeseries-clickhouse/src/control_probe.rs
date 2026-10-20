//! Verify complete RLS/guard definitions rather than trusting schema comments.
use crate::{CONTROL_SQL, transaction::sql_error};
use rss_timeseries::Error;
use sqlx::PgPool;
fn normalize(sql: &str) -> String {
    sql.to_ascii_lowercase()
        .replace("::text", "")
        .replace("pg_stat_ssl.", "")
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !matches!(c, '(' | ')' | ';'))
        .collect()
}
fn expected_view(name: &str) -> Result<&'static str, Error> {
    let marker = match name {
        "active_attempts" => {
            "CREATE VIEW rss_ts_ch.active_attempts WITH (security_barrier=true) AS"
        }
        "guard_identity" => "CREATE VIEW rss_ts_ch.guard_identity WITH (security_barrier=true) AS",
        _ => return Err(Error::Invariant),
    };
    CONTROL_SQL
        .split_once(marker)
        .and_then(|(_, v)| v.split_once(';'))
        .map(|(v, _)| v)
        .ok_or(Error::Invariant)
}
pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let policies=sqlx::query_as::<_,(String,String,String,bool,String,String,bool)>("SELECT c.relname,p.polname,p.polcmd::text,p.polpermissive,coalesce(pg_get_expr(p.polqual,p.polrelid),''),coalesce(pg_get_expr(p.polwithcheck,p.polrelid),''),CASE WHEN p.polname='tenant' THEN p.polroles=ARRAY[0::oid] ELSE p.polroles=ARRAY[c.relowner] END FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_ts_ch' ORDER BY c.relname,p.polname")
        .fetch_all(pool).await.map_err(sql_error)?;
    if policies.len() != 11 {
        return Err(Error::Invariant);
    }
    let tenant = normalize("tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid");
    for (table, name, command, permissive, using, check, roles) in policies {
        let valid = if name == "tenant" {
            normalize(&using) == tenant && normalize(&check) == tenant
        } else {
            table == "attempts" && name == "guard_owner" && using == "true" && check.is_empty()
        };
        if !valid || command != "*" || !permissive || !roles {
            return Err(Error::Unauthorized);
        }
    }
    let views=sqlx::query_as::<_,(String,String,bool)>("SELECT c.relname,pg_get_viewdef(c.oid,true),c.relowner=n.nspowner AND c.reloptions=ARRAY['security_barrier=true'] FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_ts_ch' AND c.relkind='v' ORDER BY c.relname")
        .fetch_all(pool).await.map_err(sql_error)?;
    if views.len() != 2 {
        return Err(Error::Invariant);
    }
    for (name, definition, owner) in views {
        if !owner || normalize(&definition) != normalize(expected_view(&name)?) {
            return Err(Error::Invariant);
        }
    }
    let guard:Option<bool>=sqlx::query_scalar("SELECT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid) AND has_schema_privilege(r.oid,'rss_ts_ch','USAGE') AND NOT has_schema_privilege(r.oid,'rss_ts_ch','CREATE') AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','f') AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_table_privilege(r.oid,c.oid,'SELECT')<>(n.nspname='rss_ts_ch' AND c.relname IN ('active_attempts','guard_identity')))) FROM pg_roles r WHERE r.rolname='ch_guard'")
        .fetch_optional(pool).await.map_err(sql_error)?;
    if guard != Some(true) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
