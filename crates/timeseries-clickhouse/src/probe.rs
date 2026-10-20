use crate::{Connections, transaction::sql_error};
use rss_request_context::TenantId;
use rss_timeseries::Error;
use sqlx::{PgPool, postgres::PgSslMode};
use std::collections::BTreeSet;

pub(crate) async fn validate(
    pool: &PgPool,
    ch: &Connections,
    tenant: TenantId,
) -> Result<String, Error> {
    if !matches!(pool.connect_options().get_ssl_mode(), PgSslMode::VerifyFull) {
        return Err(Error::Unauthorized);
    }
    let safe:bool=sqlx::query_scalar("SELECT current_setting('server_version_num')::int BETWEEN 160000 AND 169999 AND NOT pg_is_in_recovery() AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) FROM pg_roles r WHERE r.rolname=current_user")
        .fetch_one(pool).await.map_err(sql_error)?;
    if !safe {
        return Err(Error::Unauthorized);
    }
    let safe:bool=sqlx::query_scalar("SELECT count(*)=10 AND bool_and(c.relrowsecurity AND c.relforcerowsecurity AND NOT pg_has_role(current_user,c.relowner,'MEMBER') AND (SELECT count(*)=1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_ts_ch' AND c.relkind='r' AND c.relname<>'installation'")
        .fetch_one(pool).await.map_err(sql_error)?;
    if !safe {
        return Err(Error::Invariant);
    }
    let safe:bool=sqlx::query_scalar("SELECT NOT has_schema_privilege(current_user,'rss_ts_ch','CREATE') AND NOT has_table_privilege(current_user,'rss_ts_ch.installation','INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_table_privilege(current_user,'rss_ts_ch.active_attempts','SELECT') AND NOT EXISTS(SELECT FROM pg_roles r WHERE r.oid=(SELECT nspowner FROM pg_namespace WHERE nspname='rss_ts_ch') AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls))")
        .fetch_one(pool).await.map_err(sql_error)?;
    if !safe {
        return Err(Error::Unauthorized);
    }
    let instance: String = sqlx::query_scalar(
        "SELECT id::text FROM rss_ts_ch.installation WHERE singleton AND version=1",
    )
    .fetch_one(pool)
    .await
    .map_err(sql_error)?;
    for (client, user) in [
        (&ch.reader, &ch.users[0]),
        (&ch.writer, &ch.users[1]),
        (&ch.maintenance, &ch.users[2]),
    ] {
        let rows = client
            .query("SELECT version(),currentUser()")
            .fetch_all::<(String, String)>()
            .await
            .map_err(|_| Error::Unavailable)?;
        if rows != vec![("25.8.12.129".into(), user.clone())] {
            return Err(Error::Unsupported);
        }
        if client
            .query("SELECT id FROM rss_ts_ch.installation")
            .fetch_all::<String>()
            .await
            .map_err(|_| Error::Unavailable)?
            != vec![instance.clone()]
        {
            return Err(Error::Invariant);
        }
    }
    crate::control_probe::validate(pool).await?;
    catalog(ch).await?;
    service_grants(ch).await?;
    reader(ch, tenant).await?;
    let guard = ch
        .writer
        .query("SELECT installation,primary_server,tls,guard_user FROM rss_ts_ch.guard_identity")
        .fetch_all::<(String, u8, u8, String)>()
        .await
        .map_err(|_| Error::Unavailable)?;
    if guard != vec![(instance.clone(), 1, 1, "ch_guard".into())] {
        return Err(Error::Unauthorized);
    }
    Ok(instance)
}
fn compact(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}
async fn catalog(ch: &Connections) -> Result<(), Error> {
    let rows=ch.maintenance.query("SELECT name,engine,partition_key,sorting_key,engine_full FROM system.tables WHERE database='rss_ts_ch' ORDER BY name").fetch_all::<(String,String,String,String,String)>().await.map_err(|_|Error::Unavailable)?;
    if rows.len() != 5 {
        return Err(Error::Invariant);
    }
    let expected = [
        ("active_attempts", "PostgreSQL", "", ""),
        ("guard_identity", "PostgreSQL", "", ""),
        ("installation", "MergeTree", "", "id"),
        (
            "raw",
            "ReplacingMergeTree",
            "intDiv(observed_at,2592000000000)",
            "tenant,namespace,series,source,generation,observed_at,sequence,sample_id",
        ),
        (
            "summaries",
            "ReplacingMergeTree",
            "intDiv(lo,2592000000000)",
            "tenant,namespace,object_id,lo",
        ),
    ];
    for (actual, expected) in rows.iter().zip(expected) {
        if actual.0 != expected.0
            || actual.1 != expected.1
            || compact(&actual.2) != expected.2
            || compact(&actual.3) != expected.3
        {
            return Err(Error::Invariant);
        }
        if actual.1 == "PostgreSQL" {
            let expected = format!(
                "PostgreSQL(rss_ts_ch_guard,table='{}',schema='rss_ts_ch')",
                actual.0
            );
            if compact(&actual.4) != expected {
                return Err(Error::Invariant);
            }
        }
        if actual.1.ends_with("MergeTree") {
            let settings = actual
                .4
                .split_once("SETTINGS")
                .ok_or(Error::Invariant)?
                .1
                .split(',')
                .map(compact)
                .collect::<BTreeSet<_>>();
            let mut expected = BTreeSet::from([
                "fsync_after_insert=1".into(),
                "fsync_part_directory=1".into(),
            ]);
            if actual.0 != "installation" {
                expected.insert("non_replicated_deduplication_window=1024".into());
            }
            if settings != expected {
                return Err(Error::Invariant);
            }
        }
    }
    let attachments = ch
        .maintenance
        .query("SELECT count() FROM system.tables WHERE has(dependencies_database,'rss_ts_ch')")
        .fetch_all::<u64>()
        .await
        .map_err(|_| Error::Unavailable)?;
    if attachments != vec![0] {
        return Err(Error::Invariant);
    }
    Ok(())
}
async fn reader(ch: &Connections, tenant: TenantId) -> Result<(), Error> {
    let roles = ch
        .maintenance
        .query("SELECT count() FROM system.role_grants WHERE user_name=?")
        .bind(&ch.users[0])
        .fetch_all::<u64>()
        .await
        .map_err(|_| Error::Unauthorized)?;
    if roles != vec![0] {
        return Err(Error::Unauthorized);
    }
    let policies=ch.maintenance.query("SELECT table,select_filter,is_restrictive FROM system.row_policies WHERE database='rss_ts_ch' AND (apply_to_all OR has(apply_to_list,?)) AND NOT has(apply_to_except,?) ORDER BY table,name").bind(&ch.users[0]).bind(&ch.users[0]).fetch_all::<(String,String,u8)>().await.map_err(|_|Error::Unauthorized)?;
    let condition = format!("tenant='{}'", tenant);
    let policies = policies
        .into_iter()
        .map(|(t, s, restrictive)| (t, compact(&s), restrictive))
        .collect::<Vec<_>>();
    if policies
        != vec![
            ("raw".into(), condition.clone(), 0),
            ("summaries".into(), condition, 0),
        ]
    {
        return Err(Error::Unauthorized);
    }
    let grants=ch.maintenance.query("SELECT toString(access_type),ifNull(database,''),ifNull(table,''),ifNull(column,''),grant_option,is_partial_revoke FROM system.grants WHERE user_name=? ORDER BY database,table,access_type").bind(&ch.users[0]).fetch_all::<(String,String,String,String,u8,u8)>().await.map_err(|_|Error::Unauthorized)?;
    let expected = ["installation", "raw", "summaries"]
        .map(|t| {
            (
                "SELECT".into(),
                "rss_ts_ch".into(),
                t.into(),
                String::new(),
                0,
                0,
            )
        })
        .to_vec();
    if grants != expected {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

async fn service_grants(ch: &Connections) -> Result<(), Error> {
    for (index, user) in ch.users.iter().enumerate().skip(1) {
        let roles = ch
            .maintenance
            .query("SELECT count() FROM system.role_grants WHERE user_name=?")
            .bind(user)
            .fetch_all::<u64>()
            .await
            .map_err(|_| Error::Unauthorized)?;
        if roles != vec![0] {
            return Err(Error::Unauthorized);
        }
        let grants=ch.maintenance.query("SELECT toString(access_type),ifNull(database,''),ifNull(table,''),ifNull(column,''),grant_option,is_partial_revoke FROM system.grants WHERE user_name=?").bind(user).fetch_all::<(String,String,String,String,u8,u8)>().await.map_err(|_|Error::Unauthorized)?;
        let mut capabilities = BTreeSet::new();
        for (access, db, table, column, grant, revoke) in grants {
            if !column.is_empty() || grant != 0 || revoke != 0 {
                return Err(Error::Unauthorized);
            }
            let valid = if index == 1 {
                db == "rss_ts_ch"
                    && ((access == "SELECT"
                        && matches!(
                            table.as_str(),
                            "installation" | "active_attempts" | "guard_identity"
                        ))
                        || (access == "INSERT" && matches!(table.as_str(), "raw" | "summaries")))
            } else {
                (db == "rss_ts_ch"
                    && ((access == "SELECT"
                        && matches!(table.as_str(), "installation" | "raw" | "summaries"))
                        || (access == "ALTER DELETE"
                            && matches!(table.as_str(), "raw" | "summaries"))))
                    || (access == "SELECT" && db == "system" && table.is_empty())
                    || (db.is_empty()
                        && table.is_empty()
                        && (access == "KILL QUERY" || access.starts_with("SHOW ")))
            };
            if !valid {
                return Err(Error::Unauthorized);
            }
            capabilities.insert((access, db, table));
        }
        let required = if index == 1 {
            vec![
                ("SELECT", "rss_ts_ch", "installation"),
                ("SELECT", "rss_ts_ch", "active_attempts"),
                ("SELECT", "rss_ts_ch", "guard_identity"),
                ("INSERT", "rss_ts_ch", "raw"),
                ("INSERT", "rss_ts_ch", "summaries"),
            ]
        } else {
            vec![
                ("SELECT", "rss_ts_ch", "installation"),
                ("SELECT", "rss_ts_ch", "raw"),
                ("SELECT", "rss_ts_ch", "summaries"),
                ("ALTER DELETE", "rss_ts_ch", "raw"),
                ("ALTER DELETE", "rss_ts_ch", "summaries"),
                ("SELECT", "system", ""),
                ("KILL QUERY", "", ""),
            ]
        };
        if required
            .iter()
            .any(|(a, d, t)| !capabilities.contains(&(a.to_string(), d.to_string(), t.to_string())))
        {
            return Err(Error::Unauthorized);
        }
    }
    Ok(())
}
