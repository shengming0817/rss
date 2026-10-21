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
    let safe:bool=sqlx::query_scalar("SELECT current_setting('server_version_num')::int BETWEEN 170006 AND 179999 AND NOT pg_is_in_recovery() AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) FROM pg_roles r WHERE r.rolname=current_user")
        .fetch_one(pool).await.map_err(sql_error)?;
    if !safe {
        return Err(Error::Unauthorized);
    }
    let safe:bool=sqlx::query_scalar("SELECT count(*)=10 AND bool_and(c.relrowsecurity AND c.relforcerowsecurity AND NOT pg_has_role(current_user,c.relowner,'MEMBER') AND (SELECT count(*)=1 FROM pg_policy p WHERE p.polrelid=c.oid AND p.polname='tenant' AND pg_get_expr(p.polqual,p.polrelid)=pg_get_expr(p.polwithcheck,p.polrelid))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_ts_ch' AND c.relkind='r' AND c.relname<>'installation'")
        .fetch_one(pool).await.map_err(sql_error)?;
    if !safe {
        return Err(Error::Invariant);
    }
    let safe:bool=sqlx::query_scalar("SELECT NOT has_schema_privilege(current_user,'rss_ts_ch','CREATE') AND NOT has_table_privilege(current_user,'rss_ts_ch.installation','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AND NOT has_any_column_privilege(current_user,'rss_ts_ch.installation','INSERT,UPDATE,REFERENCES') AND NOT has_any_column_privilege(current_user,'rss_ts_ch.active_attempts','SELECT') AND NOT EXISTS(SELECT FROM pg_roles r WHERE r.oid=(SELECT nspowner FROM pg_namespace WHERE nspname='rss_ts_ch') AND (r.rolcanlogin OR r.rolsuper OR r.rolbypassrls))")
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
    crate::control_probe::validate(pool)
        .await
        .map_err(|e| diagnose("control-contract", e))?;
    catalog(ch)
        .await
        .map_err(|e| diagnose("clickhouse-catalog", e))?;
    service_grants(ch)
        .await
        .map_err(|e| diagnose("service-grants", e))?;
    reader(ch, tenant)
        .await
        .map_err(|e| diagnose("tenant-reader", e))?;
    let guard = ch
        .writer
        .query("SELECT installation,primary_server,tls,guard_user FROM rss_ts_ch.guard_identity")
        .fetch_all::<(String, u8, u8, String)>()
        .await
        .map_err(guard_error)?;
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
        return Err(diagnose("catalog-table-count", Error::Invariant));
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
            #[cfg(feature = "integration")]
            eprintln!(
                "ClickHouse table shape: name={} engine={} partition={} sorting={}",
                actual.0, actual.1, actual.2, actual.3
            );
            return Err(diagnose("catalog-table-shape", Error::Invariant));
        }
        if actual.1 == "PostgreSQL" {
            let expected = format!(
                "PostgreSQL(rss_ts_ch_guard,`table`='{}',schema='rss_ts_ch')",
                actual.0
            );
            if compact(&actual.4) != expected {
                #[cfg(feature = "integration")]
                {
                    let shape = actual
                        .4
                        .split('\'')
                        .enumerate()
                        .map(|(n, p)| {
                            if n % 2 == 0
                                || matches!(p, "active_attempts" | "guard_identity" | "rss_ts_ch")
                            {
                                p
                            } else {
                                "[literal]"
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("'");
                    eprintln!("ClickHouse guard engine shape: {shape}");
                }
                return Err(diagnose("catalog-postgresql-target", Error::Invariant));
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
                "index_granularity=8192".into(),
                "fsync_after_insert=1".into(),
                "fsync_part_directory=1".into(),
            ]);
            if actual.0 != "installation" {
                expected.insert("non_replicated_deduplication_window=1024".into());
            }
            if settings != expected {
                #[cfg(feature = "integration")]
                eprintln!("ClickHouse table settings: {} {:?}", actual.0, settings);
                return Err(diagnose("catalog-table-settings", Error::Invariant));
            }
        }
    }
    columns(ch).await?;
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
        return Err(diagnose("reader-check", Error::Unauthorized));
    }
    let policies=ch.maintenance.query("SELECT table,ifNull(select_filter,''),is_restrictive FROM system.row_policies WHERE database='rss_ts_ch' AND (apply_to_all OR has(apply_to_list,?)) AND NOT has(apply_to_except,?) ORDER BY table,name").bind(&ch.users[0]).bind(&ch.users[0]).fetch_all::<(String,String,u8)>().await.map_err(|_|diagnose("reader-query",Error::Unauthorized))?;
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
        #[cfg(feature = "integration")]
        eprintln!(
            "reader policy count={} matching_filter={:?}",
            policies.len(),
            policies
                .iter()
                .map(|(_, p, r)| (p.replace(&tenant.to_string(), "[tenant]"), r))
                .collect::<Vec<_>>()
        );
        return Err(diagnose("reader-policy-shape", Error::Unauthorized));
    }
    let grants=ch.maintenance.query("SELECT toString(access_type),ifNull(database,''),ifNull(table,''),ifNull(column,''),grant_option,is_partial_revoke FROM system.grants WHERE user_name=? ORDER BY database,table,access_type").bind(&ch.users[0]).fetch_all::<(String,String,String,String,u8,u8)>().await.map_err(|_|diagnose("reader-query",Error::Unauthorized))?;
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
        #[cfg(feature = "integration")]
        eprintln!("reader grants: {:?}", grants);
        return Err(diagnose("reader-grants", Error::Unauthorized));
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
                (access == "CREATE TEMPORARY TABLE" && db.is_empty() && table.is_empty())
                    || db == "rss_ts_ch"
                        && ((access == "SELECT"
                            && matches!(
                                table.as_str(),
                                "installation" | "active_attempts" | "guard_identity"
                            ))
                            || (access == "INSERT"
                                && matches!(table.as_str(), "raw" | "summaries")))
            } else {
                (access == "SHOW COLUMNS" && db == "rss_ts_ch" && table.is_empty())
                    || (db == "rss_ts_ch"
                        && ((access == "SELECT"
                            && matches!(table.as_str(), "installation" | "raw" | "summaries"))
                            || (access == "ALTER DELETE"
                                && matches!(table.as_str(), "raw" | "summaries"))))
                    || (access == "SELECT" && db == "system" && table.is_empty())
                    || (db.is_empty()
                        && table.is_empty()
                        && (access == "KILL QUERY"
                            || matches!(
                                access.as_str(),
                                "SHOW ACCESS"
                                    | "SHOW USERS"
                                    | "SHOW ROLES"
                                    | "SHOW ROW POLICIES"
                                    | "SHOW QUOTAS"
                                    | "SHOW SETTINGS PROFILES"
                            )))
            };
            if !valid {
                return Err(Error::Unauthorized);
            }
            capabilities.insert((access, db, table));
        }
        let required = if index == 1 {
            vec![
                ("CREATE TEMPORARY TABLE", "", ""),
                ("SELECT", "rss_ts_ch", "installation"),
                ("SELECT", "rss_ts_ch", "active_attempts"),
                ("SELECT", "rss_ts_ch", "guard_identity"),
                ("INSERT", "rss_ts_ch", "raw"),
                ("INSERT", "rss_ts_ch", "summaries"),
            ]
        } else {
            vec![
                ("SHOW COLUMNS", "rss_ts_ch", ""),
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

fn diagnose(stage: &str, error: Error) -> Error {
    #[cfg(feature = "integration")]
    eprintln!("clickhouse admission: {stage}: {error}");
    #[cfg(not(feature = "integration"))]
    let _ = stage; // reason: provider phase diagnostics exist only in integration builds.
    error
}

fn guard_error(error: clickhouse::error::Error) -> Error {
    #[cfg(feature = "integration")]
    {
        let kind = match &error {
            clickhouse::error::Error::BadResponse(s) => {
                let code = s
                    .strip_prefix("Code: ")
                    .and_then(|s| s.split('.').next())
                    .and_then(|s| s.parse::<u32>().ok());
                eprintln!("guard server code: {code:?}");
                for reason in [
                    "certificate verify failed",
                    "root certificate",
                    "No such file",
                    "could not translate host name",
                    "Connection refused",
                    "password authentication failed",
                    "Permission denied",
                    "server does not support SSL",
                    "SSL error",
                    "no pg_hba.conf entry",
                ] {
                    if s.contains(reason) {
                        eprintln!("guard connection category: {reason}");
                    }
                }
                "server"
            }
            clickhouse::error::Error::SchemaMismatch(_) => "schema",
            clickhouse::error::Error::Network(_) => "network",
            _ => "decode",
        };
        eprintln!("guard query failure: {kind}");
    }
    #[cfg(not(feature = "integration"))]
    let _ = error;
    Error::Unavailable
}

async fn columns(ch: &Connections) -> Result<(), Error> {
    // Derive the exact column contract from the sole installation DDL owner.
    let mut expected_columns = Vec::new();
    for ddl in crate::installation_sql("00000000-0000-0000-0000-000000000000")? {
        let Some(rest) = ddl.strip_prefix("CREATE TABLE rss_ts_ch.") else {
            continue;
        };
        let (table, rest) = rest.split_once(" (").ok_or(Error::Invariant)?;
        let columns = rest.split_once(") ENGINE=").ok_or(Error::Invariant)?.0;
        for (position, column) in columns.split(',').enumerate() {
            let (name, kind) = column.trim().split_once(' ').ok_or(Error::Invariant)?;
            expected_columns.push((
                table.to_owned(),
                position as u64 + 1,
                name.to_owned(),
                kind.to_owned(),
                String::new(),
                String::new(),
            ));
        }
    }
    expected_columns.sort();
    let columns=ch.maintenance.query("SELECT table,position,name,type,default_kind,default_expression FROM system.columns WHERE database='rss_ts_ch' ORDER BY table,position").fetch_all::<(String,u64,String,String,String,String)>().await.map_err(|_|Error::Invariant)?;
    if columns != expected_columns {
        #[cfg(feature = "integration")]
        {
            eprintln!(
                "column counts: actual={} expected={}",
                columns.len(),
                expected_columns.len()
            );
            if let Some((a, e)) = columns.iter().zip(&expected_columns).find(|(a, e)| a != e) {
                eprintln!(
                    "column shape: actual=({},{},{},{},{}) expected=({},{},{},{},{})",
                    a.0, a.1, a.2, a.3, a.4, e.0, e.1, e.2, e.3, e.4
                );
            }
        }
        return Err(diagnose("column-contract", Error::Invariant));
    }
    let ttl=ch.maintenance.query("SELECT count() FROM system.tables WHERE database='rss_ts_ch' AND positionCaseInsensitive(create_table_query,' TTL ')>0").fetch_all::<u64>().await.map_err(|_|Error::Invariant)?;
    if ttl != vec![0] {
        return Err(Error::Invariant);
    }
    Ok(())
}
