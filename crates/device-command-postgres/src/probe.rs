//! The bundled migration is the sole function definition source; admission never executes it.
use crate::{MIGRATION_SQL, persistence::error};
use rss_device_command::Error;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use sqlx::{PgConnection, Row};

pub(crate) async fn validate(tx: &mut PgTransaction<'_>) -> Result<(), PgError> {
    let failure = tx
        .with_connection(|conn| {
            Box::pin(async move {
                let failure: Option<String> = sqlx::query_scalar(include_str!("probe.sql"))
                    .fetch_optional(&mut *conn)
                    .await?;
                if failure.is_some() {
                    return Ok(failure);
                }
                Ok((!functions(conn).await?).then(|| "functions".to_owned()))
            })
        })
        .await?;
    if let Some(raw) = failure {
        let reason = match raw.as_str() {
            "revision" => "revision",
            "relations" => "relations",
            "runtime_role" => "runtime_role",
            "runtime_acl" => "runtime_acl",
            "rls_policy" => "rls_policy",
            "functions" => "functions",
            _ => "unknown",
        };
        tracing::warn!(
            phase = "probe",
            reason,
            "device command storage contract rejected"
        );
        return Err(error(Error::InvalidSnapshot));
    }
    Ok(())
}

async fn functions(conn: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let Ok(definitions) = definitions(MIGRATION_SQL) else {
        return Ok(false);
    };
    let signatures: Vec<_> = definitions.iter().map(|d| d.signature.as_str()).collect();
    let returns: Vec<_> = definitions.iter().map(|d| d.returns).collect();
    let rows = sqlx::query(
        r#"
WITH expected AS (SELECT * FROM unnest($1::text[],$2::text[]) AS e(signature,result))
SELECT p.proname, p.prosrc, pg_get_function_identity_arguments(p.oid) AS arguments,
    p.proretset, p.prorettype=to_regtype(e.result) AS returns,
    p.prosecdef AND p.prokind='f' AND l.lanname='sql'
        AND NOT p.proisstrict AND p.provolatile='v' AND p.proparallel='u' AND NOT p.proleakproof
        AND NOT owner.rolsuper AND NOT owner.rolbypassrls AND p.proowner=n.nspowner
        AND p.proconfig=ARRAY['search_path=pg_catalog, rss_device_command']::text[]
        AND has_function_privilege(current_user,p.oid,'EXECUTE') AS safe
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
JOIN pg_roles owner ON owner.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
LEFT JOIN expected e ON p.oid=to_regprocedure(e.signature)
WHERE n.nspname='rss_device_command'
"#,
    )
    .bind(signatures)
    .bind(returns)
    .fetch_all(conn)
    .await?;
    if rows.len() != definitions.len() {
        return Ok(false);
    }
    for definition in definitions {
        let Some(row) = rows.iter().find(|r| {
            r.try_get::<String, _>("proname")
                .is_ok_and(|name| name == definition.name)
        }) else {
            return Ok(false);
        };
        if row.try_get::<Option<bool>, _>("safe")? != Some(true)
            || row.try_get::<Option<bool>, _>("returns")? != Some(true)
            || row.try_get::<bool, _>("proretset")? != definition.setof
            || compact(&row.try_get::<String, _>("arguments")?) != compact(definition.arguments)
            || row.try_get::<String, _>("prosrc")?.trim() != definition.body.trim()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug)]
struct Definition<'a> {
    name: &'a str,
    signature: String,
    arguments: &'a str,
    returns: &'a str,
    setof: bool,
    body: &'a str,
}
fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}
// This is a reader for the shipped five-function declaration grammar, not a general SQL parser.
fn definitions(sql: &str) -> Result<Vec<Definition<'_>>, ()> {
    let mut result = Vec::new();
    for declaration in sql.split("CREATE FUNCTION ").skip(1) {
        let declaration = declaration.strip_prefix("rss_device_command.").ok_or(())?;
        let (name, rest) = declaration.split_once('(').ok_or(())?;
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            || result.iter().any(|d: &Definition<'_>| d.name == name)
        {
            return Err(());
        }
        let (arguments, rest) = rest.split_once(") RETURNS ").ok_or(())?;
        let (returns, rest) = rest.split_once("\nLANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS $$").ok_or(())?;
        let (body, _) = rest.split_once("$$;").ok_or(())?;
        let setof = returns.starts_with("SETOF ");
        let returns = returns.strip_prefix("SETOF ").unwrap_or(returns);
        let types: Result<Vec<_>, _> = arguments
            .split(',')
            .map(|arg| {
                let mut tokens = arg.split_whitespace();
                let _name = tokens.next().ok_or(())?;
                let ty = tokens.next().ok_or(())?;
                if tokens.next().is_some() {
                    return Err(());
                }
                Ok(ty)
            })
            .collect();
        if body.trim().is_empty() || returns.is_empty() {
            return Err(());
        }
        result.push(Definition {
            name,
            signature: format!("rss_device_command.{name}({})", types?.join(",")),
            arguments,
            returns,
            setof,
            body,
        });
    }
    if result.len() != 5 {
        return Err(());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_definitions_are_complete() -> Result<(), ()> {
        let definitions = definitions(MIGRATION_SQL)?;
        assert_eq!(
            definitions.iter().map(|d| d.name).collect::<Vec<_>>(),
            ["initialize", "lock_authority", "advance", "enqueue", "save"]
        );
        assert!(definitions.iter().all(|d| !d.body.trim().is_empty()));
        Ok(())
    }
    #[test]
    fn malformed_or_missing_definitions_fail_closed() {
        assert!(definitions("").is_err());
        assert!(
            definitions(&MIGRATION_SQL.replace(
                "CREATE FUNCTION rss_device_command.save",
                "CREATE FUNCTION rss_device_command.enqueue"
            ))
            .is_err()
        );
        assert!(definitions(&MIGRATION_SQL.replace("AS $$", "AS $other$")).is_err());
        let truncated = MIGRATION_SQL
            .split("CREATE FUNCTION rss_device_command.save")
            .next()
            .unwrap_or("");
        assert!(definitions(truncated).is_err());
    }
}
