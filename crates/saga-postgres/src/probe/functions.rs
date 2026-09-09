//! Read only the bundled declaration grammar; PostgreSQL resolves exact routine identities.
use crate::{Error, MIGRATION_SQL, sql_error};
use sqlx::{PgConnection, Row as _};

pub(super) async fn validate(conn: &mut PgConnection) -> Result<(), Error> {
    let definitions = definitions(MIGRATION_SQL).map_err(|()| invalid())?;
    let signatures: Vec<_> = definitions.iter().map(|d| d.signature.as_str()).collect();
    let returns: Vec<_> = definitions.iter().map(|d| d.returns).collect();
    let rows = sqlx::query(
        r#"
WITH expected AS (SELECT * FROM unnest($1::text[],$2::text[]) AS e(signature,result)),
actual AS (
    SELECT p.*, n.nspowner FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='rss_saga'
)
SELECT e.signature, p.prosrc, p.prosecdef, pg_get_function_identity_arguments(p.oid) AS arguments,
    p.prorettype=to_regtype(e.result) AND NOT p.proretset
    AND p.proowner=p.nspowner AND p.prokind='f'
    AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
    AND NOT p.proisstrict AND NOT p.proleakproof AND p.provolatile='v' AND p.proparallel='u'
    AND p.pronargdefaults=0 AND p.provariadic=0 AND p.proargmodes IS NULL
    AND p.prosupport=0 AND p.protrftypes IS NULL
    AND p.proconfig=ARRAY['search_path=pg_catalog, rss_saga']::text[]
    AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE a.grantee=0) AS canonical
FROM expected e FULL JOIN actual p ON p.oid=to_regprocedure(e.signature)
"#,
    )
    .bind(signatures)
    .bind(returns)
    .fetch_all(conn)
    .await
    .map_err(sql_error)?;
    if rows.len() != definitions.len() {
        return Err(invalid());
    }
    for definition in definitions {
        let row = rows
            .iter()
            .find(|row| {
                row.try_get::<Option<String>, _>("signature")
                    .is_ok_and(|s| s.as_deref() == Some(&definition.signature))
            })
            .ok_or_else(invalid)?;
        if row
            .try_get::<Option<bool>, _>("canonical")
            .map_err(sql_error)?
            != Some(true)
            || row.try_get::<bool, _>("prosecdef").map_err(sql_error)? != definition.definer
            || compact(&row.try_get::<String, _>("arguments").map_err(sql_error)?)
                != compact(definition.arguments)
            || row
                .try_get::<String, _>("prosrc")
                .map_err(sql_error)?
                .trim()
                != definition.body.trim()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> Error {
    Error::new(rss_saga::ErrorKind::Integrity)
}
fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}
#[derive(Debug)]
struct Definition<'a> {
    name: &'a str,
    signature: String,
    arguments: &'a str,
    returns: &'a str,
    definer: bool,
    body: &'a str,
}
// This is deliberately not a general SQL parser: unknown migration syntax fails closed.
fn definitions(sql: &str) -> Result<Vec<Definition<'_>>, ()> {
    let mut result = Vec::new();
    for declaration in sql.split("CREATE FUNCTION ").skip(1) {
        let declaration = declaration.strip_prefix("rss_saga.").ok_or(())?;
        let (name, rest) = declaration.split_once('(').ok_or(())?;
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            || result.iter().any(|d: &Definition<'_>| d.name == name)
        {
            return Err(());
        }
        let (arguments, rest) = rest.split_once(") RETURNS ").ok_or(())?;
        let (returns, rest) = rest.split_once(" LANGUAGE plpgsql ").ok_or(())?;
        let definer = rest.starts_with("SECURITY DEFINER ");
        let rest = rest.strip_prefix("SECURITY DEFINER ").unwrap_or(rest);
        let rest = rest
            .strip_prefix("SET search_path=pg_catalog,rss_saga AS $$")
            .ok_or(())?;
        let (body, _) = rest.split_once("$$;").ok_or(())?;
        if body.trim().is_empty() || !matches!(returns, "trigger" | "void" | "bigint" | "jsonb") {
            return Err(());
        }
        result.push(Definition {
            name,
            signature: format!("rss_saga.{name}({})", argument_types(arguments)?.join(",")),
            arguments,
            returns,
            definer,
            body,
        });
    }
    if result.len() != 6 {
        return Err(());
    }
    Ok(result)
}
fn argument_types(arguments: &str) -> Result<Vec<&str>, ()> {
    if arguments.is_empty() {
        return Ok(Vec::new());
    }
    arguments
        .split(',')
        .map(|arg| {
            let mut tokens = arg.split_whitespace();
            let _name = tokens.next().ok_or(())?;
            let ty = tokens.next().ok_or(())?;
            if tokens.next().is_some() || !matches!(ty, "uuid" | "jsonb" | "bigint" | "bytea") {
                return Err(());
            }
            Ok(ty)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shipped_declarations_have_exact_signatures() -> Result<(), ()> {
        let definitions = definitions(MIGRATION_SQL)?;
        assert_eq!(
            definitions
                .iter()
                .map(|d| d.signature.as_str())
                .collect::<Vec<_>>(),
            [
                "rss_saga.assert_receipt_pair()",
                "rss_saga.register(uuid,jsonb)",
                "rss_saga.claim(uuid,uuid,bigint)",
                "rss_saga.lock_instance(uuid,uuid,bigint)",
                "rss_saga.lease(uuid,uuid,bigint,bigint)",
                "rss_saga.commit_event(uuid,uuid,bigint,jsonb,bytea)",
            ]
        );
        Ok(())
    }
    #[test]
    fn incomplete_or_unknown_migration_grammar_fails_closed() {
        for sql in [
            String::new(),
            MIGRATION_SQL.replace("rss_saga.lease(", "rss_saga.claim("),
            MIGRATION_SQL.replace("AS $$", "AS $other$"),
            MIGRATION_SQL.replace("LANGUAGE plpgsql", "LANGUAGE sql"),
            MIGRATION_SQL.replace("p_ttl bigint)", "p_ttl bigint DEFAULT 1)"),
            MIGRATION_SQL.replace("RETURNS void", "RETURNS SETOF void"),
        ] {
            assert!(definitions(&sql).is_err());
        }
    }
}
