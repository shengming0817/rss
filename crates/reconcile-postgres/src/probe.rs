//! Validate the dedicated schema and reachable role posture on the actual connection.
use rss_reconcile::{Error, ErrorKind};
use sqlx::{PgConnection, PgPool, Row};
// CHECK definitions are the catalog projection of MIGRATION_SQL, verified by real PG tests.
const RUNTIME: &str = include_str!("runtime-admission.sql");
const STRUCTURE: &str = include_str!("structure-admission.sql");

#[derive(Clone, Copy)]
pub(crate) enum Admission {
    Full,
    Discovery,
}
impl Admission {
    pub(crate) async fn validate(self, conn: &mut PgConnection) -> Result<(), Error> {
        validate_runtime(conn).await?;
        match self {
            Self::Full => validate_structure(conn).await,
            // A discovery transaction cannot return authority or invoke a business callback.
            Self::Discovery => Ok(()),
        }
    }
}

pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let mut conn = pool.acquire().await.map_err(crate::transaction::map_sql)?;
    validate_connection(&mut conn).await
}
pub(crate) async fn validate_connection(conn: &mut PgConnection) -> Result<(), Error> {
    Admission::Full.validate(conn).await
}
async fn check(conn: &mut PgConnection, sql: &'static str) -> Result<(), Error> {
    let safe = sqlx::query_scalar::<_, Option<bool>>(sql)
        .fetch_one(conn)
        .await
        .map_err(crate::transaction::map_sql)?;
    if safe == Some(true) {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::StorageContract))
    }
}
async fn validate_runtime(conn: &mut PgConnection) -> Result<(), Error> {
    check(conn, RUNTIME).await
}
pub(crate) async fn validate_structure(conn: &mut PgConnection) -> Result<(), Error> {
    check(conn, STRUCTURE).await?;
    functions(conn).await
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
