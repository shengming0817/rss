use crate::{AdmissionViolation as Violation, Error, MIGRATION_SQL};
use rss_request_context::TenantId;
use sqlx::{
    Connection, PgConnection, Postgres, Row,
    postgres::{PgArguments, PgRow},
    query::Query,
};

pub(crate) async fn tenant(connection: &mut PgConnection, expected: TenantId) -> Result<(), Error> {
    let setting: Option<String> =
        sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
            .fetch_one(connection)
            .await?;
    if setting.as_deref().and_then(|s| TenantId::parse(s).ok()) != Some(expected) {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}
pub(crate) async fn validate(connection: &mut PgConnection) -> Result<(), Error> {
    inspect(connection, true).await
}
pub(crate) async fn validate_read(connection: &mut PgConnection) -> Result<(), Error> {
    inspect(connection, false).await
}
/// Check the Audit indexes, constraints and append function in the caller's transaction.
/// Reads only the PostgreSQL catalogs. The caller owns the connection, deadline and settlement.
/// Use startup admission on the actual runtime connection to verify role privileges and RLS.
pub async fn validate_structure(connection: &mut PgConnection) -> Result<(), Error> {
    let query = structure_query(concat!(
        include_str!("structure.sql"),
        "SELECT * FROM structure"
    ))?;
    let row = catalog_row(connection, query).await?;
    check(
        &row,
        &[
            ("indexes", Violation::Shape),
            ("constraints", Violation::Shape),
            ("functions", Violation::Functions),
        ],
    )
}

fn structure_query(sql: &'static str) -> Result<Query<'static, Postgres, PgArguments>, Error> {
    let append_body = MIGRATION_SQL
        .split("$append$")
        .nth(1)
        .ok_or(Error::StorageContract)?;
    let mut expected = vec![
        "records:CHECK (((octet_length(source_id) >= 1) AND (octet_length(source_id) <= 255)))",
        "records:CHECK (((octet_length(event_id) >= 1) AND (octet_length(event_id) <= 255)))",
        "records:CHECK ((\"position\" >= 0))",
        "records:CHECK ((recorded_at >= 0))",
        "records:CHECK (((octet_length(canonical) >= 1) AND (octet_length(canonical) <= 131072)))",
        "records:CHECK ((ledger_sequence >= 0))",
        "records:PRIMARY KEY (tenant_id, source_id, event_id)",
        "records:UNIQUE (tenant_id, \"position\")",
    ];
    expected.sort();
    Ok(sqlx::query(sql).bind(append_body).bind(expected))
}

async fn inspect(connection: &mut PgConnection, require_append: bool) -> Result<(), Error> {
    let query = structure_query(concat!(
        include_str!("structure.sql"),
        include_str!("admission.sql")
    ))?
    .bind("(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)")
    .bind(require_append);
    let row = catalog_row(connection, query).await?;
    check(
        &row,
        &[
            ("roles", Violation::Role),
            ("schema", Violation::Schema),
            ("forced_rls", Violation::Rls),
            ("indexes", Violation::Shape),
            ("columns", Violation::Shape),
            ("constraints", Violation::Shape),
            ("policies", Violation::Rls),
            ("functions", Violation::Functions),
            ("privileges", Violation::Permissions),
        ],
    )
}

/// SQLx tracks its own transaction depth. A PgConnection may also have a
/// transaction opened with SQL BEGIN. Never roll back that caller's work.
async fn catalog_row(
    connection: &mut PgConnection,
    query: Query<'static, Postgres, PgArguments>,
) -> Result<PgRow, Error> {
    if !connection.is_in_transaction() && has_external_transaction(connection).await? {
        sqlx::raw_sql("SAVEPOINT rss_audit_probe")
            .execute(&mut *connection)
            .await?;
        let row = pinned_row(connection, query).await;
        sqlx::raw_sql("ROLLBACK TO SAVEPOINT rss_audit_probe; RELEASE SAVEPOINT rss_audit_probe")
            .execute(connection)
            .await?;
        return row;
    }
    let mut scope = connection.begin().await?;
    let row = pinned_row(&mut scope, query).await;
    scope.rollback().await?;
    row
}

// A virtual transaction ID is stable inside a transaction (including read-only
// transactions) and distinct in successive autocommit statements. Neither read
// allocates a permanent XID or sends an intentionally failing SAVEPOINT.
async fn has_external_transaction(connection: &mut PgConnection) -> Result<bool, Error> {
    const VXID: &str = "SELECT virtualtransaction FROM pg_catalog.pg_locks
        WHERE pid OPERATOR(pg_catalog.=) pg_catalog.pg_backend_pid()
        AND locktype OPERATOR(pg_catalog.=) 'virtualxid'
        AND mode OPERATOR(pg_catalog.=) 'ExclusiveLock' AND granted";
    let first: String = sqlx::query_scalar(VXID).fetch_one(&mut *connection).await?;
    let second: String = sqlx::query_scalar(VXID).fetch_one(connection).await?;
    Ok(first == second)
}

async fn pinned_row(
    connection: &mut PgConnection,
    query: Query<'static, Postgres, PgArguments>,
) -> Result<PgRow, Error> {
    sqlx::raw_sql("SET LOCAL search_path=pg_catalog,pg_temp; SET LOCAL quote_all_identifiers=off")
        .execute(&mut *connection)
        .await?;
    Ok(query.fetch_one(connection).await?)
}

fn check(row: &PgRow, flags: &[(&str, Violation)]) -> Result<(), Error> {
    for &(column, category) in flags {
        if row.try_get::<Option<bool>, _>(column)? != Some(true) {
            return Err(Error::Admission(category));
        }
    }
    Ok(())
}
