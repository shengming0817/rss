//! Select the bounded candidate page before fetching any output-only snapshot.
use super::{AccountDirectoryRow, Cursor, after, filter, ordered_column};
use crate::transaction::{MutationError, corrupt};
use rss_identity_core::directory::{AccountQuery, Field};
use serde_json::Value;
use sqlx::{
    Arguments, Postgres, QueryBuilder, Row,
    postgres::{PgArguments, PgRow},
    types::Json,
};
use uuid::Uuid;

const SCALARS: &str = r#""principalId",login,enabled,"memberActive","hasLocalPassword","displayName",email,"profileStatus","departmentStatus""#;
const SNAPSHOT: &str = "(SELECT s.auth_facts #> '{department_snapshot,snapshot}' FROM identity_authority.sessions s WHERE s.tenant_id=$1::uuid AND s.session_id=";

fn ordering(sql: &mut QueryBuilder<Postgres>, query: &AccountQuery) {
    for (i, sort) in query.sort().iter().enumerate() {
        if i > 0 {
            sql.push(",");
        }
        sql.push(ordered_column(sort.field))
            .push(if sort.descending {
                " DESC NULLS LAST"
            } else {
                " ASC NULLS LAST"
            });
    }
}

pub(super) fn query(
    tenant: String,
    department: Option<Uuid>,
    profile: Option<&str>,
    max_age: u32,
    now: i64,
    query: &AccountQuery,
    seek: Option<&Cursor>,
) -> Result<QueryBuilder<Postgres>, MutationError> {
    let mut args = PgArguments::default();
    args.add(tenant).map_err(|_| corrupt())?;
    args.add(department).map_err(|_| corrupt())?;
    args.add(now).map_err(|_| corrupt())?;
    args.add(profile).map_err(|_| corrupt())?;
    args.add(i64::from(max_age)).map_err(|_| corrupt())?;
    let mut sql = QueryBuilder::with_arguments("WITH ", args);
    if department.is_some() {
        sql.push(include_str!("../department-facts.sql"));
    }
    sql.push(concat!(
        " profile_facts AS NOT MATERIALIZED (",
        include_str!("../profile-facts.sql"),
        ")",
        include_str!("../account-directory.sql")
    ));
    sql.push(", directory AS (SELECT b.*,");
    if department.is_some() {
        sql.push(r#"coalesce(d.status,CASE WHEN b.enabled AND b."memberActive" THEN 'missing' ELSE 'unavailable' END) AS "departmentStatus",
            CASE WHEN d.status='available' THEN d.session_id END AS accepted_session,"#);
        // This expression is used only by membership predicates; the page never carries it.
        sql.push(SNAPSHOT).push(
            r#"d.session_id) AS "departmentSnapshot"
            FROM account_base b LEFT JOIN department_facts d ON d.principal_id=b."principalId")"#,
        );
    } else {
        sql.push(r#"'unavailable'::text AS "departmentStatus", NULL::uuid AS accepted_session FROM account_base b)"#);
    }
    sql.push(", page AS (SELECT ")
        .push(SCALARS)
        .push(",accepted_session FROM directory r WHERE ");
    if let Some(expression) = query.filter() {
        filter(&mut sql, expression)?;
    } else {
        sql.push("true");
    }
    if let Some(cursor) = seek {
        after(&mut sql, query, &cursor.position)?;
    }
    sql.push(" ORDER BY ");
    ordering(&mut sql, query);
    sql.push(" LIMIT ")
        .push_bind(i64::from(query.limit()) + 1)
        .push(") SELECT ")
        .push(SCALARS);
    if query.fields().contains(&Field::DepartmentSnapshot) {
        sql.push(",CASE WHEN row_number() OVER (ORDER BY ");
        ordering(&mut sql, query);
        sql.push(") <= ")
            .push_bind(i64::from(query.limit()))
            .push(" THEN ")
            .push(SNAPSHOT)
            .push("p.accepted_session) END");
    } else {
        sql.push(",NULL::jsonb");
    }
    sql.push(" AS snapshot,");
    if department.is_some() {
        // The aggregate preserves the off-page clock even when the page has no rows.
        sql.push("w.next_change FROM (SELECT min(next_change) AS next_change FROM department_facts) w LEFT JOIN page p ON true");
    } else {
        sql.push("NULL::bigint AS next_change FROM page p");
    }
    sql.push(" ORDER BY ");
    ordering(&mut sql, query);
    Ok(sql)
}

pub(super) fn decode(row: &PgRow, id: Uuid) -> Result<AccountDirectoryRow, MutationError> {
    Ok(AccountDirectoryRow {
        principal_id: id.to_string(),
        login: row.try_get("login")?,
        enabled: row.try_get("enabled")?,
        member_active: row.try_get("memberActive")?,
        has_local_password: row.try_get("hasLocalPassword")?,
        display_name: row.try_get("displayName")?,
        email: row.try_get("email")?,
        profile_status: row.try_get("profileStatus")?,
        department_status: row.try_get("departmentStatus")?,
        department_snapshot: row
            .try_get::<Option<Json<_>>, _>("snapshot")
            .map_err(|_| corrupt())?
            .map(|v| v.0),
    })
}

pub(super) fn position(query: &AccountQuery, row: &PgRow) -> Result<Vec<Value>, MutationError> {
    query
        .sort()
        .iter()
        .map(|sort| {
            let field = sort.field;
            Ok(if field == Field::PrincipalId {
                Value::from(row.try_get::<Uuid, _>(field.name())?.to_string())
            } else if field.boolean() {
                Value::from(row.try_get::<bool, _>(field.name())?)
            } else {
                Value::from(row.try_get::<Option<&str>, _>(field.name())?)
            })
        })
        .collect()
}
