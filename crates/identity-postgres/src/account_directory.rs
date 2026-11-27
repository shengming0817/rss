//! Account queries execute before LIMIT under the authenticated tenant transaction.
//! ref: launchbadge/sqlx v0.9.0 sqlx-core/src/query_builder.rs.
use crate::{
    transaction::{MutationError, corrupt, reject},
    types::Budget,
    *,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use rss_identity_core::directory::{AccountQuery, Expression, Field};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, QueryBuilder};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDirectoryRow {
    pub principal_id: String,
    pub login: Option<String>,
    pub enabled: bool,
    pub member_active: bool,
    pub has_local_password: bool,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub profile_status: String,
    pub department_status: String,
    pub department_snapshot: Option<rss_identity_core::department::DepartmentSnapshot>,
}
/// Across pages, the directory guarantees consistency for the requested projection,
/// filter and sort. Embedded callers should use `fields` to project each row.
pub struct AccountPage {
    pub accounts: Vec<AccountDirectoryRow>,
    pub fields: Vec<Field>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    binding: Vec<u8>,
    expires: i64,
    position: Vec<Value>,
}

fn column(field: Field) -> &'static str {
    match field {
        Field::PrincipalId => "\"principalId\"",
        Field::Login => "login COLLATE \"C\"",
        Field::Enabled => "enabled",
        Field::MemberActive => "\"memberActive\"",
        Field::HasLocalPassword => "\"hasLocalPassword\"",
        Field::DisplayName => "\"displayName\" COLLATE \"C\"",
        Field::Email => "email COLLATE \"C\"",
        Field::ProfileStatus => "\"profileStatus\" COLLATE \"C\"",
        Field::DepartmentStatus => "\"departmentStatus\" COLLATE \"C\"",
        _ => unreachable!("checked scalar field"),
    }
}
// Cursor positions and text search use the public canonical rendering of a UUID.
fn ordered_column(field: Field) -> &'static str {
    if field == Field::PrincipalId {
        "\"principalId\"::text COLLATE \"C\""
    } else {
        column(field)
    }
}

fn operand(sql: &mut QueryBuilder<Postgres>, field: Field, value: &str) {
    if field.boolean() {
        sql.push_bind(value == "true");
    } else if field == Field::PrincipalId {
        sql.push_bind(uuid::Uuid::parse_str(value).expect("validated principal operand"));
    } else {
        sql.push_bind(value.to_owned());
    }
}
const ANCESTORS: &str = include_str!("department-ancestors.sql");

// Fold only siblings with the same logical operator. A mixed branch must keep its
// own subtree evaluation so that another branch can satisfy the filter first.
fn collect_terms<'a>(
    items: &'a [Expression],
    any: bool,
    other: &mut Vec<&'a Expression>,
    departments: &mut Vec<String>,
) {
    for item in items {
        match item {
            Expression::Or(nested) if any => collect_terms(nested, any, other, departments),
            Expression::And(nested) if !any => collect_terms(nested, any, other, departments),
            Expression::Compare {
                field: Field::DepartmentSubtree,
                values,
                ..
            } => {
                departments.push(values[0].clone());
            }
            _ => other.push(item),
        }
    }
}

fn subtree(sql: &mut QueryBuilder<Postgres>, targets: Vec<String>, any: bool) {
    sql.push("\"departmentStatus\"='available' AND ");
    if any || targets.len() == 1 {
        sql.push("EXISTS (")
            .push(ANCESTORS)
            .push("SELECT FROM ancestors WHERE id=ANY(")
            .push_bind(targets)
            .push("))");
    } else {
        sql.push_bind(targets)
            .push(" <@ ARRAY(")
            .push(ANCESTORS)
            .push("SELECT id FROM ancestors)");
    }
}

fn filter(sql: &mut QueryBuilder<Postgres>, expression: &Expression) {
    sql.push("(");
    match expression {
        Expression::And(items) | Expression::Or(items) => {
            let any = matches!(expression, Expression::Or(_));
            let separator = if any { " OR " } else { " AND " };
            let mut other = Vec::new();
            let mut departments = Vec::new();
            collect_terms(items, any, &mut other, &mut departments);
            for (index, item) in other.iter().enumerate() {
                if index > 0 {
                    sql.push(separator);
                }
                filter(sql, item);
            }
            if !departments.is_empty() {
                if !other.is_empty() {
                    sql.push(separator);
                }
                subtree(sql, departments, any);
            }
        }
        Expression::Compare {
            field,
            operator,
            values,
        } => {
            if *field == Field::Department {
                sql.push("\"departmentStatus\"='available' AND (\"departmentSnapshot\"->'memberships') ? ")
                    .push_bind(values[0].clone());
            } else if *field == Field::DepartmentSubtree {
                subtree(sql, values.clone(), true);
            } else if matches!(operator.as_str(), "=isnull=" | "=isnotnull=") {
                sql.push(column(*field)).push(if operator == "=isnull=" {
                    " IS NULL"
                } else {
                    " IS NOT NULL"
                });
            } else if operator == "=icontains=" {
                sql.push("strpos(lower(")
                    .push(ordered_column(*field))
                    .push("),lower(")
                    .push_bind(values[0].clone())
                    .push("))>0");
            } else {
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        sql.push(if operator == "=out=" { " AND " } else { " OR " });
                    }
                    sql.push(column(*field)).push(match operator.as_str() {
                        "==" | "=in=" => " = ",
                        "!=" | "=out=" => " <> ",
                        "=lt=" => " < ",
                        "=le=" => " <= ",
                        "=gt=" => " > ",
                        "=ge=" => " >= ",
                        _ => unreachable!("checked operator"),
                    });
                    operand(sql, *field, value);
                }
            }
        }
    }
    sql.push(")");
}
fn position(sql: &mut QueryBuilder<Postgres>, field: Field, value: &Value) {
    if value.is_null() {
        sql.push(if field.boolean() {
            "NULL::boolean"
        } else {
            "NULL::text"
        });
    } else if field.boolean() {
        sql.push_bind(value.as_bool().expect("checked boolean cursor"));
    } else {
        sql.push_bind(value.as_str().expect("checked text cursor").to_owned());
    }
}
fn after(sql: &mut QueryBuilder<Postgres>, query: &AccountQuery, values: &[Value]) {
    sql.push(" AND (");
    for (index, sort) in query.sort().iter().enumerate() {
        if index > 0 {
            sql.push(" OR ");
        }
        sql.push("(");
        for (prefix, value) in values.iter().enumerate().take(index) {
            sql.push(ordered_column(query.sort()[prefix].field))
                .push(" IS NOT DISTINCT FROM ");
            position(sql, query.sort()[prefix].field, value);
            sql.push(" AND ");
        }
        if values[index].is_null() {
            sql.push("false");
        } else {
            sql.push("(")
                .push(ordered_column(sort.field))
                .push(if sort.descending { " < " } else { " > " });
            position(sql, sort.field, &values[index]);
            sql.push(" OR ")
                .push(ordered_column(sort.field))
                .push(" IS NULL)");
        }
        sql.push(")");
    }
    sql.push(")");
}
const CURSOR_DOMAIN: &[u8] = b"identity.accounts.cursor.v2\0";

fn encode(key: &[u8], cursor: &Cursor) -> Result<String, MutationError> {
    let plain = serde_json::to_vec(cursor).map_err(|_| corrupt())?;
    let mut signed = CURSOR_DOMAIN.to_vec();
    signed.extend(&plain);
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &signed);
    let mut bytes = tag.as_ref().to_vec();
    bytes.extend(plain);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn decode(key: &[u8], raw: &str) -> Result<Cursor, MutationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| MutationError::InvalidInput)?;
    if bytes.len() <= 32 || bytes.len() > 4096 {
        return Err(MutationError::InvalidInput);
    }
    let mut signed = CURSOR_DOMAIN.to_vec();
    signed.extend(&bytes[32..]);
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &signed,
        &bytes[..32],
    )
    .map_err(|_| MutationError::CursorInvalidated)?;
    serde_json::from_slice(&bytes[32..]).map_err(|_| MutationError::InvalidInput)
}

impl Authority {
    pub async fn read_account(
        &self,
        actor: AuthenticatedSession,
        target: AccountKey,
        deadline: OperationDeadline,
    ) -> Result<AccountView, AuthorityError> {
        self.require_runtime()?;
        if target.tenant != actor.key.tenant {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        self.read_sql(actor.binding,budget.remaining(),move |c|Box::pin(async move {
            let loaded=crate::session_storage::recheck_collection(c,&actor).await?;
            crate::management::authorize(policy.as_ref(),instance,&loaded,ManagementOperation::ReadAccount,Some(target),c).await?;
            let expires=crate::sessions::checked_expiry(&loaded,budget.0.instant())?;
            let state=crate::storage::account_state_locked(c,target).await?;
            let login=sqlx::query_scalar("SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::uuid AND principal_id=$2").bind(target.tenant.to_string()).bind(target.principal.as_uuid()).fetch_optional(c).await?;
            if std::time::Instant::now()>=expires { return Err(reject().into()); }
            Ok(AccountView::new(state,login))
        })).await
    }
    pub async fn list_accounts(
        &self,
        actor: AuthenticatedSession,
        query: AccountQuery,
        cursor: Option<String>,
        deadline: OperationDeadline,
    ) -> Result<AccountPage, AuthorityError> {
        self.require_runtime()?;
        if cursor
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 4096)
        {
            return Err(AuthorityError::InvalidInput);
        }
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);
        let policy = self.policy.clone();
        let instance = self.instance;
        let max_age = self.profile_limits.max_age_seconds();
        self.read_sql(actor.binding, budget.remaining(), move |c| {
            Box::pin(async move {
                let loaded = crate::session_storage::recheck_collection(c, &actor).await?;
                let deps = crate::directory_window::ReadDependencies::accounts(&query, max_age)?;
                let profiles = deps.profile_age.is_some();
                let department_source = deps.department;
                for op in [
                    Some(ManagementOperation::ListAccounts),
                    profiles.then_some(ManagementOperation::ReadLatestProfile),
                    department_source
                        .is_some()
                        .then_some(ManagementOperation::ReadLatestDepartments),
                ]
                .into_iter()
                .flatten()
                {
                    crate::management::authorize(policy.as_ref(), instance, &loaded, op, None, c)
                        .await?;
                }
                let actor_deadline = crate::sessions::checked_expiry(&loaded, budget.0.instant())?;
                let window = deps
                    .window(
                        c,
                        actor.key.tenant,
                        actor_deadline,
                        Some(
                            loaded
                                .view
                                .idle_expires_at
                                .min(loaded.view.absolute_expires_at),
                        ),
                    )
                    .await?;
                // Persisted independently of any client credential; shared by all Authority instances.
                let key: Vec<u8> = sqlx::query_scalar(
                    "SELECT account_cursor_key FROM identity_authority.deployment",
                )
                .fetch_one(&mut *c)
                .await?;
                let key = zeroize::Zeroizing::new(key);
                let binding = Sha256::digest(
                    serde_json::to_vec(&(
                        instance.to_string(),
                        actor.key.tenant.to_string(),
                        actor.key.principal.as_uuid().to_string(),
                        loaded.view.id.to_string(),
                        window.generation,
                        deps.profile_age,
                        &query,
                    ))
                    .map_err(|_| corrupt())?,
                )
                .to_vec();
                let seek = cursor.as_ref().map(|raw| decode(&key, raw)).transpose()?;
                let mut page_deadline = window.expires;
                if let Some(seek) = &seek {
                    if seek.binding != binding || seek.expires <= window.clock.seconds() {
                        return Err(MutationError::CursorInvalidated);
                    }
                    page_deadline = page_deadline.min(window.clock.deadline(seek.expires)?);
                    if seek.position.len() != query.sort().len()
                        || query
                            .sort()
                            .iter()
                            .zip(&seek.position)
                            .any(|(sort, value)| {
                                !value.is_null()
                                    && if sort.field.boolean() {
                                        !value.is_boolean()
                                    } else {
                                        !value.is_string()
                                    }
                            })
                    {
                        return Err(MutationError::InvalidInput);
                    }
                }

                // The five prefix parameters are bound explicitly; only owner-controlled columns enter SQL.
                let mut sql = QueryBuilder::<Postgres>::with_arguments(
                    concat!(
                        include_str!("department-facts.sql"),
                        ", profile_facts AS NOT MATERIALIZED (",
                        include_str!("profile-facts.sql"),
                        ")",
                        include_str!("account-directory.sql")
                    ),
                    {
                        use sqlx::Arguments;
                        let mut args = sqlx::postgres::PgArguments::default();
                        args.add(actor.key.tenant.to_string())
                            .map_err(|_| corrupt())?;
                        args.add(department_source).map_err(|_| corrupt())?;
                        args.add(window.clock.seconds()).map_err(|_| corrupt())?;
                        args.add(query.source().filter(|_| profiles).map(str::to_owned))
                            .map_err(|_| corrupt())?;
                        args.add(i64::from(max_age)).map_err(|_| corrupt())?;
                        args
                    },
                );
                sql.push("SELECT to_jsonb(r) FROM account_rows r WHERE ");
                if let Some(expression) = query.filter() {
                    filter(&mut sql, expression);
                } else {
                    sql.push("true");
                }
                if let Some(seek) = &seek {
                    after(&mut sql, &query, &seek.position);
                }
                sql.push(" ORDER BY ");
                for (index, sort) in query.sort().iter().enumerate() {
                    if index > 0 {
                        sql.push(",");
                    }
                    sql.push(ordered_column(sort.field))
                        .push(if sort.descending {
                            " DESC NULLS LAST"
                        } else {
                            " ASC NULLS LAST"
                        });
                }
                sql.push(" LIMIT ").push_bind(i64::from(query.limit()) + 1);
                let values: Vec<Value> = sql.build_query_scalar().fetch_all(&mut *c).await?;
                let more = values.len() > usize::from(query.limit());
                let values: Vec<_> = values
                    .into_iter()
                    .take(usize::from(query.limit()))
                    .collect();
                let next_cursor = if more {
                    let last = values.last().ok_or_else(corrupt)?;
                    Some(encode(
                        &key,
                        &Cursor {
                            binding,
                            expires: window.valid_until,
                            position: query
                                .sort()
                                .iter()
                                .map(|s| last[s.field.name()].clone())
                                .collect(),
                        },
                    )?)
                } else {
                    None
                };
                let accounts = values
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| corrupt())?;
                let finished = std::time::Instant::now();
                if finished >= actor_deadline {
                    return Err(reject().into());
                }
                if finished >= page_deadline {
                    return Err(MutationError::CursorInvalidated);
                }
                Ok(AccountPage {
                    accounts,
                    fields: query.fields().to_vec(),
                    next_cursor,
                })
            })
        })
        .await
    }
}
