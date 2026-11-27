//! Fixed personnel relation for trusted embedded product queries, under current host policy.
//! ref: PostgreSQL REL_17_STABLE src/backend/commands/variable.c check_transaction_read_only.
use crate::{
    AuthenticatedSession, Authority, AuthorityError, ManagementOperation,
    directory_window::{ReadDependencies, ReadWindow},
    profiles::Reader,
    transaction::{MutationError, reject},
    types::Budget,
};
use futures::{TryStreamExt, future::BoxFuture};
use rss_identity_core::{InstanceId, account::AccountRuleError};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::{
    PgConnection,
    postgres::{PgArguments, PgRow},
};
use std::time::Instant;

/// Cursor binding. Time expiration remains significant even without a database mutation.
#[derive(Clone, Copy, Debug)]
pub struct PersonnelRevision {
    pub generation: i64,
    pub valid_until: i64,
    pub logins: bool,
    pub profiles: PersonnelProfileScope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonnelProfileScope {
    None,
    SelfOnly,
    All,
}
/// Borrowed only during the authenticated transaction; no raw connection or settlement capability.
/// SQL must be installed by trusted host code; end-user data belongs exclusively in bound arguments.
/// The authenticated personnel entry installs both personnel and session-reference relations.
/// The trusted session-reference entry installs only `identity_session_references`; neither entry grants authentication.
/// Consumers join their own authorized business relations, never private Identity tables.
pub struct PersonnelRead<'a> {
    connection: &'a mut PgConnection,
    relation: String,
    expires: Instant,
    revision: PersonnelRevision,
}
impl<'a> PersonnelRead<'a> {
    pub(crate) fn session_references(
        connection: &'a mut PgConnection,
        relation: String,
        window: ReadWindow,
    ) -> Self {
        Self {
            connection,
            relation,
            expires: window.expires,
            revision: PersonnelRevision {
                generation: window.generation,
                valid_until: window.valid_until,
                logins: false,
                profiles: PersonnelProfileScope::None,
            },
        }
    }
}
impl PersonnelRead<'_> {
    pub fn revision(&self) -> Result<PersonnelRevision, AuthorityError> {
        self.live()?;
        Ok(self.revision)
    }
    fn live(&self) -> Result<(), AuthorityError> {
        if Instant::now() >= self.expires {
            Err(AuthorityError::Rejected)
        } else {
            Ok(())
        }
    }
    /// Executes a host-installed SELECT with a bounded returned page. Join/filter/order/count before LIMIT.
    /// The enclosing SELECT and database READ ONLY mode exclude transaction control and durable writes.
    pub async fn query(
        &mut self,
        select: &'static str,
        arguments: PgArguments,
        max_rows: usize,
    ) -> Result<Vec<PgRow>, AuthorityError> {
        self.live()?;
        if !(1..=usize::from(rss_identity_core::directory::MAX_PAGE_SIZE) + 1).contains(&max_rows) {
            return Err(AuthorityError::Configuration);
        }
        let sql = format!(
            "WITH {} SELECT * FROM ({select}) AS personnel_result LIMIT {}",
            self.relation,
            max_rows + 1
        );
        let mut stream =
            sqlx::query_with(sqlx::AssertSqlSafe(sql), arguments).fetch(&mut *self.connection);
        let mut rows = Vec::new();
        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|_| AuthorityError::Unavailable)?
        {
            if rows.len() == max_rows {
                return Err(AuthorityError::Rejected);
            }
            rows.push(row);
        }
        drop(stream);
        self.live()?;
        Ok(rows)
    }
}
impl Authority {
    /// Rechecks the component-issued session and host policy, then runs a read-only same-database query.
    /// The existing tenant guard prevents Identity changes across the callback. Host device predicates
    /// and accurate statistics must share one SELECT snapshot. The callback cannot outlive this transaction.
    pub async fn with_personnel_read<T: Send + 'static, F>(
        &self,
        actor: &AuthenticatedSession,
        deadline: OperationDeadline,
        query: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(PersonnelRead<'a>) -> BoxFuture<'a, Result<T, AuthorityError>>
            + Send
            + 'static,
    {
        self.require_runtime()?;
        let reader = Reader::new(actor)?;
        let policy = self.policy.clone();
        let instance = self.instance;
        let max_age = self.profile_limits.max_age_seconds();
        let budget = Budget::new(deadline)?;
        let platform = self
            .session_checks
            .platform
            .as_ref()
            .map(|v| v.audience().to_owned());
        let failure = std::sync::Arc::new(std::sync::OnceLock::new());
        let capture = failure.clone();
        let result = self
            .read_sql(reader.binding, budget.remaining(), move |c| {
                Box::pin(async move {
                    let loaded = reader.recheck(c).await?;
                    let expires = crate::sessions::checked_expiry(
                        &loaded,
                        budget.0.instant().min(reader.expires),
                    )?;
                    let login = permission(
                        crate::management::authorize(
                            policy.as_ref(),
                            instance,
                            &loaded,
                            ManagementOperation::ListAccounts,
                            None,
                            c,
                        )
                        .await,
                    )?;
                    let all = permission(
                        crate::management::authorize(
                            policy.as_ref(),
                            instance,
                            &loaded,
                            ManagementOperation::ReadLatestProfile,
                            None,
                            c,
                        )
                        .await,
                    )?;
                    let own = if all {
                        true
                    } else {
                        permission(
                            crate::management::authorize(
                                policy.as_ref(),
                                instance,
                                &loaded,
                                ManagementOperation::ReadLatestProfile,
                                Some(reader.key),
                                c,
                            )
                            .await,
                        )?
                    };
                    let scope = if all {
                        PersonnelProfileScope::All
                    } else if own {
                        PersonnelProfileScope::SelfOnly
                    } else {
                        PersonnelProfileScope::None
                    };
                    let window = ReadDependencies::references(instance, platform.as_deref())
                        .with_personnel(login, scope, reader.key.principal.as_uuid(), max_age)
                        .window(
                            c,
                            reader.key.tenant,
                            expires,
                            Some(
                                loaded
                                    .view
                                    .idle_expires_at
                                    .min(loaded.view.absolute_expires_at),
                            ),
                        )
                        .await?;
                    let expires = window.expires;
                    let ReadWindow {
                        generation,
                        valid_until,
                        clock,
                        ..
                    } = window;
                    let now = clock.seconds();
                    let profiles = if all {
                        "true".into()
                    } else if own {
                        format!("a.principal_id='{}'::uuid", reader.key.principal.as_uuid())
                    } else {
                        "false".into()
                    };
                    let relation = include_str!("personnel.sql")
                        .replace("{profile_facts}", include_str!("profile-facts.sql"))
                        .replace("{logins}", if login { "true" } else { "false" })
                        .replace("{profiles}", &profiles)
                        .replace("{max_age}", &max_age.to_string())
                        .replace("{now}", &now.to_string())
                        .replace("{tenant}", &reader.key.tenant.to_string());
                    let relation = format!(
                        "{},{}",
                        relation,
                        session_relation(instance, reader.key.tenant, now, platform.as_deref())
                    );
                    // PostgreSQL allows r/w -> r/o after authentication/locks, and cannot reverse it after the first snapshot.
                    sqlx::query("SET TRANSACTION READ ONLY")
                        .execute(&mut *c)
                        .await?;
                    let result = query(PersonnelRead {
                        connection: c,
                        relation,
                        expires,
                        revision: PersonnelRevision {
                            generation,
                            valid_until,
                            logins: login,
                            profiles: scope,
                        },
                    })
                    .await;
                    if Instant::now() >= expires {
                        return Err(reject().into());
                    }
                    result.map_err(|error| {
                        let _ = capture.set(error);
                        MutationError::from(reject())
                    })
                })
            })
            .await;
        match result {
            Err(AuthorityError::Rejected) => {
                Err(failure.get().copied().unwrap_or(AuthorityError::Rejected))
            }
            result => result,
        }
    }
}
fn permission(result: Result<(), AccountRuleError>) -> Result<bool, MutationError> {
    match result {
        Ok(()) => Ok(true),
        Err(AccountRuleError::InsufficientPrivilege) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn session_relation(
    instance: InstanceId,
    tenant: TenantId,
    now: i64,
    platform: Option<&str>,
) -> String {
    // The host supplies its own positional query arguments. Keep these trusted context
    // literals inside the reference relation; the internal deadline probe uses bindings.
    let audience = platform.map_or_else(
        || "NULL".to_owned(),
        |s| format!("'{}'", s.replace('\'', "''")),
    );
    include_str!("session_reference.sql")
        .replace("{sessions}", "identity_authority.sessions")
        .replace(
            "{context}",
            &format!("'{tenant}'::uuid,'{instance}'::uuid,{now}::bigint,{audience}::text"),
        )
}
