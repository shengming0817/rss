//! Revision and clock dependencies of the relations installed for one collection read.
use crate::{
    PersonnelProfileScope,
    session_storage::TimeSample,
    transaction::{MutationError, corrupt},
};
use rss_identity_core::{
    InstanceId,
    directory::{AccountQuery, Field},
};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::time::Instant;
use uuid::Uuid;

// Bounds the age of a single signed continuation or borrowed read even if every fact stays current.
const CONSISTENCY_WINDOW_SECONDS: i64 = 60;
const REFERENCE_EXPIRY_CANDIDATES: i64 = 32;

pub(crate) struct ReadDependencies<'a> {
    kinds: Vec<&'static str>,
    source: Option<&'a str>,
    pub profile_age: Option<u32>,
    profile_subject: Option<Uuid>,
    pub department: Option<Uuid>,
    references: Option<(InstanceId, Option<&'a str>)>,
}

impl<'a> ReadDependencies<'a> {
    pub fn accounts(query: &'a AccountQuery, max_age: u32) -> Result<Self, MutationError> {
        let fields = query.used_fields();
        let profiles = fields.iter().any(|f| f.profile());
        let departments = fields.iter().any(|f| f.department());
        let source = query.source().filter(|_| profiles || departments);
        let department = if departments {
            Some(Uuid::parse_str(source.ok_or_else(corrupt)?).map_err(|_| corrupt())?)
        } else {
            None
        };
        let mut kinds = vec!["rows"];
        for (field, kind) in [
            (Field::Enabled, "enabled"),
            (Field::MemberActive, "member"),
            (Field::Login, "login"),
            (Field::HasLocalPassword, "password"),
        ] {
            if fields.contains(&field) {
                kinds.push(kind);
            }
        }
        if profiles || departments {
            kinds.extend(["enabled", "member"]);
            if source != Some("local") {
                kinds.push("origin");
            }
        }
        if profiles {
            kinds.push("profile");
        }
        if departments {
            kinds.extend(["epoch", "department"]);
        }
        Ok(Self {
            kinds,
            source,
            profile_age: profiles.then_some(max_age),
            profile_subject: None,
            department,
            references: None,
        })
    }

    pub fn references(instance: InstanceId, platform: Option<&'a str>) -> Self {
        Self {
            kinds: vec!["rows", "enabled", "member", "epoch", "origin", "reference"],
            source: None,
            profile_age: None,
            profile_subject: None,
            department: None,
            references: Some((instance, platform)),
        }
    }

    pub fn with_personnel(
        mut self,
        login: bool,
        scope: PersonnelProfileScope,
        subject: Uuid,
        max_age: u32,
    ) -> Self {
        if login {
            self.kinds.push("login");
        }
        if scope != PersonnelProfileScope::None {
            self.kinds.push("profile");
            self.profile_age = Some(max_age);
            self.profile_subject = (scope == PersonnelProfileScope::SelfOnly).then_some(subject);
        }
        self
    }

    pub async fn window(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        deadline: Instant,
        actor_until: Option<i64>,
    ) -> Result<ReadWindow, MutationError> {
        let tenant_id = tenant.to_string();
        let sampled = Instant::now();
        // ANY selects each persisted key once, including keys shared by several fields.
        let (generation, micros): (i64, i64) =
            sqlx::query_as(include_str!("directory-generation.sql"))
                .bind(&tenant_id)
                .bind(&self.kinds)
                .bind(self.source)
                .fetch_one(&mut *c)
                .await?;
        let clock = TimeSample::from_database(sampled, micros)?;
        let now = clock.seconds();
        let mut valid_until = now
            .saturating_add(CONSISTENCY_WINDOW_SECONDS)
            .min(actor_until.unwrap_or(i64::MAX));
        if let Some(max_age) = self.profile_age {
            const FACTS: &str = concat!(
                "WITH profile_facts AS NOT MATERIALIZED (",
                include_str!("profile-facts.sql"),
                "), scoped AS NOT MATERIALIZED (SELECT * FROM profile_facts WHERE eligible AND tenant_id=$1::uuid"
            );
            let filter = match (self.source, self.profile_subject) {
                (Some(_), _) => " AND source=$5",
                (None, Some(_)) => " AND principal_id=$5",
                _ => "",
            };
            let sql = format!(
                "{FACTS}{filter}) {}",
                include_str!("profile-transition.sql")
            );
            let mut query = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(&tenant_id)
                .bind(now)
                .bind(i64::from(max_age))
                .bind(valid_until);
            if let Some(source) = self.source {
                query = query.bind(source);
            } else if let Some(subject) = self.profile_subject {
                query = query.bind(subject);
            }
            let next: Option<i64> = query.fetch_one(&mut *c).await?;
            if let Some(next) = next {
                valid_until = valid_until.min(next);
            }
        }
        if let Some(source) = self.department {
            let next: Option<i64> = sqlx::query_scalar(concat!(
                include_str!("department-facts.sql"),
                include_str!("department-expiry.sql")
            ))
            .bind(&tenant_id)
            .bind(source)
            .bind(now)
            .fetch_one(&mut *c)
            .await?;
            if let Some(next) = next {
                valid_until = valid_until.min(next);
            }
        }
        if let Some((instance, platform)) = self.references {
            let relation = include_str!("session_reference.sql")
                .replace("{context}", "$1::uuid,$2::uuid,$3::bigint,$4::text")
                .replace("{sessions}", "candidates");
            let sql = include_str!("reference-transition.sql").replace("{relation}", &relation);
            let next: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(&tenant_id)
                .bind(instance.as_uuid())
                .bind(now)
                .bind(platform)
                .bind(valid_until)
                .bind(REFERENCE_EXPIRY_CANDIDATES)
                .fetch_one(&mut *c)
                .await?;
            if let Some(next) = next {
                valid_until = valid_until.min(next);
            }
        }
        let expires = deadline.min(clock.deadline(valid_until)?);
        Ok(ReadWindow {
            generation,
            clock,
            valid_until,
            expires,
        })
    }
}

pub(crate) struct ReadWindow {
    pub generation: i64,
    pub valid_until: i64,
    pub clock: TimeSample,
    pub expires: Instant,
}
