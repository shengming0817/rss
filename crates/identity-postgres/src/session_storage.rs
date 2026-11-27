//! Session reads restore current facts after all required authority locks have been acquired.
use crate::{
    AccountKey, AccountState,
    groups::GroupFacts,
    sessions::*,
    storage::*,
    transaction::{corrupt, reject},
};
use rss_identity_core::SessionId;
use rss_identity_core::assurance::Assurance;
use rss_identity_core::session::{CredentialKind, SessionLifetime, SessionPolicy};
use rss_request_context::Clock;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};
use std::time::{Duration, Instant};

/// Anchor before the query: all database and post-sample latency consumes the deadline.
pub(crate) struct TimeSample {
    started: Instant,
    micros: i64,
}
impl TimeSample {
    async fn read(
        c: &mut PgConnection,
        timer: &rss_request_context::SharedExecutionTimer,
    ) -> Result<Self, PgError> {
        let started = timer.now();
        let micros = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
        )
        .fetch_one(c)
        .await?;
        Self::from_database(started, micros)
    }
    pub(crate) fn from_database(started: Instant, micros: i64) -> Result<Self, PgError> {
        if micros <= 0 {
            return Err(corrupt());
        }
        Ok(Self { started, micros })
    }
    fn within_age(&self, authenticated: i64, max_age: Duration, now: Instant) -> bool {
        if max_age.is_zero() {
            return false;
        }
        i64::try_from(max_age.as_secs())
            .ok()
            .and_then(|age| authenticated.checked_add(age))
            .and_then(|end| self.deadline(end).ok())
            .is_some_and(|deadline| now < deadline)
    }
    fn renew(
        &self,
        lifetime: &mut SessionLifetime,
        original_cutoff: Instant,
        now: Instant,
    ) -> Result<(), PgError> {
        // Source verification can wait after the post-guard time sample.
        if now >= original_cutoff {
            return Err(reject());
        }
        lifetime.renew(self.seconds()).map_err(|_| reject())
    }
    pub(crate) fn seconds(&self) -> i64 {
        self.micros / 1_000_000
    }
    pub(crate) fn started(&self) -> Instant {
        self.started
    }
    pub(crate) fn deadline(&self, seconds: i64) -> Result<Instant, PgError> {
        if seconds <= 0 {
            return Err(corrupt());
        }
        // PostgreSQL floors to microseconds; discard the remaining fractional microsecond.
        let remaining = i128::from(seconds) * 1_000_000 - i128::from(self.micros) - 1;
        if remaining <= 0 {
            return Ok(self.started);
        }
        let micros = u64::try_from(remaining).map_err(|_| corrupt())?;
        self.started
            .checked_add(Duration::from_micros(micros))
            .ok_or_else(corrupt)
    }
}

pub(crate) async fn now(c: &mut PgConnection) -> Result<i64, PgError> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(c)
            .await?,
    )
}
pub(crate) fn session_id(value: &str) -> Result<SessionId, PgError> {
    SessionId::parse(value).map_err(|_| corrupt())
}

pub(crate) struct Loaded {
    pub(crate) timer: rss_request_context::SharedExecutionTimer,
    pub source_identity: Option<uuid::Uuid>,
    /// Qualified on this transaction's connection, with the host's binding locks held.
    pub verified_platform: Option<Box<crate::platform::PlatformBinding>>,
    pub source: rss_identity_core::session::AuthenticationSource,
    pub assurance: Assurance,
    pub groups: GroupFacts,
    pub department_snapshot: Box<crate::department::DepartmentFacts>,
    pub(crate) sample: TimeSample,
    pub expires: Instant,
    pub state: AccountState,
    pub view: SessionView,
    pub lifetime: SessionLifetime,
    pub now: i64,
}
impl Loaded {
    /// Recheck the original cutoff even when the stored idle deadline is already sufficient.
    pub(crate) fn renew_idle(&mut self) -> Result<bool, PgError> {
        self.sample
            .renew(&mut self.lifetime, self.expires, self.timer.now())?;
        let idle = self.lifetime.idle_expires_at();
        if idle == self.view.idle_expires_at {
            return Ok(false);
        }
        self.expires = self.sample.deadline(idle)?;
        self.view.idle_expires_at = idle;
        Ok(true)
    }

    /// The post-lock sample includes all time spent awaiting the host policy.
    pub(crate) fn recently_authenticated(&self, max_age: Duration) -> bool {
        self.assurance.auth_time().is_some_and(|authenticated| {
            authenticated <= self.now
                && self
                    .sample
                    .within_age(authenticated, max_age, self.timer.now())
        })
    }
}
// Restore in a new statement after the scoped or collection lock has been acquired.
macro_rules! session_row {
    ($predicate:literal) => {
        sqlx::query(concat!(
            "SELECT session_id,credential_kind,principal_id,auth_epoch,membership_epoch,issued_at,
             idle_timeout,absolute_timeout,idle_expires_at,absolute_expires_at,authentication_source,
             local_authenticated_at,platform_authentication,revoked_at,external_identity_id,
             provider_epoch,auth_facts,facts_sequence FROM identity_authority.sessions
             WHERE tenant_id=$1::uuid AND ", $predicate))
    };
}

pub(crate) enum SessionAccess {
    Inspect,
    Activity,
    Rotate,
    Revoke,
    RevokeAll,
    Host,
    Account(AccountKey),
    Provider(rss_identity_core::federation::ProviderId),
    ProfileWrite(AccountKey),
}

pub(crate) async fn lock_session(
    c: &mut PgConnection,
    digest: Option<&[u8; 32]>,
    reference: Option<SessionId>,
    kind: CredentialKind,
    access: SessionAccess,
) -> Result<(), PgError> {
    let (intent, target) = match access {
        SessionAccess::Inspect => ("inspect", None),
        SessionAccess::Activity => ("activity", None),
        SessionAccess::Rotate => ("rotate", None),
        SessionAccess::Revoke => ("revoke", None),
        SessionAccess::RevokeAll => ("all", None),
        SessionAccess::Host => ("host", None),
        SessionAccess::Account(key) => ("account", Some(key.principal.as_uuid())),
        SessionAccess::Provider(id) => (
            "provider",
            Some(uuid::Uuid::parse_str(&id.to_string()).map_err(|_| corrupt())?),
        ),
        SessionAccess::ProfileWrite(key) => ("profile_write", Some(key.principal.as_uuid())),
    };
    let found: bool = sqlx::query_scalar("SELECT identity_authority.lock_session($1,$2,$3,$4,$5)")
        .bind(digest.map(|d| d.as_slice()))
        .bind(reference.map(|id| id.as_uuid()))
        .bind(kind.as_str())
        .bind(intent)
        .bind(target)
        .fetch_one(c)
        .await?;
    if !found {
        return Err(reject());
    }
    Ok(())
}

pub(crate) async fn lookup_locked(
    c: &mut PgConnection,
    tenant: TenantId,
    digest: &[u8; 32],
    kind: CredentialKind,
    instance: uuid::Uuid,
    session_checks: &crate::session_checks::SessionChecks,
) -> Result<Loaded, PgError> {
    let row = session_row!("token_hash=$2 AND credential_kind=$3")
        .bind(tenant.to_string())
        .bind(digest.as_slice())
        .bind(kind.as_str())
        .fetch_optional(&mut *c)
        .await?
        .ok_or_else(reject)?;
    restore(c, tenant, &row, instance, session_checks).await
}

pub(crate) async fn by_id_locked(
    c: &mut PgConnection,
    key: AccountKey,
    sid: SessionId,
    kind: CredentialKind,
    instance: uuid::Uuid,
    session_checks: &crate::session_checks::SessionChecks,
) -> Result<Loaded, PgError> {
    let row = session_row!("session_id=$2 AND principal_id=$3 AND credential_kind=$4")
        .bind(key.tenant.to_string())
        .bind(sid.as_uuid())
        .bind(key.principal.as_uuid())
        .bind(kind.as_str())
        .fetch_optional(&mut *c)
        .await?
        .ok_or_else(reject)?;
    restore(c, key.tenant, &row, instance, session_checks).await
}

async fn restore(
    c: &mut PgConnection,
    tenant: TenantId,
    row: &sqlx::postgres::PgRow,
    instance: uuid::Uuid,
    session_checks: &crate::session_checks::SessionChecks,
) -> Result<Loaded, PgError> {
    let id = session_id(&row.try_get::<uuid::Uuid, _>("session_id")?.to_string())?;
    let key = AccountKey {
        tenant,
        principal: principal(&row.try_get::<uuid::Uuid, _>("principal_id")?.to_string())?,
    };
    let state = account_state_locked(c, key).await?;
    if !state.active()
        || row.try_get::<i64, _>("auth_epoch")? != state.epoch()
        || row.try_get::<i64, _>("membership_epoch")? != state.membership_epoch()
        || row.try_get::<Option<i64>, _>("revoked_at")?.is_some()
    {
        return Err(reject());
    }
    let origin = crate::federation_storage::decode_origin(row)?;
    let source = match &origin {
        Some((origin, _)) => Some(crate::federation_storage::check_origin(c, key, origin).await?),
        None => None,
    };
    let lifetime = lifetime(row)?;
    let sample = TimeSample::read(c, &session_checks.timer).await?;
    let now = sample.seconds();
    if !lifetime.valid_at(now) {
        return Err(reject());
    }

    let source_kind: String = row.try_get("authentication_source")?;
    let source_identity = origin.as_ref().map(|(origin, _)| origin.identity);
    let mut verified_platform = None;
    let (assurance, groups, department) = match (source_kind.as_str(), origin, source) {
        ("oidc", Some((_, facts)), Some(source)) => facts.into_views(source, &sample)?,
        ("local_password", None, None) => (
            Assurance::password(row.try_get("local_authenticated_at")?).map_err(|_| corrupt())?,
            rss_identity_core::groups::Groups::unavailable(
                rss_identity_core::facts::FactUnavailableReason::LocalIdentity,
            ),
            crate::department::DepartmentFacts::Unavailable(
                rss_identity_core::department::DepartmentUnavailableReason::LocalIdentity,
            ),
        ),
        ("platform", None, None) => {
            let platform: crate::platform::PlatformAuthentication =
                serde_json::from_value(row.try_get("platform_authentication")?)
                    .map_err(|_| corrupt())?;
            let verifier = platform.verifier(key, instance, session_checks)?;
            crate::platform::recheck_binding(c, &platform.binding, verifier).await?;
            let assurance = platform.assurance()?;
            verified_platform = Some(Box::new(platform.binding));
            (
                assurance,
                rss_identity_core::groups::Groups::unavailable(
                    rss_identity_core::facts::FactUnavailableReason::NotConfigured,
                ),
                crate::department::DepartmentFacts::Unavailable(
                    rss_identity_core::department::DepartmentUnavailableReason::NotConfigured,
                ),
            )
        }
        _ => return Err(corrupt()),
    };
    let source = match source_kind.as_str() {
        "local_password" => rss_identity_core::session::AuthenticationSource::LocalPassword,
        "oidc" => rss_identity_core::session::AuthenticationSource::Oidc,
        "platform" => rss_identity_core::session::AuthenticationSource::Platform,
        _ => return Err(corrupt()),
    };
    // Signed-time skew was checked at issuance. Restoration retains frozen expiry
    // instead of applying a new deployment policy to an already accepted fact.
    Ok(Loaded {
        timer: session_checks.timer.clone(),
        source_identity,
        verified_platform,
        source,
        assurance,
        groups: GroupFacts::new(groups, &sample)?,
        department_snapshot: Box::new(department),
        expires: sample.deadline(lifetime.idle_expires_at())?,
        sample,
        state,
        view: SessionView::new(id, lifetime, credential_kind(row)?),
        lifetime,
        now,
    })
}
/// Borrowed host transaction admission shared by live-session and step-up operations.
/// ref: sqlx v0.9.0 sqlx-core/src/connection.rs (transaction detection).
pub(crate) async fn recheck_on(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
) -> Result<Loaded, PgError> {
    use sqlx::Connection;
    if !c.is_in_transaction() {
        return Err(reject());
    }
    let (scope, isolation): (Option<String>, String) = sqlx::query_as(
        "SELECT current_setting('rss.tenant_id',true),current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *c)
    .await?;
    if scope.as_deref() != Some(actor.key.tenant.to_string().as_str())
        || isolation != "read committed"
    {
        return Err(reject());
    }
    sqlx::query("SELECT rss_transactional_messaging.check_execution()")
        .execute(&mut *c)
        .await?;
    recheck_for(c, actor, SessionAccess::Host).await
}

pub(crate) async fn recheck_collection(
    c: &mut PgConnection,
    proof: &AuthenticatedSession,
) -> Result<Loaded, PgError> {
    validate_proof(c, proof).await?;
    lock_tenant_collection(c, proof.key.tenant).await?;
    recheck_locked(c, proof).await
}

async fn validate_proof(c: &mut PgConnection, proof: &AuthenticatedSession) -> Result<(), PgError> {
    if proof.session_checks.timer.now() >= proof.expires
        || authority_id(c).await? != proof.authority.as_uuid()
    {
        return Err(reject());
    }
    crate::transaction::check_binding(c, proof.binding).await?;
    Ok(())
}
pub(crate) async fn recheck_for(
    c: &mut PgConnection,
    proof: &AuthenticatedSession,
    access: SessionAccess,
) -> Result<Loaded, PgError> {
    validate_proof(c, proof).await?;
    lock_session(
        c,
        Some(&proof.digest),
        None,
        proof.view.credential_kind,
        access,
    )
    .await?;
    recheck_locked(c, proof).await
}

/// The caller has established the proof's exact deployment and execution binding in this transaction.
pub(crate) async fn recheck_locked(
    c: &mut PgConnection,
    proof: &AuthenticatedSession,
) -> Result<Loaded, PgError> {
    let mut loaded = lookup_locked(
        c,
        proof.key.tenant,
        &proof.digest,
        proof.view.credential_kind,
        proof.authority.as_uuid(),
        &proof.session_checks,
    )
    .await?;
    loaded.expires = loaded.expires.min(proof.expires);
    if loaded.state.key() != proof.key
        || loaded.view.id != proof.view.id
        || loaded.timer.now() >= loaded.expires
    {
        return Err(reject());
    }
    Ok(loaded)
}
pub(crate) async fn touch(c: &mut PgConnection, loaded: &mut Loaded) -> Result<(), PgError> {
    if !loaded.renew_idle()? {
        return Ok(());
    }
    sqlx::query(
        "UPDATE identity_authority.sessions SET idle_expires_at=$3
         WHERE tenant_id=$1::uuid AND session_id=$2",
    )
    .bind(loaded.state.key().tenant.to_string())
    .bind(loaded.view.id.as_uuid())
    .bind(loaded.view.idle_expires_at)
    .execute(c)
    .await?;
    Ok(())
}
pub(crate) async fn close(
    c: &mut PgConnection,
    key: AccountKey,
    id: SessionId,
    now: i64,
) -> Result<(), PgError> {
    sqlx::query(concat!(
        "UPDATE identity_authority.sessions SET revoked_at=$3 WHERE tenant_id=$1::uuid AN",
        "D session_id=$2::uuid"
    ))
    .bind(key.tenant.to_string())
    .bind(id.to_string())
    .bind(now)
    .execute(c)
    .await?;
    Ok(())
}

pub(crate) fn lifetime(row: &sqlx::postgres::PgRow) -> Result<SessionLifetime, PgError> {
    SessionLifetime::restore(
        row.try_get("issued_at")?,
        row.try_get("idle_expires_at")?,
        row.try_get("absolute_expires_at")?,
        lifetime_policy(row)?,
    )
    .map_err(|_| corrupt())
}

pub(crate) fn lifetime_policy(row: &sqlx::postgres::PgRow) -> Result<SessionPolicy, PgError> {
    SessionPolicy::new(
        row.try_get("idle_timeout")?,
        row.try_get("absolute_timeout")?,
    )
    .map_err(|_| corrupt())
}

pub(crate) fn credential_kind(row: &sqlx::postgres::PgRow) -> Result<CredentialKind, PgError> {
    match row.try_get::<&str, _>("credential_kind")? {
        "cookie" => Ok(CredentialKind::Cookie),
        "bearer" => Ok(CredentialKind::Bearer),
        _ => Err(corrupt()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(
        clippy::disallowed_methods,
        clippy::unwrap_used,
        reason = "test fixture"
    )]
    fn idle_renewal_respects_the_original_monotonic_cutoff() {
        let start = Instant::now();
        let sample = TimeSample {
            started: start,
            micros: 105_000_000,
        };
        let policy = SessionPolicy::new(10, 90).unwrap();
        let original = SessionLifetime::new(100, policy).unwrap();
        let cutoff = sample.deadline(original.idle_expires_at()).unwrap();
        let mut alive = original;
        sample.renew(&mut alive, cutoff, start).unwrap();
        assert_eq!(alive.idle_expires_at(), 115);
        let mut expired = original;
        assert!(sample.renew(&mut expired, cutoff, cutoff).is_err());
        assert_eq!(expired, original);
    }
    #[test]
    #[allow(clippy::disallowed_methods, reason = "test fixture")]
    fn policy_wait_cannot_extend_recent_authentication() {
        let start = Instant::now();
        let sample = TimeSample {
            started: start,
            micros: 399_000_000,
        };
        let age = Duration::from_secs(300);
        assert!(sample.within_age(100, age, start));
        assert!(!sample.within_age(100, age, start + Duration::from_secs(2)));
        assert!(!sample.within_age(100, Duration::ZERO, start));
    }
    #[test]
    #[allow(
        clippy::disallowed_methods,
        clippy::unwrap_used,
        reason = "test fixture"
    )]
    fn database_fraction_and_all_later_latency_consume_deadline() {
        let start = Instant::now();
        let sample = TimeSample {
            started: start,
            micros: 100_750_000,
        };
        assert_eq!(sample.seconds(), 100);
        assert_eq!(
            sample.deadline(101).unwrap(),
            start + Duration::from_micros(249_999)
        );
        assert_eq!(sample.deadline(100).unwrap(), start);
        assert!(sample.deadline(0).is_err());
        assert!(sample.deadline(i64::MAX).is_err());
        let exact = TimeSample {
            started: start,
            micros: 101_000_000,
        };
        assert_eq!(exact.deadline(101).unwrap(), start);
        let edge = TimeSample {
            started: start,
            micros: 100_999_999,
        };
        assert_eq!(edge.deadline(101).unwrap(), start);
    }
}

#[cfg(test)]
mod fact_ownership_tests {
    use super::*;
    use rss_identity_core::{
        department::{DepartmentSnapshotClaim, UpstreamDepartmentSnapshot},
        facts::FactSource,
        federation::UpstreamClaims,
        groups::{GroupFactsMaxAge, Groups, UpstreamGroups},
    };
    #[test]
    #[allow(
        clippy::disallowed_methods,
        clippy::panic,
        clippy::unwrap_used,
        reason = "test fixture"
    )]
    fn collection_and_projection_transfer_group_and_department_storage() {
        let groups = vec!["engineering".to_owned()];
        let id = rss_identity_core::department::DepartmentId::new("dept".into()).unwrap();
        let department = rss_identity_core::department::DepartmentSnapshot::new(
            "fixture-r1".into(),
            vec![
                rss_identity_core::department::DepartmentNode::new(
                    id.clone(),
                    "Department".into(),
                    None,
                )
                .unwrap(),
            ],
            vec![id],
        )
        .unwrap();
        let group_buffer = groups.as_ptr();
        let nodes = department.nodes().as_ptr();
        let memberships = department.memberships().as_ptr();
        let claims = UpstreamClaims {
            issuer: "https://idp.test".into(),
            subject: rss_identity_core::entra::ExternalSubject::Oidc("subject".into()),
            profile: rss_identity_core::profile::Profile::missing(),
            groups: UpstreamGroups::Present(groups),
            department_snapshot: UpstreamDepartmentSnapshot::Present(department),
            assurance: Assurance::password(1000).unwrap(),
            issued_at: 1000,
            expires_at: 1600,
        };
        let facts = crate::auth_facts::AuthenticationFacts::collect(
            claims,
            1,
            GroupFactsMaxAge::new(300).unwrap(),
            Some(&DepartmentSnapshotClaim::new("department".into(), 60).unwrap()),
            1000,
            0,
        )
        .unwrap();
        let source = FactSource::new(uuid::Uuid::new_v4(), "https://idp.test".into()).unwrap();
        let sample = TimeSample {
            started: Instant::now(),
            micros: 1_000_000_000,
        };
        let (
            _,
            Groups::Available { values, .. },
            crate::department::DepartmentFacts::Available { snapshot, .. },
        ) = facts.into_views(source, &sample).unwrap()
        else {
            panic!("expected live facts")
        };
        assert_eq!(values.as_ptr(), group_buffer);
        assert_eq!(snapshot.nodes().as_ptr(), nodes);
        assert_eq!(snapshot.memberships().as_ptr(), memberships);
    }
}
