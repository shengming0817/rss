//! Source admission counts successful and unsuccessful authentication alike.
//! ref: vaultwarden src/ratelimit.rs@b71cb7a832080d9fdfdd97bcccf065307cf73236.
use crate::{
    AttemptSource, Authority, AuthorityError,
    storage::{lock_attempt_capacity, lock_tenant_scope},
};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row};
/// A finite fixed window. Counts and Retry-After retain their persisted integer domains.
#[derive(Clone, Copy, Debug)]
pub struct AttemptWindow {
    pub(crate) limit: i32,
    pub(crate) seconds: u32,
}
impl AttemptWindow {
    pub fn new(limit: u32, seconds: u32) -> Result<Self, AuthorityError> {
        let limit = i32::try_from(limit).map_err(|_| AuthorityError::Configuration)?;
        if limit == 0 || seconds == 0 {
            return Err(AuthorityError::Configuration);
        }
        Ok(Self { limit, seconds })
    }
}
/// Immutable deployment choices; shared database counters remain authoritative.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationPolicy {
    pub(crate) source: AttemptWindow,
    pub(crate) scope: AttemptWindow,
    pub(crate) password: AttemptWindow,
    pub(crate) record_capacity: u32,
    pub(crate) cleanup_batch: u16,
    pub(crate) claim_ttl: std::time::Duration,
}
impl AuthenticationPolicy {
    /// Existing safe defaults. The host explicitly selects the password claim lifetime.
    pub fn standard(claim_ttl: std::time::Duration) -> Result<Self, AuthorityError> {
        Self::new(
            AttemptWindow::new(30, 300)?,
            AttemptWindow::new(5, 900)?,
            AttemptWindow::new(5, 600)?,
            10000,
            128,
            claim_ttl,
        )
    }
    pub fn new(
        source: AttemptWindow,
        scope: AttemptWindow,
        password: AttemptWindow,
        record_capacity: u32,
        cleanup_batch: u16,
        claim_ttl: std::time::Duration,
    ) -> Result<Self, AuthorityError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AuthorityError::Configuration)?;
        if record_capacity == 0
            || !(1..=1024).contains(&cleanup_batch)
            || claim_ttl.is_zero()
            || !claim_ttl.subsec_nanos().is_multiple_of(1000)
            || claim_ttl
                .as_micros()
                .checked_add(now.as_micros())
                .is_none_or(|v| v > i64::MAX as u128)
            || std::time::Instant::now().checked_add(claim_ttl).is_none()
        {
            return Err(AuthorityError::Configuration);
        }
        Ok(Self {
            source,
            scope,
            password,
            record_capacity,
            cleanup_batch,
            claim_ttl,
        })
    }
}

pub(crate) struct Attempt {
    key: String,
    count: i32,
    seconds: u32,
    pub exists: bool,
    pub retry: i64,
}
impl Attempt {
    pub async fn consume(self, c: &mut PgConnection, tenant: TenantId) -> Result<(), PgError> {
        sqlx::query("INSERT INTO identity_authority.attempts VALUES($1::uuid,$2,1,clock_timestamp()+make_interval(secs=>$3)) ON CONFLICT(tenant_id,key) DO UPDATE SET count=$4,expires_at=CASE WHEN $4=1 THEN excluded.expires_at ELSE attempts.expires_at END")
            .bind(tenant.to_string()).bind(self.key).bind(f64::from(self.seconds)).bind(self.count.checked_add(1).ok_or_else(crate::transaction::corrupt)?).execute(c).await?;
        Ok(())
    }
}
pub(crate) async fn attempt(
    c: &mut PgConnection,
    tenant: TenantId,
    key: String,
    window: AttemptWindow,
) -> Result<Attempt, PgError> {
    let row = sqlx::query("SELECT CASE WHEN expires_at>clock_timestamp() THEN count ELSE 0 END AS count,CASE WHEN count>=$3 AND expires_at>clock_timestamp() THEN greatest(1,ceil(extract(epoch FROM expires_at-clock_timestamp())))::bigint ELSE 0 END AS retry FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND key=$2")
        .bind(tenant.to_string()).bind(&key).bind(window.limit).fetch_optional(c).await?;
    Ok(Attempt {
        key,
        seconds: window.seconds,
        exists: row.is_some(),
        count: row
            .as_ref()
            .map(|r| r.try_get("count"))
            .transpose()?
            .unwrap_or(0),
        retry: row
            .as_ref()
            .map(|r| r.try_get("retry"))
            .transpose()?
            .unwrap_or(0),
    })
}
pub(crate) fn rate_limited(seconds: i64) -> Result<AuthorityError, PgError> {
    let seconds = u32::try_from(seconds)
        .ok()
        .and_then(std::num::NonZeroU32::new)
        .ok_or_else(crate::transaction::corrupt)?;
    Ok(AuthorityError::RateLimited {
        retry_after_seconds: seconds,
    })
}
pub(crate) async fn total(c: &mut PgConnection, tenant: TenantId) -> Result<i64, PgError> {
    Ok(sqlx::query_scalar("SELECT (SELECT count(*) FROM identity_authority.attempts WHERE tenant_id=$1::uuid)+(SELECT count(*) FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid)")
        .bind(tenant.to_string()).fetch_one(c).await?)
}
pub(crate) async fn cleanup(
    c: &mut PgConnection,
    tenant: TenantId,
    batch: u16,
) -> Result<(), PgError> {
    let removed=sqlx::query("DELETE FROM identity_authority.attempts WHERE (tenant_id,key) IN (SELECT tenant_id,key FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $2)")
        .bind(tenant.to_string()).bind(i64::from(batch)).execute(&mut *c).await?.rows_affected();
    sqlx::query("DELETE FROM identity_authority.password_attempts WHERE (tenant_id,login_digest) IN (SELECT tenant_id,login_digest FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid AND (window_until IS NULL OR window_until<=clock_timestamp()) AND (claim_until IS NULL OR claim_until<=clock_timestamp()) ORDER BY window_until NULLS FIRST LIMIT $2)")
        .bind(tenant.to_string()).bind(i64::from(batch)-i64::try_from(removed).map_err(|_|crate::transaction::corrupt())?).execute(c).await?;
    Ok(())
}
impl Authority {
    /// OIDC/platform reservation commits independently and is never refunded.
    pub(crate) async fn reserve(
        &self,
        binding: ExecutionBinding,
        scope: String,
        source: &AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        let tenant = binding.tenant();
        let source = format!("s:{}", source.value());
        let policy = self.authentication;
        self.read(binding, deadline, move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        lock_tenant_scope(c, tenant).await?;
                        lock_attempt_capacity(c, tenant).await?;
                        cleanup(c, tenant, policy.cleanup_batch).await?;
                        let source = attempt(c, tenant, source, policy.source).await?;
                        let scope = attempt(c, tenant, scope, policy.scope).await?;
                        let retry = source.retry.max(scope.retry);
                        if retry > 0 {
                            return Ok(Err(rate_limited(retry)?));
                        }
                        if total(c, tenant).await?
                            + i64::from(!source.exists)
                            + i64::from(!scope.exists)
                            > i64::from(policy.record_capacity)
                        {
                            return Ok(Err(AuthorityError::Busy));
                        }
                        source.consume(c, tenant).await?;
                        scope.consume(c, tenant).await?;
                        Ok(Ok(()))
                    })
                })
                .await
            })
        })
        .await?
    }
}
