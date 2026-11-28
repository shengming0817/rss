//! Source admission counts successful and unsuccessful authentication alike.
//! ref: vaultwarden src/ratelimit.rs@b71cb7a832080d9fdfdd97bcccf065307cf73236.
use crate::{
    AttemptSource, Authority, AuthorityError,
    storage::{lock_attempt_capacity, lock_tenant_scope},
};
use rss_request_context::Deadline;
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::ExecutionBinding;
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
        if record_capacity == 0
            || !(1..=1024).contains(&cleanup_batch)
            || claim_ttl.is_zero()
            || !claim_ttl.subsec_nanos().is_multiple_of(1000)
            || claim_ttl.as_micros() >= i64::MAX as u128
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

pub(crate) struct Attempt<'a> {
    key: &'a str,
    count: i32,
    seconds: u32,
    pub exists: bool,
    pub retry: i64,
}
impl Attempt<'_> {
    pub async fn consume(self, c: &mut PgConnection, tenant: TenantId) -> Result<(), PgError> {
        sqlx::query("INSERT INTO identity_authority.attempts VALUES($1::uuid,$2,1,clock_timestamp()+make_interval(secs=>$3)) ON CONFLICT(tenant_id,key) DO UPDATE SET count=$4,expires_at=CASE WHEN $4=1 THEN excluded.expires_at ELSE attempts.expires_at END")
            .bind(tenant.to_string()).bind(self.key).bind(f64::from(self.seconds)).bind(self.count.checked_add(1).ok_or_else(crate::transaction::corrupt)?).execute(c).await?;
        Ok(())
    }
}
pub(crate) async fn attempt<'a>(
    c: &mut PgConnection,
    tenant: TenantId,
    key: &'a str,
    window: AttemptWindow,
) -> Result<Attempt<'a>, PgError> {
    let row = sqlx::query("SELECT CASE WHEN expires_at>clock_timestamp() THEN count ELSE 0 END AS count,CASE WHEN count>=$3 AND expires_at>clock_timestamp() THEN greatest(1,ceil(extract(epoch FROM expires_at-clock_timestamp())))::bigint ELSE 0 END AS retry FROM identity_authority.attempts WHERE tenant_id=$1::uuid AND key=$2")
        .bind(tenant.to_string()).bind(key).bind(window.limit).fetch_optional(c).await?;
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
pub(crate) enum Room {
    Available,
    RecheckKeys,
    Full,
}

/// A single admission under the existing tenant capacity lock. After reclamation
/// reread the requested keys: the deleted batch may have included an expired one.
pub(crate) struct Capacity {
    occupied: i64,
    limit: i64,
    cleanup: Option<u16>,
}
impl Capacity {
    pub(crate) async fn lock(
        c: &mut PgConnection,
        tenant: TenantId,
        policy: AuthenticationPolicy,
    ) -> Result<Self, PgError> {
        Ok(Self {
            occupied: lock_attempt_capacity(c, tenant).await?,
            limit: i64::from(policy.record_capacity),
            cleanup: Some(policy.cleanup_batch),
        })
    }
    pub(crate) async fn room(
        &mut self,
        c: &mut PgConnection,
        tenant: TenantId,
        missing: i64,
    ) -> Result<Room, PgError> {
        if self.occupied <= self.limit - missing {
            return Ok(Room::Available);
        }
        let Some(batch) = self.cleanup.take() else {
            return Ok(Room::Full);
        };
        let removed: i64 = sqlx::query_scalar(include_str!("reclaim-attempts.sql"))
            .bind(tenant.to_string())
            .bind(i64::from(batch))
            .fetch_one(c)
            .await?;
        self.occupied -= removed;
        Ok(if removed == 0 {
            Room::Full
        } else {
            Room::RecheckKeys
        })
    }
}
impl Authority {
    /// OIDC/platform reservation commits independently and is never refunded.
    pub(crate) async fn reserve(
        &self,
        binding: ExecutionBinding,
        scope: String,
        source: &AttemptSource,
        deadline: Deadline,
    ) -> Result<(), AuthorityError> {
        let tenant = binding.tenant();
        let source = format!("s:{}", source.value());
        let policy = self.authentication;
        self.read(binding, deadline, move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        lock_tenant_scope(c, tenant).await?;
                        let mut capacity = Capacity::lock(c, tenant, policy).await?;
                        loop {
                            let source = attempt(c, tenant, &source, policy.source).await?;
                            let scope = attempt(c, tenant, &scope, policy.scope).await?;
                            let room = capacity
                                .room(
                                    c,
                                    tenant,
                                    i64::from(!source.exists) + i64::from(!scope.exists),
                                )
                                .await?;
                            if matches!(room, Room::RecheckKeys) {
                                continue;
                            }
                            let retry = source.retry.max(scope.retry);
                            if retry > 0 {
                                return Ok(Err(rate_limited(retry)?));
                            }
                            if matches!(room, Room::Full) {
                                return Ok(Err(AuthorityError::Busy));
                            }
                            source.consume(c, tenant).await?;
                            scope.consume(c, tenant).await?;
                            return Ok(Ok(()));
                        }
                    })
                })
                .await
            })
        })
        .await?
    }
}
