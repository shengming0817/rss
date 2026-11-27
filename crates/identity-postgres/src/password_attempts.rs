//! Password failures are independent of source/resource admission.
//! ref: kanidm server/lib/src/idm/server.rs@50bc4f988b139e2d767429c554348fd66423054e.
use crate::{
    attempts::*,
    storage::{lock_attempt_capacity, lock_tenant_scope},
    *,
};
use rss_identity_core::account::LoginKey;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

/// Private, database-fenced permission to perform one password verification.
pub(crate) struct PasswordClaim {
    binding: ExecutionBinding,
    login: Vec<u8>,
    token: uuid::Uuid,
}

impl Authority {
    pub(crate) async fn claim_password(
        &self,
        binding: ExecutionBinding,
        login: &LoginKey,
        source: &AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<PasswordClaim, AuthorityError> {
        let tenant = binding.tenant();
        let digest = Sha256::digest(login.as_str().as_bytes()).to_vec();
        let source = format!("s:{}", source.value());
        let policy = self.authentication;
        let seconds = policy.claim_ttl.as_secs_f64();
        self.read(binding, deadline, move |tx| Box::pin(async move {
            crate::transaction::connection(tx, move |c| Box::pin(async move {
                lock_tenant_scope(c, tenant).await?;
                lock_attempt_capacity(c, tenant).await?;
                cleanup(c, tenant, policy.cleanup_batch).await?;
                let source = attempt(c, tenant, source, policy.source).await?;
                let row = sqlx::query("SELECT CASE WHEN failures>=$3 AND window_until>clock_timestamp() THEN greatest(1,ceil(extract(epoch FROM window_until-clock_timestamp())))::bigint ELSE 0 END AS retry,claim_until>clock_timestamp() AS busy FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid AND login_digest=$2")
                    .bind(tenant.to_string()).bind(&digest).bind(policy.password.limit).fetch_optional(&mut *c).await?;
                let retry = row.as_ref().map(|r| r.try_get::<i64,_>("retry")).transpose()?.unwrap_or(0).max(source.retry);
                if retry > 0 { return Ok(Err(rate_limited(retry)?)); }
                if row.as_ref().map(|r| r.try_get::<Option<bool>,_>("busy")).transpose()?.flatten().unwrap_or(false) {
                    return Ok(Err(AuthorityError::Busy));
                }
                if total(c, tenant).await? + i64::from(!source.exists) + i64::from(row.is_none()) > i64::from(policy.record_capacity) {
                    return Ok(Err(AuthorityError::Busy));
                }
                source.consume(c, tenant).await?;
                let token = uuid::Uuid::new_v4();
                sqlx::query("INSERT INTO identity_authority.password_attempts(tenant_id,login_digest,claim_token,claim_until) VALUES($1::uuid,$2,$3,clock_timestamp()+make_interval(secs=>$4)) ON CONFLICT(tenant_id,login_digest) DO UPDATE SET failures=CASE WHEN password_attempts.window_until>clock_timestamp() THEN password_attempts.failures ELSE 0 END,window_until=CASE WHEN password_attempts.window_until>clock_timestamp() THEN password_attempts.window_until ELSE NULL END,claim_token=excluded.claim_token,claim_until=excluded.claim_until")
                    .bind(tenant.to_string()).bind(&digest).bind(token).bind(seconds).execute(c).await?;
                Ok(Ok(PasswordClaim {binding,login:digest,token}))
            })).await
        })).await?
    }

    /// Return credential outcomes as values so their accounting commits independently.
    pub(crate) async fn settle_password(
        &self,
        claim: PasswordClaim,
        outcome: Result<AuthenticationCandidate, AuthorityError>,
        deadline: OperationDeadline,
    ) -> Result<AuthenticationCandidate, AuthorityError> {
        let policy = self.authentication;
        self.read(claim.binding, deadline, move |tx| Box::pin(async move {
            crate::transaction::connection(tx, move |c| Box::pin(async move {
                lock_tenant_scope(c, claim.binding.tenant()).await?;
                if let Ok(candidate) = &outcome { storage::current(c, candidate).await?; }
                lock_attempt_capacity(c, claim.binding.tenant()).await?;
                let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid AND login_digest=$2 AND claim_token=$3 AND claim_until>clock_timestamp())")
                    .bind(claim.binding.tenant().to_string()).bind(&claim.login).bind(claim.token).fetch_one(&mut *c).await?;
                if !owned {return Ok(Err(AuthorityError::Rejected));}
                match outcome {
                    Ok(candidate) => {
                        sqlx::query("DELETE FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid AND login_digest=$2 AND claim_token=$3")
                            .bind(claim.binding.tenant().to_string()).bind(claim.login).bind(claim.token).execute(c).await?;
                        Ok(Ok(candidate))
                    }
                    Err(error) => {
                        if error == AuthorityError::Rejected {
                            sqlx::query("UPDATE identity_authority.password_attempts SET failures=CASE WHEN window_until>clock_timestamp() THEN failures+1 ELSE 1 END,window_until=CASE WHEN window_until>clock_timestamp() THEN window_until ELSE clock_timestamp()+make_interval(secs=>$4) END,claim_token=NULL,claim_until=NULL WHERE tenant_id=$1::uuid AND login_digest=$2 AND claim_token=$3")
                                .bind(claim.binding.tenant().to_string()).bind(claim.login).bind(claim.token).bind(f64::from(policy.password.seconds)).execute(c).await?;
                        } else {
                            sqlx::query("UPDATE identity_authority.password_attempts SET claim_token=NULL,claim_until=NULL WHERE tenant_id=$1::uuid AND login_digest=$2 AND claim_token=$3")
                                .bind(claim.binding.tenant().to_string()).bind(claim.login).bind(claim.token).execute(c).await?;
                        }
                        Ok(Err(error))
                    }
                }
            })).await
        })).await?
    }
}

/// Caller holds the tenant guard in the successful credential-change transaction.
pub(crate) async fn clear(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    sqlx::query("DELETE FROM identity_authority.password_attempts p USING identity_authority.local_credentials l WHERE p.tenant_id=$1::uuid AND l.tenant_id=p.tenant_id AND l.principal_id=$2 AND p.login_digest=sha256(convert_to(l.login_key,'UTF8'))")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).execute(c).await?;
    Ok(())
}
