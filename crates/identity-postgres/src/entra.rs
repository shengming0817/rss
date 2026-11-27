//! Native Entra personnel proofs. Never issues a browser session or device permission.
use crate::{
    Authority, AuthorityError, Budget,
    federation::{Action, event},
    federation_storage as db, storage,
    transaction::reject,
};
use rss_identity_core::{
    InstanceId,
    account::{AccountKey, AccountState},
    entra::{EntraTokenClaims, EntraTokenProfile, EntraTokenVerifier, SubjectMapping},
    federation::{FederationError, ProviderId, ProviderView},
};
use rss_request_context::TenantId;
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// One product-approved resource binding, installed by trusted composition.
#[derive(Clone)]
pub struct EntraAuthority {
    authority: Authority,
    verifier: Arc<dyn EntraTokenVerifier>,
    tenant: TenantId,
    provider: ProviderId,
    profile: EntraTokenProfile,
}

/// Private construction follows verification through the configured adapter.
/// ```compile_fail
/// fn bypass() { let _ = rss_identity_postgres::VerifiedExternalSubject {}; }
/// ```
pub struct VerifiedExternalSubject {
    binding: ExecutionBinding,
    instance: InstanceId,
    tenant: TenantId,
    provider: ProviderId,
    version: i64,
    epoch: i64,
    profile: EntraTokenProfile,
    claims: EntraTokenClaims,
    expires: Instant,
}
impl VerifiedExternalSubject {
    pub fn claims(&self) -> Result<&EntraTokenClaims, AuthorityError> {
        self.check_live()?;
        Ok(&self.claims)
    }
    pub fn check_live(&self) -> Result<(), AuthorityError> {
        if Instant::now() >= self.expires {
            Err(AuthorityError::Rejected)
        } else {
            Ok(())
        }
    }
}

/// Current personnel facts, distinct from AuthenticatedSession and resource grants.
pub struct RevalidatedAccount {
    subject: VerifiedExternalSubject,
    state: AccountState,
    identity: Uuid,
}
impl RevalidatedAccount {
    pub fn check_live(&self) -> Result<(), AuthorityError> {
        self.subject.check_live()
    }
    pub fn instance(&self) -> InstanceId {
        self.subject.instance
    }
    pub fn account(&self) -> AccountKey {
        self.state.key()
    }
    pub fn claims(&self) -> Result<&EntraTokenClaims, AuthorityError> {
        self.subject.claims()
    }
}
impl std::fmt::Debug for RevalidatedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevalidatedAccount(<private>)")
    }
}

impl EntraAuthority {
    pub fn new(
        authority: Authority,
        verifier: Arc<dyn EntraTokenVerifier>,
        tenant: TenantId,
        provider: ProviderId,
        profile: EntraTokenProfile,
    ) -> Result<Self, AuthorityError> {
        authority.require_runtime()?;
        profile.validate()?;
        Ok(Self {
            authority,
            verifier,
            tenant,
            provider,
            profile,
        })
    }
    /// The product must check its scope/consent/device policy before calling resolve.
    pub async fn verify(
        &self,
        binding: ExecutionBinding,
        token: Zeroizing<String>,
        deadline: OperationDeadline,
    ) -> Result<VerifiedExternalSubject, AuthorityError> {
        if binding.tenant() != self.tenant {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let tenant = self.tenant;
        let provider = self.provider;
        let profile = self.profile.clone();
        let view = self
            .authority
            .read_sql(binding, budget.remaining(), move |c| {
                Box::pin(async move {
                    storage::lock_tenant_collection(c, tenant).await?;
                    let view = db::provider(c, tenant, provider).await?;
                    check_provider(&view, &profile)?;
                    Ok(view)
                })
            })
            .await?;
        let claims = tokio::time::timeout(
            budget.remaining().timeout(),
            self.verifier.verify(&self.profile, token, budget.0),
        )
        .await
        .map_err(|_| AuthorityError::DeadlineElapsed)??;
        claims.validate(&self.profile)?;
        let tenant = self.tenant;
        let sampled = Instant::now();
        let now_ms: i64 = self
            .authority
            .read_sql(binding, budget.remaining(), |c| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar(
                        "SELECT ceil(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
                    )
                    .fetch_one(c)
                    .await?)
                })
            })
            .await?;
        if claims
            .issued_at
            .checked_mul(1000)
            .is_none_or(|iat| iat > now_ms)
        {
            return Err(AuthorityError::Rejected);
        }
        let expires = proof_expiry(claims.expires_at, now_ms, sampled, budget.0.instant())?;
        let proof = VerifiedExternalSubject {
            binding,
            instance: self.authority.instance(),
            tenant,
            provider: self.provider,
            version: view.version,
            epoch: view.revocation_epoch,
            profile: self.profile.clone(),
            claims,
            expires,
        };
        proof.check_live()?;
        Ok(proof)
    }
    /// Resolve/JIT only an already-verified subject. Unknown commit never returns a proof.
    pub async fn resolve(
        &self,
        subject: VerifiedExternalSubject,
        deadline: OperationDeadline,
    ) -> Result<RevalidatedAccount, AuthorityError> {
        self.bound(&subject)?;
        let binding = subject.binding;
        let budget = Budget::new(deadline)?;
        let tenant = self.tenant;
        let result = self.authority.conditional_write_sql(binding, budget.remaining(), move |c| Box::pin(async move {
            subject.check_live().map_err(|_| reject())?;
            storage::lock_tenant_collection(c, tenant).await?;
            let view = db::provider(c, tenant, subject.provider).await?;
            check_current(&subject, &view)?;
            let key = subject.claims.subject().storage_key();
            let existing = sqlx::query("SELECT identity_id,principal_id FROM identity_authority.external_identities WHERE tenant_id=$1::uuid AND provider_id=$2::uuid AND issuer=$3 AND subject=$4")
                .bind(tenant.to_string()).bind(subject.provider.to_string()).bind(view.settings.issuer().as_str()).bind(&key).fetch_optional(&mut *c).await?;
            let mut events = Vec::new();
            let (identity, principal) = if let Some(row) = existing {
                (row.try_get("identity_id")?, storage::principal(&row.try_get::<Uuid,_>("principal_id")?.to_string())?)
            } else {
                if !view.settings.jit() { return Err(FederationError::Rejected.into()); }
                let principal = rss_identity_core::PrincipalId::generate();
                let account = AccountKey { tenant, principal };
                storage::insert_federated_account(c, account).await?;
                let identity = Uuid::new_v4();
                sqlx::query("INSERT INTO identity_authority.external_identities(tenant_id,identity_id,principal_id,provider_id,issuer,subject) VALUES($1::uuid,$2,$3,$4::uuid,$5,$6)")
                    .bind(tenant.to_string()).bind(identity).bind(principal.as_uuid()).bind(subject.provider.to_string()).bind(view.settings.issuer().as_str()).bind(key).execute(&mut *c).await?;
                events.push(event(tenant, Action::JitCreated, &view, Some(principal)));
                (identity, principal)
            };
            let state = storage::account_state_locked(c, AccountKey { tenant, principal }).await?;
            if !state.active() { return Err(reject().into()); }
            subject.check_live().map_err(|_| reject())?;
            Ok((RevalidatedAccount { subject, state, identity }, events))
        })).await?;
        result.check_live()?;
        Ok(result)
    }
    /// Refresh facts without extending the original token or silently accepting epoch drift.
    pub async fn recheck(
        &self,
        proof: RevalidatedAccount,
        deadline: OperationDeadline,
    ) -> Result<RevalidatedAccount, AuthorityError> {
        self.bound(&proof.subject)?;
        let binding = proof.subject.binding;
        let tenant = self.tenant;
        let result = self.authority.read_sql(binding, deadline, move |c| Box::pin(async move {
            proof.check_live().map_err(|_| reject())?;
            storage::lock_tenant_collection(c, tenant).await?;
            let view = db::provider(c, tenant, proof.subject.provider).await?;
            check_current(&proof.subject, &view)?;
            let linked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identity_authority.external_identities WHERE tenant_id=$1::uuid AND identity_id=$2 AND principal_id=$3 AND provider_id=$4::uuid AND issuer=$5 AND subject=$6)")
                .bind(tenant.to_string()).bind(proof.identity).bind(proof.state.key().principal.as_uuid()).bind(proof.subject.provider.to_string()).bind(view.settings.issuer().as_str()).bind(proof.subject.claims.subject().storage_key()).fetch_one(&mut *c).await?;
            let current = storage::account_state_locked(c, proof.state.key()).await?;
            if !linked || !current.active() || !current.matches_verification(proof.state) { return Err(reject().into()); }
            proof.check_live().map_err(|_| reject())?; Ok(proof)
        })).await?;
        result.check_live()?;
        Ok(result)
    }
    fn bound(&self, p: &VerifiedExternalSubject) -> Result<(), AuthorityError> {
        p.check_live()?;
        if p.instance != self.authority.instance()
            || p.tenant != self.tenant
            || p.provider != self.provider
            || p.profile != self.profile
        {
            return Err(AuthorityError::Rejected);
        }
        Ok(())
    }
}
fn check_provider(view: &ProviderView, profile: &EntraTokenProfile) -> Result<(), FederationError> {
    if !view.enabled
        || view.settings.issuer().as_str() != profile.issuer()
        || view.settings.claims().subject
            != (SubjectMapping::Entra {
                tenant: profile.tenant,
            })
    {
        return Err(FederationError::Rejected);
    }
    Ok(())
}
fn check_current(p: &VerifiedExternalSubject, view: &ProviderView) -> Result<(), FederationError> {
    check_provider(view, &p.profile)?;
    if view.version != p.version || view.revocation_epoch != p.epoch {
        return Err(FederationError::Rejected);
    }
    Ok(())
}

// Anchor before the entire read/settlement, ceil wall time so conversion cannot extend exp.
fn proof_expiry(
    exp: i64,
    now_ms: i64,
    sampled: Instant,
    budget: Instant,
) -> Result<Instant, AuthorityError> {
    let remaining = exp
        .checked_mul(1000)
        .and_then(|v| v.checked_sub(now_ms))
        .filter(|v| *v > 0)
        .ok_or(AuthorityError::Rejected)?;
    Ok(budget.min(sampled + Duration::from_millis(remaining as u64).min(Duration::from_secs(10))))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_conversion_deducts_fractional_seconds_and_settlement_latency() {
        let sampled = Instant::now();
        let budget = sampled + Duration::from_secs(30);
        assert_eq!(
            proof_expiry(11, 10_800, sampled, budget).unwrap(),
            sampled + Duration::from_millis(200)
        );
        // Returning 150ms later cannot grant a new 200ms lease.
        let returned = sampled + Duration::from_millis(150);
        assert_eq!(
            proof_expiry(11, 10_800, sampled, budget)
                .unwrap()
                .duration_since(returned),
            Duration::from_millis(50)
        );
        assert!(proof_expiry(11, 11_000, sampled, budget).is_err());
        assert!(proof_expiry(i64::MAX, 10_800, sampled, budget).is_err());
    }
}
