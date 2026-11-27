//! Trusted host platform adapter and Identity-owned one-use browser challenges.
//! The host verifies devices and platform cryptography; Identity alone issues sessions.
//! ref: webauthn-rs 0.5.3 src/lib.rs (server-owned, one-use ceremony state).
use rss_transactional_messaging::fence::ExecutionBinding;
mod admission;
mod enterprise;
pub use admission::{
    PlatformSubjectAdmissionError, PlatformSubjectVersion, admit_platform_subject_on,
};
pub use enterprise::{EnterpriseAssertion, EnterpriseConfig, PlatformLogin, PlatformPurpose};

use crate::{
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use futures::future::BoxFuture;
use rss_identity_core::{
    assurance::{Acr, Assurance},
    federation::{ProviderId, UpstreamClaims, digest, random_secret},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformBinding {
    #[serde(with = "instance_codec")]
    pub instance: rss_identity_core::InstanceId,
    #[serde(with = "account_codec")]
    pub account: AccountKey,
    pub binding_id: Uuid,
    pub binding_epoch: i64,
    pub source_id: Uuid,
    pub source_version: i64,
    pub external_identity: Option<ExternalBinding>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalBinding {
    pub identity_id: Uuid,
    pub provider: ProviderId,
    pub config_version: i64,
    pub revocation_epoch: i64,
}
impl PlatformBinding {
    fn valid(&self) -> bool {
        !self.binding_id.is_nil()
            && self.binding_epoch > 0
            && !self.source_id.is_nil()
            && self.source_version > 0
            && self.external_identity.as_ref().is_none_or(|v| {
                !v.identity_id.is_nil() && v.config_version > 0 && v.revocation_epoch > 0
            })
    }
}
/// Only supplied to the verifier installed by trusted composition, never accepted from HTTP JSON.
#[derive(Serialize)]
pub struct PlatformChallengeContext {
    pub purpose: PlatformPurpose,
    pub binding: PlatformBinding,
    pub audience: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
}
impl PlatformChallengeContext {
    /// Canonical JSON bytes signed by the device; binds purpose/RP as well as the nonce.
    pub fn signing_payload(&self) -> Result<Vec<u8>, PlatformError> {
        serde_json::to_vec(self).map_err(|_| PlatformError::Rejected)
    }
}
/// Intermediate adapter output, not a transferable proof or session-issuance input.
pub struct PlatformEvidence {
    pub key_possession: bool,
    pub hardware_key: bool,
    pub user_presence: bool,
    pub user_verification: bool,
    pub authenticated_at: Option<i64>,
    pub profile: PlatformProfile,
}
pub enum PlatformProfile {
    Unavailable,
    IdentityLocal,
    /// Only freshly verified ID-token claims bound to this challenge and external identity.
    Idp {
        provider: ProviderId,
        claims: Box<UpstreamClaims>,
    },
}
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum PlatformError {
    #[error("platform evidence rejected")]
    Rejected,
    #[error("platform verifier unavailable")]
    Unavailable,
    #[error("user interaction required")]
    InteractionRequired,
    #[error("authentication cancelled")]
    Cancelled,
}
/// Installed once by trusted composition, like UpstreamOidc. This does not distrust host code.
/// Resolve/recheck borrow the caller's transaction: never commit, change tenant, take another
/// connection, perform network calls or release the authoritative binding locks.
pub trait PlatformVerifier: Send + Sync {
    fn audience(&self) -> &str;
    /// Approve this RP and current binding in the same settlement transaction.
    fn authorize_purpose<'a>(
        &'a self,
        binding: &'a PlatformBinding,
        purpose: &'a PlatformPurpose,
        c: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>>;
    fn challenge_seconds(&self) -> u32 {
        120
    }
    fn resolve<'a>(
        &'a self,
        instance: rss_identity_core::InstanceId,
        tenant: TenantId,
        binding: Uuid,
        c: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<PlatformBinding, PlatformError>>;
    fn verify<'a>(
        &'a self,
        challenge: &'a PlatformChallengeContext,
        evidence: &'a [u8],
    ) -> BoxFuture<'a, Result<PlatformEvidence, PlatformError>>;
    fn recheck<'a>(
        &'a self,
        binding: &'a PlatformBinding,
        c: &'a mut PgConnection,
    ) -> BoxFuture<'a, Result<(), PlatformError>>;
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformChallenge {
    pub signing_payload: Vec<u8>,
    pub id: Uuid,
    pub nonce: String,
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PlatformAuthentication {
    pub binding: PlatformBinding,
    pub audience: String,
    pub authenticated_at: Option<i64>,
    pub hardware_key: bool,
    pub user_presence: bool,
    pub user_verification: bool,
}
impl PlatformAuthentication {
    pub(crate) fn assurance(
        &self,
    ) -> Result<Assurance, rss_transactional_messaging_postgres::PgError> {
        if !self.binding.valid() || self.authenticated_at.is_some() && !self.user_verification {
            return Err(corrupt());
        }
        Assurance::new(self.authenticated_at, Acr::Unspecified, vec![]).map_err(|_| corrupt())
    }
}
fn failure(error: PlatformError) -> rss_transactional_messaging_postgres::PgError {
    match error {
        PlatformError::Rejected | PlatformError::Cancelled | PlatformError::InteractionRequired => {
            reject()
        }
        PlatformError::Unavailable => rss_transactional_messaging_postgres::PgError::from(
            rss_transactional_messaging::error::MessagingError::new(
                rss_transactional_messaging::error::MessagingErrorKind::Transient,
                std::io::Error::other("platform verifier unavailable"),
            ),
        ),
    }
}
impl PlatformAuthentication {
    pub(crate) fn verifier<'a>(
        &self,
        key: AccountKey,
        instance: Uuid,
        checks: &'a crate::session_checks::SessionChecks,
    ) -> Result<&'a dyn PlatformVerifier, rss_transactional_messaging_postgres::PgError> {
        let verifier = checks.platform.as_deref().ok_or_else(reject)?;
        if !self.binding.valid()
            || self.binding.account != key
            || self.binding.instance.as_uuid() != instance
            || verifier.audience() != self.audience
        {
            return Err(reject());
        }
        Ok(verifier)
    }
}

pub(crate) async fn recheck_binding(
    c: &mut PgConnection,
    binding: &PlatformBinding,
    verifier: &dyn PlatformVerifier,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    verifier.recheck(binding, c).await.map_err(failure)?;
    external(c, binding).await
}
async fn external(
    c: &mut PgConnection,
    binding: &PlatformBinding,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    if !external_valid(c, binding).await? {
        return Err(reject());
    }
    Ok(())
}
async fn external_valid(
    c: &mut PgConnection,
    binding: &PlatformBinding,
) -> Result<bool, rss_transactional_messaging_postgres::PgError> {
    if let Some(external) = &binding.external_identity {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.external_identities e JOIN identity_authority.providers p USING(tenant_id,provider_id) WHERE e.tenant_id=$1::uuid AND e.principal_id=$2 AND e.identity_id=$3 AND e.provider_id=$4::uuid AND p.enabled AND p.config_version=$5 AND p.revocation_epoch=$6)")
            .bind(binding.account.tenant.to_string()).bind(binding.account.principal.as_uuid()).bind(external.identity_id).bind(external.provider.to_string()).bind(external.config_version).bind(external.revocation_epoch).fetch_one(c).await?;
        return Ok(valid);
    }
    Ok(true)
}
impl Authority {
    pub async fn begin_platform_login(
        &self,
        execution: ExecutionBinding,
        binding: Uuid,
        purpose: PlatformPurpose,
        browser: String,
        source: AttemptSource,
        deadline: OperationDeadline,
    ) -> Result<PlatformChallenge, AuthorityError> {
        let tenant = execution.tenant();
        self.require_runtime()?;
        crate::federation_login::check_browser(&browser)?;
        let verifier = self
            .session_checks
            .platform
            .clone()
            .ok_or(AuthorityError::Configuration)?;
        if verifier.audience().is_empty()
            || verifier.audience().len() > 256
            || verifier.challenge_seconds() == 0
            || binding.is_nil()
        {
            return Err(AuthorityError::Configuration);
        }
        let budget = Budget::new(deadline)?;
        self.reserve(
            execution,
            format!("platform:{binding}"),
            &source,
            budget.remaining(),
        )
        .await?;
        let target = match &self.enterprise {
            Some(config) => config.target(&purpose)?,
            None if purpose == PlatformPurpose::BrowserLogin => None,
            None => return Err(AuthorityError::Configuration),
        };
        let instance = self.instance;
        self.read_sql(execution,budget.remaining(),move|c|Box::pin(async move{
            lock_tenant_collection(c,tenant).await?;
            let resolved=verifier.resolve(instance,tenant,binding,c).await.map_err(failure)?;
            if !resolved.valid() || resolved.instance!=instance || resolved.account.tenant!=tenant || resolved.binding_id!=binding || !account_state_locked(c,resolved.account).await?.active(){return Err(reject().into());}
            external(c,&resolved).await?;
            verifier.authorize_purpose(&resolved,&purpose,c).await.map_err(failure)?;
            let state=account_state_locked(c,resolved.account).await?;
            let now=crate::session_storage::now(c).await?;
            sqlx::query("DELETE FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND challenge_id IN (SELECT challenge_id FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND expires_at<=$2 LIMIT 128)")
                .bind(tenant.to_string()).bind(now).execute(&mut *c).await?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid").bind(tenant.to_string()).fetch_one(&mut *c).await?;
            if count>=10000{return Err(reject().into());}
            let id=Uuid::new_v4();let nonce=random_secret()?;let expires=now.checked_add(i64::from(verifier.challenge_seconds())).ok_or_else(reject)?;
            let sequence=crate::profiles::sequence(c,tenant).await?;
            sqlx::query("INSERT INTO identity_authority.platform_challenges(tenant_id,challenge_id,principal_id,binding,audience,nonce_hash,browser_hash,auth_epoch,membership_epoch,created_at,expires_at,profile_sequence,purpose,target) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                .bind(tenant.to_string()).bind(id).bind(resolved.account.principal.as_uuid()).bind(serde_json::to_value(&resolved).map_err(|_|corrupt())?).bind(verifier.audience()).bind(digest(&nonce).as_slice()).bind(digest(&browser).as_slice()).bind(state.epoch()).bind(state.membership_epoch()).bind(now).bind(expires).bind(sequence).bind(serde_json::to_value(&purpose).map_err(|_|corrupt())?).bind(target.map(serde_json::to_value).transpose().map_err(|_|corrupt())?).execute(c).await?;
            let payload=PlatformChallengeContext{binding:resolved,audience:verifier.audience().to_owned(),purpose,nonce:nonce.to_string(),created_at:now,expires_at:expires}.signing_payload().map_err(failure)?;
            Ok(PlatformChallenge{id,nonce:nonce.to_string(),expires_at:expires,signing_payload:payload})
        })).await
    }
    /// No principal/assurance DTO is accepted. Only the installed verifier can supply evidence.
    pub async fn complete_platform_login(
        &self,
        execution: ExecutionBinding,
        id: Uuid,
        nonce: String,
        browser: String,
        evidence: Vec<u8>,
        deadline: OperationDeadline,
    ) -> Result<PlatformLogin, AuthorityError> {
        let tenant = execution.tenant();
        self.require_runtime()?;
        crate::federation_login::check_browser(&browser)?;
        if nonce.len() != 43 || evidence.is_empty() || evidence.len() > 65_536 || id.is_nil() {
            return Err(AuthorityError::InvalidInput);
        }
        let budget = Budget::new(deadline)?;
        let verifier = self
            .session_checks
            .platform
            .clone()
            .ok_or(AuthorityError::Configuration)?;
        let expected_nonce = digest(&nonce);
        let expected_browser = digest(&browser);
        let context = self
            .read_sql(execution, budget.remaining(), move |c| {
                Box::pin(async move {
                    lock_tenant_collection(c, tenant).await?;
                    let row = challenge(c, tenant, id, &expected_nonce, &expected_browser).await?;
                    Ok(PlatformChallengeContext {
                        purpose: serde_json::from_value(row.try_get("purpose")?)
                            .map_err(|_| corrupt())?,
                        binding: serde_json::from_value(row.try_get("binding")?)
                            .map_err(|_| corrupt())?,
                        audience: row.try_get("audience")?,
                        nonce,
                        created_at: row.try_get("created_at")?,
                        expires_at: row.try_get("expires_at")?,
                    })
                })
            })
            .await?;
        let verified = tokio::time::timeout(
            budget.remaining().timeout(),
            verifier.verify(&context, &evidence),
        )
        .await
        .map_err(|_| AuthorityError::DeadlineElapsed)?
        .map_err(|e| match e {
            PlatformError::Rejected => AuthorityError::Rejected,
            PlatformError::Unavailable => AuthorityError::Unavailable,
            PlatformError::InteractionRequired => AuthorityError::InteractionRequired,
            PlatformError::Cancelled => AuthorityError::Cancelled,
        })?;
        if !verified.key_possession
            || verified.authenticated_at.is_some() && !verified.user_verification
        {
            return Err(AuthorityError::Rejected);
        }
        let stored = PlatformAuthentication {
            binding: context.binding,
            audience: context.audience,
            authenticated_at: verified.authenticated_at,
            hardware_key: verified.hardware_key,
            user_presence: verified.user_presence,
            user_verification: verified.user_verification,
        };
        let enterprise = self.enterprise.clone();
        let checks = self.session_checks.clone();
        let instance = self.instance.as_uuid();
        let policy = self.session_policy;
        let max_auth_facts_bytes = self.max_auth_facts_bytes;
        let future_skew_seconds = self.future_skew_seconds;
        let limits = self.profile_limits;
        self.write_sql(execution,budget.remaining(),move|c|Box::pin(async move{
            lock_tenant_collection(c,tenant).await?;
            let row=challenge(c,tenant,id,&expected_nonce,&expected_browser).await?;
            let actual:PlatformBinding=serde_json::from_value(row.try_get("binding")?).map_err(|_|corrupt())?;
            if actual!=stored.binding || row.try_get::<String,_>("audience")?!=stored.audience {return Err(reject().into());}
            let key=actual.account;let state=account_state_locked(c,key).await?;
            if !state.active() || state.epoch()!=row.try_get::<i64,_>("auth_epoch")? || state.membership_epoch()!=row.try_get::<i64,_>("membership_epoch")? {return Err(reject().into());}
            recheck_binding(c,&stored.binding,stored.verifier(key,instance,&checks)?).await?;
            let purpose:PlatformPurpose=serde_json::from_value(row.try_get("purpose")?).map_err(|_|corrupt())?;
            if purpose != context.purpose {return Err(reject().into());}
            verifier.authorize_purpose(&actual,&purpose,c).await.map_err(failure)?;
            let target = match &enterprise {
                Some(config)=>config.target(&purpose).map_err(|_|reject())?,
                None if purpose==PlatformPurpose::BrowserLogin=>None,
                None=>return Err(reject().into()),
            };
            if row.try_get::<Option<serde_json::Value>,_>("target")? != target.as_ref().map(serde_json::to_value).transpose().map_err(|_|corrupt())? {return Err(reject().into());}
            let now=crate::session_storage::now(c).await?;
            if stored.authenticated_at.is_some_and(|t| t< context.created_at.saturating_sub(i64::from(future_skew_seconds)) || t>now) {return Err(reject().into());}
            let sequence=row.try_get("profile_sequence")?;
            let observation=match verified.profile {
                PlatformProfile::Unavailable=>None,
                PlatformProfile::IdentityLocal=>{
                    let local_sequence=crate::profiles::sequence(c,tenant).await?;
                    let observed=crate::session_storage::now(c).await?;
                    Some(crate::profiles::local_observation(c,key,observed,local_sequence).await?)
                },
                PlatformProfile::Idp{provider,claims}=>{
                    let binding=actual.external_identity.as_ref().ok_or_else(reject)?;
                    if provider!=binding.provider || claims.issued_at<context.created_at.saturating_sub(i64::from(future_skew_seconds)){return Err(reject().into());}
                    let view=crate::federation_storage::provider(c,tenant,provider).await?;
                    let (_,issuer,subject)=crate::federation_storage::identity(c,tenant,binding.identity_id).await?;
                    if claims.issuer!=issuer || claims.subject.storage_key()!=subject {return Err(reject().into());}
                    Some(crate::profiles::oidc_observation(&claims,&view,sequence))
                }
            };
            let (issued,event)=crate::sessions::insert(c,state,None,crate::sessions::SessionAuthentication::Platform(stored.clone()),now,policy,max_auth_facts_bytes).await?;
            let assertion = match target {
                Some(target)=>Some(enterprise::issue(enterprise.as_ref().ok_or_else(reject)?,target,&stored,now,issued.view().absolute_expires_at.min(issued.view().idle_expires_at))?),
                None=>None,
            };
            let mut events=vec![event];
            if let Some(observation)=observation {events.extend(crate::profiles::accept(c,key,issued.view().id,issued.view().absolute_expires_at,observation,limits).await?);}
            if crate::session_storage::now(c).await?>=row.try_get::<i64,_>("expires_at")? {return Err(reject().into());}
            sqlx::query("DELETE FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND challenge_id=$2").bind(tenant.to_string()).bind(id).execute(c).await?;
            Ok((PlatformLogin{session:issued,assertion},events))
        })).await
    }
}
async fn challenge(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    nonce: &[u8; 32],
    browser: &[u8; 32],
) -> Result<sqlx::postgres::PgRow, transaction::MutationError> {
    let row=sqlx::query("SELECT * FROM identity_authority.platform_challenges WHERE tenant_id=$1::uuid AND challenge_id=$2 FOR UPDATE").bind(tenant.to_string()).bind(id).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
    let now = crate::session_storage::now(c).await?;
    if row.try_get::<Vec<u8>, _>("nonce_hash")? != nonce
        || row.try_get::<Vec<u8>, _>("browser_hash")? != browser
        || now < row.try_get("created_at")?
        || now >= row.try_get("expires_at")?
    {
        return Err(reject().into());
    }
    Ok(row)
}

mod instance_codec {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &rss_identity_core::InstanceId,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<rss_identity_core::InstanceId, D::Error> {
        rss_identity_core::InstanceId::parse(&String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}
mod account_codec {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Coordinates {
        tenant: String,
        principal: String,
    }
    pub fn serialize<S: serde::Serializer>(value: &AccountKey, s: S) -> Result<S::Ok, S::Error> {
        Coordinates {
            tenant: value.tenant.to_string(),
            principal: value.principal.as_uuid().to_string(),
        }
        .serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<AccountKey, D::Error> {
        let c = Coordinates::deserialize(d)?;
        Ok(AccountKey {
            tenant: TenantId::parse(&c.tenant).map_err(serde::de::Error::custom)?,
            principal: rss_identity_core::PrincipalId::parse(&c.principal)
                .map_err(serde::de::Error::custom)?,
        })
    }
}
