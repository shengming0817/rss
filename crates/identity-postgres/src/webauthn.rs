//! Enterprise RP ceremonies. Cryptography is delegated to webauthn-rs; settlement stays here.
//! ref: webauthn-rs webauthn-rs/src/lib.rs@d2c10d53ca5ef033d37ee6462e936e9eb72ad98c.
use crate::{
    step_up::{AuthenticationAction, GrantSource},
    transaction::{MutationError, corrupt, reject},
    *,
};
use rss_identity_core::{federation::digest, step_up::StepUpContext};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Instance-level RP configuration. Device approval and authenticator attestation are not implied.
#[derive(Clone)]
pub struct WebauthnAuthority {
    authority: Authority,
    verifier: Arc<Webauthn>,
    rp: String,
    config: [u8; 32],
    workers: Arc<tokio::sync::Semaphore>,
}
/// Deployment-trusted RP generation for one operation. Never deserialize browser input into it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpGeneration(i64);
impl RpGeneration {
    pub fn new(value: i64) -> Result<Self, AuthorityError> {
        if value <= 0 {
            return Err(AuthorityError::Configuration);
        }
        Ok(Self(value))
    }
}

/// Host-only authorization choice; never deserialize this from a browser.
pub enum RegistrationAuthorization {
    First,
    StepUp(String),
    /// Host policy must verify an independently authorized recovery in its own authoritative data.
    HostRecovery,
}
#[derive(Serialize)]
pub struct WebauthnChallenge<T: Serialize> {
    pub id: Uuid,
    pub options: T,
    pub expires_at: i64,
}
#[derive(Serialize)]
pub struct WebauthnCredentialView {
    pub id: Uuid,
    pub label: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Ceremony {
    Register {
        state: PasskeyRegistration,
        label: String,
        recover: bool,
        authorization: Option<GrantSource>,
        host_recovery: bool,
    },
    Authenticate {
        state: PasskeyAuthentication,
        context: StepUpContext,
        credentials: Vec<CredentialSnapshot>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialSnapshot {
    id: Uuid,
    version: i64,
    epoch: i64,
    passkey: Passkey,
}
struct Snapshot {
    ceremony: Ceremony,
    epoch: i64,
    observed_at: i64,
    expires_at: i64,
}

/// Stable host-side context for the self-service authenticator operation.
pub fn webauthn_management_context(
    key: AccountKey,
    operation: &str,
    credential: Option<Uuid>,
) -> Result<StepUpContext, AuthorityError> {
    if !matches!(operation, "register" | "remove" | "recover") {
        return Err(AuthorityError::InvalidInput);
    }
    let value = format!(
        "{}/{}/{}/{}",
        key.tenant,
        key.principal.as_uuid(),
        operation,
        credential.map(|v| v.to_string()).unwrap_or_default()
    );
    StepUpContext::new(format!("identity.webauthn.{operation}"), digest(&value))
        .map_err(|_| AuthorityError::InvalidInput)
}
impl WebauthnAuthority {
    pub fn new(authority: Authority, rp: String, origin: url::Url) -> Result<Self, AuthorityError> {
        authority.require_runtime()?;
        let (verifier, config) =
            rp_configuration(&rp, &origin).map_err(|_| AuthorityError::Configuration)?;
        Ok(Self {
            authority,
            verifier: Arc::new(verifier),
            rp,
            config,
            workers: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }
    async fn check_configuration(
        &self,
        c: &mut PgConnection,
        tenant: TenantId,
        expected: RpGeneration,
    ) -> Result<i64, MutationError> {
        // Serialize first use with deployment-owner activation. An unknown tenant cannot
        // create a guard or RP as a side effect of an unauthenticated request.
        storage::lock_tenant_collection(c, tenant).await?;
        sqlx::query("INSERT INTO identity_authority.webauthn_rp(tenant_id,rp,fingerprint,generation) VALUES($1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(tenant.to_string()).bind(&self.rp).bind(self.config.as_slice()).bind(expected.0)
            .execute(&mut *c).await?;
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM identity_authority.webauthn_rp WHERE tenant_id=$1::uuid AND rp=$2 AND fingerprint=$3 AND generation=$4)")
            .bind(tenant.to_string()).bind(&self.rp).bind(self.config.as_slice()).bind(expected.0)
            .fetch_one(c).await?;
        if !valid {
            return Err(reject().into());
        }
        Ok(expected.0)
    }
    pub fn authority(&self) -> Authority {
        self.authority.clone()
    }
    async fn verify<T: Send + 'static>(
        &self,
        budget: &Budget,
        work: impl FnOnce(Arc<Webauthn>) -> Result<T, AuthorityError> + Send + 'static,
    ) -> Result<T, AuthorityError> {
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthorityError::Busy)?;
        let verifier = self.verifier.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(verifier)
        });
        tokio::time::timeout_at(budget.0.instant().into(), task)
            .await
            .map_err(|_| AuthorityError::DeadlineElapsed)?
            .map_err(|_| AuthorityError::Unavailable)?
    }
    pub async fn list(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        deadline: OperationDeadline,
    ) -> Result<Vec<WebauthnCredentialView>, AuthorityError> {
        let this = self.clone();
        let rp = self.rp.clone();
        let config = self.config;
        self.authority.read_sql(actor.binding,deadline,move|c|Box::pin(async move{
            session_storage::recheck_collection(c,&actor).await?;
            this.check_configuration(c,actor.key.tenant,generation).await?;
            let rows=sqlx::query("SELECT id,label FROM identity_authority.webauthn_credentials WHERE tenant_id=$1::uuid AND principal_id=$2 AND rp=$3 AND rp_config=$4 AND NOT revoked ORDER BY id LIMIT 32").bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).bind(rp).bind(config.as_slice()).fetch_all(c).await?;
            rows.into_iter().map(|r|Ok(WebauthnCredentialView{id:r.try_get("id")?,label:r.try_get("label")?})).collect()
        })).await
    }
    pub async fn begin_registration(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        label: String,
        recover: bool,
        authorization: RegistrationAuthorization,
        deadline: OperationDeadline,
    ) -> Result<WebauthnChallenge<CreationChallengeResponse>, AuthorityError> {
        if label.is_empty() || label.len() > 255 || label.chars().any(char::is_control) {
            return Err(AuthorityError::InvalidInput);
        }
        let this = self.clone();
        let context = webauthn_management_context(
            actor.key,
            if recover { "recover" } else { "register" },
            None,
        )?;
        self.authority
            .read_sql(actor.binding, deadline, move |c| {
                Box::pin(async move {
                    let loaded = session_storage::recheck_collection(c, &actor).await?;
                    this.check_configuration(c, actor.key.tenant, generation)
                        .await?;
                    let (handle, enrolled, epoch) = account(c, actor.key).await?;
                    let host_recovery =
                        matches!(authorization, RegistrationAuthorization::HostRecovery);
                    let operation = if host_recovery {
                        ManagementOperation::AuthorizeWebauthnRecovery
                    } else if recover {
                        ManagementOperation::RecoverWebauthn
                    } else {
                        ManagementOperation::RegisterWebauthn
                    };
                    management::authorize(
                        this.authority.policy.as_ref(),
                        this.authority.instance,
                        &loaded,
                        operation,
                        Some(actor.key),
                        c,
                    )
                    .await?;
                    let mut authorization_expires = None;
                    let source = match authorization {
                        RegistrationAuthorization::First
                            if !enrolled
                                && !recover
                                && loaded.recently_authenticated(Duration::from_secs(
                                    u64::from(this.authority.operation_proof_seconds.get()),
                                )) =>
                        {
                            authorization_expires = Some(
                                loaded
                                    .assurance
                                    .auth_time()
                                    .ok_or_else(reject)?
                                    .checked_add(i64::from(
                                        this.authority.operation_proof_seconds.get(),
                                    ))
                                    .ok_or_else(reject)?,
                            );
                            None
                        }
                        RegistrationAuthorization::StepUp(token) => {
                            let consumed =
                                crate::consume_step_up_on(c, &actor, &context, &token).await?;
                            authorization_expires = Some(consumed.expires_at);
                            Some(consumed.source)
                        }
                        RegistrationAuthorization::HostRecovery if recover => None,
                        _ => return Err(reject().into()),
                    };
                    let keys = credentials(c, actor.key, &this.rp, &this.config).await?;
                    if !recover && keys.len() >= 16 {
                        return Err(reject().into());
                    }
                    let exclude = keys.iter().map(|v| v.passkey.cred_id().clone()).collect();
                    let (options, state) = this
                        .verifier
                        .start_passkey_registration(
                            handle,
                            &actor.key.principal.as_uuid().to_string(),
                            &actor.key.principal.as_uuid().to_string(),
                            Some(exclude),
                        )
                        .map_err(|_| reject())?;
                    let ceremony = Ceremony::Register {
                        state,
                        label,
                        recover,
                        authorization: source,
                        host_recovery,
                    };
                    let (id, expires_at) = store(
                        c,
                        &loaded,
                        epoch,
                        this.config,
                        &ceremony,
                        authorization_expires,
                    )
                    .await?;
                    Ok(WebauthnChallenge {
                        id,
                        options,
                        expires_at,
                    })
                })
            })
            .await
    }
    pub async fn finish_registration(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        id: Uuid,
        response: RegisterPublicKeyCredential,
        deadline: OperationDeadline,
    ) -> Result<WebauthnCredentialView, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let snapshot = self
            .snapshot(&actor, generation, id, budget.remaining())
            .await?;
        let Ceremony::Register {
            state,
            label,
            recover,
            authorization,
            host_recovery,
        } = snapshot.ceremony
        else {
            return Err(AuthorityError::Rejected);
        };
        if serde_json::to_vec(&response)
            .map_err(|_| AuthorityError::InvalidInput)?
            .len()
            > 65536
        {
            return Err(AuthorityError::InvalidInput);
        }
        let passkey = self
            .verify(&budget, move |v| {
                v.finish_passkey_registration(&response, &state)
                    .map_err(|_| AuthorityError::Rejected)
            })
            .await?;
        let this = self.clone();
        self.authority.write_sql(actor.binding,budget.remaining(),move|c|Box::pin(async move{
            let loaded=session_storage::recheck_collection(c,&actor).await?;
            this.check_configuration(c,actor.key.tenant,generation).await?;
            let current=read(c,&actor,id,this.config).await?;
            if current.epoch!=snapshot.epoch || !matches!(current.ceremony,Ceremony::Register{..}) {return Err(reject().into());}
            management::authorize(this.authority.policy.as_ref(),this.authority.instance,&loaded,if host_recovery{ManagementOperation::AuthorizeWebauthnRecovery}else if recover{ManagementOperation::RecoverWebauthn}else{ManagementOperation::RegisterWebauthn},Some(actor.key),c).await?;
            if let Some(source)=authorization {crate::step_up::validate_source(c,actor.key,&source).await?;}
            if recover {sqlx::query("UPDATE identity_authority.webauthn_credentials SET revoked=true,epoch=epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2 AND NOT revoked").bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).execute(&mut *c).await?;}
            let id_new=Uuid::new_v4();let hash=Sha256::digest(passkey.cred_id().as_ref());
            let inserted=sqlx::query("INSERT INTO identity_authority.webauthn_credentials(tenant_id,principal_id,id,rp,rp_config,credential_hash,value,label) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(rp,credential_hash) DO NOTHING")
                .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).bind(id_new).bind(&this.rp).bind(this.config.as_slice()).bind(hash.as_slice()).bind(serde_json::to_value(passkey).map_err(|_|corrupt())?).bind(&label).execute(&mut *c).await?.rows_affected();
            if inserted!=1 {return Err(reject().into());}
            sqlx::query("UPDATE identity_authority.webauthn_accounts SET enrolled=true,epoch=epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2").bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).execute(&mut *c).await?;
            if session_storage::now(c).await?>=current.expires_at{return Err(reject().into());}
            consume(c,actor.key,id).await?;
            Ok((WebauthnCredentialView{id:id_new,label},vec![crate::step_up::event(actor.key,if recover{AuthenticationAction::Recovered}else{AuthenticationAction::Registered})]))
        })).await
    }
    pub async fn begin_authentication(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        context: StepUpContext,
        deadline: OperationDeadline,
    ) -> Result<WebauthnChallenge<RequestChallengeResponse>, AuthorityError> {
        let this = self.clone();
        self.authority
            .read_sql(actor.binding, deadline, move |c| {
                Box::pin(async move {
                    let loaded = session_storage::recheck_collection(c, &actor).await?;
                    this.check_configuration(c, actor.key.tenant, generation)
                        .await?;
                    let (_, _, epoch) = account(c, actor.key).await?;
                    let keys = credentials(c, actor.key, &this.rp, &this.config).await?;
                    if keys.is_empty() {
                        return Err(reject().into());
                    }
                    let passkeys = keys.iter().map(|v| v.passkey.clone()).collect::<Vec<_>>();
                    let (options, state) = this
                        .verifier
                        .start_passkey_authentication(&passkeys)
                        .map_err(|_| reject())?;
                    let (id, expires_at) = store(
                        c,
                        &loaded,
                        epoch,
                        this.config,
                        &Ceremony::Authenticate {
                            state,
                            context,
                            credentials: keys,
                        },
                        None,
                    )
                    .await?;
                    Ok(WebauthnChallenge {
                        id,
                        options,
                        expires_at,
                    })
                })
            })
            .await
    }
    pub async fn finish_authentication(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        id: Uuid,
        response: PublicKeyCredential,
        deadline: OperationDeadline,
    ) -> Result<StepUpGrant, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let snapshot = self
            .snapshot(&actor, generation, id, budget.remaining())
            .await?;
        let Ceremony::Authenticate {
            state,
            context,
            mut credentials,
        } = snapshot.ceremony
        else {
            return Err(AuthorityError::Rejected);
        };
        if serde_json::to_vec(&response)
            .map_err(|_| AuthorityError::InvalidInput)?
            .len()
            > 65536
        {
            return Err(AuthorityError::InvalidInput);
        }
        let result = self
            .verify(&budget, move |v| {
                v.finish_passkey_authentication(&response, &state)
                    .map_err(|_| AuthorityError::Rejected)
            })
            .await?;
        if !result.user_verified() {
            return Err(AuthorityError::Rejected);
        }
        let index = credentials
            .iter()
            .position(|v| v.passkey.cred_id() == result.cred_id())
            .ok_or(AuthorityError::Rejected)?;
        let mut selected = credentials.swap_remove(index);
        selected
            .passkey
            .update_credential(&result)
            .ok_or(AuthorityError::Rejected)?;
        let this = self.clone();
        self.authority.write_sql(actor.binding,budget.remaining(),move|c|Box::pin(async move{
            let loaded=session_storage::recheck_collection(c,&actor).await?;
            this.check_configuration(c,actor.key.tenant,generation).await?;
            let current=read(c,&actor,id,this.config).await?;
            if current.epoch!=snapshot.epoch || !matches!(current.ceremony,Ceremony::Authenticate{..}) {return Err(reject().into());}
            let updated=sqlx::query("UPDATE identity_authority.webauthn_credentials SET value=$6,version=version+1 WHERE tenant_id=$1::uuid AND principal_id=$2 AND id=$3 AND version=$4 AND epoch=$5 AND NOT revoked")
                .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).bind(selected.id).bind(selected.version).bind(selected.epoch).bind(serde_json::to_value(selected.passkey).map_err(|_|corrupt())?).execute(&mut *c).await?.rows_affected();
            if updated!=1 {return Err(reject().into());}
            let now=snapshot.observed_at;
            let grant=crate::step_up::issue(c,&loaded,&context,GrantSource::Webauthn{credential:selected.id,epoch:selected.epoch,configuration:generation.0,rp:this.rp},now, this.authority.operation_proof_seconds).await?;
            if session_storage::now(c).await?>=current.expires_at{return Err(reject().into());}
            consume(c,actor.key,id).await?;
            Ok((grant,vec![crate::step_up::event(actor.key,AuthenticationAction::Verified)]))
        })).await
    }
    pub async fn remove(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        id: Uuid,
        grant: String,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        let this = self.clone();
        let context = webauthn_management_context(actor.key, "remove", Some(id))?;
        self.authority.write_sql(actor.binding,deadline,move|c|Box::pin(async move{
            let loaded=session_storage::recheck_collection(c,&actor).await?;
            this.check_configuration(c,actor.key.tenant,generation).await?;
            management::authorize(this.authority.policy.as_ref(),this.authority.instance,&loaded,ManagementOperation::RemoveWebauthn,Some(actor.key),c).await?;
            crate::consume_step_up_on(c,&actor,&context,&grant).await?;
            let changed=sqlx::query("UPDATE identity_authority.webauthn_credentials SET revoked=true,epoch=epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2 AND id=$3 AND NOT revoked").bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).bind(id).execute(&mut *c).await?.rows_affected();
            if changed!=1 {return Err(reject().into());}
            sqlx::query("UPDATE identity_authority.webauthn_accounts SET epoch=epoch+1 WHERE tenant_id=$1::uuid AND principal_id=$2").bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).execute(c).await?;
            Ok(((),vec![crate::step_up::event(actor.key,AuthenticationAction::Removed)]))
        })).await
    }
    pub async fn cancel(
        &self,
        actor: AuthenticatedSession,
        generation: RpGeneration,
        id: Uuid,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        let config = self.config;
        let this = self.clone();
        self.authority
            .read_sql(actor.binding, deadline, move |c| {
                Box::pin(async move {
                    read(c, &actor, id, config).await?;
                    this.check_configuration(c, actor.key.tenant, generation)
                        .await?;
                    consume(c, actor.key, id).await?;
                    Ok(())
                })
            })
            .await
    }
    async fn snapshot(
        &self,
        actor: &AuthenticatedSession,
        generation: RpGeneration,
        id: Uuid,
        deadline: OperationDeadline,
    ) -> Result<Snapshot, AuthorityError> {
        // Keep the original actor to recheck its digest again at final settlement.
        let key = actor.key;
        let session = actor.view.id;
        let checks = actor.session_checks.clone();
        let expected = actor.digest;
        let authority = actor.authority;
        let config = self.config;
        let this = self.clone();
        self.authority
            .read_sql(actor.binding, deadline, move |c| {
                Box::pin(async move {
                    if storage::authority_id(c).await? != authority {
                        return Err(reject().into());
                    }
                    storage::lock_tenant_collection(c, key.tenant).await?;
                    let loaded = session_storage::lookup_locked(
                        c,
                        key.tenant,
                        &expected,
                        rss_identity_core::session::CredentialKind::Cookie,
                        authority,
                        &checks,
                    )
                    .await?;
                    if loaded.view.id != session || loaded.state.key() != key {
                        return Err(reject().into());
                    }
                    this.check_configuration(c, key.tenant, generation).await?;
                    read_loaded(c, &loaded, id, config).await
                })
            })
            .await
    }
}
async fn account(
    c: &mut PgConnection,
    key: AccountKey,
) -> Result<(Uuid, bool, i64), MutationError> {
    sqlx::query("INSERT INTO identity_authority.webauthn_accounts(tenant_id,principal_id) VALUES($1::uuid,$2) ON CONFLICT DO NOTHING").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).execute(&mut *c).await?;
    Ok(sqlx::query_as("SELECT user_handle,enrolled,epoch FROM identity_authority.webauthn_accounts WHERE tenant_id=$1::uuid AND principal_id=$2 FOR UPDATE").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_one(c).await?)
}
async fn credentials(
    c: &mut PgConnection,
    key: AccountKey,
    rp: &str,
    config: &[u8; 32],
) -> Result<Vec<CredentialSnapshot>, MutationError> {
    let rows=sqlx::query("SELECT id,version,epoch,value FROM identity_authority.webauthn_credentials WHERE tenant_id=$1::uuid AND principal_id=$2 AND rp=$3 AND rp_config=$4 AND NOT revoked ORDER BY id LIMIT 17").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(rp).bind(config.as_slice()).fetch_all(c).await?;
    rows.into_iter()
        .map(|r| {
            Ok(CredentialSnapshot {
                id: r.try_get("id")?,
                version: r.try_get("version")?,
                epoch: r.try_get("epoch")?,
                passkey: serde_json::from_value(r.try_get("value")?).map_err(|_| corrupt())?,
            })
        })
        .collect()
}
async fn store(
    c: &mut PgConnection,
    loaded: &session_storage::Loaded,
    epoch: i64,
    config: [u8; 32],
    state: &Ceremony,
    authorization_expires: Option<i64>,
) -> Result<(Uuid, i64), MutationError> {
    let key = loaded.state.key();
    let now = session_storage::now(c).await?;
    sqlx::query("DELETE FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND principal_id=$2 AND expires_at<=$3")
        .bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(now).execute(&mut *c).await?;
    sqlx::query("DELETE FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND id IN (SELECT id FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND expires_at<=$2 ORDER BY expires_at LIMIT 128)").bind(key.tenant.to_string()).bind(now).execute(&mut *c).await?;
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND principal_id=$2").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).fetch_one(&mut *c).await?;
    if count >= 8 {
        return Err(reject().into());
    }
    let id = Uuid::new_v4();
    let expires = now
        .checked_add(120)
        .ok_or_else(reject)?
        .min(loaded.view.idle_expires_at)
        .min(loaded.view.absolute_expires_at)
        .min(authorization_expires.unwrap_or(i64::MAX));
    if expires <= now {
        return Err(reject().into());
    }
    sqlx::query("INSERT INTO identity_authority.webauthn_ceremonies(tenant_id,id,principal_id,session_id,auth_epoch,membership_epoch,credential_epoch,rp_config,state,created_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(key.tenant.to_string()).bind(id).bind(key.principal.as_uuid()).bind(loaded.view.id.as_uuid()).bind(loaded.state.epoch()).bind(loaded.state.membership_epoch()).bind(epoch).bind(config.as_slice()).bind(serde_json::to_value(state).map_err(|_|corrupt())?).bind(now).bind(expires).execute(c).await?;
    Ok((id, expires))
}
async fn read(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
    id: Uuid,
    config: [u8; 32],
) -> Result<Snapshot, MutationError> {
    let loaded = session_storage::recheck_collection(c, actor).await?;
    read_loaded(c, &loaded, id, config).await
}
async fn read_loaded(
    c: &mut PgConnection,
    loaded: &session_storage::Loaded,
    id: Uuid,
    config: [u8; 32],
) -> Result<Snapshot, MutationError> {
    let key = loaded.state.key();
    let row=sqlx::query("SELECT * FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE").bind(key.tenant.to_string()).bind(id).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
    let (_, _, epoch) = account(c, key).await?;
    let now = session_storage::now(c).await?;
    if row.try_get::<Uuid, _>("principal_id")? != key.principal.as_uuid()
        || row.try_get::<Uuid, _>("session_id")? != loaded.view.id.as_uuid()
        || row.try_get::<i64, _>("auth_epoch")? != loaded.state.epoch()
        || row.try_get::<i64, _>("membership_epoch")? != loaded.state.membership_epoch()
        || row.try_get::<i64, _>("credential_epoch")? != epoch
        || row.try_get::<Vec<u8>, _>("rp_config")? != config
        || now < row.try_get::<i64, _>("created_at")?
        || now >= row.try_get::<i64, _>("expires_at")?
    {
        return Err(reject().into());
    }
    Ok(Snapshot {
        ceremony: serde_json::from_value(row.try_get("state")?).map_err(|_| corrupt())?,
        epoch,
        observed_at: now,
        expires_at: row.try_get("expires_at")?,
    })
}
async fn consume(c: &mut PgConnection, key: AccountKey, id: Uuid) -> Result<(), MutationError> {
    let count=sqlx::query("DELETE FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND principal_id=$2 AND id=$3").bind(key.tenant.to_string()).bind(key.principal.as_uuid()).bind(id).execute(c).await?.rows_affected();
    if count != 1 {
        return Err(reject().into());
    }
    Ok(())
}

fn rp_configuration(
    rp: &str,
    origin: &url::Url,
) -> Result<(Webauthn, [u8; 32]), rss_transactional_messaging_postgres::PgError> {
    if origin.scheme() != "https"
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err(reject());
    }
    let verifier = WebauthnBuilder::new(rp, origin)
        .map_err(|_| reject())?
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|_| reject())?;
    Ok((verifier, digest(&format!("{rp}\n{origin}\nuv-required-v1"))))
}
/// Deployment-owner operation, in an explicit tenant-scoped transaction. Runtime lacks UPDATE
/// permission on this table. Advance by expected generation; stale deployments cannot revert it.
/// The host owns deployment authorization, audit and transaction settlement.
pub async fn activate_webauthn_rp_on(
    c: &mut PgConnection,
    instance: rss_identity_core::InstanceId,
    tenant: TenantId,
    rp: &str,
    origin: &url::Url,
    expected_generation: i64,
) -> Result<i64, rss_transactional_messaging_postgres::PgError> {
    use sqlx::Connection;
    if !c.is_in_transaction() || expected_generation < 1 {
        return Err(reject());
    }
    let (scope, isolation): (Option<String>, String) = sqlx::query_as(
        "SELECT current_setting('rss.tenant_id',true),current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *c)
    .await?;
    if scope.as_deref() != Some(tenant.to_string().as_str())
        || isolation != "read committed"
        || storage::authority_id(c).await? != instance.as_uuid()
    {
        return Err(reject());
    }
    let (_, fingerprint) = rp_configuration(rp, origin)?;
    storage::lock_tenant_collection(c, tenant).await?;
    let previous: Vec<u8> = sqlx::query_scalar(
        "SELECT fingerprint FROM identity_authority.webauthn_rp WHERE tenant_id=$1::uuid AND rp=$2",
    )
    .bind(tenant.to_string())
    .bind(rp)
    .fetch_one(&mut *c)
    .await?;
    let next=sqlx::query_scalar("UPDATE identity_authority.webauthn_rp SET fingerprint=$3,generation=generation+1 WHERE tenant_id=$1::uuid AND rp=$2 AND generation=$4 RETURNING generation").bind(tenant.to_string()).bind(rp).bind(fingerprint.as_slice()).bind(expected_generation).fetch_optional(&mut *c).await?.ok_or_else(reject)?;
    // Also invalidate same-config rotations and A→B→A transitions under the tenant guard.
    sqlx::query("DELETE FROM identity_authority.webauthn_ceremonies WHERE tenant_id=$1::uuid AND rp_config=$2")
        .bind(tenant.to_string()).bind(previous).execute(&mut *c).await?;
    sqlx::query("UPDATE identity_authority.webauthn_credentials SET revoked=true,epoch=epoch+1 WHERE tenant_id=$1::uuid AND rp=$2 AND NOT revoked").bind(tenant.to_string()).bind(rp).execute(c).await?;
    Ok(next)
}
