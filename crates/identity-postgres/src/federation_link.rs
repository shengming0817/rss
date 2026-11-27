use crate::{
    federation::{Action, event},
    federation_login::{check_actor, check_browser},
    federation_storage as db,
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use rss_identity_core::assurance::AuthenticationMode;
use rss_identity_core::{PrincipalId, SessionId, account::LoginKey, federation::*};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
use uuid::Uuid;
pub(crate) struct Intent {
    pub browser: Vec<u8>,
    pub id: Uuid,
    pub principal: PrincipalId,
    pub session: SessionId,
    pub epoch: i64,
    pub member_epoch: i64,
    pub origin: Option<db::Origin>,
    pub local_authenticated_at: Option<i64>,
    pub target: ProviderId,
    pub version: i64,
    pub stage: LinkStage,
    pub created: i64,
    pub expiry: i64,
}
pub(crate) async fn intent(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<Intent, rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(
        "SELECT source_identity AS external_identity_id, source_epoch AS provider_epoch,
                source_facts AS auth_facts, browser_hash, principal_id, session_id, auth_epoch,
                membership_epoch, local_authenticated_at, target_provider, target_version, stage,
                created_at, expires_at FROM identity_authority.link_intents
         WHERE tenant_id=$1::uuid AND intent_id=$2 FOR UPDATE",
    )
    .bind(tenant.to_string())
    .bind(id)
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    // Strictly validate the locked source before a later INSERT SELECT can forward it.
    let origin = db::decode_origin(&r)?.map(|(origin, _)| origin);
    Ok(Intent {
        browser: r.try_get("browser_hash")?,
        id,
        principal: PrincipalId::parse(&r.try_get::<Uuid, _>("principal_id")?.to_string())
            .map_err(|_| corrupt())?,
        session: SessionId::parse(&r.try_get::<Uuid, _>("session_id")?.to_string())
            .map_err(|_| corrupt())?,
        epoch: r.try_get("auth_epoch")?,
        member_epoch: r.try_get("membership_epoch")?,
        origin,
        local_authenticated_at: r.try_get("local_authenticated_at")?,
        target: ProviderId::parse(&r.try_get::<Uuid, _>("target_provider")?.to_string())
            .map_err(|_| corrupt())?,
        version: r.try_get("target_version")?,
        stage: LinkStage::restore(r.try_get("stage")?)?,
        created: r.try_get("created_at")?,
        expiry: r.try_get("expires_at")?,
    })
}
impl Federation {
    pub async fn begin_link(
        &self,
        request: LinkRequest,
        deadline: OperationDeadline,
    ) -> Result<FederatedRedirect, AuthorityError> {
        let LinkRequest {
            actor,
            target_provider,
            password,
            browser,
            target,
            source,
        } = request;
        if actor.view().credential_kind != rss_identity_core::session::CredentialKind::Cookie {
            return Err(AuthorityError::Rejected);
        }

        check_browser(&browser)?;
        let binding = actor.binding;
        let tenant = binding.tenant();
        let mut budget = Budget::new(deadline)?;
        budget.0 = budget.0.shortened_to(actor.expires);
        let return_url = self.target(&target)?;
        let max_auth_facts_bytes = self.authority.max_auth_facts_bytes;
        let (actor,account,source_identity,login)=self.authority.read_sql(binding,budget.remaining(),move |c| { Box::pin(async move {
                    let loaded = session_storage::recheck_collection(c, &actor).await?;
                    let login: Option<String> = sqlx::query_scalar(concat!(
                        "SELECT login_key FROM identity_authority.local_credentials WHERE tenant_id=$1::u",
                        "uid AND principal_id=$2::uuid"
                    ))
                    .bind(tenant.to_string())
                    .bind(actor.key.principal.as_uuid().to_string())
                    .fetch_optional(c)
                    .await?;
                    Ok((actor, loaded.state, loaded.source_identity, login))
                }) }).await?;
        let candidate = if let Some(login) = login {
            let candidate = self
                .authority
                .verify_password(
                    binding,
                    LoginKey::parse(&login).map_err(|_| AuthorityError::Rejected)?,
                    password.ok_or(AuthorityError::Rejected)?,
                    source,
                    budget.remaining(),
                )
                .await?;
            if candidate.state.key() != account.key() {
                return Err(AuthorityError::Rejected);
            }
            Some(candidate)
        } else {
            if password.is_some() {
                return Err(AuthorityError::Rejected);
            }
            self.authority
                .reserve(
                    binding,
                    format!("link:{}", actor.key.principal.as_uuid()),
                    &source,
                    budget.remaining(),
                )
                .await?;
            None
        };
        let target = db::read_provider(
            &self.authority,
            binding,
            target_provider,
            budget.remaining(),
        )
        .await?;
        if !target.enabled {
            return Err(AuthorityError::Rejected);
        }
        let (provider, purpose) = if candidate.is_some() {
            (target.clone(), Purpose::Link)
        } else {
            let identity = source_identity.ok_or(AuthorityError::Rejected)?;
            let id = self
                .authority
                .read_sql(binding, budget.remaining(), move |c| {
                    Box::pin(async move { Ok(db::identity(c, tenant, identity).await?.0) })
                })
                .await?;
            (
                db::read_provider(&self.authority, binding, id, budget.remaining()).await?,
                Purpose::Reauthenticate,
            )
        };
        let state = self
            .signer
            .issue(self.authority.instance(), binding, purpose)?;
        let locator = self.signer.verify(self.authority.instance(), &state)?;
        let material = ProtocolMaterial::new(state)?;
        self.check_assurance_profile(tenant, &provider)?;
        let installed = self
            .installed_provider(binding, &provider, budget.remaining())
            .await?;
        let url = self
            .upstream(
                &budget,
                self.oidc.prepare(
                    installed,
                    &material,
                    if purpose == Purpose::Reauthenticate {
                        AuthenticationMode::Reauthenticate
                    } else {
                        AuthenticationMode::Login
                    },
                    budget.0,
                ),
            )
            .await?;
        self.authority.read_sql(binding,budget.remaining(),move |c| { Box::pin(async move {
                    let loaded = session_storage::recheck_collection(c, &actor).await?;
                    if !loaded.state.matches_verification(account) {
                        return Err(reject().into());
                    }
                    let target_now = db::provider(c, tenant, target.id).await?;
                    db::exact(&target_now, target.version)?;
                    let local_authenticated_at = candidate.as_ref().map(|c| c.authenticated_at);
                    if let Some(candidate) = candidate {
                        current(c, &candidate).await?;
                    } else if loaded.source_identity != source_identity {
                        return Err(reject().into());
                    }
                    let now = session_storage::now(c).await?;
                    let id = Uuid::new_v4();
                    let expiry = now + 300;
                    let written = sqlx::query(concat!(
                        "WITH candidate(identity, epoch, sequence, facts, budget) AS (
                            SELECT NULL::uuid, NULL::bigint, NULL::bigint, NULL::jsonb, $14::bigint
                            WHERE $13::bigint IS NOT NULL
                            UNION ALL
                            SELECT external_identity_id, provider_epoch, facts_sequence, auth_facts, $14
                            FROM identity_authority.sessions
                            WHERE tenant_id=$1::uuid AND principal_id=$3 AND session_id=$4
                              AND external_identity_id IS NOT NULL AND $13 IS NULL
                         )",
                        include_str!("admit-auth-facts.sql"),
                        "INSERT INTO identity_authority.link_intents (
                            tenant_id,intent_id,principal_id,session_id,auth_epoch,membership_epoch,
                            source_identity,source_epoch,source_facts,source_facts_sequence,
                            target_provider,target_version,browser_hash,stage,created_at,expires_at,local_authenticated_at)
                         SELECT $1::uuid,$2,$3,$4,$5,$6,identity,epoch,accepted_facts,sequence,
                                $7::uuid,$8,$9,$10,$11,$12,$13 FROM admitted"
                    ))
                    .bind(tenant.to_string()).bind(id).bind(account.key().principal.as_uuid())
                    .bind(actor.view.id.as_uuid()).bind(account.epoch()).bind(account.membership_epoch())
                    .bind(target.id.to_string()).bind(target.version).bind(digest(&browser).as_slice())
                    .bind(if purpose == Purpose::Link { LinkStage::TargetReady.code() } else { LinkStage::ReauthenticationRequired.code() })
                    .bind(now).bind(expiry).bind(local_authenticated_at)
                    .bind(i64::from(max_auth_facts_bytes.get()))
                    .execute(&mut *c).await?;
                    if written.rows_affected() != 1 { return Err(reject().into()); }
                    db::insert_attempt(
                        c,
                        db::NewAttempt {
                        context: None,
                            mode: if purpose == Purpose::Reauthenticate { AuthenticationMode::Reauthenticate } else { AuthenticationMode::Login },
                            locator,
                            material,
                            provider,
                            browser,
                                            return_url,
                            link: Some(id),
                            replacement: None,
                            expiry: Some(expiry),
                        },
                    )
                    .await
                }) }).await?;
        Ok(FederatedRedirect { url })
    }
    pub(crate) async fn finish_reauthentication(
        &self,
        input: Reauthentication,
        budget: &Budget,
    ) -> Result<FederatedOutcome, AuthorityError> {
        let Reauthentication {
            state,
            browser,
            session,
            old,
            source,
            claims,
        } = input;
        let locator = self.signer.verify(self.authority.instance(), &state)?;
        let binding = locator.binding();
        let tenant = binding.tenant();
        let intent_id = old.link.ok_or(AuthorityError::Rejected)?;
        let target = self
            .authority
            .read_sql(binding, budget.remaining(), move |c| {
                Box::pin(async move {
                    let i = intent(c, tenant, intent_id).await?;
                    let target = db::provider(c, tenant, i.target).await?;
                    db::exact(&target, i.version)?;
                    Ok(target)
                })
            })
            .await?;
        let new_state = self
            .signer
            .issue(self.authority.instance(), binding, Purpose::Link)?;
        let new_locator = self.signer.verify(self.authority.instance(), &new_state)?;
        let material = ProtocolMaterial::new(new_state)?;
        self.check_assurance_profile(tenant, &target)?;
        let installed = self
            .installed_provider(binding, &target, budget.remaining())
            .await?;
        let url = self
            .upstream(
                budget,
                self.oidc
                    .prepare(installed, &material, AuthenticationMode::Login, budget.0),
            )
            .await?;
        let group_policy = self.group_policy;
        let future_skew_seconds = self.authority.future_skew_seconds;
        let max_auth_facts_bytes = self.authority.max_auth_facts_bytes;
        let instance = self.authority.instance.as_uuid();
        self.authority
            .write_sql(binding, budget.remaining(), move |c| {
                Box::pin(async move {
                    lock_tenant_collection(c, tenant).await?;
                    let (attempt, _) = db::attempt(c, &locator, &state, &browser, true).await?;
                    let current_source = db::provider(c, tenant, source.id).await?;
                    db::exact(&current_source, source.version)?;
                    let (_, checked_intent) =
                        check_actor(c, tenant, instance, &attempt, session).await?;
                    let i = checked_intent.ok_or_else(reject)?;
                    let origin = i.origin.as_ref().ok_or_else(reject)?;
                    db::check_origin(
                        c,
                        rss_identity_core::account::AccountKey {
                            tenant,
                            principal: i.principal,
                        },
                        origin,
                    )
                    .await?;
                    let (source_id, issuer, subject) =
                        db::identity(c, tenant, origin.identity).await?;
                    let now = session_storage::now(c).await?;
                    if source_id != source.id
                        || issuer != claims.issuer
                        || subject != claims.subject.storage_key()
                        || claims
                            .assurance
                            .check(
                                AuthenticationMode::Reauthenticate,
                                attempt.created,
                                now,
                                future_skew_seconds,
                            )
                            .is_err()
                    {
                        return Err(FederationError::Claims.into());
                    }
                    let facts = crate::auth_facts::AuthenticationFacts::collect(
                        claims,
                        source.version,
                        group_policy,
                        current_source
                            .settings
                            .claims()
                            .department_snapshot
                            .as_ref(),
                        now,
                        future_skew_seconds,
                    )?;
                    let written = sqlx::query(concat!(
                        "WITH candidate(facts, budget) AS (VALUES ($3::jsonb, $5::bigint))",
                        include_str!("admit-auth-facts.sql"),
                        "UPDATE identity_authority.link_intents
                         SET source_facts=admitted.accepted_facts, source_facts_sequence=$4
                         FROM admitted WHERE tenant_id=$1::uuid AND intent_id=$2"
                    ))
                    .bind(tenant.to_string())
                    .bind(intent_id)
                    .bind(sqlx::types::Json(facts))
                    .bind(crate::profiles::sequence(c, tenant).await?)
                    .bind(i64::from(max_auth_facts_bytes.get()))
                    .execute(&mut *c)
                    .await?;
                    if written.rows_affected() != 1 {
                        return Err(reject().into());
                    }
                    advance(c, tenant, intent_id, LinkStage::ReauthenticationRequired).await?;
                    db::consume(c, &locator).await?;
                    db::insert_attempt(
                        c,
                        db::NewAttempt {
                            context: None,
                            mode: AuthenticationMode::Login,
                            locator: new_locator,
                            material,
                            provider: target,
                            browser,
                            return_url: attempt.return_url,
                            link: Some(intent_id),
                            replacement: None,
                            expiry: Some(i.expiry),
                        },
                    )
                    .await?;
                    Ok((
                        (),
                        vec![event(
                            tenant,
                            Action::Reauthenticated,
                            &source,
                            Some(i.principal),
                        )],
                    ))
                })
            })
            .await?;
        Ok(FederatedOutcome::Redirect(FederatedRedirect { url }))
    }
}
pub(crate) struct Reauthentication {
    pub state: String,
    pub browser: String,
    pub session: Option<[u8; 32]>,
    pub old: db::Attempt,
    pub source: ProviderView,
    pub claims: UpstreamClaims,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkStage {
    ReauthenticationRequired,
    TargetReady,
    Completed,
}
impl LinkStage {
    fn restore(value: i16) -> Result<Self, rss_transactional_messaging_postgres::PgError> {
        match value {
            0 => Ok(Self::ReauthenticationRequired),
            1 => Ok(Self::TargetReady),
            2 => Ok(Self::Completed),
            _ => Err(corrupt()),
        }
    }
    pub(crate) fn code(self) -> i16 {
        match self {
            Self::ReauthenticationRequired => 0,
            Self::TargetReady => 1,
            Self::Completed => 2,
        }
    }
}
pub(crate) async fn advance(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    id: Uuid,
    from: LinkStage,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    let next = match from {
        LinkStage::ReauthenticationRequired => LinkStage::TargetReady,
        LinkStage::TargetReady => LinkStage::Completed,
        LinkStage::Completed => return Err(corrupt()),
    };
    let result=sqlx::query("UPDATE identity_authority.link_intents SET stage=$4 WHERE tenant_id=$1::uuid AND intent_id=$2 AND stage=$3").bind(tenant.to_string()).bind(id).bind(from.code()).bind(next.code()).execute(c).await?;
    if result.rows_affected() != 1 {
        return Err(reject());
    }
    Ok(())
}
