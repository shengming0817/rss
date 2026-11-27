use crate::{
    federation::{Action, event},
    federation_storage as db,
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use rss_identity_core::assurance::AuthenticationMode;
use rss_identity_core::{PrincipalId, account::AccountKey, federation::*, session::SessionSecret};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use sqlx::Row;
use uuid::Uuid;
use zeroize::Zeroizing;
impl Federation {
    pub async fn begin_login(
        &self,
        request: LoginRequest,
        deadline: OperationDeadline,
    ) -> Result<FederatedRedirect, AuthorityError> {
        self.begin_authentication(request, AuthenticationMode::Login, None, deadline)
            .await
    }
    /// Prove one host-selected operation for the same already-linked principal.
    pub async fn begin_step_up(
        &self,
        request: LoginRequest,
        context: rss_identity_core::step_up::StepUpContext,
        deadline: OperationDeadline,
    ) -> Result<FederatedRedirect, AuthorityError> {
        if request.replacement.is_none() {
            return Err(FederationError::Rejected.into());
        }
        self.begin_authentication(request, AuthenticationMode::StepUp, Some(context), deadline)
            .await
    }
    pub(crate) async fn begin_authentication(
        &self,
        request: LoginRequest,
        mode: AuthenticationMode,
        context: Option<rss_identity_core::step_up::StepUpContext>,
        deadline: OperationDeadline,
    ) -> Result<FederatedRedirect, AuthorityError> {
        let LoginRequest {
            binding,
            provider,
            browser,
            target,
            replacement,
            source,
        } = request;
        let tenant = binding.tenant();
        if replacement.as_ref().is_some_and(|p| {
            p.binding != binding
                || p.view().credential_kind != rss_identity_core::session::CredentialKind::Cookie
        }) {
            return Err(AuthorityError::Rejected);
        }
        check_browser(&browser)?;
        let budget = Budget::new(deadline)?;
        let return_url = self.target(&target)?;
        let (view, replacement) = if mode == AuthenticationMode::StepUp {
            let actor = replacement.ok_or(FederationError::Rejected)?;
            let oidc = self.oidc.clone();
            self.authority
                .read_sql(binding, budget.remaining(), move |c| {
                    Box::pin(async move {
                        lock_tenant_collection(c, tenant).await?;
                        if actor.key.tenant != tenant {
                            return Err(reject().into());
                        }
                        session_storage::recheck_collection(c, &actor).await?;
                        let view = db::provider(c, tenant, provider).await?;
                        crate::federation::check_step_up(c, actor.key, &view, oidc.as_ref())
                            .await?;
                        Ok((view, Some(actor)))
                    })
                })
                .await?
        } else {
            (
                db::read_provider(&self.authority, binding, provider, budget.remaining()).await?,
                replacement,
            )
        };
        self.check_assurance_profile(tenant, &view)?;
        let installed = self
            .installed_provider(binding, &view, budget.remaining())
            .await?;
        if !view.enabled {
            return Err(FederationError::Rejected.into());
        }
        self.authority
            .reserve(
                binding,
                format!("oidc:{}:{}", provider, hex_digest(&browser)),
                &source,
                budget.remaining(),
            )
            .await?;
        let state = self
            .signer
            .issue(self.authority.instance(), binding, Purpose::Login)?;
        let locator = self.signer.verify(self.authority.instance(), &state)?;
        let material = ProtocolMaterial::new(state)?;
        let url = self
            .upstream(
                &budget,
                self.oidc.prepare(installed, &material, mode, budget.0),
            )
            .await?;
        let oidc = self.oidc.clone();
        self.authority
            .read_sql(binding, budget.remaining(), move |c| {
                Box::pin(async move {
                    lock_tenant_collection(c, tenant).await?;
                    let replacement = match replacement {
                        Some(proof) => {
                            if proof.key.tenant != tenant {
                                return Err(reject().into());
                            }
                            let loaded = session_storage::recheck_collection(c, &proof).await?;
                            if mode == AuthenticationMode::StepUp {
                                let current = db::provider(c, tenant, provider).await?;
                                db::exact(&current, view.version)?;
                                crate::federation::check_step_up(
                                    c,
                                    proof.key,
                                    &current,
                                    oidc.as_ref(),
                                )
                                .await?;
                            }
                            Some(loaded.view.id)
                        }
                        None => None,
                    };
                    db::insert_attempt(
                        c,
                        db::NewAttempt {
                            context,
                            locator,
                            material,
                            provider: view,
                            browser,
                            return_url,
                            link: None,
                            replacement,
                            expiry: None,
                            mode,
                        },
                    )
                    .await
                })
            })
            .await?;
        Ok(FederatedRedirect { url })
    }
    /// End a bound upstream rejection without contacting the token endpoint.
    pub async fn cancel(
        &self,
        state: String,
        browser: String,
        response_issuer: String,
        session: Option<SessionSecret>,
        deadline: OperationDeadline,
    ) -> Result<(), AuthorityError> {
        check_browser(&browser)?;
        let locator = self.signer.verify(self.authority.instance(), &state)?;
        let binding = locator.binding();
        let tenant = binding.tenant();
        let session = session.map(|s| s.digest());
        let instance = self.authority.instance.as_uuid();
        self.authority
            .read_sql(binding, deadline, move |c| {
                Box::pin(async move {
                    lock_tenant_collection(c, tenant).await?;
                    let (attempt, _) = db::attempt(c, &locator, &state, &browser, false).await?;
                    let view = db::provider(c, tenant, attempt.provider).await?;
                    db::exact(&view, attempt.version)?;
                    if view.settings.issuer().as_str() != response_issuer {
                        return Err(FederationError::Claims.into());
                    }
                    check_actor(c, tenant, instance, &attempt, session).await?;
                    db::consume(c, &locator).await?;
                    Ok(())
                })
            })
            .await
    }

    pub async fn complete(
        &self,
        state: String,
        browser: String,
        code: Zeroizing<String>,
        response_issuer: String,
        session: Option<SessionSecret>,
        deadline: OperationDeadline,
    ) -> Result<FederatedOutcome, AuthorityError> {
        // Keep the protocol/transaction orchestration off the caller's async frame.
        Box::pin(async move {
        check_browser(&browser)?;
        let budget = Budget::new(deadline)?;
        let locator = self.signer.verify(self.authority.instance(), &state)?;
        let binding = locator.binding();
        let tenant = binding.tenant();
        let session = session.map(|s| s.digest());
        let claim_state = state.clone();
        let claim_browser = browser.clone();
        let claimed_issuer = response_issuer;
        let claim_oidc = self.oidc.clone();
        let instance = self.authority.instance.as_uuid();
        let (attempt,view,material)=self.authority.read_sql(binding,budget.remaining(),move |c| { Box::pin(async move {
                    lock_tenant_collection(c, tenant).await?;
                    let (attempt, secrets) = db::attempt(c, &locator, &claim_state, &claim_browser, false).await?;
                    let view = db::provider(c, tenant, attempt.provider).await?;
                    db::exact(&view, attempt.version)?;
                    if view.settings.issuer().as_str()!=claimed_issuer{return Err(FederationError::Claims.into())}
                    let (actor, _) = check_actor(c, tenant, instance, &attempt, session).await?;
                    if attempt.mode == AuthenticationMode::StepUp {
                        crate::federation::check_step_up(c, actor.as_ref().ok_or_else(reject)?.state.key(), &view, claim_oidc.as_ref()).await?;
                    }
                    let (nonce, verifier) = secrets.ok_or_else(corrupt)?;
                    sqlx::query(concat!(
                        "UPDATE identity_authority.oidc_transactions SET claimed=true,nonce=NULL,verifier",
                        "=NULL WHERE tenant_id=$1::uuid AND attempt_id=$2"
                    ))
                    .bind(tenant.to_string())
                    .bind(locator.id().as_slice())
                    .execute(c)
                    .await?;
                    Ok((
                        attempt,
                        view,
                        ProtocolMaterial {
                            state: Zeroizing::new(claim_state),
                            nonce: Zeroizing::new(nonce),
                            verifier: Zeroizing::new(verifier),
                        },
                    ))
                }) }).await?;
        self.check_assurance_profile(tenant, &view)?;
        let installed = self
            .installed_provider(binding, &view, budget.remaining())
            .await?;
        if !self.allowed_return(&attempt.return_url) {
            return Err(FederationError::Rejected.into());
        }
        let claims = self
            .upstream(
                &budget,
                self.oidc
                    .exchange(installed, material, code, budget.0),
            )
            .await?;
        claims.validate()?;
        if !claims.subject.matches(&view.settings.claims().subject) { return Err(FederationError::Claims.into()); }
        if claims.issuer != view.settings.issuer().as_str() {
            return Err(FederationError::Claims.into());
        }
        if attempt.purpose == Purpose::Reauthenticate {
            return self
                .finish_reauthentication(
                    crate::federation_link::Reauthentication {
                        state,
                        browser,
                        session,
                        old: attempt,
                        source: view,
                        claims,
                    },
                    &budget,
                )
                .await;
        }
        let locator = self.signer.verify(self.authority.instance(), &state)?;
        let commit_oidc = self.oidc.clone();
        let group_policy = self.group_policy;
        let future_skew_seconds = self.authority.future_skew_seconds;
        let max_auth_facts_bytes = self.authority.max_auth_facts_bytes;
        let operation_proof_seconds = self.authority.operation_proof_seconds;
        let session_policy = self.authority.session_policy;
        let limits = self.authority.profile_limits;
        let instance = self.authority.instance.as_uuid();
        self.authority.write_sql(binding,budget.remaining(),move |c| { Box::pin(async move {
                    lock_tenant_collection(c, tenant).await?;
                    let (attempt, _) = db::attempt(c, &locator, &state, &browser, true).await?;
                    let view = db::provider(c, tenant, attempt.provider).await?;
                    db::exact(&view, attempt.version)?;
                    let (actor, intent) = check_actor(c, tenant, instance, &attempt, session).await?;
                    if attempt.mode == AuthenticationMode::StepUp {
                        crate::federation::check_step_up(c, actor.as_ref().ok_or_else(reject)?.state.key(), &view, commit_oidc.as_ref()).await?;
                    }
                    let existing = sqlx::query(concat!(
                        "SELECT identity_id,principal_id FROM identity_authority.external_identities WHER",
                        "E tenant_id=$1::uuid AND provider_id=$2::uuid AND issuer=$3 AND subject=$4"
                    ))
                    .bind(tenant.to_string())
                    .bind(view.id.to_string())
                    .bind(&claims.issuer)
                    .bind(claims.subject.storage_key())
                    .fetch_optional(&mut *c)
                    .await?;
                    let linked = attempt.purpose == Purpose::Link;
                    // JIT account/link inserts acquire directory revision keys via triggers.
                    // Reserve issuance order before the first such write in this transaction.
                    let facts_sequence = if !linked && attempt.mode != AuthenticationMode::StepUp {
                        Some(crate::profiles::sequence(c, tenant).await?)
                    } else {
                        None
                    };
                    let (key, new_account) = if linked {
                        (actor.as_ref().ok_or_else(reject)?.state.key(), false)
                    } else if let Some(row) = &existing {
                        (
                            AccountKey {
                                tenant,
                                principal: PrincipalId::parse(&row.try_get::<Uuid, _>("principal_id")?.to_string())
                                    .map_err(|_| corrupt())?,
                            },
                            false,
                        )
                    } else {
                        if attempt.mode == AuthenticationMode::StepUp || !view.settings.jit() {
                            return Err(FederationError::Rejected.into());
                        }
                        let key=AccountKey{tenant,principal:PrincipalId::generate()};
                        insert_federated_account(c,key).await?;
                        (key, true)
                    };
                    let already = existing.is_some();
                    let identity_id = if let Some(row) = existing {
                        if row.try_get::<Uuid, _>("principal_id")? != key.principal.as_uuid() {
                            return Err(FederationError::Conflict.into());
                        }
                        row.try_get("identity_id")?
                    } else {
                        let id = Uuid::new_v4();
                        sqlx::query("INSERT INTO identity_authority.external_identities(tenant_id,identity_id,principal_id,provider_id,issuer,subject) VALUES($1::uuid,$2,$3,$4::uuid,$5,$6)").bind(tenant.to_string()).bind(id).bind(key.principal.as_uuid()).bind(view.id.to_string()).bind(&claims.issuer).bind(claims.subject.storage_key()).execute(&mut *c).await?;
                        id
                    };
                    let mut state = account_state_locked(c, key).await?;
                    if !state.active() {
                        return Err(reject().into());
                    }
                    let now = session_storage::now(c).await?;
                    claims.assurance.check(attempt.mode, attempt.created, now, future_skew_seconds)?;
                    if attempt.mode == AuthenticationMode::StepUp {
                        let actor = actor.as_ref().ok_or_else(reject)?;
                        if actor.state.key()!=key {return Err(reject().into());}
                        let context=attempt.context.as_ref().ok_or_else(corrupt)?;
                        let grant=crate::step_up::issue(c,actor,context,crate::step_up::GrantSource::Oidc {
                            identity:identity_id,provider:Uuid::parse_str(&view.id.to_string()).map_err(|_|corrupt())?,version:view.version,epoch:view.revocation_epoch,
                        },claims.assurance.auth_time().ok_or_else(reject)?, operation_proof_seconds).await?;
                        if session_storage::now(c).await?>=attempt.expiry {return Err(reject().into());}
                        db::consume(c,&locator).await?;
                        return Ok((FederatedOutcome::StepUp{grant,return_url:attempt.return_url},vec![crate::step_up::event(key,crate::step_up::AuthenticationAction::Verified)]));
                    }
                    let observation = (!linked).then(|| crate::profiles::oidc_observation(&claims,&view,attempt.profile_sequence));
                    let (origin, replaced) = if linked {
                        let intent = intent.ok_or_else(reject)?;
                        if intent.stage != crate::federation_link::LinkStage::TargetReady || intent.target != view.id || intent.version != view.version {
                            return Err(reject().into());
                        }
                        state = state.revoke_sessions()?;
                        sqlx::query(concat!(
                            "UPDATE identity_authority.accounts SET auth_epoch=$3 WHERE tenant_id=$1::uuid AN",
                            "D principal_id=$2::uuid"
                        ))
                        .bind(tenant.to_string())
                        .bind(key.principal.as_uuid().to_string())
                        .bind(state.epoch())
                        .execute(&mut *c)
                        .await?;
                        crate::federation_link::advance(c,tenant,intent.id,crate::federation_link::LinkStage::TargetReady).await?;
                        if let Some(origin) = &intent.origin {
                            db::check_origin(c, key, origin).await?;
                        }
                        (match intent.origin {
                            Some(_) => sessions::SessionAuthentication::LinkedOidc { intent: intent.id },
                            None => sessions::SessionAuthentication::LocalPassword(intent.local_authenticated_at.ok_or_else(reject)?, rss_identity_core::session::CredentialKind::Cookie),
                        }, Some(intent.session))
                    } else {
                        if let Some(actor) = actor
                            && actor.state.key() != key
                        {
                            return Err(reject().into());
                        }
                        (
                            sessions::SessionAuthentication::Oidc(sessions::NewOidcFacts {
                                identity: identity_id,
                                epoch: view.revocation_epoch,
                                sequence: facts_sequence.ok_or_else(corrupt)?,
                                facts: crate::auth_facts::AuthenticationFacts::collect(claims, view.version, group_policy, view.settings.claims().department_snapshot.as_ref(), now, future_skew_seconds)?,
                            }),
                            attempt.replacement,
                        )
                    };
                    let (issued, session_event) = sessions::insert(c, state, replaced, origin, now, session_policy, max_auth_facts_bytes).await?;
                    if linked {crate::profiles::retain_binding(c,key,replaced.ok_or_else(reject)?,issued.view().id).await?;}
                    if session_storage::now(c).await? >= attempt.expiry {
                        return Err(reject().into());
                    }
                    let profile_event = match observation {
                        Some(observation) => crate::profiles::accept(c,key,issued.view().id,issued.view().absolute_expires_at,observation,limits).await?,
                        None => None,
                    };
                    db::consume(c, &locator).await?;
                    let action = if linked {
                        if already {
                            Action::AlreadyLinked
                        } else {
                            Action::Linked
                        }
                    } else if attempt.mode == AuthenticationMode::StepUp {
                        Action::SteppedUp
                    } else if new_account {
                        Action::JitCreated
                    } else {
                        Action::LoggedIn
                    };
                    Ok((
                        FederatedOutcome::Session {
                            issued,
                            return_url: attempt.return_url,
                            link_result: if linked {Some(if already {LinkResult::AlreadyLinked}else{LinkResult::Linked})}else{None},
                        },
                        { let mut events=vec![event(tenant, action, &view, Some(key.principal)),session_event]; events.extend(profile_event); events },
                    ))
                }) }).await
        }).await
    }
}
pub(crate) fn check_browser(browser: &str) -> Result<(), AuthorityError> {
    if browser.len() != 43
        || !browser
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Err(FederationError::Rejected.into())
    } else {
        Ok(())
    }
}
fn hex_digest(browser: &str) -> String {
    digest(browser).iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) async fn check_actor(
    c: &mut sqlx::PgConnection,
    tenant: TenantId,
    instance: uuid::Uuid,
    attempt: &db::Attempt,
    session: Option<[u8; 32]>,
) -> Result<
    (
        Option<session_storage::Loaded>,
        Option<crate::federation_link::Intent>,
    ),
    rss_transactional_messaging_postgres::PgError,
> {
    if let Some(id) = attempt.link {
        let intent = crate::federation_link::intent(c, tenant, id).await?;
        let now = session_storage::now(c).await?;
        if intent.browser != attempt.browser
            || now < intent.created
            || now >= intent.expiry
            || intent.stage
                != if attempt.purpose == Purpose::Reauthenticate {
                    crate::federation_link::LinkStage::ReauthenticationRequired
                } else {
                    crate::federation_link::LinkStage::TargetReady
                }
        {
            return Err(reject());
        }
        let actor = session_storage::lookup_locked(
            c,
            tenant,
            &session.ok_or_else(reject)?,
            rss_identity_core::session::CredentialKind::Cookie,
            instance,
            &Default::default(),
        )
        .await?;
        if actor.view.id != intent.session
            || actor.state.key().principal != intent.principal
            || actor.state.epoch() != intent.epoch
            || actor.state.membership_epoch() != intent.member_epoch
        {
            return Err(reject());
        }
        Ok((Some(actor), Some(intent)))
    } else if let Some(expected) = attempt.replacement {
        let actor = session_storage::lookup_locked(
            c,
            tenant,
            &session.ok_or_else(reject)?,
            rss_identity_core::session::CredentialKind::Cookie,
            instance,
            &Default::default(),
        )
        .await?;
        if actor.view.id != expected {
            return Err(reject());
        }
        Ok((Some(actor), None))
    } else {
        Ok((None, None))
    }
}
