use crate::{
    storage::*,
    transaction::{corrupt, reject},
    *,
};
use rss_identity_core::assurance::AuthenticationMode;
use rss_identity_core::federation::*;
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
pub(crate) async fn provider(
    c: &mut PgConnection,
    tenant: TenantId,
    id: ProviderId,
) -> Result<ProviderView, rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(concat!(
        "SELECT config_version,revocation_epoch,enabled,settings,assurance_profile,credential_version FROM identity_authority.",
        "providers WHERE tenant_id=$1::uuid AND provider_id=$2::uuid FOR UPDATE"
    ))
    .bind(tenant.to_string())
    .bind(id.to_string())
    .fetch_optional(c)
    .await?
    .ok_or_else(reject)?;
    let settings: ProviderSettings =
        serde_json::from_value(r.try_get("settings")?).map_err(|_| corrupt())?;

    let version = r.try_get("config_version")?;
    let epoch = r.try_get("revocation_epoch")?;
    if version < 1 || epoch < 1 {
        return Err(corrupt());
    }
    Ok(ProviderView {
        id,
        version,
        revocation_epoch: epoch,
        enabled: r.try_get("enabled")?,
        settings,
        assurance_profile: r
            .try_get::<Vec<u8>, _>("assurance_profile")?
            .try_into()
            .map_err(|_| corrupt())?,
        credential_version: r.try_get("credential_version")?,
    })
}
pub(crate) fn exact(view: &ProviderView, version: i64) -> Result<(), FederationError> {
    if !view.enabled {
        Err(FederationError::Rejected)
    } else if view.version != version {
        Err(FederationError::StaleConfiguration)
    } else {
        Ok(())
    }
}
pub(crate) async fn read_provider(
    authority: &Authority,
    binding: ExecutionBinding,
    id: ProviderId,
    d: rss_transactional_messaging::policy::OperationDeadline,
) -> Result<ProviderView, AuthorityError> {
    let tenant = binding.tenant();
    authority
        .read_sql(binding, d, move |c| {
            Box::pin(async move {
                lock_tenant_collection(c, tenant).await?;
                Ok(provider(c, tenant, id).await?)
            })
        })
        .await
}
pub(crate) struct Origin {
    pub identity: Uuid,
    epoch: i64,
    version: i64,
}

pub(crate) fn decode_origin(
    row: &sqlx::postgres::PgRow,
) -> Result<
    Option<(Origin, crate::auth_facts::AuthenticationFacts)>,
    rss_transactional_messaging_postgres::PgError,
> {
    match (
        row.try_get("external_identity_id")?,
        row.try_get("provider_epoch")?,
        crate::auth_facts::AuthenticationFacts::read(row)?,
    ) {
        (Some(identity), Some(epoch), Some(facts)) => Ok(Some((
            Origin {
                identity,
                epoch,
                version: facts.provider_config_version,
            },
            facts,
        ))),
        (None, None, None) => Ok(None),
        _ => Err(corrupt()),
    }
}
pub(crate) async fn check_origin(
    c: &mut PgConnection,
    key: AccountKey,
    origin: &Origin,
) -> Result<rss_identity_core::facts::FactSource, rss_transactional_messaging_postgres::PgError> {
    let row = sqlx::query(concat!(
        "SELECT e.provider_id,e.issuer FROM identity_authority.external_identities e JOIN identity",
        "_authority.providers p USING(tenant_id,provider_id) WHERE e.tenant_id=$1::uuid A",
        "ND e.identity_id=$2 AND p.enabled AND p.revocation_epoch=$3 AND p.config_version=$4 AND e.principal_id=$5"
    ))
    .bind(key.tenant.to_string()).bind(origin.identity).bind(origin.epoch)
    .bind(origin.version).bind(key.principal.as_uuid())
    .fetch_optional(c).await?.ok_or_else(reject)?;
    rss_identity_core::facts::FactSource::new(row.try_get("provider_id")?, row.try_get("issuer")?)
        .map_err(|_| corrupt())
}
pub(crate) async fn identity(
    c: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
) -> Result<(ProviderId, String, String), rss_transactional_messaging_postgres::PgError> {
    let r = sqlx::query(concat!(
        "SELECT provider_id::text,issuer,subject FROM identity_authority.external_identit",
        "ies WHERE tenant_id=$1::uuid AND identity_id=$2"
    ))
    .bind(tenant.to_string())
    .bind(id)
    .fetch_one(c)
    .await?;
    Ok((
        ProviderId::parse(&r.try_get::<String, _>("provider_id")?).map_err(|_| corrupt())?,
        r.try_get("issuer")?,
        r.try_get("subject")?,
    ))
}
pub(crate) struct Attempt {
    pub context: Option<rss_identity_core::step_up::StepUpContext>,
    pub profile_sequence: i64,
    pub mode: AuthenticationMode,
    pub browser: [u8; 32],
    pub provider: ProviderId,
    pub version: i64,
    pub purpose: Purpose,
    pub expiry: i64,
    pub created: i64,
    pub return_url: String,
    pub link: Option<Uuid>,
    pub replacement: Option<rss_identity_core::SessionId>,
}
pub(crate) async fn attempt(
    c: &mut PgConnection,
    locator: &StateLocator,
    state: &str,
    browser: &str,
    claimed: bool,
) -> Result<(Attempt, Option<(String, String)>), rss_transactional_messaging_postgres::PgError> {
    let tenant = locator.tenant();
    let r = sqlx::query(concat!(
        "SELECT * FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid AND ",
        "attempt_id=$2 FOR UPDATE"
    ))
    .bind(tenant.to_string())
    .bind(locator.id().as_slice())
    .fetch_optional(&mut *c)
    .await?
    .ok_or_else(reject)?;
    let now = crate::session_storage::now(c).await?;
    if r.try_get::<Vec<u8>, _>("state_hash")? != digest(state)
        || r.try_get::<Vec<u8>, _>("browser_hash")? != digest(browser)
        || r.try_get::<bool, _>("claimed")? != claimed
        || r.try_get::<i16, _>("purpose")? != i16::from(locator.purpose().code())
        || now < r.try_get("created_at")?
        || now >= r.try_get("expires_at")?
    {
        return Err(reject());
    }
    let secrets = if claimed {
        None
    } else {
        Some((r.try_get("nonce")?, r.try_get("verifier")?))
    };
    Ok((
        Attempt {
            context: r
                .try_get::<Option<serde_json::Value>, _>("operation_context")?
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| corrupt())?,
            profile_sequence: r.try_get("profile_sequence")?,
            mode: AuthenticationMode::from_storage(r.try_get("authentication_mode")?)
                .map_err(|_| corrupt())?,
            browser: digest(browser),
            provider: ProviderId::parse(&r.try_get::<Uuid, _>("provider_id")?.to_string())
                .map_err(|_| corrupt())?,
            version: r.try_get("config_version")?,
            purpose: locator.purpose(),
            expiry: r.try_get("expires_at")?,
            created: r.try_get("created_at")?,
            return_url: r.try_get("return_url")?,
            link: r.try_get("link_intent")?,
            replacement: r
                .try_get::<Option<Uuid>, _>("replacement_session")?
                .map(|id| {
                    rss_identity_core::SessionId::parse(&id.to_string()).map_err(|_| corrupt())
                })
                .transpose()?,
        },
        secrets,
    ))
}
pub(crate) struct NewAttempt {
    pub context: Option<rss_identity_core::step_up::StepUpContext>,
    pub mode: AuthenticationMode,
    pub locator: StateLocator,
    pub material: ProtocolMaterial,
    pub provider: ProviderView,
    pub browser: String,
    pub return_url: String,
    pub link: Option<Uuid>,
    pub replacement: Option<rss_identity_core::SessionId>,
    pub expiry: Option<i64>,
}
pub(crate) async fn insert_attempt(
    c: &mut PgConnection,
    input: NewAttempt,
) -> Result<(), transaction::MutationError> {
    let tenant = input.locator.tenant();
    let current = provider(c, tenant, input.provider.id).await?;
    exact(&current, input.provider.version)?;
    let now = crate::session_storage::now(c).await?;
    let expiry = input.expiry.unwrap_or(now + 120).min(now + 120);
    if (input.mode == AuthenticationMode::StepUp) != input.context.is_some() {
        return Err(reject().into());
    }
    if now >= expiry {
        return Err(reject().into());
    }
    sqlx::query(concat!(
        "DELETE FROM identity_authority.oidc_transactions WHERE (tenant_id,attempt_id) IN",
        " (SELECT tenant_id,attempt_id FROM identity_authority.oidc_transactions WHERE te",
        "nant_id=$1::uuid AND expires_at<=$2 ORDER BY expires_at LIMIT 128)"
    ))
    .bind(tenant.to_string())
    .bind(now)
    .execute(&mut *c)
    .await?;
    sqlx::query(concat!(
        "DELETE FROM identity_authority.link_intents l WHERE l.tenant_id=$1::uuid AND l.i",
        "ntent_id IN (SELECT i.intent_id FROM identity_authority.link_intents i WHERE i.t",
        "enant_id=$1::uuid AND i.expires_at<=$2 AND NOT EXISTS(SELECT FROM identity_autho",
        "rity.oidc_transactions t WHERE t.tenant_id=i.tenant_id AND t.link_intent=i.inten",
        "t_id) LIMIT 128)"
    ))
    .bind(tenant.to_string())
    .bind(now)
    .execute(&mut *c)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .fetch_one(&mut *c)
    .await?;
    if count >= 10000 {
        return Err(reject().into());
    }
    let profile_sequence = crate::profiles::sequence(c, tenant).await?;
    sqlx::query(concat!(
        "INSERT INTO identity_authority.oidc_transactions(tenant_id,attempt_id,provider_i",
        "d,config_version,state_hash,browser_hash,purpose,nonce,verifier,created_at,expir",
        "es_at,return_url,link_intent,replacement_session,authentication_mode,profile_sequence,operation_context) VALUES($1::uuid,",
        "$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::uuid,$15,$16,$17)"
    ))
    .bind(tenant.to_string())
    .bind(input.locator.id().as_slice())
    .bind(input.provider.id.to_string())
    .bind(input.provider.version)
    .bind(digest(&input.material.state).as_slice())
    .bind(digest(&input.browser).as_slice())
    .bind(i16::from(input.locator.purpose().code()))
    .bind(input.material.nonce.as_str())
    .bind(input.material.verifier.as_str())
    .bind(now)
    .bind(expiry)
    .bind(input.return_url)
    .bind(input.link)
    .bind(input.replacement.map(|v| v.to_string()))
    .bind(input.mode as i16)
    .bind(profile_sequence)
    .bind(input.context.map(serde_json::to_value).transpose().map_err(|_|corrupt())?)
    .execute(c)
    .await?;
    Ok(())
}
pub(crate) async fn consume(
    c: &mut PgConnection,
    locator: &StateLocator,
) -> Result<(), rss_transactional_messaging_postgres::PgError> {
    sqlx::query("DELETE FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid AND attempt_id=$2").bind(locator.tenant().to_string()).bind(locator.id().as_slice()).execute(c).await?;
    Ok(())
}
