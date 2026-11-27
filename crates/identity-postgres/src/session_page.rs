//! Read one bounded candidate window under the caller's tenant guard.
use crate::federation_storage::{Origin, check_origins};
use crate::{
    AuthenticatedSession, SessionPage, SessionView,
    platform::{PlatformAuthentication, PlatformBinding},
    session_storage::{self, Loaded},
    transaction::corrupt,
};
use rss_identity_core::SessionId;
use rss_request_context::Clock;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::PgError;
use sqlx::{PgConnection, Row, postgres::PgRow};
use std::collections::HashMap;
use uuid::Uuid;

fn oidc_origin(row: &PgRow) -> Result<Origin, PgError> {
    Ok(Origin {
        identity: row.try_get("external_identity_id")?,
        epoch: row.try_get("provider_epoch")?,
        version: row.try_get("provider_config_version")?,
    })
}

async fn current_platform(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
    row: &PgRow,
    checks: &crate::session_checks::SessionChecks,
    checked: &mut HashMap<PlatformBinding, bool>,
) -> Result<bool, PgError> {
    let stored: PlatformAuthentication =
        serde_json::from_value(row.try_get("platform_authentication")?).map_err(|_| corrupt())?;
    let verifier = stored.verifier(actor.key, actor.authority.as_uuid(), checks)?;
    let valid = match checked.entry(stored.binding.clone()) {
        std::collections::hash_map::Entry::Occupied(hit) => *hit.get(),
        std::collections::hash_map::Entry::Vacant(slot) => {
            let valid = match crate::platform::recheck_binding(c, &stored.binding, verifier).await {
                Ok(()) => true,
                Err(e) if e.kind() == MessagingErrorKind::Conflict => false,
                Err(e) => return Err(e),
            };
            *slot.insert(valid)
        }
    };
    if valid {
        stored.assurance()?;
    }
    Ok(valid)
}

pub(crate) async fn read(
    c: &mut PgConnection,
    actor: &AuthenticatedSession,
    checks: &crate::session_checks::SessionChecks,
    loaded: &Loaded,
    cursor: Option<SessionId>,
    limit: u16,
) -> Result<SessionPage, PgError> {
    let mut rows = sqlx::query("SELECT session_id,credential_kind,issued_at,idle_timeout,absolute_timeout,idle_expires_at,absolute_expires_at,
        authentication_source,external_identity_id,source_provider_id,provider_epoch,provider_config_version,platform_authentication
        FROM identity_authority.sessions WHERE tenant_id=$1::uuid AND principal_id=$2
        AND auth_epoch=$3 AND membership_epoch=$4 AND revoked_at IS NULL
        AND issued_at<=$5 AND idle_expires_at>$5 AND absolute_expires_at>$5
        AND ($6::uuid IS NULL OR session_id>$6) ORDER BY session_id LIMIT $7")
        .bind(actor.key.tenant.to_string()).bind(actor.key.principal.as_uuid()).bind(loaded.state.epoch())
        .bind(loaded.state.membership_epoch()).bind(loaded.now).bind(cursor.map(|v|v.as_uuid())).bind(i64::from(limit)+1)
        .fetch_all(&mut *c).await?;
    let more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    let mut wanted = Vec::new();
    for row in &rows {
        if row.try_get::<&str, _>("authentication_source")? == "oidc" {
            wanted.push(oidc_origin(row)?);
        }
    }
    let origins = check_origins(
        c,
        actor.key,
        &wanted,
        checks,
        loaded.checked_provider.as_ref(),
    )
    .await?;
    let mut platforms = HashMap::new();
    if let Some(binding) = loaded.verified_platform.as_deref() {
        platforms.insert(binding.clone(), true);
    }
    let mut accepted = Vec::with_capacity(rows.len());
    let mut scanned = None;
    for row in rows {
        let id = session_storage::session_id(&row.try_get::<Uuid, _>("session_id")?.to_string())?;
        scanned = Some(id);
        let lifetime = session_storage::lifetime(&row)?;
        let expires = loaded.sample.deadline(lifetime.idle_expires_at())?;
        if checks.timer.now() >= expires {
            continue;
        }
        let valid = match row.try_get::<&str, _>("authentication_source")? {
            "local_password" => true,
            "oidc" => {
                let provider: Uuid = row.try_get("source_provider_id")?;
                matches!(origins.get(&oidc_origin(&row)?).map(|result|result.as_ref()).transpose().map_err(|_|corrupt())?,Some(origin) if origin.source.provider_id()==provider)
            }
            "platform" => match current_platform(c, actor, &row, checks, &mut platforms).await {
                Err(e) if e.kind() == MessagingErrorKind::Conflict => false,
                result => result?,
            },
            _ => return Err(corrupt()),
        };
        if valid {
            accepted.push((
                SessionView::new(id, lifetime, session_storage::credential_kind(&row)?),
                expires,
            ));
        }
    }
    // A later verifier may have waited on an authoritative host lock.
    let finished = checks.timer.now();
    let sessions = accepted
        .into_iter()
        .filter_map(|(view, expires)| (finished < expires).then_some(view))
        .collect();
    Ok(SessionPage {
        sessions,
        next_cursor: if more { scanned } else { None },
    })
}
