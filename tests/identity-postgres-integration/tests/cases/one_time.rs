//! Real PG + real WebAuthn cryptography using a software test authenticator, not hardware evidence.
use crate::support;
use rss_identity_core::step_up::StepUpContext;
use rss_identity_postgres::*;

use support::*;
use url::Url;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
const ORIGIN: &str = "https://identity.example.test";
async fn actor(f: &Fixture, s: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            rss_identity_core::session::SessionSecret::parse(s.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
async fn consume(
    f: &Fixture,
    s: &IssuedSession,
    context: &StepUpContext,
    grant: &str,
    commit: bool,
) -> anyhow::Result<bool> {
    let proof = actor(f, s).await?;
    let mut tx = f.owner.begin().await?;
    crate::support::fence(&mut tx, binding(f.key.tenant)).await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    recheck_authenticated_session_on(&mut tx, &proof).await?;
    let accepted = consume_step_up_on(&mut tx, &proof, context, grant)
        .await
        .is_ok();
    if accepted && commit {
        tx.commit().await?
    } else {
        tx.rollback().await?
    }
    Ok(accepted)
}
#[allow(clippy::unwrap_used, reason = "test fixture")]
#[allow(
    clippy::cognitive_complexity,
    reason = "test fixture and ordered assertions"
)]
pub async fn webauthn(f: &Fixture) -> anyhow::Result<()> {
    let s = f.login().await?;
    let w = WebauthnAuthority::new(
        f.store.clone(),
        "identity.example.test".into(),
        Url::parse(ORIGIN)?,
    )?;
    let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let registration = w
        .begin_registration(
            actor(f, &s).await?,
            RpGeneration::new(1)?,
            "laptop".into(),
            false,
            RegistrationAuthorization::First,
            deadline(),
        )
        .await?;
    let response = key.do_registration(Url::parse(ORIGIN)?, registration.options)?;
    w.finish_registration(
        actor(f, &s).await?,
        RpGeneration::new(1)?,
        registration.id,
        response,
        deadline(),
    )
    .await?;
    assert_eq!(
        w.list(actor(f, &s).await?, RpGeneration::new(1)?, deadline())
            .await?
            .len(),
        1
    );
    assert!(
        w.begin_registration(
            actor(f, &s).await?,
            RpGeneration::new(1)?,
            "bypass".into(),
            false,
            RegistrationAuthorization::First,
            deadline()
        )
        .await
        .is_err()
    );
    let context = StepUpContext::new("device.erase".into(), [9; 32]).unwrap();
    let a = w
        .begin_authentication(
            actor(f, &s).await?,
            RpGeneration::new(1)?,
            context.clone(),
            deadline(),
        )
        .await?;
    let response = key.do_authentication(Url::parse(ORIGIN)?, a.options)?;
    let copy = serde_json::from_value(serde_json::to_value(&response)?)?;
    let (left, right) = tokio::join!(
        w.finish_authentication(
            actor(f, &s).await?,
            RpGeneration::new(1)?,
            a.id,
            response,
            deadline()
        ),
        w.finish_authentication(
            actor(f, &s).await?,
            RpGeneration::new(1)?,
            a.id,
            copy,
            deadline()
        )
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let grant = left.or(right)?;
    let wrong = StepUpContext::new("device.erase".into(), [8; 32]).unwrap();
    assert!(!consume(f, &s, &wrong, grant.expose(), true).await?);
    assert!(
        consume(f, &s, &context, grant.expose(), false).await?,
        "rollback preserves proof"
    );
    assert!(consume(f, &s, &context, grant.expose(), true).await?);
    assert!(!consume(f, &s, &context, grant.expose(), true).await?);
    Ok(())
}
