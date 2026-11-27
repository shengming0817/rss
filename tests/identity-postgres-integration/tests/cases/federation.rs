use crate::{federation_support::*, support::*};
use rss_identity_core::federation::ProviderView;
use rss_identity_postgres::*;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;
#[allow(clippy::unwrap_used, reason = "test fixture")]
async fn step_begin(
    f: &Fixture,
    s: &Federation,
    p: &ProviderView,
    session: &IssuedSession,
) -> anyhow::Result<String> {
    f.reset_attempts().await?;
    Ok(state(
        s.begin_step_up(
            LoginRequest {
                binding: crate::support::binding(f.key.tenant),
                provider: p.id,
                browser: BROWSER.into(),
                target: "home".into(),
                replacement: Some(
                    f.store
                        .inspect_session(
                            crate::support::binding(f.key.tenant),
                            secret(session),
                            deadline(),
                        )
                        .await?,
                ),
                source: source(),
            },
            rss_identity_core::step_up::StepUpContext::new("test.operation".into(), [7; 32])
                .unwrap(),
            deadline(),
        )
        .await?,
    ))
}

async fn step_finish(
    s: &Federation,
    token: String,
    session: &IssuedSession,
    subject: &str,
) -> Result<FederatedOutcome, AuthorityError> {
    s.complete(
        token,
        BROWSER.into(),
        Zeroizing::new(subject.into()),
        "https://idp.example.test".into(),
        Some(secret(session)),
        deadline(),
    )
    .await
}

#[allow(clippy::unwrap_used, reason = "test fixture")]
#[allow(
    clippy::cognitive_complexity,
    reason = "test fixture and ordered assertions"
)]
pub async fn step_up(f: &Fixture) -> anyhow::Result<()> {
    use rss_identity_core::assurance::Assurance;
    let upstream = ScriptedOidc::new();
    let s = service(f, upstream.clone());
    let p = enabled(f, &s).await?;
    let old = issued(finish(&s, begin(f, &s, &p).await?, "alice").await?);
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    *upstream.assurance.lock().unwrap() = Some(Assurance::new(
        Some(now),
        rss_identity_core::assurance::Acr::Mfa,
        vec![],
    )?);
    let token = step_begin(f, &s, &p, &old).await?;
    let FederatedOutcome::StepUp { grant, .. } =
        step_finish(&s, token.clone(), &old, "alice").await?
    else {
        anyhow::bail!("expected operation proof")
    };
    assert!(step_finish(&s, token, &old, "alice").await.is_err());
    let proof = f
        .store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            secret(&old),
            deadline(),
        )
        .await?;
    let context =
        rss_identity_core::step_up::StepUpContext::new("test.operation".into(), [7; 32]).unwrap();
    let mut tx = f.owner.begin().await?;
    crate::support::fence(&mut tx, crate::support::binding(f.key.tenant)).await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    rss_identity_postgres::consume_step_up_on(&mut tx, &proof, &context, grant.expose()).await?;
    tx.commit().await?;
    let mut replay = f.owner.begin().await?;
    crate::support::fence(&mut replay, binding(f.key.tenant)).await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *replay)
        .await?;
    assert!(
        rss_identity_postgres::consume_step_up_on(&mut replay, &proof, &context, grant.expose())
            .await
            .is_err()
    );
    replay.rollback().await?;
    Ok(())
}
pub async fn state_once(f: &Fixture) -> anyhow::Result<()> {
    let upstream = ScriptedOidc::new();
    let s = service(f, upstream.clone());
    let p = enabled(f, &s).await?;
    let token = begin(f, &s, &p).await?;
    assert!(
        s.complete(
            token.clone(),
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            Zeroizing::new("alice".into()),
            "https://idp.example.test".into(),
            None,
            deadline()
        )
        .await
        .is_err()
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    let restarted = service(f, upstream.clone());
    let (a, b) = tokio::join!(
        finish(&s, token.clone(), "alice"),
        finish(&restarted, token.clone(), "alice")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert!(finish(&s, token, "alice").await.is_err());
    Ok(())
}
