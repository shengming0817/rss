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
    let upstream = &f.oidc;
    let s = service(f);
    let p = enabled(f, &s).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&f.owner)
            .await?;
    *upstream.assurance.lock().unwrap() = Some(Assurance::new(
        Some(now),
        rss_identity_core::assurance::Acr::Mfa,
        vec![],
    )?);
    let old = issued(finish(&s, begin(f, &s, &p).await?, "alice").await?);
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
    let withdrawn = withdrawn_authority(f).await?;
    denied_after_replacement(f, &withdrawn, &old, &proof, &context, grant.expose()).await?;
    let mut tx = f.owner.begin().await?;
    crate::support::fence(&mut tx, crate::support::binding(f.key.tenant)).await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    f.store
        .consume_step_up_on(&mut tx, &proof, &context, grant.expose())
        .await?;
    tx.commit().await?;
    let mut replay = f.owner.begin().await?;
    crate::support::fence(&mut replay, binding(f.key.tenant)).await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *replay)
        .await?;
    assert!(
        f.store
            .consume_step_up_on(&mut replay, &proof, &context, grant.expose())
            .await
            .is_err()
    );
    replay.rollback().await?;
    Ok(())
}
pub async fn state_once(f: &Fixture) -> anyhow::Result<()> {
    let upstream = &f.oidc;
    let s = service(f);
    let p = enabled(f, &s).await?;
    probe_audit(f, &s, &p).await?;
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
    let moved = service_at(f, "https://identity.example.test/new/callback");
    assert!(begin(f, &moved, &p).await.is_err());
    let restarted = service(f);
    let (a, b) = tokio::join!(
        finish(&s, token.clone(), "alice"),
        finish(&restarted, token.clone(), "alice")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert!(finish(&s, token, "alice").await.is_err());
    Ok(())
}

#[allow(clippy::unwrap_used, reason = "isolated provider fixture")]
async fn probe_audit(f: &Fixture, s: &Federation, p: &ProviderView) -> anyhow::Result<()> {
    use rss_identity_core::federation::{FederationError, ProviderReason, ProviderStage};
    for error in [
        FederationError::Unavailable,
        FederationError::provider(ProviderStage::Jwks, ProviderReason::Timeout),
    ] {
        let actor = actor(f).await?;
        let before = f.events().await?;
        *f.oidc.probe_error.lock().unwrap() = Some(error);
        assert!(matches!(s.test_provider(actor, p.id, deadline()).await,
            Err(AuthorityError::Federation(actual)) if actual == error));
        assert_eq!(f.events().await?, before + 1);
        let bytes: Vec<u8> = sqlx::query_scalar("SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid ORDER BY position DESC LIMIT 1")
            .bind(f.key.tenant.to_string()).fetch_one(&f.owner).await?;
        let record = rss_audit_core::decode_untrusted(&bytes)?;
        assert_eq!(
            record.event().facts().action().as_str(),
            "identity.federation.provider_test_failed"
        );
        let payload: serde_json::Value =
            serde_json::from_slice(record.event().context().payload().as_bytes())?;
        assert_eq!(
            payload.get("diagnostic").cloned(),
            error.diagnostic().map(|d| serde_json::json!(d))
        );
    }
    *f.oidc.probe_error.lock().unwrap() = None;
    Ok(())
}

#[allow(clippy::unwrap_used, reason = "isolated PG fixtures")]
async fn withdrawn_authority(f: &Fixture) -> anyhow::Result<Authority> {
    let kdf = rss_identity_core::account::PasswordKdf::new(
        std::num::NonZeroUsize::MIN,
        std::num::NonZeroU64::new(128 * 1024 * 1024).unwrap(),
    )?;
    Ok(Authority::connect_runtime(
        f.runtime.clone(),
        std::sync::Arc::new(kdf),
        f.config().with_oidc(ScriptedOidc::new(false)),
        binding(f.key.tenant),
        f.policy.clone(),
        deadline(),
    )
    .await?)
}
#[allow(
    clippy::unwrap_used,
    clippy::cognitive_complexity,
    reason = "ordered trust replacement assertions"
)]
async fn denied_after_replacement(
    f: &Fixture,
    withdrawn: &Authority,
    session: &IssuedSession,
    proof: &AuthenticatedSession,
    context: &rss_identity_core::step_up::StepUpContext,
    grant: &str,
) -> anyhow::Result<()> {
    let scope = binding(f.key.tenant);
    f.policy.managers.write().unwrap().push(proof.account());
    *f.policy.recent.write().unwrap() =
        ReauthenticationRequirement::RecentMfa(std::time::Duration::from_secs(300));
    let actor = f
        .store
        .inspect_session(scope, secret(session), deadline())
        .await?;
    f.store
        .create_local_account(actor, login("before-withdrawal"), password(), deadline())
        .await?;
    let retained = f
        .store
        .inspect_session(scope, secret(session), deadline())
        .await?;
    assert!(
        withdrawn
            .create_local_account(retained, login("after-withdrawal"), password(), deadline())
            .await
            .is_err()
    );
    assert!(
        withdrawn
            .inspect_session(scope, secret(session), deadline())
            .await
            .is_err()
    );
    let mut denied = f.owner.begin().await?;
    crate::support::fence(&mut denied, scope).await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *denied)
        .await?;
    assert!(
        withdrawn
            .consume_step_up_on(&mut denied, proof, context, grant)
            .await
            .is_err()
    );
    denied.rollback().await?;
    *f.policy.recent.write().unwrap() = ReauthenticationRequirement::None;
    f.policy
        .managers
        .write()
        .unwrap()
        .retain(|key| *key != proof.account());
    Ok(())
}
