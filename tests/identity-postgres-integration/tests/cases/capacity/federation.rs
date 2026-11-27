use super::*;
use rss_identity_core::{
    federation::{FederationError, ProviderView},
    session::SessionSecret,
    step_up::StepUpContext,
};
use zeroize::Zeroizing;

const ISSUER: &str = "https://idp.example.test";
async fn cancel(
    s: &Federation,
    token: &str,
    session: Option<SessionSecret>,
) -> Result<(), AuthorityError> {
    s.cancel(
        token.into(),
        oidc::BROWSER.into(),
        ISSUER.into(),
        session,
        deadline(),
    )
    .await
}
async fn actor(f: &Fixture, session: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(binding(f.key.tenant), oidc::secret(session), deadline())
        .await?)
}
async fn link(
    f: &Fixture,
    s: &Federation,
    p: ProviderId,
    session: &IssuedSession,
    pwd: bool,
) -> anyhow::Result<String> {
    Ok(oidc::state(
        s.begin_link(
            LinkRequest {
                actor: actor(f, session).await?,
                target_provider: p,
                password: pwd.then(password),
                browser: oidc::BROWSER.into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await?,
    ))
}
async fn consume(
    s: &Federation,
    token: String,
    subject: &str,
    session: &IssuedSession,
) -> Result<FederatedOutcome, AuthorityError> {
    s.complete(
        token,
        oidc::BROWSER.into(),
        Zeroizing::new(subject.into()),
        ISSUER.into(),
        Some(oidc::secret(session)),
        deadline(),
    )
    .await
}
async fn amount(f: &Fixture) -> anyhow::Result<i64> {
    occupied(f, A, "oidc_capacity").await
}
async fn inventory(f: &Fixture, n: i32, template: &serde_json::Value) -> anyhow::Result<()> {
    oidc::seed_inventory(f, n, template).await?;
    assert_eq!(amount(f).await?, i64::from(n));
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "run the same enrollment assertions at each specified inventory"
)]
pub(super) async fn lifecycle(f: &Fixture, s: &Federation, p: &ProviderView) -> anyhow::Result<()> {
    let local = f.login().await?;
    let state = oidc::state(s.begin_login(request(f, p.id, "test")?, deadline()).await?);
    let before = amount(f).await?;
    let external = oidc::issued(oidc::finish(s, state, "external").await?);
    assert_eq!(amount(f).await?, before - 1);
    s.begin_login(request(f, p.id, "test")?, deadline()).await?;
    let template:serde_json::Value=sqlx::query_scalar("SELECT to_jsonb(t) FROM identity_authority.oidc_transactions t WHERE link_intent IS NULL AND NOT claimed LIMIT 1").fetch_one(&f.owner).await?;
    for n in [0, 5000, 9999, 10000] {
        inventory(f, n, &template).await?;
        if n < 10000 {
            enrollment(f, s, p, &local, &external, Outcome::Expire).await?;
            enrollment(f, s, p, &local, &external, Outcome::Cancel).await?;
        } else {
            enrollment(f, s, p, &local, &external, Outcome::Full).await?;
        }
        assert_eq!(amount(f).await?, i64::from(n));
    }
    inventory(f, 9999, &template).await?;
    last_slot(f, s, p).await?;
    replace_at_capacity(f, s, p, &external).await?;
    expiry(f, s, p, &local, &template).await?;
    failed(f, s, p).await
}

#[derive(Clone, Copy)]
enum Outcome {
    Full,
    Expire,
    Cancel,
}

async fn check_start(
    f: &Fixture,
    s: &Federation,
    result: Result<FederatedRedirect, AuthorityError>,
    actor: Option<&IssuedSession>,
    outcome: Outcome,
) -> anyhow::Result<()> {
    if matches!(outcome, Outcome::Full) {
        anyhow::ensure!(
            matches!(result, Err(AuthorityError::Rejected)),
            "full store admitted a request"
        );
        return Ok(());
    }
    let token = oidc::state(result?);
    if matches!(outcome, Outcome::Expire) {
        let changed=sqlx::query("UPDATE identity_authority.oidc_transactions SET created_at=1,expires_at=2
            WHERE tenant_id=$1::uuid AND state_hash=$2 AND expires_at>floor(extract(epoch FROM now()))::bigint
            AND expires_at-created_at<=120")
            .bind(A).bind(rss_identity_core::federation::digest(&token).as_slice()).execute(&f.owner).await?;
        assert_eq!(changed.rows_affected(), 1);
    } else {
        cancel(s, &token, actor.map(oidc::secret)).await?;
    }
    assert!(cancel(s, &token, actor.map(oidc::secret)).await.is_err());
    Ok(())
}
async fn enrollment(
    f: &Fixture,
    s: &Federation,
    p: &ProviderView,
    local: &IssuedSession,
    external: &IssuedSession,
    outcome: Outcome,
) -> anyhow::Result<()> {
    let login = s.begin_login(request(f, p.id, "test")?, deadline()).await;
    check_start(f, s, login, None, outcome).await?;
    let linked = s
        .begin_link(
            LinkRequest {
                actor: actor(f, local).await?,
                target_provider: p.id,
                password: Some(password()),
                browser: oidc::BROWSER.into(),
                target: "home".into(),
                source: source(),
            },
            deadline(),
        )
        .await;
    check_start(f, s, linked, Some(local), outcome).await?;
    let mut req = request(f, p.id, "test")?;
    req.replacement = Some(actor(f, external).await?);
    let step = s
        .begin_step_up(
            req,
            StepUpContext::new("test.operation".into(), [7; 32]).map_err(anyhow::Error::msg)?,
            deadline(),
        )
        .await;
    check_start(f, s, step, Some(external), outcome).await
}
async fn last_slot(f: &Fixture, s: &Federation, p: &ProviderView) -> anyhow::Result<()> {
    let (a, b) = tokio::join!(
        s.begin_login(request(f, p.id, "first")?, deadline()),
        s.begin_login(request(f, p.id, "second")?, deadline())
    );
    let winner = match (a, b) {
        (Ok(v), Err(AuthorityError::Rejected)) | (Err(AuthorityError::Rejected), Ok(v)) => {
            oidc::state(v)
        }
        _ => anyhow::bail!("last OIDC slot granted incorrectly"),
    };
    assert_eq!(amount(f).await?, 10000);
    other_tenant(f, s).await?;
    cancel(s, &winner, None).await?;
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "ordered assertions on one federation transaction history"
)]
async fn replace_at_capacity(
    f: &Fixture,
    s: &Federation,
    p: &ProviderView,
    external: &IssuedSession,
) -> anyhow::Result<()> {
    let token = link(f, s, p.id, external, false).await?;
    sqlx::query("UPDATE identity_authority.link_intents SET expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+45
        WHERE intent_id=(SELECT link_intent FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid AND link_intent IS NOT NULL)")
        .bind(A).execute(&f.owner).await?;
    let FederatedOutcome::Redirect(next) = consume(s, token, "external", external).await? else {
        anyhow::bail!("expected link target")
    };
    assert_eq!(amount(f).await?, 10000);
    let shortened:bool=sqlx::query_scalar("SELECT t.expires_at=i.expires_at AND t.expires_at-t.created_at<=120 FROM identity_authority.oidc_transactions t
        JOIN identity_authority.link_intents i ON (i.tenant_id,i.intent_id)=(t.tenant_id,t.link_intent) WHERE t.tenant_id=$1::uuid").bind(A).fetch_one(&f.owner).await?;
    assert!(shortened);
    let token = oidc::state(next);
    assert!(matches!(
        consume(s, token.clone(), "external", external).await?,
        FederatedOutcome::Session {
            link_result: Some(LinkResult::AlreadyLinked),
            ..
        }
    ));
    assert!(consume(s, token, "external", external).await.is_err());
    assert_eq!(amount(f).await?, 9999);
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "ordered assertions on one federation transaction history"
)]
async fn expiry(
    f: &Fixture,
    s: &Federation,
    p: &ProviderView,
    local: &IssuedSession,
    template: &serde_json::Value,
) -> anyhow::Result<()> {
    inventory(f, 9999, template).await?;
    let link = link(f, s, p.id, local, true).await?;
    let id:uuid::Uuid=sqlx::query_scalar("SELECT link_intent FROM identity_authority.oidc_transactions WHERE link_intent IS NOT NULL").fetch_one(&f.owner).await?;
    assert_eq!(amount(f).await?, 10000);
    sqlx::query("INSERT INTO identity_authority.link_intents SELECT copy.* FROM identity_authority.link_intents i
       CROSS JOIN generate_series(1,129) n CROSS JOIN LATERAL jsonb_populate_record(i,jsonb_build_object(
         'intent_id',md5(n::text)::uuid,'created_at',1,'expires_at',2)) copy WHERE i.intent_id=$1").bind(id).execute(&f.owner).await?;
    sqlx::query("UPDATE identity_authority.oidc_transactions SET created_at=1,expires_at=CASE WHEN link_intent IS NULL THEN 2 ELSE 3 END
        WHERE link_intent IS NOT NULL OR attempt_id IN(SELECT sha256(int4send(n)) FROM generate_series(1,300) n)").execute(&f.owner).await?;
    sqlx::query(
        "UPDATE identity_authority.link_intents SET created_at=1,expires_at=3 WHERE intent_id=$1",
    )
    .bind(id)
    .execute(&f.owner)
    .await?;
    assert!(cancel(s, &link, Some(oidc::secret(local))).await.is_err());
    for (rows, retained, remaining) in [(9873, true, 1_i64), (9746, true, 0), (9702, false, 0)] {
        s.begin_login(request(f, p.id, "expiry")?, deadline())
            .await?;
        assert_eq!(amount(f).await?, rows);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM identity_authority.link_intents WHERE intent_id=$1)",
        )
        .bind(id)
        .fetch_one(&f.owner)
        .await?;
        assert_eq!(exists, retained);
        let expired:i64=sqlx::query_scalar("SELECT count(*) FROM identity_authority.link_intents WHERE tenant_id=$1::uuid AND expires_at=2").bind(A).fetch_one(&f.owner).await?;
        assert_eq!(expired, remaining);
    }
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "ordered assertions on one federation transaction history"
)]
async fn failed(f: &Fixture, s: &Federation, p: &ProviderView) -> anyhow::Result<()> {
    let before = amount(f).await?;
    let token = oidc::state(
        s.begin_login(request(f, p.id, "failed")?, deadline())
            .await?,
    );
    f.oidc
        .exchange_error
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let result = oidc::finish(s, token.clone(), "external").await;
    f.oidc
        .exchange_error
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        result,
        Err(AuthorityError::Federation(FederationError::Unavailable))
    ));
    assert!(oidc::finish(s, token, "external").await.is_err());
    let token = oidc::state(
        s.begin_login(request(f, p.id, "audit")?, deadline())
            .await?,
    );
    let seq:i64=sqlx::query_scalar("SELECT value FROM identity_authority.tenant_state WHERE tenant_id=$1::uuid AND kind='profile_sequence'").bind(A).fetch_one(&f.owner).await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_capacity_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture'; END $$;
        CREATE TRIGGER reject_capacity_audit BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_capacity_audit()").execute(&f.owner).await?;
    assert!(matches!(
        oidc::finish(s, token.clone(), "external").await,
        Err(AuthorityError::RolledBack(_))
    ));
    sqlx::query("DROP TRIGGER reject_capacity_audit ON rss_audit.records")
        .execute(&f.owner)
        .await?;
    assert!(oidc::finish(s, token, "external").await.is_err());
    assert_eq!(amount(f).await?, before + 2);
    let snapshot:(i64,i64)=sqlx::query_as("SELECT value,(SELECT count(*) FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid AND claimed) FROM identity_authority.tenant_state WHERE tenant_id=$1::uuid AND kind='profile_sequence'").bind(A).fetch_one(&f.owner).await?;
    assert_eq!(snapshot, (seq, 2));
    Ok(())
}

async fn other_tenant(f: &Fixture, s: &Federation) -> anyhow::Result<()> {
    use rss_identity_core::federation::ProviderCredentials;
    let scope = binding(f.system_key.tenant);
    let store = s.authority();
    let local = store
        .login_local(
            scope,
            login("platform"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    let actor = || store.inspect_session(scope, oidc::secret(&local), deadline());
    let provider = s
        .create_provider(
            actor().await?,
            oidc::settings(),
            ProviderCredentials::new("fixture-secret".into(), None)?,
            deadline(),
        )
        .await?;
    let provider = s
        .enable_provider(
            actor().await?,
            provider.id,
            provider.version,
            true,
            deadline(),
        )
        .await?;
    let token = oidc::state(
        s.begin_login(
            LoginRequest {
                binding: scope,
                provider: provider.id,
                browser: oidc::BROWSER.into(),
                target: "home".into(),
                replacement: None,
                source: source(),
            },
            deadline(),
        )
        .await?,
    );
    assert_eq!(occupied(f, SYSTEM, "oidc_capacity").await?, 1);
    cancel(s, &token, None).await?;
    assert_eq!(occupied(f, SYSTEM, "oidc_capacity").await?, 0);
    assert_eq!(amount(f).await?, 10000);
    Ok(())
}
