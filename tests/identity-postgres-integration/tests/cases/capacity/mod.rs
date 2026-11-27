use crate::{federation_support as oidc, support::*};
use rss_identity_core::{
    account::{Password, PasswordKdf},
    federation::ProviderId,
};
use rss_identity_postgres::*;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
mod federation;

#[allow(clippy::expect_used, reason = "fixed positive fixture budget")]
async fn configured(f: &Fixture, limit: u32, batch: u16) -> anyhow::Result<Authority> {
    let window = AttemptWindow::new(100_000, 600)?;
    let policy = AuthenticationPolicy::new(
        window,
        window,
        window,
        limit,
        batch,
        Duration::from_secs(30),
    )?;
    Ok(Authority::connect_runtime(
        f.runtime.clone(),
        Arc::new(PasswordKdf::new(
            NonZeroUsize::MIN,
            NonZeroU64::new(128 * 1024 * 1024).expect("constant"),
        )?),
        f.config().with_authentication_policy(policy),
        binding(f.key.tenant),
        f.policy.clone(),
        deadline(),
    )
    .await?)
}

pub async fn occupied(f: &Fixture, tenant: &str, kind: &str) -> anyhow::Result<i64> {
    let (state, physical): (i64, i64) = sqlx::query_as(
        "SELECT occupied,CASE kind WHEN 'oidc_capacity' THEN
        (SELECT count(*) FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid)
        ELSE (SELECT count(*) FROM identity_authority.attempts WHERE tenant_id=$1::uuid)
        +(SELECT count(*) FROM identity_authority.password_attempts WHERE tenant_id=$1::uuid) END
        FROM identity_authority.tenant_state WHERE tenant_id=$1::uuid AND kind=$2",
    )
    .bind(tenant)
    .bind(kind)
    .fetch_one(&f.owner)
    .await?;
    anyhow::ensure!(
        state == physical,
        "{kind} state {state}, physical {physical}"
    );
    Ok(state)
}
fn request(f: &Fixture, provider: ProviderId, src: &str) -> anyhow::Result<LoginRequest> {
    Ok(LoginRequest {
        binding: binding(f.key.tenant),
        provider,
        browser: oidc::BROWSER.into(),
        target: "home".into(),
        replacement: None,
        source: AttemptSource::parse(src)?,
    })
}
#[allow(clippy::expect_used, reason = "fixed fixture password")]
async fn bad(f: &Fixture, store: &Authority, name: &str) -> Result<IssuedSession, AuthorityError> {
    store
        .login_local(
            binding(f.key.tenant),
            login(name),
            Password::new("wrong fixture password".into()).expect("test password"),
            source(),
            None,
            deadline(),
        )
        .await
}
pub async fn run(f: &Fixture) -> anyhow::Result<()> {
    let broad = configured(f, 10000, 2).await?;
    let fed = oidc::service_for(broad.clone(), oidc::settings().redirect_uri());
    let p = oidc::enabled(f, &fed).await?;
    let target = broad
        .create_local_account(
            f.actor().await?,
            login("reset-target"),
            password(),
            deadline(),
        )
        .await?
        .key();
    f.reset_attempts().await?;
    let narrow = configured(f, 2, 2).await?;
    let limited = oidc::service_for(narrow.clone(), oidc::settings().redirect_uri());
    last_slot(f, &narrow, &limited, p.id).await?;
    reset_passwords(f, &broad, &narrow, target).await?;
    cleanup(f, &narrow, &limited, p.id).await?;
    federation::lifecycle(f, &fed, &p).await
}

async fn last_slot(
    f: &Fixture,
    narrow: &Authority,
    limited: &Federation,
    p: ProviderId,
) -> anyhow::Result<()> {
    // An acknowledged login leaves just the source key.
    narrow
        .login_local(
            binding(f.key.tenant),
            login("admin"),
            password(),
            source(),
            None,
            deadline(),
        )
        .await?;
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 1);
    let (ordinary, pwd) = tokio::join!(
        limited.begin_login(request(f, p, "local-test")?, deadline()),
        bad(f, narrow, "missing")
    );
    match (ordinary, pwd) {
        (Ok(_), Err(AuthorityError::Busy))
        | (Err(AuthorityError::Busy), Err(AuthorityError::Rejected)) => (),
        _ => anyhow::bail!("ordinary and password admission must grant exactly one slot"),
    }
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 2);
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "verify each committed change in password occupancy"
)]
async fn reset_passwords(
    f: &Fixture,
    broad: &Authority,
    narrow: &Authority,
    target: rss_identity_core::account::AccountKey,
) -> anyhow::Result<()> {
    // Repeated credential failures retain one row. Both password change owners release it.
    f.reset_attempts().await?;
    for _ in 0..2 {
        assert!(matches!(
            bad(f, narrow, "reset-target").await,
            Err(AuthorityError::Rejected)
        ));
    }
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 2);
    broad
        .reset_local_password(f.actor().await?, target, password(), deadline())
        .await?;
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 1);
    assert!(matches!(
        bad(f, narrow, "reset-target").await,
        Err(AuthorityError::Rejected)
    ));
    f.maintenance
        .recover_local_password(binding(f.key.tenant), target, password(), deadline())
        .await?;
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 1);
    Ok(())
}
#[allow(
    clippy::cognitive_complexity,
    reason = "observe consecutive bounded sweeps and domain error precedence"
)]
async fn cleanup(
    f: &Fixture,
    store: &Authority,
    fed: &Federation,
    p: ProviderId,
) -> anyhow::Result<()> {
    // Start over quota. Only two rows may be reclaimed per call, including denied calls.
    sqlx::query("INSERT INTO identity_authority.attempts SELECT $1::uuid,'old:'||i,1,now()-interval '1 minute' FROM generate_series(1,3) i").bind(A).execute(&f.owner).await?;
    sqlx::query("INSERT INTO identity_authority.password_attempts(tenant_id,login_digest) SELECT $1::uuid,sha256(int4send(i)) FROM generate_series(1,2) i").bind(A).execute(&f.owner).await?;
    sqlx::query("INSERT INTO identity_authority.password_attempts(tenant_id,login_digest,claim_token,claim_until) VALUES($1::uuid,sha256(int4send(99)),gen_random_uuid(),now()+interval '1 hour')").bind(A).execute(&f.owner).await?;
    sqlx::query("INSERT INTO identity_authority.attempts VALUES($1::uuid,'other',1,now()-interval '1 hour')").bind(SYSTEM).execute(&f.owner).await?;
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 7);
    for expected in [5, 3, 2] {
        assert!(matches!(
            fed.begin_login(request(f, p, "local-test")?, deadline())
                .await,
            Err(AuthorityError::Busy)
        ));
        assert_eq!(occupied(f, A, "attempt_capacity").await?, expected);
    }
    assert_eq!(occupied(f, SYSTEM, "attempt_capacity").await?, 1);
    sqlx::query("UPDATE identity_authority.password_attempts SET claim_until=now()-interval '1 second' WHERE tenant_id=$1::uuid").bind(A).execute(&f.owner).await?;
    fed.begin_login(request(f, p, "local-test")?, deadline())
        .await?;
    fed.begin_login(request(f, p, "local-test")?, deadline())
        .await?;
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 2);
    let lowered = configured(f, 1, 2).await?;
    let strict = oidc::service_for(lowered, oidc::settings().redirect_uri());
    assert!(matches!(
        strict
            .begin_login(request(f, p, "local-test")?, deadline())
            .await,
        Err(AuthorityError::Busy)
    ));
    sqlx::query("UPDATE identity_authority.attempts SET count=100000 WHERE tenant_id=$1::uuid AND key='s:local-test'").bind(A).execute(&f.owner).await?;
    assert!(
        matches!(strict.begin_login(request(f,p,"local-test")?,deadline()).await,Err(AuthorityError::RateLimited{retry_after_seconds}) if retry_after_seconds.get()>0)
    );
    recheck_keys(f, store, fed, p).await?;
    rollback_claim(f, store).await
}
async fn recheck_keys(
    f: &Fixture,
    store: &Authority,
    fed: &Federation,
    p: ProviderId,
) -> anyhow::Result<()> {
    for ordinary in [true, false] {
        f.reset_attempts().await?;
        sqlx::query("INSERT INTO identity_authority.attempts VALUES
          ($1::uuid,'s:local-test',1,now()-interval '1 minute'),($1::uuid,'other',1,now()+interval '5 minutes')")
          .bind(A).execute(&f.owner).await?;
        if ordinary {
            assert!(matches!(
                fed.begin_login(request(f, p, "local-test")?, deadline())
                    .await,
                Err(AuthorityError::Busy)
            ));
        } else {
            assert!(matches!(
                bad(f, store, "absent").await,
                Err(AuthorityError::Busy)
            ));
        }
        assert_eq!(occupied(f, A, "attempt_capacity").await?, 1);
    }
    Ok(())
}
async fn rollback_claim(f: &Fixture, store: &Authority) -> anyhow::Result<()> {
    // Force the second insertion to fail after the source and its charge have been written.
    f.reset_attempts().await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'claim fixture'; END $$;
        CREATE TRIGGER reject_claim BEFORE INSERT ON identity_authority.password_attempts FOR EACH ROW EXECUTE FUNCTION public.reject_claim()").execute(&f.owner).await?;
    assert!(matches!(
        bad(f, store, "admin").await,
        Err(AuthorityError::RolledBack(_))
    ));
    assert_eq!(occupied(f, A, "attempt_capacity").await?, 0);
    sqlx::query("DROP TRIGGER reject_claim ON identity_authority.password_attempts")
        .execute(&f.owner)
        .await?;
    Ok(())
}
