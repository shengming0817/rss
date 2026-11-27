use crate::support::*;
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::AuthorityError;

pub async fn rotation(f: &Fixture) -> anyhow::Result<()> {
    let session = f.login().await?;
    let scope = binding(f.key.tenant);
    let old = || SessionSecret::parse(session.secret().expose().into());
    let (a, b) = tokio::join!(
        f.store.refresh_session(scope, old()?, deadline()),
        f.store.refresh_session(scope, old()?, deadline())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let next = a.or(b)?;
    assert!(
        f.store
            .inspect_session(scope, old()?, deadline())
            .await
            .is_err()
    );
    let next_secret = || SessionSecret::parse(next.secret().expose().into());
    let actor = f
        .store
        .inspect_session(scope, next_secret()?, deadline())
        .await?;
    f.store.revoke_current_session(actor, deadline()).await?;
    assert!(
        f.store
            .inspect_session(scope, next_secret()?, deadline())
            .await
            .is_err()
    );
    Ok(())
}

async fn ledger_state(f: &Fixture) -> anyhow::Result<(i64, serde_json::Value)> {
    Ok(sqlx::query_as("SELECT (SELECT count(*) FROM rss_ledger.entries),coalesce(jsonb_agg(to_jsonb(h) ORDER BY tenant_id,chain_id),'[]') FROM rss_ledger.heads h").fetch_one(&f.owner).await?)
}
#[allow(
    clippy::cognitive_complexity,
    reason = "test fixture and ordered assertions"
)]
pub async fn audit_settlement(f: &Fixture) -> anyhow::Result<()> {
    let session = f.login().await?;
    let ledger_before = ledger_state(f).await?;
    let before = f.events().await?;
    let scope = binding(f.key.tenant);
    let old = || SessionSecret::parse(session.secret().expose().into());
    let cancel = Default::default();
    let end = deadline();
    let control = rss_audit_postgres::Control::new(&Timer, end, end, &cancel);
    let held = f.audit_budget.reserve(8, 1024 * 1024, &control).await?;
    assert!(matches!(
        f.store.refresh_session(scope, old()?, deadline()).await,
        Err(AuthorityError::RolledBack(_))
    ));
    drop(held);
    assert_eq!(f.events().await?, before);
    assert_eq!(ledger_state(f).await?, ledger_before);
    f.store.inspect_session(scope, old()?, deadline()).await?;
    sqlx::raw_sql("CREATE FUNCTION public.reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit rejection'; END $$; CREATE TRIGGER reject_event BEFORE INSERT ON rss_audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_event()").execute(&f.owner).await?;
    assert!(matches!(
        f.store.refresh_session(scope, old()?, deadline()).await,
        Err(AuthorityError::RolledBack(_))
    ));
    assert_eq!(f.events().await?, before);
    assert_eq!(ledger_state(f).await?, ledger_before);
    f.store.inspect_session(scope, old()?, deadline()).await?;
    sqlx::query("DROP TRIGGER reject_event ON rss_audit.records")
        .execute(&f.owner)
        .await?;
    let next = f.store.refresh_session(scope, old()?, deadline()).await?;
    assert!(next.secret().expose() != session.secret().expose());
    assert!(
        f.store
            .inspect_session(scope, old()?, deadline())
            .await
            .is_err()
    );
    let (total, linked): (i64, i64) =
        sqlx::query_as("SELECT count(*),count(ledger_sequence) FROM rss_audit.records")
            .fetch_one(&f.owner)
            .await?;
    assert!(total > before);
    assert_eq!(total, linked);
    let (entries, heads) = ledger_state(f).await?;
    assert_eq!(entries - ledger_before.0, total - before);
    assert_ne!(heads, ledger_before.1);
    Ok(())
}
