//! Host-owned transactions serialize live-session admission with Identity revocation.

use crate::support;
use rss_identity_core::session::SessionSecret;
use rss_identity_postgres::*;

use sqlx::{Connection, PgConnection, Postgres, Transaction};

use support::*;

async fn transaction<'a>(
    c: &'a mut PgConnection,
    tenant: &str,
) -> anyhow::Result<Transaction<'a, Postgres>> {
    let mut tx = c.begin().await?;
    if let Ok(tenant) = rss_request_context::TenantId::parse(tenant) {
        crate::support::fence(&mut tx, binding(tenant)).await?;
    } else {
        sqlx::query("SELECT set_config('rss.tenant_id','',true)")
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("SET LOCAL statement_timeout = '8s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL ROLE identity_runtime")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn actor(f: &Fixture, issued: &IssuedSession) -> anyhow::Result<AuthenticatedSession> {
    Ok(f.store
        .inspect_session(
            crate::support::binding(f.key.tenant),
            SessionSecret::parse(issued.secret().expose().into())?,
            deadline(),
        )
        .await?)
}
async fn accepted(f: &Fixture, actor: &AuthenticatedSession) -> anyhow::Result<bool> {
    let mut c = f.owner.acquire().await?;
    let mut tx = transaction(&mut c, A).await?;
    let result = recheck_authenticated_session_on(&mut tx, actor)
        .await
        .is_ok();
    tx.rollback().await?;
    Ok(result)
}
async fn marker_table(f: &Fixture) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE TABLE public.host_binding(id integer PRIMARY KEY); GRANT SELECT,INSERT ON public.host_binding TO identity_runtime").execute(&f.owner).await?;
    Ok(())
}
async fn marker_count(f: &Fixture) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM public.host_binding")
            .fetch_one(&f.owner)
            .await?,
    )
}

pub async fn borrowed(f: &Fixture) -> anyhow::Result<()> {
    marker_table(f).await?;
    // Admission wins. The real public revoke operation must wait for either host outcome.
    for commit in [true, false] {
        let issued = f.login().await?;
        let admission = actor(f, &issued).await?;
        let revoke_actor = actor(f, &issued).await?;
        let mut c = f.owner.acquire().await?;
        let mut tx = transaction(&mut c, A).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await?;
        recheck_authenticated_session_on(&mut tx, &admission).await?;
        sqlx::query("INSERT INTO public.host_binding VALUES($1)")
            .bind(i32::from(commit))
            .execute(&mut *tx)
            .await?;
        let store = f.store.clone();
        let revoke =
            tokio::spawn(
                async move { store.revoke_current_session(revoke_actor, deadline()).await },
            );
        wait_for_blocked_backend(f, pid).await?;
        if commit {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        revoke.await??;
        assert!(!accepted(f, &admission).await?);
    }
    assert_eq!(marker_count(f).await?, 1);
    // Hold the real revoke after its row update. A forced failure checks rollback as well.
    for commit in [true, false] {
        let issued = f.login().await?;
        let admission = actor(f, &issued).await?;
        let revoker = actor(f, &issued).await?;
        let mut controller = f.owner.begin().await?;
        let controller_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *controller)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(3331,1)")
            .execute(&mut *controller)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE OR REPLACE FUNCTION public.pause_session_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN PERFORM pg_advisory_xact_lock(3331,1);
             IF {fail} THEN RAISE EXCEPTION 'rolled back test revocation'; END IF;
             RETURN NEW; END $$;
             CREATE TRIGGER pause_revoke AFTER UPDATE OF revoked_at ON identity_authority.sessions
             FOR EACH ROW EXECUTE FUNCTION public.pause_session_revoke()",fail=!commit
        ))).execute(&f.owner).await?;
        let store = f.store.clone();
        let writer =
            tokio::spawn(async move { store.revoke_current_session(revoker, deadline()).await });
        let writer_pid = wait_for_blocked_backend(f, controller_pid).await?;
        let pool = f.owner.clone();
        let reader = tokio::spawn(async move {
            let mut c = pool.acquire().await?;
            let mut tx = transaction(&mut c, A).await?;
            let admitted = recheck_authenticated_session_on(&mut tx, &admission)
                .await
                .is_ok();
            if admitted {
                sqlx::query("INSERT INTO public.host_binding VALUES(2)")
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            Ok::<_, anyhow::Error>(admitted)
        });
        wait_for_blocked_backend(f, writer_pid).await?;
        controller.commit().await?;
        assert_eq!(writer.await?.is_ok(), commit);
        assert_eq!(reader.await??, !commit);
        assert_eq!(marker_count(f).await?, if commit { 1 } else { 2 });
        sqlx::query("DROP TRIGGER pause_revoke ON identity_authority.sessions")
            .execute(&f.owner)
            .await?;
    }
    Ok(())
}
