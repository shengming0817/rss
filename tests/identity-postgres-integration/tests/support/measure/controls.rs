//! Force isolated, known waits to verify diagnostic classification independently of natural contention.
use super::*;

/// Install only in the diagnostic database after Authority has verified its production schema.
/// The marker runs after a real counter update, including the update caused by batch expiry.
pub(super) async fn observe_oidc_changes(f: &Fixture) -> anyhow::Result<()> {
    let has_counter:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_attribute
        WHERE attrelid='identity_authority.tenant_state'::regclass AND attname='occupied' AND NOT attisdropped)").fetch_one(&f.owner).await?;
    if has_counter {
        sqlx::raw_sql("CREATE FUNCTION public.measure_oidc_change() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE LOG 'RSS_OIDC_OCCUPANCY_CHANGED'; RETURN NULL; END $$;
            CREATE TRIGGER measure_oidc_change AFTER UPDATE OF occupied ON identity_authority.tenant_state
            FOR EACH ROW WHEN(NEW.kind='oidc_capacity' AND NEW.occupied<>OLD.occupied)
            EXECUTE FUNCTION public.measure_oidc_change()").execute(&f.owner).await?;
    }
    Ok(())
}

pub(super) async fn collect(
    f: &Fixture,
    s: &Federation,
    p: ProviderId,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut windows = vec![];
    for (kind, first_change) in [
        ("collection", None),
        ("attempt_capacity", None),
        ("profile_sequence", None),
        ("oidc_capacity", Some("insert")),
        ("oidc_capacity", Some("reclaim")),
    ] {
        let mut blocker = f.owner.begin().await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        if kind == "collection" {
            sqlx::query("SELECT tenant_id FROM identity_authority.tenants WHERE tenant_id=$1::uuid FOR UPDATE").bind(A).fetch_one(&mut *blocker).await?;
        } else {
            let row=sqlx::query("SELECT kind FROM identity_authority.tenant_state WHERE tenant_id=$1::uuid AND kind=$2 FOR UPDATE").bind(A).bind(kind).fetch_optional(&mut *blocker).await?;
            if row.is_none() && kind == "oidc_capacity" {
                blocker.rollback().await?;
                continue;
            }
            anyhow::ensure!(row.is_some(), "missing control row");
        }
        if first_change == Some("reclaim") {
            let seeded=sqlx::query("UPDATE identity_authority.oidc_transactions SET created_at=1,expires_at=2
                WHERE ctid=(SELECT ctid FROM identity_authority.oidc_transactions WHERE tenant_id=$1::uuid LIMIT 1)").bind(A).execute(&f.owner).await?;
            anyhow::ensure!(
                seeded.rows_affected() == 1,
                "expected a real expiry candidate"
            );
        }
        let start = clock_us(f).await?;
        let request = async {
            anyhow::Ok(
                s.begin_login(
                    LoginRequest {
                        binding: binding(f.key.tenant),
                        provider: p,
                        browser: BROWSER.into(),
                        target: "home".into(),
                        replacement: None,
                        source: source(),
                    },
                    deadline(),
                )
                .await?,
            )
        };
        let release = async {
            let waiter = wait_for_blocked_backend(f, pid).await?;
            tokio::time::sleep(Duration::from_millis(12)).await;
            blocker.commit().await?;
            anyhow::Ok(waiter)
        };
        let (_, waiter) = tokio::try_join!(request, release)?;
        let window = json!({"db":f.database,"start":start,"end":clock_us(f).await?,"waiter":waiter,"first_change":first_change,"lock":if kind=="profile_sequence" {"sequence"} else {kind}});
        println!("AUTH_CONTROL {window}");
        windows.push(window);
    }
    Ok(windows)
}
