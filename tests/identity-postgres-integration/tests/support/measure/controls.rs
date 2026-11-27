//! Force isolated, known waits to verify diagnostic classification independently of natural contention.
use super::*;

pub(super) async fn collect(
    f: &Fixture,
    s: &Federation,
    p: ProviderId,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut windows = vec![];
    for kind in [
        "collection",
        "attempt_capacity",
        "profile_sequence",
        "oidc_capacity",
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
        let window = json!({"db":f.database,"start":start,"end":clock_us(f).await?,"waiter":waiter,"lock":if kind=="profile_sequence" {"sequence"} else {kind}});
        println!("AUTH_CONTROL {window}");
        windows.push(window);
    }
    Ok(windows)
}
