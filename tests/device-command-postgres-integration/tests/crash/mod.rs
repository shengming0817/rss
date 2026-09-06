use super::*;
use std::process::{Command as Process, Stdio};
pub(super) async fn recovery(f: &Fixture, postgres: &testkit::PgTlsFixture) -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("rss-device-crash-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    let ca = root.join("ca.pem");
    std::fs::write(&ca, postgres.ca_pem())?;
    for (name, committed_before_kill) in [("crash-before", false), ("crash-after", true)] {
        let marker = root.join(name);
        let p = postgres.params();
        let mut child = Process::new(std::env::current_exe()?)
            .args(["--exact", "crash::device_child", "--ignored", "--nocapture"])
            .env("DEVICE_TEST_HOST", &p.host)
            .env("DEVICE_TEST_PORT", p.port.to_string())
            .env("DEVICE_TEST_DB", &p.database)
            .env("DEVICE_TEST_CA", &ca)
            .env("DEVICE_TEST_MARKER", &marker)
            .env("DEVICE_TEST_ID", name)
            .env(
                "DEVICE_TEST_COMMITTED",
                if committed_before_kill { "yes" } else { "no" },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let ready = tokio::time::timeout(Duration::from_secs(20), async {
            while !marker.exists() {
                if child.try_wait()?.is_some() {
                    anyhow::bail!("worker exited before crash point");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await;
        let killed = child.kill();
        child.wait()?;
        killed?;
        ready??;
        assert_eq!(
            f.count("commands", name).await?,
            i64::from(committed_before_kill)
        );
        assert_eq!(
            f.count("outbox", &format!("dispatch.{name}")).await?,
            i64::from(committed_before_kill)
        );
        f.queue(name, scope(TENANT)?, Coordinate::new(2, 3)?)
            .await?;
        assert_eq!(f.count("commands", name).await?, 1);
        assert_eq!(f.count("outbox", &format!("dispatch.{name}")).await?, 1);
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
#[ignore = "child process stopped by recovery at a real transaction boundary"]
async fn device_child() -> anyhow::Result<()> {
    let config = PgConfig::new(
        &std::env::var("DEVICE_TEST_HOST")?,
        std::env::var("DEVICE_TEST_PORT")?.parse()?,
        &std::env::var("DEVICE_TEST_DB")?,
        "device_runtime",
        PgPassword::new("fixture-only"),
        PgPrivateCa::from_pem(std::fs::read(std::env::var("DEVICE_TEST_CA")?)?)?,
    );
    let (runtime, store, _) = stores(config).await?;
    let s = scope(TENANT)?;
    let name = std::env::var("DEVICE_TEST_ID")?;
    let request = spec(&name, s, Coordinate::new(2, 3)?)?;
    let msg = message(&name, s.tenant())?;
    let marker = std::env::var("DEVICE_TEST_MARKER")?;
    let committed_before_kill = std::env::var("DEVICE_TEST_COMMITTED")? == "yes";
    let before_marker = marker.clone();
    committed(
        runtime
            .local_tx(s.tenant(), budget()?, move |tx| {
                Box::pin(async move {
                    store.queue(tx, request, msg).await?;
                    if !committed_before_kill {
                        std::fs::write(before_marker, b"staged").map_err(sqlx::Error::Io)?;
                        std::future::pending::<()>().await;
                    }
                    Ok(())
                })
            })
            .await,
    )?;
    std::fs::write(marker, b"committed")?;
    std::future::pending::<()>().await;
    Ok(())
}
