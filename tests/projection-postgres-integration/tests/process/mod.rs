use super::*;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

pub(super) async fn crash(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("process-crash", TENANT)?;
    store
        .initialize(&s, GenerationStart::beginning(), ReplayBound::Live, control)
        .await?;
    let root = std::env::temp_dir().join(format!("rss-projection-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    let ca = root.join("ca.pem");
    std::fs::write(&ca, fixture.ca_pem())?;
    let marker = root.join("applied");
    let params = fixture.params();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "process::projection_worker_child",
            "--ignored",
            "--nocapture",
        ])
        .env("PROJECTION_TEST_HOST", &params.host)
        .env("PROJECTION_TEST_PORT", params.port.to_string())
        .env("PROJECTION_TEST_DB", &params.database)
        .env("PROJECTION_TEST_CA", &ca)
        .env("PROJECTION_TEST_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ready = tokio::time::timeout(Duration::from_secs(20), async {
        while !marker.exists() {
            if child.try_wait()?.is_some() {
                return Err(anyhow::anyhow!("worker exited before staging effect"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    child.kill()?;
    child.wait()?;
    ready??;
    assert_eq!(count(owner, &s).await?, 0);
    let projection = store.projection(store.takeover(&s, control).await?, Counter)?;
    assert_eq!(projection.checkpoint().await?.position, None);
    projection
        .execute(None, &event(&s, 0, "crash-fact", b"x")?, control)
        .await?;
    assert_eq!(count(owner, &s).await?, 1);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
struct CrashEffect(PathBuf);
impl PgEffect for CrashEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        increment(tx, scope).await?;
        std::fs::write(&self.0, b"staged").map_err(PgOperationError::unavailable)?;
        std::future::pending().await
    }
}
#[tokio::test]
#[ignore = "spawned and killed by projection_postgres_suite after a real uncommitted effect"]
async fn projection_worker_child() -> anyhow::Result<()> {
    let ca = std::fs::read(std::env::var("PROJECTION_TEST_CA")?)?;
    let options = PgConnectOptions::new()
        .host(&std::env::var("PROJECTION_TEST_HOST")?)
        .port(std::env::var("PROJECTION_TEST_PORT")?.parse()?)
        .database(&std::env::var("PROJECTION_TEST_DB")?)
        .username("projection_runtime")
        .password("fixture-only")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca);
    let store = PgStore::new(
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?,
    )
    .await?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(60), &cancel);
    let s = scope("process-crash", TENANT)?;
    let projection = store.projection(
        store.takeover(&s, &control).await?,
        CrashEffect(std::env::var("PROJECTION_TEST_MARKER")?.into()),
    )?;
    projection
        .execute(None, &event(&s, 0, "crash-fact", b"x")?, &control)
        .await?;
    Ok(())
}
