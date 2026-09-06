use super::{fixture::*, scenarios::model};
use rss_observation::{Body, Change, Id, JournalReadGrant, ObservationStore};
use rss_observation_postgres::{PgSource, PgStore};
use rss_projection::{
    BatchLimit, Control, Event, Execution, GenerationStart, ProjectionScope, ReplayBound, RunLimit,
    Source,
};
use rss_projection_postgres::{PgEffect, PgEffectOutcome, PgOperationError, PgTransaction};
use rss_request_context::TenantId;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};
const CRASH_TENANT: &str = "00000000-0000-0000-0000-000000000073";
pub async fn crash(f: &Fixture) -> anyhow::Result<()> {
    let source = seed_source(f).await?;
    let projection = f.projection().await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(40), &cancel);
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "crash")?;
    projection
        .initialize(
            &scope,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    kill_staged_worker(f).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.observation_facts WHERE tenant_id=$1::uuid",
    )
    .bind(CRASH_TENANT)
    .fetch_one(&f.admin)
    .await?;
    assert_eq!(count, 0);
    let execution = projection.projection(
        projection.takeover(&scope, &control).await?,
        model::Facts::new(source.clone()),
    )?;
    assert_eq!(execution.checkpoint().await?.position, None);
    let report = rss_projection::run(
        source.as_ref(),
        &execution,
        &control,
        RunLimit::new(BatchLimit::new(1)?, 10)?,
    )
    .await
    .into_result()?;
    assert_eq!(report.applied, 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.observation_facts WHERE tenant_id=$1::uuid",
    )
    .bind(CRASH_TENANT)
    .fetch_one(&f.admin)
    .await?;
    assert_eq!(count, 1);
    Ok(())
}
async fn seed_source(f: &Fixture) -> anyhow::Result<Arc<PgSource<Clock>>> {
    let store = f.store().await?;
    let source = f.source(store.clone(), CRASH_TENANT)?;
    let stream = scope(CRASH_TENANT, "crash", "r", "agent", "e")?;
    activate(&store, &stream, None).await?;
    let input = batch(
        &stream,
        "crash",
        0,
        "all",
        Body::Snapshot(vec![Change::upsert(Id::new("one")?, vec![1])]),
    )?;
    store.receive(&input, deadline()).await?;
    Ok(source)
}
async fn kill_staged_worker(f: &Fixture) -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let ca = root.path().join("ca.pem");
    let marker = root.path().join("staged");
    std::fs::write(&ca, f.server.ca_pem())?;
    let params = f.server.params();
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "observation_projection::process::worker_child",
            "--nocapture",
        ])
        .env("OBS_HANDOFF_HOST", &params.host)
        .env("OBS_HANDOFF_PORT", params.port.to_string())
        .env("OBS_HANDOFF_DB", &params.database)
        .env("OBS_HANDOFF_CA", &ca)
        .env("OBS_HANDOFF_MARKER", &marker)
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ready = tokio::time::timeout(Duration::from_secs(20), async {
        while !marker.exists() {
            if child.try_wait()?.is_some() {
                return Err(anyhow::anyhow!("worker exited before effect"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    child.kill().await?;
    child.wait().await?;
    ready??;
    Ok(())
}
struct CrashEffect {
    inner: model::Facts<Clock>,
    marker: PathBuf,
}
impl PgEffect for CrashEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        event: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        self.inner.apply(tx, scope, event).await?;
        std::fs::write(&self.marker, b"staged").map_err(PgOperationError::unavailable)?;
        std::future::pending().await
    }
}
#[tokio::test]
async fn worker_child() -> anyhow::Result<()> {
    let Ok(marker) = std::env::var("OBS_HANDOFF_MARKER") else {
        return Ok(());
    }; // reason: only the parent crash scenario starts the child workload.
    let options = PgConnectOptions::new()
        .host(&std::env::var("OBS_HANDOFF_HOST")?)
        .port(std::env::var("OBS_HANDOFF_PORT")?.parse()?)
        .database(&std::env::var("OBS_HANDOFF_DB")?)
        .username("handoff_runtime")
        .password("fixture-only")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(std::fs::read(std::env::var("OBS_HANDOFF_CA")?)?);
    let store = Arc::new(
        PgStore::new(
            PgPoolOptions::new()
                .max_connections(2)
                .connect_with(options.clone())
                .await?,
            Clock,
            deadline(),
        )
        .await?,
    );
    let source = Arc::new(PgSource::new(
        store,
        JournalReadGrant::verify(&Trusted, TenantId::parse(CRASH_TENANT)?)?,
    )?);
    let projection = rss_projection_postgres::PgStore::new(
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?,
    )
    .await?;
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(60), &cancel);
    let scope = ProjectionScope::new(source.scope().clone(), "facts", "crash")?;
    let event = source
        .read(source.scope(), None, BatchLimit::new(1)?)
        .await?;
    let execution = projection.projection(
        projection.takeover(&scope, &control).await?,
        CrashEffect {
            inner: model::Facts::new(source),
            marker: marker.into(),
        },
    )?;
    execution.execute(None, &event[0], &control).await?;
    Ok(())
}
