//! Bound the same real PG operations on either side of rollback entry.
use super::super::budget::ManualTimer;
use super::*;
use anyhow::Context as _;
use futures::FutureExt as _;
use rss_projection::{Error, ErrorKind, Phase, ReceiptQuery, ReceiptStatus, Report, Stop};
use std::future::IntoFuture as _;
use tokio_util::sync::CancellationToken;

const END: u64 = 60;
const GUARD: Duration = Duration::from_secs(15);

pub(super) async fn verify(
    f: &Fixture,
    input: &Inputs,
    execution: &Session,
    projection: &rss_projection_postgres::PgStore,
    events: &[rss_observation_postgres::VerifiedObservation],
) -> anyhow::Result<()> {
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = CancellationToken::new();
    let inspect = Control::new(&clock, GUARD, &cancel);
    input
        .store
        .inject_next_fault(rss_observation_postgres::Fault::RollbackAckLost);
    let read = input
        .source
        .read(input.source.scope(), None, BatchLimit::new(2)?, &inspect)
        .await;
    assert_rollback(
        read.err()
            .context("source accepted lost rollback acknowledgment")?,
    );

    let timer = ManualTimer::new();
    let control = Control::new(&timer, Duration::from_secs(END), &cancel);
    let entered = input.store.inject_pending_rollback();
    let direct = input
        .source
        .resolve(events[1].as_ref(), &control)
        .map(|result| result.map(|_| ()));
    let result = expire_after(
        &timer,
        "resolve rollback",
        async { Ok(entered.await?) },
        direct,
    )
    .await?;
    assert_rollback(result.err().context("resolve accepted pending rollback")?);
    assert_durable(f, execution, projection, events).await?;

    let mut blocker = f.admin.begin().await?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    sqlx::query("LOCK TABLE rss_projection.checkpoints IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    // This injection must still be armed for the following run after checkpoint expires.
    let entered = input.store.inject_pending_rollback();
    let limit = RunLimit::new(BatchLimit::new(2)?, 2)?;
    let timer = ManualTimer::new();
    let control = Control::new(&timer, Duration::from_secs(END), &cancel);
    let run = rss_projection::run(input.source.as_ref(), execution, &control, limit);
    let report = expire_after(
        &timer,
        "runner checkpoint lock",
        f.wait_for_blocked(pid, 1),
        run.into_future(),
    )
    .await?;
    let error = failed_without_progress(report)?;
    assert_eq!(
        error.kind(),
        ErrorKind::Deadline,
        "checkpoint lock reached: {error:?}"
    );
    blocker.rollback().await?;
    assert_durable(f, execution, projection, events).await?;

    let timer = ManualTimer::new();
    let control = Control::new(&timer, Duration::from_secs(END), &cancel);
    let run = rss_projection::run(input.source.as_ref(), execution, &control, limit);
    let report = expire_after(
        &timer,
        "runner source rollback",
        async { Ok(entered.await?) },
        run.into_future(),
    )
    .await?;
    assert_rollback(failed_without_progress(report)?);
    assert_durable(f, execution, projection, events).await
}

// Wall time only bounds a broken fixture. The operation's deadline advances at the handshake.
async fn expire_after<T: std::fmt::Debug>(
    timer: &ManualTimer,
    stage: &str,
    entered: impl Future<Output = anyhow::Result<()>>,
    operation: impl Future<Output = T>,
) -> anyhow::Result<T> {
    tokio::pin!(operation);
    tokio::time::timeout(GUARD, async {
        tokio::select! {
            result = &mut operation => anyhow::bail!("operation stopped before {stage}: {result:?}"),
            signal = entered => signal.with_context(|| format!("failed to reach {stage}")),
        }
    }).await.with_context(|| format!("timed out before {stage}"))??;
    timer.advance(END);
    tokio::time::timeout(GUARD, operation)
        .await
        .with_context(|| format!("operation did not stop after {stage}"))
}

fn failed_without_progress(report: Report) -> anyhow::Result<Error> {
    assert_eq!(
        (
            report.position,
            report.applied,
            report.duplicates,
            report.filtered
        ),
        (None, 0, 0, 0),
        "unexpected progress: {report:?}"
    );
    match report.stop {
        Stop::Failed(error) => Ok(error),
        stop => anyhow::bail!("runner failed to report the interruption: {stop:?}"),
    }
}
fn assert_rollback(error: Error) {
    let diagnostic = error.diagnostic();
    assert_eq!(
        (
            error.kind(),
            diagnostic.map(|d| d.phase()),
            diagnostic.and_then(|d| d.position())
        ),
        (ErrorKind::RollbackFailed, Some(Phase::Rollback), None),
        "rollback entered: {error:?}"
    );
}
async fn assert_durable(
    f: &Fixture,
    execution: &Session,
    projection: &rss_projection_postgres::PgStore,
    events: &[rss_observation_postgres::VerifiedObservation],
) -> anyhow::Result<()> {
    // Inspect settled state on a fresh budget after each independently controlled interruption.
    let clock = ProjectionClock(rss_observation::Clock::now(&Clock));
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, GUARD, &cancel);
    let checkpoint = execution.checkpoint(&control).await?;
    assert_eq!(checkpoint.position, None);
    for event in events {
        let query = ReceiptQuery::new(
            execution.scope().clone(),
            *execution.definition_identity(),
            event.as_ref().id(),
        )?;
        assert_eq!(
            projection.receipt_status(&query, &control).await?,
            ReceiptStatus::Pending(checkpoint)
        );
    }
    assert!(
        tokio::time::timeout(GUARD, values(f, execution.scope().generation(), "inside"))
            .await
            .context("timed out inspecting the read model")??
            .is_empty()
    );
    Ok(())
}
