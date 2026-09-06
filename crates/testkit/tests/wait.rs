//! testkit `wait` 模块自测：有界条件轮询与固定延时。

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use testkit::{TestkitError, await_delay, await_try};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug)]
enum TryWaitError {
    Timeout(TestkitError),
    Probe,
}

impl std::fmt::Display for TryWaitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout(error) => error.fmt(formatter),
            Self::Probe => formatter.write_str("probe failed"),
        }
    }
}

impl std::error::Error for TryWaitError {}

impl From<TestkitError> for TryWaitError {
    fn from(error: TestkitError) -> Self {
        Self::Timeout(error)
    }
}

struct DropProbe(Rc<Cell<bool>>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[tokio::test(start_paused = true)]
async fn await_try_returns_first_non_send_value_and_lends_state() -> TestResult {
    let value = Rc::new(String::from("ready-value"));
    let mut calls = 0;

    let observed = await_try(Duration::from_secs(1), async || {
        calls += 1;
        Ok::<_, TestkitError>((calls == 2).then(|| Rc::clone(&value)))
    })
    .await?;

    assert!(Rc::ptr_eq(&observed, &value));
    assert_eq!(calls, 2, "ready probe must not run after returning a value");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn await_try_pending_times_out_with_exact_budget() -> TestResult {
    let error = await_try(Duration::from_millis(25), async || {
        Ok::<Option<()>, TestkitError>(None)
    })
    .await;
    assert!(matches!(
        error,
        Err(TestkitError::WaitTimeout { waited_ms: 25 })
    ));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn await_try_propagates_first_fatal_error() -> TestResult {
    let mut calls = 0;
    let result = await_try(Duration::from_secs(1), async || {
        calls += 1;
        Err::<Option<()>, _>(TryWaitError::Probe)
    })
    .await;
    let Err(error) = result else {
        return Err("fatal probe error must return immediately".into());
    };

    assert!(matches!(error, TryWaitError::Probe));
    assert_eq!(calls, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn await_try_timeout_cancels_inflight_probe() -> TestResult {
    let dropped = Rc::new(Cell::new(false));
    let probe_drop = Rc::clone(&dropped);

    let result = await_try(Duration::from_millis(10), async || {
        let _probe = DropProbe(Rc::clone(&probe_drop));
        std::future::pending::<Result<Option<()>, TryWaitError>>().await
    })
    .await;
    let Err(error) = result else {
        return Err("inflight probe must be cancelled by the total deadline".into());
    };

    assert!(matches!(
        error,
        TryWaitError::Timeout(TestkitError::WaitTimeout { waited_ms: 10 })
    ));
    assert!(dropped.get(), "timeout must drop the inflight probe future");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn await_delay_completes_after_duration() -> TestResult {
    // paused clock：短于 delay 的 timeout 必须先触发，证明 await_delay 真的在睡满 duration。
    let early = tokio::time::timeout(
        Duration::from_millis(10),
        await_delay(Duration::from_millis(50)),
    )
    .await;
    assert!(
        early.is_err(),
        "await_delay must not resolve before the requested duration"
    );
    await_delay(Duration::from_millis(50)).await;
    Ok(())
}
