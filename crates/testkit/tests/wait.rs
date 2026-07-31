//! testkit `wait` 模块自测：有界条件轮询、固定延时与 Notify 唤醒。

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use testkit::{TestkitError, await_delay, await_map, await_notified, await_try, await_try_every};

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
async fn await_map_returns_first_non_send_value_and_lends_state() -> TestResult {
    let value = Rc::new(String::from("ready-value"));
    let mut calls = 0;

    let observed = await_map(Duration::from_secs(1), async || {
        calls += 1;
        (calls == 2).then(|| Rc::clone(&value))
    })
    .await?;

    assert!(Rc::ptr_eq(&observed, &value));
    assert_eq!(calls, 2, "ready probe must not run after returning a value");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn await_map_pending_times_out_with_exact_budget() -> TestResult {
    let error = await_map(Duration::from_millis(25), async || None::<()>).await;
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
async fn await_try_every_uses_custom_interval_and_converts_timeout() -> TestResult {
    let mut calls = 0;
    let result = await_try_every(
        Duration::from_millis(25),
        Duration::from_millis(10),
        async || {
            calls += 1;
            Ok::<Option<()>, TryWaitError>(None)
        },
    )
    .await;
    let Err(error) = result else {
        return Err("pending probe must time out".into());
    };

    assert!(matches!(
        error,
        TryWaitError::Timeout(TestkitError::WaitTimeout { waited_ms: 25 })
    ));
    assert_eq!(calls, 3, "probe should run at t=0ms, 10ms, and 20ms");
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

#[tokio::test]
async fn await_notified_wakes_after_spawned_notify() -> TestResult {
    let notify = Arc::new(Notify::new());
    let signal = Arc::clone(&notify);
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        signal.notify_one();
    });
    await_notified(&notify, Duration::from_secs(1)).await?;
    Ok(())
}

#[tokio::test]
async fn await_notified_times_out() -> TestResult {
    let notify = Notify::new();
    let result = await_notified(&notify, Duration::from_millis(30)).await;
    let Err(err) = result else {
        return Err("no notify must time out".into());
    };
    match err {
        TestkitError::WaitTimeout { waited_ms } => {
            assert!(
                waited_ms >= 30,
                "waited_ms={waited_ms} should cover the timeout budget"
            );
        }
        other => return Err(format!("expected WaitTimeout, got {other:?}").into()),
    }
    Ok(())
}
