//! testkit `wait` 模块自测：有界条件轮询、固定延时与 Notify 唤醒。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;

use testkit::{TestkitError, await_condition, await_condition_async, await_delay, await_notified};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn await_condition_succeeds_immediately() -> TestResult {
    await_condition(Duration::from_secs(1), || true).await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn await_condition_polls_until_predicate_true() -> TestResult {
    // 先假后真：至少一次 false → poll_sleep → 再 true，锁同步轮询路径。
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    await_condition(Duration::from_secs(1), move || {
        counter.fetch_add(1, Ordering::SeqCst) >= 1
    })
    .await?;
    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "predicate must run again after an initial false (poll sleep path)"
    );
    Ok(())
}

#[tokio::test]
async fn await_condition_times_out() -> TestResult {
    let err = await_condition(Duration::from_millis(30), || false)
        .await
        .expect_err("predicate never true must time out");
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

#[tokio::test]
async fn await_condition_async_succeeds() -> TestResult {
    let ready = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ready);
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        flag.store(true, Ordering::SeqCst);
    });
    await_condition_async(Duration::from_secs(1), || {
        let ready = Arc::clone(&ready);
        async move { ready.load(Ordering::SeqCst) }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn await_condition_async_times_out() -> TestResult {
    let err = await_condition_async(Duration::from_millis(30), || async { false })
        .await
        .expect_err("async predicate never true must time out");
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
    let err = await_notified(&notify, Duration::from_millis(30))
        .await
        .expect_err("no notify must time out");
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
