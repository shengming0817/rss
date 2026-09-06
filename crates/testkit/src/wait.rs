//! Bounded fallible readiness probes and fixed delays.
//! Probe errors propagate immediately; the total timeout drops any inflight probe future.

use std::time::Duration;

use crate::TestkitError;

/// Interval between readiness observations.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 有界轮询 fallible 异步 probe，返回首次产生的值或首次 fatal error。
///
/// - `Ok(None)`：尚未就绪，间隔后重试；
/// - `Ok(Some(value))`：就绪，返回本次观察值；
/// - `Err(error)`：fatal，立即原样传播。
///
/// timeout 转为 [`TestkitError::WaitTimeout`] 后经 `E::from` 进入调用方错误类型。
pub async fn await_try<T, E>(
    timeout: Duration,
    mut probe: impl AsyncFnMut() -> Result<Option<T>, E>,
) -> Result<T, E>
where
    E: From<TestkitError>,
{
    match tokio::time::timeout(timeout, async {
        loop {
            if let Some(value) = probe().await? {
                return Ok(value);
            }
            poll_sleep(POLL_INTERVAL).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(E::from(wait_timeout(timeout))),
    }
}

/// Wait for the requested duration. Dropping the future cancels the delay.
/// Use [`await_try`] for readiness; a fixed delay does not prove a condition became true.
pub async fn await_delay(duration: Duration) {
    poll_sleep(duration).await;
}

fn wait_timeout(timeout: Duration) -> TestkitError {
    TestkitError::WaitTimeout {
        waited_ms: duration_ms(timeout),
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[allow(unknown_lints, rss_test_no_bare_sleep)]
async fn poll_sleep(interval: Duration) {
    tokio::time::sleep(interval).await;
}
