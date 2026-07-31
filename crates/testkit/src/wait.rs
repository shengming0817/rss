//! 有界等待 helpers：ready-signal 轮询 / Notify 唤醒，以及显式固定延时。
//!
//! # 四 API
//!
//! | API | 用途 |
//! |-----|------|
//! | [`await_condition`] | 同步谓词有界轮询（ready-signal） |
//! | [`await_condition_async`] | 异步谓词有界轮询（ready-signal） |
//! | [`await_notified`] | 有界等待 [`Notify`](tokio::sync::Notify) 唤醒（ready-signal） |
//! | [`await_delay`] | 有界固定等待（显式固定延时 funnel） |
//!
//! ready-signal 超时一律回 [`TestkitError::WaitTimeout`]，不 panic。不导出公开 `sleep` 名字——
//! 内部 poll / delay 仅用模块内短 sleep（带 `rss_test_no_bare_sleep` allow）。
//!
//! # 选用约定
//!
//! - **ready-signal**（标志位 / TCP / 日志 marker / `Notify`）→ [`await_condition`] /
//!   [`await_condition_async`] / [`await_notified`]。
//! - **固定延时**（确需 sleep 满一段时长）→ **必须** [`await_delay`]。
//! - **禁止** `await_condition(timeout, \|\| false)` /
//!   `await_condition_async(..., \|\| async { false })` 伪装固定延时：谓词永不成立只会烧完超时
//!   预算，语义仍是「等条件」，不是合法延时原语。

use std::future::Future;
use std::time::Duration;

use crate::TestkitError;

/// 条件轮询间隔（与 journeys 旧 `wait_until` 同量级）。
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 有界轮询直至同步谓词为真；超时返回 [`TestkitError::WaitTimeout`]。
pub async fn await_condition(
    timeout: Duration,
    mut pred: impl FnMut() -> bool,
) -> Result<(), TestkitError> {
    match tokio::time::timeout(timeout, async {
        loop {
            if pred() {
                return;
            }
            poll_sleep(POLL_INTERVAL).await;
        }
    })
    .await
    {
        Ok(()) => Ok(()),
        Err(_) => Err(wait_timeout(timeout)),
    }
}

/// 有界轮询直至异步谓词为真；超时返回 [`TestkitError::WaitTimeout`]。
pub async fn await_condition_async<F, Fut>(timeout: Duration, pred: F) -> Result<(), TestkitError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    await_condition_async_every(timeout, POLL_INTERVAL, pred).await
}

/// 同 [`await_condition_async`]，但允许自定义 poll 间隔。
///
/// journeys / 重探活若需长间隔（避免默认 5ms 打爆 docker CLI）用本入口；
/// rabbitmqctl / vault / mosquitto 控制面重试走 attempts + [`await_delay`]，不把 exec I/O 计入 timeout。
pub async fn await_condition_async_every<F, Fut>(
    timeout: Duration,
    interval: Duration,
    mut pred: F,
) -> Result<(), TestkitError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    match tokio::time::timeout(timeout, async {
        loop {
            if pred().await {
                return;
            }
            poll_sleep(interval).await;
        }
    })
    .await
    {
        Ok(()) => Ok(()),
        Err(_) => Err(wait_timeout(timeout)),
    }
}

/// 有界等待 [`Notify`](tokio::sync::Notify) 唤醒；超时返回 [`TestkitError::WaitTimeout`]。
///
/// 须在本函数已订阅后发出 notify（例如 `spawn` 延后 `notify_one`）；先 notify 再调用可能丢信号。
pub async fn await_notified(
    notify: &tokio::sync::Notify,
    timeout: Duration,
) -> Result<(), TestkitError> {
    match tokio::time::timeout(timeout, notify.notified()).await {
        Ok(()) => Ok(()),
        Err(_) => Err(wait_timeout(timeout)),
    }
}

/// 有界固定等待：sleep 满 `duration` 后返回。
///
/// 这是测试里**唯一**合法的固定延时 funnel。需要 ready-signal 时请用 [`await_condition`] /
/// [`await_condition_async`] / [`await_notified`]，不要用本 API 伪装轮询。
///
/// 被 cancel（task abort / drop）时不会返回；正常跑完即返回（与 [`TestkitError::WaitTimeout`] 无关）。
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
