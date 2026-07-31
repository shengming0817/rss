//! 有界等待 helpers：ready-signal 轮询 / Notify 唤醒，以及显式固定延时。
//!
//! # 四类 API
//!
//! | API | 用途 |
//! |-----|------|
//! | [`await_map`] / [`await_map_every`] | `Option<T>` 值携带 ready-signal |
//! | [`await_try`] / [`await_try_every`] | `Result<Option<T>, E>` 值携带 fallible ready-signal |
//! | [`await_notified`] | 有界等待 [`Notify`](tokio::sync::Notify) 唤醒（ready-signal） |
//! | [`await_delay`] | 有界固定等待（显式固定延时 funnel） |
//!
//! ready-signal 超时一律回 [`TestkitError::WaitTimeout`]，不 panic。不导出公开 `sleep` 名字——
//! 内部 poll / delay 仅用模块内短 sleep（带 `rss_test_no_bare_sleep` allow）。
//!
//! # 选用约定
//!
//! - **ready-signal**（标志位 / TCP / 日志 marker）→ 无错误用 [`await_map`]，fallible probe 用
//!   [`await_try`]；Docker / CLI 等重 probe 用对应的 `*_every` 自定义间隔；`Notify` 用
//!   [`await_notified`]。
//! - **固定延时**（确需 sleep 满一段时长）→ **必须** [`await_delay`]。
//! - **禁止** `await_map(timeout, async \|\| None::<()>)` 伪装固定延时：永不就绪只会烧完超时
//!   预算，语义仍是「等条件」，不是合法延时原语。

use std::time::Duration;

use crate::TestkitError;

/// 条件轮询间隔（与 journeys 旧 `wait_until` 同量级）。
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// 有界轮询异步 probe，返回首次产生的值。
///
/// `None` 表示尚未就绪，`Some(value)` 表示就绪并把本次观察值原样返回。probe 与返回值不要求
/// `Send` / `Sync` / `Clone` / `'static`；本函数不 spawn，timeout 会取消并 drop 当前 probe future。
pub async fn await_map<T>(
    timeout: Duration,
    probe: impl AsyncFnMut() -> Option<T>,
) -> Result<T, TestkitError> {
    await_map_every(timeout, POLL_INTERVAL, probe).await
}

/// 同 [`await_map`]，但允许自定义 poll 间隔。
pub async fn await_map_every<T>(
    timeout: Duration,
    interval: Duration,
    mut probe: impl AsyncFnMut() -> Option<T>,
) -> Result<T, TestkitError> {
    await_try_every(timeout, interval, async || {
        Ok::<Option<T>, TestkitError>(probe().await)
    })
    .await
}

/// 有界轮询 fallible 异步 probe，返回首次产生的值或首次 fatal error。
///
/// - `Ok(None)`：尚未就绪，间隔后重试；
/// - `Ok(Some(value))`：就绪，返回本次观察值；
/// - `Err(error)`：fatal，立即原样传播。
///
/// timeout 转为 [`TestkitError::WaitTimeout`] 后经 `E::from` 进入调用方错误类型。
pub async fn await_try<T, E>(
    timeout: Duration,
    probe: impl AsyncFnMut() -> Result<Option<T>, E>,
) -> Result<T, E>
where
    E: From<TestkitError>,
{
    await_try_every(timeout, POLL_INTERVAL, probe).await
}

/// 同 [`await_try`]，但允许自定义 poll 间隔。
pub async fn await_try_every<T, E>(
    timeout: Duration,
    interval: Duration,
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
            poll_sleep(interval).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(E::from(wait_timeout(timeout))),
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
/// 这是测试里**唯一**合法的固定延时 funnel。需要 ready-signal 时请用 [`await_map`] /
/// [`await_try`] / [`await_notified`]，不要用本 API 伪装轮询。
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
