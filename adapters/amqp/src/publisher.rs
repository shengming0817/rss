//! lapin AMQP 发布 adapter——impl `diport::Publisher` + `diport::ManagedResource`。
//!
//! ref: lapin examples/pubsub.rs@main（basic_publish 默认 exchange + routing key=topic + 双 await confirm）。

use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use diport::{
    EnvelopeMetadata, KEY_OCCURRED_AT, ManagedResource, PublishRequest, Publisher, PublisherError,
    ShutdownError,
};
use lapin::options::BasicPublishOptions;
use lapin::protocol::{AMQPErrorKind, AMQPSoftError};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{BasicProperties, Channel, Connection, ErrorKind};
use tokio::task::JoinHandle;

use crate::conn::{self, REPLY_SUCCESS};

/// 与 `eventexec::RELAY_BUDGET_MAX_MILLIS` 和 PostgreSQL 0062 对齐的 adapter 二次防线。
const MAX_PUBLISH_TIMEOUT_MILLIS: u64 = 86_400_000;

/// envelope metadata → [`BasicProperties`]：`event_id` 盖 `message_id`（去重锚点）；`occurred_at`
/// 独占 AMQP typed `timestamp`（unix 秒 u64），不再重复进 headers；其余 pair 进 `FieldTable` LongString。
///
/// 纯函数——无 broker 依赖；integration-gated（lapin 类型只在 integration feature 链接）。
fn build_properties(event_id: &str, md: &EnvelopeMetadata) -> BasicProperties {
    let props = BasicProperties::default().with_message_id(event_id.into());
    // occurred_at 用 AMQP 原生 timestamp 字段（u64），不重复进 headers（避免双写歧义）。
    // wire metadata bag 是 public scalar——畸形负值（epoch 前，理论不可达但 bag 可携）经 `u64::try_from`
    // fail-closed 跳过 timestamp，不 `as u64` wrap 成超大值（不依赖 producer 非负保证；F3 review）。
    let props = match md
        .occurred_at_secs()
        .and_then(|secs| u64::try_from(secs).ok())
    {
        Some(ts) => props.with_timestamp(ts),
        None => props,
    };
    let mut table = FieldTable::default();
    for (k, v) in md.iter_transport_headers() {
        if k == KEY_OCCURRED_AT {
            // occurred_at 已进 timestamp 字段，不重复入 headers。
            continue;
        }
        table.insert(
            k.into(),
            AMQPValue::LongString(v.as_bytes().to_vec().into()),
        );
    }
    if table.inner().is_empty() {
        props
    } else {
        props.with_headers(table)
    }
}

/// publish 被 broker 拒绝（durable publish-ok 语义失败）。internal source（不进 Display 凭据边界）。
#[derive(Debug, thiserror::Error)]
enum PublishRejected {
    /// broker nack（队列错误 / 资源不足等）。
    #[error("amqp broker nacked the message")]
    Nack,
    /// 消息不可路由（mandatory=true 下无绑定 queue，被 broker 退回）。
    #[error("amqp message was unroutable (no bound queue)")]
    Unroutable,
}

/// AMQP 发布流水线所处阶段。仅进入低基数审计字段，不携 routing key / event id。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishPhase {
    BasicPublish,
    Confirm,
}

impl PublishPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BasicPublish => "basic_publish",
            Self::Confirm => "confirm",
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::BasicPublish => 0,
            Self::Confirm => 1,
        }
    }

    const fn from_u8(value: u8) -> Self {
        if value == Self::Confirm.as_u8() {
            Self::Confirm
        } else {
            Self::BasicPublish
        }
    }
}

/// 单一共享 deadline 已耗尽。Display 固定，不携 endpoint、请求或第三方错误链。
#[derive(Debug, thiserror::Error)]
#[error("amqp publish deadline elapsed")]
struct PublishDeadlineElapsed {
    phase: PublishPhase,
}

#[derive(Debug)]
enum PublishPipelineError<E> {
    Client(E),
    Deadline(PublishDeadlineElapsed),
}

impl<E> PublishPipelineError<E> {
    #[cfg(test)]
    fn timeout_phase(&self) -> Option<PublishPhase> {
        match self {
            Self::Client(_) => None,
            Self::Deadline(elapsed) => Some(elapsed.phase),
        }
    }
}

/// 用**一个** Tokio deadline 覆盖 `basic_publish` 与 `PublisherConfirm` 两次 await。
///
/// helper 保持 adapter-private 且只抽象 future，不引入 mock trait/公共 provider 抽象。第一阶段完成后仅
/// 切换审计 phase；第二阶段继续消费同一个 timeout 的剩余预算。
async fn run_publish_pipeline<PublishFuture, ConfirmFactory, ConfirmFuture, PendingConfirm, T, E>(
    publish_timeout: Duration,
    basic_publish: PublishFuture,
    confirm: ConfirmFactory,
) -> Result<T, PublishPipelineError<E>>
where
    PublishFuture: Future<Output = Result<PendingConfirm, E>>,
    ConfirmFactory: FnOnce(PendingConfirm) -> ConfirmFuture,
    ConfirmFuture: Future<Output = Result<T, E>>,
{
    let phase = AtomicU8::new(PublishPhase::BasicPublish.as_u8());
    let result = tokio::time::timeout(publish_timeout, async {
        let pending = basic_publish.await.map_err(PublishPipelineError::Client)?;
        phase.store(PublishPhase::Confirm.as_u8(), Ordering::Relaxed);
        confirm(pending).await.map_err(PublishPipelineError::Client)
    })
    .await;

    match result {
        Ok(result) => result,
        Err(_) => Err(PublishPipelineError::Deadline(PublishDeadlineElapsed {
            phase: PublishPhase::from_u8(phase.load(Ordering::Relaxed)),
        })),
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum PublishTimeoutConfigError {
    #[error("publish timeout must be non-zero")]
    Zero,
    #[error("publish timeout must be an integral number of milliseconds")]
    NonIntegralMilliseconds,
    #[error("publish timeout exceeds operational maximum {max_millis}ms")]
    OperationalRangeExceeded { max_millis: u64 },
}

fn validate_publish_timeout(timeout: Duration) -> Result<(), PublishTimeoutConfigError> {
    if timeout.is_zero() {
        return Err(PublishTimeoutConfigError::Zero);
    }
    if !timeout.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(PublishTimeoutConfigError::NonIntegralMilliseconds);
    }
    if timeout.as_millis() > u128::from(MAX_PUBLISH_TIMEOUT_MILLIS) {
        return Err(PublishTimeoutConfigError::OperationalRangeExceeded {
            max_millis: MAX_PUBLISH_TIMEOUT_MILLIS,
        });
    }
    Ok(())
}

/// 一次 publish 对当前 confirm channel 的短生命周期快照。
///
/// generation 让 timeout 只能退休自己实际使用的 channel；若并发 recovery 已安装 replacement，stale
/// timeout 的 CAS 会失败，不能误伤新 channel。
#[derive(Clone)]
struct ChannelSnapshot<C> {
    generation: u64,
    channel: C,
}

/// 单次 channel recovery 的所有权凭证。只有成功将 `Ready(generation)` 转为 `Recovering` 的首个
/// timeout 能取得它，故并发 timeout 不会重复 drain/close/rotate 同一 channel。
struct ChannelRecovery<C> {
    generation: u64,
    retiring: Option<C>,
}

/// confirm channel 的 adapter-private 生命周期。
///
/// `Recovering` 不提供 snapshot，类型状态保证旧 channel 一旦退休便不可再接收新 publish。`Unavailable`
/// 允许下一次 publish 触发一次无旧资源的 single-flight rebuild；调用本身仍 fail-fast transient。
enum ChannelSlot<C> {
    Ready {
        generation: u64,
        channel: C,
    },
    Recovering {
        generation: u64,
        retiring: Option<C>,
    },
    Unavailable {
        generation: u64,
    },
    ShuttingDown,
}

impl<C> ChannelSlot<C>
where
    C: Clone,
{
    fn ready(channel: C) -> Self {
        Self::Ready {
            generation: 0,
            channel,
        }
    }

    fn snapshot(&self) -> Result<ChannelSnapshot<C>, PublisherChannelError> {
        match self {
            Self::Ready {
                generation,
                channel,
            } => Ok(ChannelSnapshot {
                generation: *generation,
                channel: channel.clone(),
            }),
            Self::Recovering { .. } => Err(PublisherChannelError::Recovering),
            Self::Unavailable { .. } => Err(PublisherChannelError::Unavailable),
            Self::ShuttingDown => Err(PublisherChannelError::ShuttingDown),
        }
    }

    fn begin_timeout_recovery(&mut self, expected_generation: u64) -> Option<ChannelRecovery<C>> {
        let (generation, retiring) = match self {
            Self::Ready {
                generation,
                channel,
            } if *generation == expected_generation => (*generation, channel.clone()),
            _ => return None,
        };
        self.clone_into_recovering(generation, Some(retiring.clone()));
        Some(ChannelRecovery {
            generation,
            retiring: Some(retiring),
        })
    }

    fn begin_unavailable_recovery(&mut self) -> Option<ChannelRecovery<C>> {
        let generation = match self {
            Self::Unavailable { generation } => *generation,
            _ => return None,
        };
        self.clone_into_recovering(generation, None);
        Some(ChannelRecovery {
            generation,
            retiring: None,
        })
    }

    fn clone_into_recovering(&mut self, generation: u64, retiring: Option<C>) {
        *self = Self::Recovering {
            generation,
            retiring,
        };
    }

    fn install_replacement(&mut self, recovery_generation: u64, channel: C) -> bool {
        let Self::Recovering { generation, .. } = self else {
            return false;
        };
        if *generation != recovery_generation {
            return false;
        }
        let Some(next_generation) = generation.checked_add(1) else {
            *self = Self::Unavailable {
                generation: *generation,
            };
            return false;
        };
        *self = Self::Ready {
            generation: next_generation,
            channel,
        };
        true
    }

    fn fail_recovery(&mut self, recovery_generation: u64) {
        if matches!(self, Self::Recovering { generation, .. } if *generation == recovery_generation)
        {
            *self = Self::Unavailable {
                generation: recovery_generation,
            };
        }
    }

    fn begin_shutdown(&mut self) -> Option<C> {
        let retiring = match self {
            Self::Ready { channel, .. } => Some(channel.clone()),
            Self::Recovering { retiring, .. } => retiring.clone(),
            Self::Unavailable { .. } | Self::ShuttingDown => None,
        };
        *self = Self::ShuttingDown;
        retiring
    }
}

struct PublisherChannelLifecycle {
    slot: ChannelSlot<Channel>,
    recovery: Option<JoinHandle<()>>,
}

impl PublisherChannelLifecycle {
    fn new(channel: Channel) -> Self {
        Self {
            slot: ChannelSlot::ready(channel),
            recovery: None,
        }
    }
}

/// 固定安全摘要；不携 endpoint、event、payload 或 lapin 原始错误链。
#[derive(Debug, thiserror::Error)]
enum PublisherChannelError {
    #[error("amqp publisher channel is recovering")]
    Recovering,
    #[error("amqp publisher channel is unavailable")]
    Unavailable,
    #[error("amqp publisher is shutting down")]
    ShuttingDown,
    #[error("amqp publisher channel state is poisoned")]
    StatePoisoned,
    #[error("amqp publisher channel close failed")]
    Close(#[source] lapin::Error),
}

/// `lapin::Error` → [`PublisherError`]，按瞬态/永久分类（#1212：永久错误首投即 DLX，不熬满重试预算）。
///
/// 分类策略（ref: amqp-rs/lapin src/error.rs@v4.10.0 `Error::can_be_recovered`）：
/// - **AMQP soft（channel-level）非自愈错误** → permanent：重试同一消息必然再失败（权限拒绝、声明参数冲突、
///   消息超限——非启动时序问题），见 [`is_permanent_soft_error`]。
/// - 其余按 lapin 内建 `can_be_recovered()` 兜底：可恢复（IOError / channel·connection state /
///   MissingHeartbeat / hard ProtocolError / **路由目标尚未声明类 soft 错误 NOROUTE·NOTFOUND**）→ **transient**
///   退避重连/等拓扑收敛；不可恢复（SerialisationError / ParsingError / InvalidProtocolVersion /
///   AuthProviderError / ChannelsLimitReached / ...）→ **permanent**。`ErrorKind` 是 `#[non_exhaustive]`——
///   `can_be_recovered()` 兜底，无需在此穷尽 match。
///
/// **default-transient 取向（review #278 F1）**：「路由目标当前不存在」（NOROUTE/NOTFOUND/`basic.return`
/// unroutable）**不**判永久——AMQP queue 由 `AmqpSubscriber::subscribe_ackable` 声明、无组合根级硬屏障保证
/// relay 发布前队列已就绪，启动/重启窗口的 unroutable 可经退避重试等订阅完成收敛。瞬态误判永久会跳过 outbox
/// 自愈、破坏 L2 最终送达（代价高于「永久错误慢 DLX」）。彻底解（启动期声明 active subscriber 队列 + relay
/// readiness 屏障 / topology provisioning port）属组合根，OOS follow-up。
fn classify_publish(e: lapin::Error) -> PublisherError {
    if is_permanent_lapin(&e) {
        PublisherError::permanent(e)
    } else {
        PublisherError::transient(e)
    }
}

/// 该 lapin 错误是否永久（重试同一消息必然再失败）。
fn is_permanent_lapin(e: &lapin::Error) -> bool {
    if let ErrorKind::ProtocolError(amqp) = e.kind()
        && let AMQPErrorKind::Soft(soft) = amqp.kind()
        && is_permanent_soft_error(soft)
    {
        return true;
    }
    !e.can_be_recovered()
}

/// AMQP soft（channel-level）错误中「重试同一消息必然再失败」的**非自愈**类——首投即 DLX。
///
/// 仅含 message/config-intrinsic 因（权限 / 声明参数冲突 / 消息超限）：退避重试同一消息不会改变结果。
/// **不含**「路由目标尚未声明」类（NOROUTE / NOTFOUND）与「可随生命周期自愈」类（NOCONSUMERS 消费者上线 /
/// RESOURCELOCKED 锁释放）——后者归 transient，由 [`classify_publish`] 的 `can_be_recovered()` 兜底（review
/// #278 F1：拓扑/路由尚未收敛 ≠ 永久非法）。
fn is_permanent_soft_error(soft: &AMQPSoftError) -> bool {
    matches!(
        soft,
        AMQPSoftError::ACCESSREFUSED        // 403 权限拒绝（ACL 非启动时序问题）
            | AMQPSoftError::PRECONDITIONFAILED // 406 声明参数冲突
            | AMQPSoftError::CONTENTTOOLARGE // 311 消息超 broker 限制（消息固有）
    )
}

/// AMQP 事件发布 adapter（lapin）。raw client（`Arc<Connection>` + `Channel`）**私有**——仅本 adapter
/// 内部（publish / shutdown）使用，不向 crate 内其它模块暴露 raw 连接。
/// 同时 impl `Publisher` 与 `ManagedResource`（各有 `shutdown`）；消费经 `DynPublisher` /
/// `Box<DynManagedResource>` 无歧义，直接操作 raw struct 时用 UFCS 消歧。
pub struct AmqpPublisher {
    conn: Arc<Connection>,
    channels: Arc<Mutex<PublisherChannelLifecycle>>,
    name: String,
    publish_timeout: Duration,
}

impl AmqpPublisher {
    /// 从单个 per-domain AMQP URL 连接（URL 含 `user:pass@host/vhost`）。`name` 是 `ManagedResource`
    /// 可读名（kebab/snake 稳定标识）。`publish_timeout` 在任何网络连接前再次校验非零、整毫秒且可由
    /// 数据库/审计 `i64` 表示；连接失败日志只经 redaction funnel，URL 原文绝不进日志。
    pub async fn connect(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
        publish_timeout: Duration,
    ) -> Result<Self, conn::AmqpConnectError> {
        validate_publish_timeout(publish_timeout).map_err(|_| conn::invalid_publisher_timeout())?;
        let name = name.into();
        // confirm=true：启用 publisher confirms，使 publish 能检测 broker ack/nack（durable publish-ok）。
        let (conn, channel) = conn::connect(endpoint, &name, true).await?;
        Ok(Self {
            conn,
            channels: Arc::new(Mutex::new(PublisherChannelLifecycle::new(channel))),
            name,
            publish_timeout,
        })
    }

    fn lock_channels(
        &self,
    ) -> Result<MutexGuard<'_, PublisherChannelLifecycle>, PublisherChannelError> {
        self.channels
            .lock()
            .map_err(|_| PublisherChannelError::StatePoisoned)
    }

    /// 正常路径只在 std mutex 下 clone 当前 `(generation, Channel)`，不跨 broker await 持锁，故并发 publish
    /// 不会被整次串行化。Unavailable 的首次 caller 只触发 single-flight rebuild，自身仍 fail-fast。
    fn channel_snapshot(&self) -> Result<ChannelSnapshot<Channel>, PublisherChannelError> {
        let mut lifecycle = self.lock_channels()?;
        match lifecycle.slot.snapshot() {
            Ok(snapshot) => Ok(snapshot),
            Err(PublisherChannelError::Unavailable) => {
                if let Some(recovery) = lifecycle.slot.begin_unavailable_recovery() {
                    self.spawn_channel_recovery(&mut lifecycle, recovery);
                }
                Err(PublisherChannelError::Unavailable)
            }
            Err(error) => Err(error),
        }
    }

    /// timeout 以 snapshot generation 做 CAS；只有首个 timeout 能把 Ready 转为 Recovering 并 spawn cleanup。
    fn retire_timed_out_channel(&self, generation: u64) {
        let Ok(mut lifecycle) = self.lock_channels() else {
            tracing::error!(target: "amqp", resource = %self.name, "amqp publisher channel state poisoned");
            return;
        };
        if let Some(recovery) = lifecycle.slot.begin_timeout_recovery(generation) {
            self.spawn_channel_recovery(&mut lifecycle, recovery);
        }
    }

    fn spawn_channel_recovery(
        &self,
        lifecycle: &mut PublisherChannelLifecycle,
        recovery: ChannelRecovery<Channel>,
    ) {
        if let Some(previous) = lifecycle.recovery.take()
            && !previous.is_finished()
        {
            // 只能命中「上一 task 已把状态落为 Unavailable、尚未 return」的窄窗口。abort 保 single-flight；
            // 上一 task 不再持 retiring 的唯一句柄，slot/connection 仍是资源收口真源。
            previous.abort();
        }
        lifecycle.recovery = Some(tokio::spawn(run_channel_recovery(
            Arc::clone(&self.conn),
            Arc::clone(&self.channels),
            self.name.clone(),
            self.publish_timeout,
            recovery,
        )));
    }

    async fn shutdown_channels(&self) -> Result<(), PublisherChannelError> {
        let (recovery, channel) = {
            let mut lifecycle = self.lock_channels()?;
            let channel = lifecycle.slot.begin_shutdown();
            (lifecycle.recovery.take(), channel)
        };
        if let Some(recovery) = recovery {
            recovery.abort();
            let _ = recovery.await;
        }
        if let Some(channel) = channel
            && channel.status().connected()
        {
            channel
                .close(REPLY_SUCCESS, "publisher shutdown".into())
                .await
                .map_err(PublisherChannelError::Close)?;
        }
        Ok(())
    }
}

/// timeout 后的资源恢复在 owned task 中执行，避免 Postgres 外层 publisher watchdog drop caller 时把 cleanup
/// 一并取消。一个 lifecycle 同时至多保存一个 task；Recovering 期间 caller fail-fast，不会继续向 retiring
/// channel 注册 confirm。
#[allow(clippy::cognitive_complexity)]
// reason: 实际分支仅 replacement 成功/失败与 lifecycle lock 成功/失败；tracing 宏展开抬高认知复杂度。
async fn run_channel_recovery(
    conn: Arc<Connection>,
    channels: Arc<Mutex<PublisherChannelLifecycle>>,
    name: String,
    operation_timeout: Duration,
    recovery: ChannelRecovery<Channel>,
) {
    let generation = recovery.generation;
    let Some(replacement) =
        recover_confirm_channel(conn.as_ref(), recovery.retiring, &name, operation_timeout).await
    else {
        match channels.lock() {
            Ok(mut lifecycle) => lifecycle.slot.fail_recovery(generation),
            Err(_) => {
                tracing::error!(target: "amqp", resource = %name, "amqp publisher channel state poisoned")
            }
        }
        return;
    };

    let installed = match channels.lock() {
        Ok(mut lifecycle) => lifecycle
            .slot
            .install_replacement(generation, replacement.clone()),
        Err(_) => {
            tracing::error!(target: "amqp", resource = %name, "amqp publisher channel state poisoned");
            false
        }
    };
    if installed {
        tracing::info!(
            target: "amqp",
            resource = %name,
            channel_generation = generation.saturating_add(1),
            "amqp publisher confirm channel rotated",
        );
    } else {
        // shutdown 或另一代 recovery 已先完成：replacement 不能成为无主可发布 channel。
        close_channel_bounded(&replacement, operation_timeout, &name, "orphan_replacement").await;
    }
}

#[derive(Debug)]
enum RecoveryStageError<E> {
    Client(E),
    Deadline,
}

struct ConfirmChannelRecoveryResult<T, E> {
    drain: Option<Result<(), RecoveryStageError<E>>>,
    close: Option<Result<(), RecoveryStageError<E>>>,
    replacement: Result<T, RecoveryStageError<E>>,
}

/// 用一个 absolute recovery deadline 覆盖 drain → close → replacement create。
///
/// 有 retiring channel 时，前 1/3 给 drain、第二个 1/3 给 close、最后 1/3 给 create；每个阶段使用从
/// 同一 start 派生的 `timeout_at`，前一阶段耗时会从后续可用 wall-clock 中扣除。无 retiring channel 时，
/// create 可使用完整 budget。无论哪个 future 半开，整条 pipeline 都不会超过 `operation_timeout`。
#[allow(clippy::disallowed_methods)]
// reason: adapter-private Tokio I/O absolute deadline；不表达业务时间，且必须与 timeout_at 使用同一 monotonic clock。
async fn run_confirm_channel_recovery_pipeline<
    Drain,
    DrainOutput,
    Close,
    CloseOutput,
    Create,
    T,
    E,
>(
    operation_timeout: Duration,
    has_retiring: bool,
    drain: Drain,
    close: Close,
    create: Create,
) -> ConfirmChannelRecoveryResult<T, E>
where
    Drain: Future<Output = Result<DrainOutput, E>>,
    Close: Future<Output = Result<CloseOutput, E>>,
    Create: Future<Output = Result<T, E>>,
{
    let started = tokio::time::Instant::now();
    let recovery_deadline = started + operation_timeout;
    let (drain, close) = if has_retiring {
        let cleanup_stage = operation_timeout / 3;
        let drain_deadline = started + cleanup_stage;
        let close_deadline = drain_deadline + cleanup_stage;
        (
            Some(
                run_recovery_stage_at(drain_deadline, drain)
                    .await
                    .map(|_| ()),
            ),
            Some(
                run_recovery_stage_at(close_deadline, close)
                    .await
                    .map(|_| ()),
            ),
        )
    } else {
        (None, None)
    };
    let replacement = run_recovery_stage_at(recovery_deadline, create).await;
    ConfirmChannelRecoveryResult {
        drain,
        close,
        replacement,
    }
}

async fn run_recovery_stage_at<F, T, E>(
    deadline: tokio::time::Instant,
    future: F,
) -> Result<T, RecoveryStageError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout_at(deadline, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(RecoveryStageError::Client(error)),
        Err(_) => Err(RecoveryStageError::Deadline),
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: drain/close/create 三阶段各自需安全审计；复杂度主要来自 tracing 宏展开。
async fn recover_confirm_channel(
    conn: &Connection,
    retiring: Option<Channel>,
    name: &str,
    operation_timeout: Duration,
) -> Option<Channel> {
    let has_retiring = retiring.is_some();
    let result = run_confirm_channel_recovery_pipeline(
        operation_timeout,
        has_retiring,
        async {
            match retiring.as_ref() {
                Some(channel) => channel.wait_for_confirms().await.map(|_| ()),
                None => Ok(()),
            }
        },
        async {
            match retiring.as_ref() {
                Some(channel) if channel.status().connected() => {
                    channel
                        .close(REPLY_SUCCESS, "publisher channel rotation".into())
                        .await
                }
                Some(_) | None => Ok(()),
            }
        },
        conn::confirmed_channel(conn),
    )
    .await;

    match result.drain {
        None | Some(Ok(())) => {}
        Some(Err(RecoveryStageError::Client(error))) => tracing::warn!(
            target: "amqp",
            resource = %name,
            phase = "confirm_cleanup",
            error = %secure::redact_error(&error),
            "amqp timed-out confirm drain failed",
        ),
        Some(Err(RecoveryStageError::Deadline)) => tracing::warn!(
            target: "amqp",
            resource = %name,
            phase = "confirm_cleanup",
            publish_timeout_ms = operation_timeout.as_millis() as i64,
            delivery_outcome = "unknown",
            broker_may_have_received = true,
            "amqp timed-out confirm drain deadline elapsed",
        ),
    }
    match result.close {
        None | Some(Ok(())) => {}
        Some(Err(RecoveryStageError::Client(error))) => tracing::warn!(
            target: "amqp",
            resource = %name,
            phase = "retiring_channel",
            error = %secure::redact_error(&error),
            "amqp publisher retiring channel close failed",
        ),
        Some(Err(RecoveryStageError::Deadline)) => tracing::warn!(
            target: "amqp",
            resource = %name,
            phase = "retiring_channel",
            publish_timeout_ms = operation_timeout.as_millis() as i64,
            delivery_outcome = "unknown",
            broker_may_have_received = true,
            "amqp publisher retiring channel close deadline elapsed",
        ),
    }
    match result.replacement {
        Ok(channel) => Some(channel),
        Err(RecoveryStageError::Client(error)) => {
            tracing::warn!(
                target: "amqp",
                resource = %name,
                phase = "channel_rebuild",
                error = %secure::redact_error(&error),
                "amqp publisher confirm channel rebuild failed",
            );
            None
        }
        Err(RecoveryStageError::Deadline) => {
            tracing::warn!(
                target: "amqp",
                resource = %name,
                phase = "channel_rebuild",
                publish_timeout_ms = operation_timeout.as_millis() as i64,
                delivery_outcome = "unknown",
                broker_may_have_received = true,
                "amqp publisher confirm channel rebuild deadline elapsed",
            );
            None
        }
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: close 成功/client error/deadline 三态需独立安全审计；复杂度主要来自 tracing 宏展开。
#[allow(clippy::disallowed_methods)]
// reason: orphan channel close 的 Tokio I/O absolute deadline；不表达业务时间。
async fn close_channel_bounded(
    channel: &Channel,
    operation_timeout: Duration,
    name: &str,
    phase: &'static str,
) {
    if !channel.status().connected() {
        return;
    }
    let deadline = tokio::time::Instant::now() + operation_timeout;
    match tokio::time::timeout_at(
        deadline,
        channel.close(REPLY_SUCCESS, "publisher channel rotation".into()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(
            target: "amqp",
            resource = %name,
            phase,
            error = %secure::redact_error(&error),
            "amqp publisher channel close failed",
        ),
        Err(_) => tracing::warn!(
            target: "amqp",
            resource = %name,
            phase,
            publish_timeout_ms = operation_timeout.as_millis() as i64,
            delivery_outcome = "unknown",
            broker_may_have_received = true,
            "amqp publisher channel close deadline elapsed",
        ),
    }
}

impl Publisher for AmqpPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        let channel = self.channel_snapshot().map_err(PublisherError::transient)?;
        // 默认 exchange（""）+ routing key = topic：消息路由到同名 queue（consumer 声明）。
        // per-domain 隔离经 vhost（连接 URL），非 exchange 命名。
        // mandatory=true + publisher confirms：不可路由（无绑定 queue）消息被 broker **退回**而非静默丢弃，
        // 经 confirm 检测为失败——durable publish-ok 语义闭合（不再依赖「subscriber 先启动」运行顺序约定）。
        // message_id = event_id（去重锚点）：经 broker envelope 流到订阅侧 `Message.id`（subscriber 的
        // `pick_message_id` 优先读 message_id 再回退 delivery_tag），实现跨进程「至少一次 + 幂等去重」。
        // envelope metadata 透传：occurred_at → AMQP timestamp；其余 → FieldTable LongString headers。
        let event_id = request.event_id().as_str().to_string();
        let topic = request.topic().as_str().to_string();
        let properties = build_properties(&event_id, request.metadata());
        // into_payload()：move payload 出 request（event_id / topic / metadata 已借用完毕）。
        let payload = request.into_payload();
        let confirmation = run_publish_pipeline(
            self.publish_timeout,
            channel.channel.basic_publish(
                "".into(),
                topic.into(),
                BasicPublishOptions {
                    mandatory: true,
                    ..Default::default()
                },
                &payload,
                properties,
            ),
            // confirm_select 已启用 ⇒ await PublisherConfirm 拿到真实 Ack/Nack/返回消息。
            |pending| pending,
        )
        .await;
        let confirmation = match confirmation {
            Ok(confirmation) => confirmation,
            Err(PublishPipelineError::Client(error)) => return Err(classify_publish(error)),
            Err(PublishPipelineError::Deadline(elapsed)) => {
                // 先以 generation CAS 将 channel 置 Recovering，再返回 transient。cleanup 持有 owned task，
                // 不会被 Postgres 外层 publisher watchdog 连带 drop；旧 channel 从此不再产生新 confirm。
                self.retire_timed_out_channel(channel.generation);
                tracing::warn!(
                    target: "amqp",
                    phase = elapsed.phase.as_str(),
                    publish_timeout_ms = self.publish_timeout.as_millis() as i64,
                    delivery_outcome = "unknown",
                    broker_may_have_received = true,
                    "amqp publisher confirm deadline elapsed",
                );
                return Err(PublisherError::transient(elapsed));
            }
        };
        if confirmation.is_nack() {
            // broker nack（队列错误 / 资源压力等）→ transient：退避后可能恢复，不首投即 DLX。
            return Err(PublisherError::transient(PublishRejected::Nack));
        }
        // unroutable（mandatory 退回，无绑定 queue）→ transient（review #278 F1）：queue 由
        // AmqpSubscriber::subscribe_ackable 声明、无组合根级硬屏障保证 relay 发布前队列已就绪，启动/重启窗口
        // 「当前无绑定 queue」可经退避重试等订阅完成收敛。判永久会跳过 outbox 自愈、破坏 L2 最终送达——「路由
        // 目标当前不存在」≠ 永久非法（RabbitMQ basic.return 语义；与 NOROUTE/NOTFOUND 一致归 transient）。
        if confirmation.take_message().is_some() {
            return Err(PublisherError::transient(PublishRejected::Unroutable));
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // port-local 先停止 owned recovery，再关当前/retiring channel；connection 仍由 ManagedResource 关。
        self.shutdown_channels()
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp channel close error");
            })
            // shutdown 不经 relay settle，kind 无关——transient benign 默认（不夸大为永久）。
            .map_err(PublisherError::transient)
    }
}

impl ManagedResource for AmqpPublisher {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        if let Err(error) = self.shutdown_channels().await {
            // 即使 channel 状态损坏/关闭失败，也继续关 connection，确保其内部 channels 与 confirms 收口。
            tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(&error), "amqp publisher channel teardown failed");
        }
        self.conn
            .close(REPLY_SUCCESS, "publisher resource shutdown".into())
            .await
            .inspect_err(|e| {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(e), "amqp connection close error");
            })
            .map_err(ShutdownError::new)
    }
}

#[cfg(test)]
mod classify_tests {
    //! #1212 lapin 错误瞬态/永久分类表驱动：永久错误首投即 DLX，瞬态退避重试。无需真实 broker——
    //! 仅构造 `lapin::Error` 值检验分类逻辑（`Error::from(ErrorKind::..)` + `AMQPError::new(..)`）。
    use std::sync::Arc;

    use diport::PublishErrorKind;
    use lapin::ErrorKind;
    use lapin::protocol::{AMQPError, AMQPErrorKind, AMQPHardError, AMQPSoftError};

    use super::{PublishRejected, classify_publish, is_permanent_lapin};

    fn io() -> lapin::Error {
        lapin::Error::from(ErrorKind::IOError(Arc::new(std::io::Error::other("reset"))))
    }
    fn soft(s: AMQPSoftError) -> lapin::Error {
        lapin::Error::from(ErrorKind::ProtocolError(AMQPError::new(
            AMQPErrorKind::Soft(s),
            "test".into(),
        )))
    }
    fn hard(h: AMQPHardError) -> lapin::Error {
        lapin::Error::from(ErrorKind::ProtocolError(AMQPError::new(
            AMQPErrorKind::Hard(h),
            "test".into(),
        )))
    }

    #[test]
    fn classify_table() {
        // (lapin 错误, 期望 permanent?, 标签)
        let cases: Vec<(lapin::Error, bool, &str)> = vec![
            (io(), false, "IOError→transient"),
            (
                lapin::Error::from(ErrorKind::ChannelsLimitReached),
                true,
                "ChannelsLimitReached→permanent",
            ),
            (
                lapin::Error::from(ErrorKind::AuthProviderError("bad".into())),
                true,
                "AuthProviderError→permanent",
            ),
            // 路由目标尚未声明类 → transient（review #278 F1：拓扑未收敛 ≠ 永久非法）。
            (
                soft(AMQPSoftError::NOTFOUND),
                false,
                "soft404 NOTFOUND→transient (target not declared yet)",
            ),
            (
                soft(AMQPSoftError::NOROUTE),
                false,
                "soft312 NOROUTE→transient (no route yet)",
            ),
            // 非自愈类（权限 / 参数 / 大小）→ permanent。
            (
                soft(AMQPSoftError::ACCESSREFUSED),
                true,
                "soft403 ACCESSREFUSED→permanent",
            ),
            (
                soft(AMQPSoftError::PRECONDITIONFAILED),
                true,
                "soft406 PRECONDITIONFAILED→permanent",
            ),
            (
                soft(AMQPSoftError::CONTENTTOOLARGE),
                true,
                "soft311 CONTENTTOOLARGE",
            ),
            (
                soft(AMQPSoftError::NOCONSUMERS),
                false,
                "soft313 NOCONSUMERS→transient",
            ),
            (
                soft(AMQPSoftError::RESOURCELOCKED),
                false,
                "soft405 RESOURCELOCKED→transient",
            ),
            (
                hard(AMQPHardError::CONNECTIONFORCED),
                false,
                "hard320 CONNECTIONFORCED→transient",
            ),
            (
                hard(AMQPHardError::RESOURCEERROR),
                false,
                "hard506 RESOURCEERROR→transient",
            ),
        ];
        for (err, want_permanent, label) in cases {
            assert_eq!(
                is_permanent_lapin(&err),
                want_permanent,
                "is_permanent_lapin: {label}"
            );
            let want = if want_permanent {
                PublishErrorKind::Permanent
            } else {
                PublishErrorKind::Transient
            };
            assert_eq!(
                classify_publish(err).kind(),
                want,
                "classify_publish: {label}"
            );
        }
    }

    // 我方 PublishRejected 在 publish() 调用点直接分类（不经 classify_publish）——锁定 disposition 接线意图：
    // Nack（资源压力）→ transient 退避；Unroutable（无绑定 queue，路由目标尚未声明）→ transient 退避等订阅
    // 完成收敛（review #278 F1：不首投即 DLX，保 L2 最终送达）。
    #[test]
    fn publish_rejected_dispositions() {
        assert!(diport::PublisherError::transient(PublishRejected::Nack).is_transient());
        assert!(diport::PublisherError::transient(PublishRejected::Unroutable).is_transient());
    }
}

/// `build_properties` 纯函数单测（integration-gated：lapin 类型只在 integration feature 链接）。
/// 验证 occurred_at → AMQP timestamp（不进 headers）、其余 pair → headers LongString。
#[cfg(test)]
mod build_properties_tests {
    use diport::{
        EnvelopeMetadata, KEY_ACTOR, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_PRINCIPAL,
        KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_SUBJECT_ID,
    };
    use lapin::types::AMQPValue;

    use super::build_properties;

    #[test]
    fn empty_metadata_sets_only_message_id() {
        let md = EnvelopeMetadata::empty();
        let props = build_properties("evt-1", &md);
        assert_eq!(
            props.message_id().as_ref().map(|s| s.as_str()),
            Some("evt-1")
        );
        assert!(
            props.timestamp().is_none(),
            "no timestamp for empty metadata"
        );
        assert!(props.headers().is_none(), "no headers for empty metadata");
    }

    #[test]
    fn negative_occurred_at_skips_timestamp() {
        // F3 review：wire bag 可携畸形负 occurred_at（epoch 前）；`u64::try_from` fail-closed 跳过
        // timestamp，不 `as u64` wrap 成超大值。anti-vacuity：正值仍设 timestamp（见上一测试）。
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_OCCURRED_AT, "-5");
        let props = build_properties("evt-neg", &md);
        assert!(
            props.timestamp().is_none(),
            "负 occurred_at 不应 cast 成超大 timestamp，应跳过"
        );
    }

    #[test]
    fn occurred_at_goes_to_timestamp_not_headers() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        let props = build_properties("evt-2", &md);
        assert_eq!(props.timestamp(), &Some(1_700_000_000_u64));
        // occurred_at 不得出现在 headers。
        if let Some(table) = props.headers() {
            let has_occurred_at = table
                .inner()
                .iter()
                .any(|(k, _)| k.as_str() == KEY_OCCURRED_AT);
            assert!(
                !has_occurred_at,
                "occurred_at must not be duplicated in headers"
            );
        }
    }

    #[test]
    // reason: 测试断言 build_properties 在有 metadata 时必设 headers（非生产路径）。
    #[allow(clippy::expect_used)]
    fn transport_metadata_goes_to_headers_and_sensitive_metadata_is_excluded() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_CORRELATION, "corr-9");
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(
            KEY_SCHEMA_HASH,
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        md.insert_wire_pair(KEY_SUBJECT_ID, "user-42");
        md.insert_wire_pair(KEY_PRINCIPAL, "principal-42");
        md.insert_wire_pair(KEY_ACTOR, "actor-42");
        let _ = md.try_insert("requestPath", "/login");
        let props = build_properties("evt-3", &md);
        assert!(props.timestamp().is_none(), "no occurred_at → no timestamp");
        let table = props.headers().as_ref().expect("headers should be set");
        let get = |key: &str| {
            table.inner().iter().find_map(|(k, v)| {
                if k.as_str() == key {
                    if let AMQPValue::LongString(ls) = v {
                        Some(ls.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        };
        assert_eq!(get(KEY_CORRELATION).as_deref(), Some("corr-9"));
        assert_eq!(get(KEY_SCHEMA_VERSION).as_deref(), Some("v1"));
        assert_eq!(
            get(KEY_SCHEMA_HASH).as_deref(),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(get(KEY_SUBJECT_ID), None);
        assert_eq!(get(KEY_PRINCIPAL), None);
        assert_eq!(get(KEY_ACTOR), None);
        assert_eq!(get("requestPath"), None);
    }

    #[test]
    // reason: 测试断言 build_properties 在有 metadata 时必设 headers（非生产路径）。
    #[allow(clippy::expect_used)]
    fn full_roundtrip_occurred_at_and_other_fields() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000001");
        md.insert_wire_pair(KEY_CORRELATION, "corr-full");
        let props = build_properties("evt-full", &md);
        // message_id = event_id。
        assert_eq!(
            props.message_id().as_ref().map(|s| s.as_str()),
            Some("evt-full")
        );
        // occurred_at → timestamp（不进 headers）。
        assert_eq!(props.timestamp(), &Some(1_700_000_001_u64));
        let table = props.headers().as_ref().expect("headers set");
        // correlation 在 headers。
        let has_correlation = table
            .inner()
            .iter()
            .any(|(k, _)| k.as_str() == KEY_CORRELATION);
        assert!(has_correlation, "correlation should be in headers");
        // occurred_at 不在 headers。
        let has_occurred_at = table
            .inner()
            .iter()
            .any(|(k, _)| k.as_str() == KEY_OCCURRED_AT);
        assert!(
            !has_occurred_at,
            "occurred_at must not be duplicated in headers"
        );
    }
}

#[cfg(test)]
mod publish_deadline_tests {
    use std::convert::Infallible;
    use std::future;
    use std::time::Duration;

    use super::{
        MAX_PUBLISH_TIMEOUT_MILLIS, PublishDeadlineElapsed, PublishPhase,
        PublishTimeoutConfigError, run_publish_pipeline, validate_publish_timeout,
    };

    #[test]
    fn deadline_error_is_static_and_transient() {
        let elapsed = PublishDeadlineElapsed {
            phase: PublishPhase::Confirm,
        };
        assert_eq!(elapsed.to_string(), "amqp publish deadline elapsed");
        assert!(diport::PublisherError::transient(elapsed).is_transient());
    }

    #[test]
    fn publish_timeout_validation_is_fail_closed() {
        assert_eq!(
            validate_publish_timeout(Duration::ZERO),
            Err(PublishTimeoutConfigError::Zero)
        );
        assert_eq!(
            validate_publish_timeout(Duration::from_micros(1)),
            Err(PublishTimeoutConfigError::NonIntegralMilliseconds)
        );
        assert_eq!(
            validate_publish_timeout(Duration::from_millis((i64::MAX as u64 / 1_000) + 1)),
            Err(PublishTimeoutConfigError::OperationalRangeExceeded {
                max_millis: MAX_PUBLISH_TIMEOUT_MILLIS,
            })
        );
        assert_eq!(validate_publish_timeout(Duration::from_secs(40)), Ok(()));
        assert_eq!(
            validate_publish_timeout(Duration::from_millis(MAX_PUBLISH_TIMEOUT_MILLIS)),
            Ok(())
        );
        assert_eq!(
            validate_publish_timeout(Duration::from_millis(MAX_PUBLISH_TIMEOUT_MILLIS + 1)),
            Err(PublishTimeoutConfigError::OperationalRangeExceeded {
                max_millis: MAX_PUBLISH_TIMEOUT_MILLIS,
            })
        );
    }

    #[tokio::test(start_paused = true)]
    // reason: paused-time 测试必须断言共享 deadline 以错误终止。
    #[allow(clippy::expect_used)]
    async fn basic_publish_half_open_consumes_the_shared_deadline() {
        let err = run_publish_pipeline(
            Duration::from_secs(10),
            future::pending::<Result<(), Infallible>>(),
            |()| future::ready(Ok::<(), Infallible>(())),
        )
        .await
        .expect_err("half-open basic_publish must time out");

        assert_eq!(err.timeout_phase(), Some(PublishPhase::BasicPublish));
    }

    #[tokio::test(start_paused = true)]
    // reason: paused-time 测试必须断言共享 deadline 以错误终止。
    #[allow(clippy::expect_used)]
    async fn publisher_confirm_half_open_consumes_the_shared_deadline() {
        let err = run_publish_pipeline(
            Duration::from_secs(10),
            future::ready(Ok::<(), Infallible>(())),
            |()| future::pending::<Result<(), Infallible>>(),
        )
        .await
        .expect_err("half-open confirm must time out");

        assert_eq!(err.timeout_phase(), Some(PublishPhase::Confirm));
    }

    #[tokio::test(start_paused = true)]
    // reason: 若 confirm 错获完整 10s，此 case 会成功；expect_err 锁定第一阶段耗时已扣减。
    #[allow(clippy::expect_used)]
    async fn basic_publish_elapsed_time_is_deducted_from_confirm_budget() {
        let err = run_publish_pipeline(
            Duration::from_secs(10),
            async {
                tokio::time::sleep(Duration::from_secs(7)).await;
                Ok::<(), Infallible>(())
            },
            |()| async {
                tokio::time::sleep(Duration::from_secs(4)).await;
                Ok::<(), Infallible>(())
            },
        )
        .await
        .expect_err("confirm must only receive the remaining three seconds");

        assert_eq!(err.timeout_phase(), Some(PublishPhase::Confirm));
    }
}

#[cfg(test)]
mod publisher_channel_state_tests {
    #![allow(clippy::expect_used)]
    // reason: 状态机单测用 expect 把 invariant 失败定位到精确 transition。

    use super::ChannelSlot;

    #[test]
    fn consecutive_timeouts_retire_a_generation_once() {
        let mut slot = ChannelSlot::ready("channel-0");
        let snapshot = slot.snapshot().expect("initial channel must be ready");

        let recovery = slot
            .begin_timeout_recovery(snapshot.generation)
            .expect("first timeout must own recovery");
        assert_eq!(recovery.generation, snapshot.generation);
        assert_eq!(recovery.retiring, Some("channel-0"));
        assert!(
            slot.begin_timeout_recovery(snapshot.generation).is_none(),
            "concurrent timeout must not retire the same generation twice"
        );
    }

    #[test]
    fn recovering_channel_fails_snapshot_closed() {
        let mut slot = ChannelSlot::ready("channel-0");
        let generation = slot
            .snapshot()
            .expect("initial channel must be ready")
            .generation;
        slot.begin_timeout_recovery(generation)
            .expect("timeout must start recovery");

        assert!(
            slot.snapshot().is_err(),
            "retiring channel must never be handed to another publish"
        );
    }

    #[test]
    fn replacement_advances_generation_without_reusing_retired_channel() {
        let mut slot = ChannelSlot::ready("channel-0");
        let generation = slot
            .snapshot()
            .expect("initial channel must be ready")
            .generation;
        slot.begin_timeout_recovery(generation)
            .expect("timeout must start recovery");

        assert!(slot.install_replacement(generation, "channel-1"));
        let replacement = slot.snapshot().expect("replacement must be ready");
        assert_eq!(replacement.generation, generation + 1);
        assert_eq!(replacement.channel, "channel-1");
    }
}

#[cfg(test)]
mod publisher_channel_recovery_deadline_tests {
    #![allow(clippy::disallowed_methods)]
    // reason: paused Tokio time 测试直接观察 adapter-private monotonic absolute deadline。
    #![allow(clippy::expect_used)]
    // reason: recovery 状态机单测用 expect 把 invariant 失败定位到精确 transition。

    use std::convert::Infallible;
    use std::future;
    use std::time::Duration;

    use super::{
        ChannelSlot, PublisherChannelError, RecoveryStageError,
        run_confirm_channel_recovery_pipeline,
    };

    #[tokio::test(start_paused = true)]
    async fn replacement_create_hang_exits_within_total_recovery_budget() {
        let mut slot = ChannelSlot::ready("channel-0");
        let generation = slot
            .snapshot()
            .expect("initial channel must be ready")
            .generation;
        slot.begin_timeout_recovery(generation)
            .expect("timeout must enter recovery");
        let started = tokio::time::Instant::now();
        let result = run_confirm_channel_recovery_pipeline(
            Duration::from_secs(9),
            false,
            future::ready(Ok::<(), Infallible>(())),
            future::ready(Ok::<(), Infallible>(())),
            future::pending::<Result<(), Infallible>>(),
        )
        .await;

        assert!(matches!(
            result.replacement,
            Err(RecoveryStageError::Deadline)
        ));
        slot.fail_recovery(generation);
        assert!(matches!(
            slot.snapshot(),
            Err(PublisherChannelError::Unavailable)
        ));
        assert_eq!(started.elapsed(), Duration::from_secs(9));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_close_and_create_share_one_absolute_recovery_deadline() {
        let started = tokio::time::Instant::now();
        let result = run_confirm_channel_recovery_pipeline(
            Duration::from_secs(9),
            true,
            future::pending::<Result<(), Infallible>>(),
            future::pending::<Result<(), Infallible>>(),
            future::pending::<Result<(), Infallible>>(),
        )
        .await;

        assert!(matches!(
            result.drain,
            Some(Err(RecoveryStageError::Deadline))
        ));
        assert!(matches!(
            result.close,
            Some(Err(RecoveryStageError::Deadline))
        ));
        assert!(matches!(
            result.replacement,
            Err(RecoveryStageError::Deadline)
        ));
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(9),
            "three stages must not each receive a fresh nine-second timeout"
        );
    }
}

#[cfg(all(test, feature = "integration"))]
mod publisher_channel_rotation_integration_tests {
    use std::time::Duration;

    use anyhow::anyhow;
    use diport::{ManagedResource, MessageId, PublishRequest, Publisher, Topic};
    use lapin::options::{BasicGetOptions, QueueDeclareOptions};
    use lapin::types::FieldTable;
    use testkit::FixtureError;

    use super::AmqpPublisher;

    #[tokio::test(flavor = "multi_thread")]
    async fn integration_timeout_retirement_rotates_real_channel_and_allows_same_id_retry()
    -> Result<(), FixtureError> {
        let rmq = testkit::env_or_rabbitmq().await?;
        let url = rmq.vhost_url("rss_confirm_rotation").await?;
        let endpoint =
            secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
        let publisher =
            AmqpPublisher::connect(&endpoint, "amqp-it-rotation", Duration::from_secs(6)).await?;
        let topic = Topic::new("rss.it.confirm.rotation");

        // 默认 exchange 只向同名 queue 路由；独立 probe channel 同时用于读取两次 same-ID delivery。
        let probe = publisher.conn.create_channel().await?;
        probe
            .queue_declare(
                topic.as_str().into(),
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;

        let before = publisher
            .channel_snapshot()
            .map_err(|error| anyhow!(error))?;
        let event_id = MessageId::new("evt-confirm-timeout-retry-1");
        publisher
            .publish(PublishRequest::new(
                topic.clone(),
                event_id.clone(),
                b"same-id".to_vec(),
            ))
            .await?;

        // 可控 TCP confirm-delay proxy 目前不在 fixture 中；直接调用 timeout 唯一生产 hook，随后以真实
        // lapin/RabbitMQ 证明 retiring channel 被关闭、replacement confirm channel 可继续 same-ID 重试。
        publisher.retire_timed_out_channel(before.generation);
        let replacement = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(snapshot) = publisher.channel_snapshot()
                    && snapshot.generation > before.generation
                {
                    break snapshot;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| anyhow!("publisher confirm channel rotation timed out"))?;
        assert!(
            !before.channel.status().connected(),
            "retired channel must be closed before replacement becomes ready"
        );
        assert!(
            replacement.channel.status().connected(),
            "replacement confirm channel must be connected"
        );

        publisher
            .publish(PublishRequest::new(topic, event_id, b"same-id".to_vec()))
            .await?;

        for _ in 0..2 {
            let delivery = tokio::time::timeout(
                Duration::from_secs(5),
                probe.basic_get(
                    "rss.it.confirm.rotation".into(),
                    BasicGetOptions { no_ack: true },
                ),
            )
            .await??
            .ok_or_else(|| anyhow!("same-ID retry delivery missing"))?;
            assert_eq!(
                delivery
                    .properties
                    .message_id()
                    .as_ref()
                    .map(|value| value.as_str()),
                Some("evt-confirm-timeout-retry-1")
            );
        }

        probe
            .close(super::REPLY_SUCCESS, "rotation probe shutdown".into())
            .await?;
        Publisher::shutdown(&publisher).await?;
        ManagedResource::shutdown(&publisher).await?;
        Ok(())
    }
}
