//! lapin AMQP 发布 adapter——impl `diport::Publisher` + `diport::ManagedResource`。
//!
//! ref: amqp-rs/lapin src/generated/channel.rs@v4.10.0（采纳 basic_publish → PublisherConfirm 生命周期；
//! 偏离其可选 auto-recovery，由 RSS absolute deadline 独占整套 connection+confirm transport replacement）。

use std::future::Future;
#[cfg(feature = "integration-test-support")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::conn::{self, REPLY_SUCCESS};

/// 与 `eventexec::RELAY_BUDGET_MAX_MILLIS` 和 PostgreSQL 0062 对齐的 adapter 二次防线。
const MAX_PUBLISH_TIMEOUT_MILLIS: u64 = 86_400_000;

/// envelope metadata → [`BasicProperties`]：`event_id` 盖 `message_id`（去重锚点）；`occurred_at`
/// 独占 AMQP typed `timestamp`（unix 秒 u64），不再重复进 headers；其余 pair 进 `FieldTable` LongString。
///
/// 纯函数——无 broker 依赖；integration-gated（lapin 类型只在 integration feature 链接）。
fn build_properties(event_id: &str, md: &EnvelopeMetadata) -> BasicProperties {
    let props = BasicProperties::default()
        .with_message_id(event_id.into())
        .with_delivery_mode(2);
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
    PreSend,
    PostSend,
    Confirm,
}

impl PublishPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PreSend => "pre_send",
            Self::PostSend => "post_send",
            Self::Confirm => "confirm",
        }
    }

    const fn as_u8(self) -> u8 {
        match self {
            Self::PreSend => 0,
            Self::PostSend => 1,
            Self::Confirm => 2,
        }
    }

    const fn from_u8(value: u8) -> Self {
        match value {
            value if value == Self::Confirm.as_u8() => Self::Confirm,
            value if value == Self::PostSend.as_u8() => Self::PostSend,
            _ => Self::PreSend,
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
    Client { phase: PublishPhase, source: E },
    Deadline(PublishDeadlineElapsed),
}

impl<E> PublishPipelineError<E> {
    #[cfg(test)]
    fn timeout_phase(&self) -> Option<PublishPhase> {
        match self {
            Self::Client { .. } => None,
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
    // `basic_publish` 的 future 只有在 AMQP method frame 已交给 lapin driver 后才返回
    // `PublisherConfirm`；因此该 await 的 client failure 一律按发送后不确定窗口处理。
    let phase = AtomicU8::new(PublishPhase::PostSend.as_u8());
    let result = tokio::time::timeout(publish_timeout, async {
        let pending = basic_publish
            .await
            .map_err(|source| PublishPipelineError::Client {
                phase: PublishPhase::PostSend,
                source,
            })?;
        phase.store(PublishPhase::Confirm.as_u8(), Ordering::Relaxed);
        confirm(pending)
            .await
            .map_err(|source| PublishPipelineError::Client {
                phase: PublishPhase::Confirm,
                source,
            })
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

/// 一个 publisher generation 的完整 AMQP transport。connection 与 confirm channel 必须同生共死，
/// 不能在旧 connection 上只换 channel，否则 connection reset 后会持续复用已失效的 transport。
#[derive(Clone)]
struct PublisherTransport<C, H> {
    connection: C,
    confirm_channel: H,
}

impl<C, H> PublisherTransport<C, H> {
    fn new(connection: C, confirm_channel: H) -> Self {
        Self {
            connection,
            confirm_channel,
        }
    }
}

/// Per-generation admission gate. The high bit closes admission atomically; the remaining bits are
/// the number of admitted publish attempts. Permits are RAII and deliberately non-cloneable, so the
/// counter exactly matches callers that can still reach `basic_publish` or await a confirm.
struct TransportAdmission {
    state: AtomicUsize,
    idle: Notify,
}

const ADMISSION_CLOSED: usize = 1usize << (usize::BITS - 1);
const ADMISSION_COUNT_MASK: usize = ADMISSION_CLOSED - 1;

impl TransportAdmission {
    fn open() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicUsize::new(0),
            idle: Notify::new(),
        })
    }

    fn acquire(self: &Arc<Self>) -> Result<TransportAdmissionPermit, PublisherTransportError> {
        let result = self
            .state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & ADMISSION_CLOSED != 0
                    || state & ADMISSION_COUNT_MASK == ADMISSION_COUNT_MASK
                {
                    None
                } else {
                    Some(state + 1)
                }
            });
        match result {
            Ok(_) => Ok(TransportAdmissionPermit {
                admission: Arc::clone(self),
            }),
            Err(state) if state & ADMISSION_CLOSED != 0 => {
                Err(PublisherTransportError::AdmissionClosed)
            }
            Err(_) => Err(PublisherTransportError::AdmissionSaturated),
        }
    }

    fn close(&self) {
        self.state.fetch_or(ADMISSION_CLOSED, Ordering::AcqRel);
    }

    async fn wait_until_idle(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Register before the count check so a final permit drop cannot be missed between
            // observing a non-zero count and awaiting. Multiple shutdown/recovery observers are
            // supported without relying on a stored single notification permit.
            notified.as_mut().enable();
            if self.state.load(Ordering::Acquire) & ADMISSION_COUNT_MASK == 0 {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.state.load(Ordering::Acquire) & ADMISSION_COUNT_MASK
    }
}

struct TransportAdmissionPermit {
    admission: Arc<TransportAdmission>,
}

impl Drop for TransportAdmissionPermit {
    fn drop(&mut self) {
        if let Ok(previous) =
            self.admission
                .state
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    ((state & ADMISSION_COUNT_MASK) > 0).then_some(state - 1)
                })
            && previous & ADMISSION_COUNT_MASK == 1
        {
            self.admission.idle.notify_waiters();
        }
    }
}

/// 一次 publish 对当前 transport 的短生命周期快照。
///
/// generation 让失败只能退休自己实际使用的 connection+channel；若并发 recovery 已安装 replacement，
/// stale failure 的 CAS 会失败，不能误伤新 transport。
struct TransportSnapshot<T> {
    generation: u64,
    transport: T,
    _admission: TransportAdmissionPermit,
}

#[derive(Clone)]
struct RetiringTransport<T> {
    transport: T,
    admission: Arc<TransportAdmission>,
}

/// 单次 transport recovery 的所有权凭证。只有成功将 `Ready(generation)` 转为 `Recovering` 的首个
/// failure 能取得它，故并发失败不会重复 drain/close/reconnect 同一 transport。
struct TransportRecovery<T> {
    generation: u64,
    retiring: Option<RetiringTransport<T>>,
}

/// publisher transport 的 adapter-private 生命周期。
///
/// `Recovering` 不提供 snapshot，类型状态保证旧 transport 一旦退休便不可再接收新 publish。`Unavailable`
/// 允许下一次 publish 触发一次无旧资源的 single-flight reconnect；调用本身仍 fail-fast transient。
enum TransportSlot<T> {
    Ready {
        generation: u64,
        transport: T,
        admission: Arc<TransportAdmission>,
    },
    Recovering {
        generation: u64,
        retiring: Option<RetiringTransport<T>>,
    },
    Unavailable {
        generation: u64,
    },
    /// port-local shutdown 先关 confirm channel，但保留最新 connection，供 runtime ManagedResource
    /// 随后从 lifecycle 单源取得并关闭，不能保存初始 connection 的陈旧 Arc。
    ShuttingDown {
        retiring: Option<RetiringTransport<T>>,
    },
}

impl<T> TransportSlot<T>
where
    T: Clone,
{
    fn ready(transport: T) -> Self {
        Self::Ready {
            generation: 0,
            transport,
            admission: TransportAdmission::open(),
        }
    }

    fn snapshot(&self) -> Result<TransportSnapshot<T>, PublisherTransportError> {
        match self {
            Self::Ready {
                generation,
                transport,
                admission,
            } => Ok(TransportSnapshot {
                generation: *generation,
                transport: transport.clone(),
                _admission: admission.acquire()?,
            }),
            Self::Recovering { .. } => Err(PublisherTransportError::Recovering),
            Self::Unavailable { .. } => Err(PublisherTransportError::Unavailable),
            Self::ShuttingDown { .. } => Err(PublisherTransportError::ShuttingDown),
        }
    }

    fn begin_recovery(&mut self, expected_generation: u64) -> Option<TransportRecovery<T>> {
        let (generation, retiring) = match self {
            Self::Ready {
                generation,
                transport,
                admission,
            } if *generation == expected_generation => {
                admission.close();
                (
                    *generation,
                    RetiringTransport {
                        transport: transport.clone(),
                        admission: Arc::clone(admission),
                    },
                )
            }
            _ => return None,
        };
        *self = Self::Recovering {
            generation,
            retiring: Some(retiring.clone()),
        };
        Some(TransportRecovery {
            generation,
            retiring: Some(retiring),
        })
    }

    fn begin_unavailable_recovery(&mut self) -> Option<TransportRecovery<T>> {
        let generation = match self {
            Self::Unavailable { generation } => *generation,
            _ => return None,
        };
        *self = Self::Recovering {
            generation,
            retiring: None,
        };
        Some(TransportRecovery {
            generation,
            retiring: None,
        })
    }

    fn install_replacement(&mut self, recovery_generation: u64, transport: T) -> bool {
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
            transport,
            admission: TransportAdmission::open(),
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

    fn begin_port_shutdown(&mut self) -> Option<RetiringTransport<T>> {
        let retiring = match self {
            Self::Ready {
                transport,
                admission,
                ..
            } => {
                admission.close();
                Some(RetiringTransport {
                    transport: transport.clone(),
                    admission: Arc::clone(admission),
                })
            }
            Self::Recovering { retiring, .. } => retiring.clone(),
            Self::ShuttingDown { retiring } => return retiring.clone(),
            Self::Unavailable { .. } => None,
        };
        *self = Self::ShuttingDown {
            retiring: retiring.clone(),
        };
        retiring
    }

    fn take_for_resource_shutdown(&mut self) -> Option<RetiringTransport<T>> {
        let retiring = match self {
            Self::Ready {
                transport,
                admission,
                ..
            } => {
                admission.close();
                Some(RetiringTransport {
                    transport: transport.clone(),
                    admission: Arc::clone(admission),
                })
            }
            Self::Recovering { retiring, .. } => retiring.clone(),
            Self::ShuttingDown { retiring } => retiring.take(),
            Self::Unavailable { .. } => None,
        };
        *self = Self::ShuttingDown { retiring: None };
        retiring
    }
}

type LapinPublisherTransport = PublisherTransport<Arc<Connection>, Channel>;

struct PublisherTransportLifecycle {
    slot: TransportSlot<LapinPublisherTransport>,
    recovery: Option<OwnedTransportRecovery>,
}

struct OwnedTransportRecovery {
    cancellation: CancellationToken,
    deadline: tokio::time::Instant,
    task: JoinHandle<()>,
}

impl PublisherTransportLifecycle {
    fn new(transport: LapinPublisherTransport) -> Self {
        Self {
            slot: TransportSlot::ready(transport),
            recovery: None,
        }
    }

    fn is_ready(&self) -> bool {
        matches!(
            &self.slot,
            TransportSlot::Ready { transport, .. }
                if transport.connection.status().connected()
                    && transport.confirm_channel.status().connected()
        )
    }
}

/// 固定安全摘要；不携 endpoint、event、payload 或 lapin 原始错误链。
#[derive(Debug, thiserror::Error)]
enum PublisherTransportError {
    #[error("amqp publisher transport admission is closed")]
    AdmissionClosed,
    #[error("amqp publisher transport admission capacity exhausted")]
    AdmissionSaturated,
    #[error("amqp publisher transport is recovering")]
    Recovering,
    #[error("amqp publisher transport is unavailable")]
    Unavailable,
    #[error("amqp publisher is shutting down")]
    ShuttingDown,
    #[error("amqp publisher transport state is poisoned")]
    StatePoisoned,
    #[error("amqp publisher transport close failed")]
    Close(#[source] lapin::Error),
    #[error("amqp publisher admission drain deadline elapsed")]
    AdmissionDrainDeadline,
    #[error("amqp publisher recovery task panicked")]
    RecoveryTaskPanicked,
    #[error("amqp publisher recovery task was cancelled")]
    RecoveryTaskCancelled,
    #[error("amqp publisher recovery task terminated unexpectedly")]
    RecoveryTaskUnknown,
    #[error("amqp publisher recovery join deadline elapsed")]
    RecoveryJoinDeadline,
}

/// `Publisher::publish` 的唯一内部失败载体。Display 只含固定安全摘要；endpoint、routing key、event id、
/// payload 与 lapin source 都不会越过 `PublisherError` 的 redacted source 边界。
#[derive(Debug, thiserror::Error)]
enum PublishAttemptFailure {
    #[error("amqp publish admission failed")]
    Admission(#[source] PublisherTransportError),
    #[error("amqp publish client failed")]
    Client {
        generation: u64,
        phase: PublishPhase,
        #[source]
        source: lapin::Error,
    },
    #[error("amqp publish deadline elapsed")]
    Deadline {
        generation: u64,
        #[source]
        elapsed: PublishDeadlineElapsed,
    },
    #[error(transparent)]
    Rejected(#[from] PublishRejected),
}

impl PublishAttemptFailure {
    fn from_pipeline(generation: u64, error: PublishPipelineError<lapin::Error>) -> Self {
        match error {
            PublishPipelineError::Client { phase, source } => Self::Client {
                generation,
                phase,
                source,
            },
            PublishPipelineError::Deadline(elapsed) => Self::Deadline {
                generation,
                elapsed,
            },
        }
    }

    fn decision(&self) -> PublishFailureDecision {
        match self {
            Self::Admission(_) | Self::Rejected(_) => {
                PublishFailureDecision::KeepDefinitive(DefinitivePublishKind::Transient)
            }
            Self::Client {
                generation,
                phase,
                source,
            } => decide_publish_failure(
                *generation,
                &PublishPipelineError::Client {
                    phase: *phase,
                    source: source.clone(),
                },
            ),
            Self::Deadline { generation, .. } => PublishFailureDecision::RetireAmbiguous {
                generation: *generation,
            },
        }
    }

    fn phase(&self) -> PublishPhase {
        match self {
            Self::Admission(_) => PublishPhase::PreSend,
            Self::Client { phase, .. } => *phase,
            Self::Deadline { elapsed, .. } => elapsed.phase,
            Self::Rejected(_) => PublishPhase::Confirm,
        }
    }
}

/// Definitive outcomes cannot represent `Ambiguous`; this private closed vocabulary makes invalid
/// Keep/Retire-Ambiguous states unconstructable even though the public port has three result kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefinitivePublishKind {
    Transient,
    Permanent,
}

/// publish failure 对当前 transport 的闭合处置。只有该枚举能决定是否退休 generation；调用方不能把
/// Ambiguous 与 definitive retry 混成同一条隐式 bool 路径。
///
/// 这是 Hard owner：类型系统锁定合法 decision 空间。Medium `AMQP-PUBLISH-BYPASS-01` 只补强
/// `Publisher::publish` 不得直接绕过 decision 去构造 `PublisherError` / `retire_transport`；
/// budget/fencing/ambiguity 行为归 enrolled provider capability。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishFailureDecision {
    KeepDefinitive(DefinitivePublishKind),
    RetireDefinitive {
        generation: u64,
        kind: DefinitivePublishKind,
    },
    RetireAmbiguous {
        generation: u64,
    },
}

impl PublishFailureDecision {
    const fn retirement_generation(self) -> Option<u64> {
        match self {
            Self::KeepDefinitive(_) => None,
            Self::RetireDefinitive { generation, .. } | Self::RetireAmbiguous { generation } => {
                Some(generation)
            }
        }
    }
}

/// Production-used decision applicator seam: closed decision → optional generation retirement +
/// three-state wire. Name is not a Medium carrier; only the typed pairing is Hard.
struct AppliedPublishFailure {
    retirement_generation: Option<u64>,
    needs_ambiguous_audit: bool,
    error: PublisherError,
}

fn apply_publish_failure_decision(
    decision: PublishFailureDecision,
    failure: PublishAttemptFailure,
) -> AppliedPublishFailure {
    let retirement_generation = decision.retirement_generation();
    let needs_ambiguous_audit = matches!(decision, PublishFailureDecision::RetireAmbiguous { .. });
    let error = match decision {
        PublishFailureDecision::KeepDefinitive(DefinitivePublishKind::Transient)
        | PublishFailureDecision::RetireDefinitive {
            kind: DefinitivePublishKind::Transient,
            ..
        } => PublisherError::transient(failure),
        PublishFailureDecision::KeepDefinitive(DefinitivePublishKind::Permanent)
        | PublishFailureDecision::RetireDefinitive {
            kind: DefinitivePublishKind::Permanent,
            ..
        } => PublisherError::permanent(failure),
        PublishFailureDecision::RetireAmbiguous { .. } => PublisherError::ambiguous(failure),
    };
    AppliedPublishFailure {
        retirement_generation,
        needs_ambiguous_audit,
        error,
    }
}

/// phase-aware lapin client/deadline 决策表。
///
/// post-send/confirm 的 transport lifecycle 丢失无法判断 broker 是否已接收，必须退休并返回 Ambiguous；
/// pre-send 的同类错误明确未发送，保持 definitive Transient，但仍退休坏 transport。协议明确拒绝保持
/// definitive；若协议错误同时关闭 channel/connection，则退休后返回原 definitive kind。
fn decide_publish_failure(
    generation: u64,
    error: &PublishPipelineError<lapin::Error>,
) -> PublishFailureDecision {
    match error {
        PublishPipelineError::Deadline(_) => PublishFailureDecision::RetireAmbiguous { generation },
        PublishPipelineError::Client { phase, source } => {
            decide_client_failure(generation, *phase, source)
        }
    }
}

fn decide_client_failure(
    generation: u64,
    phase: PublishPhase,
    source: &lapin::Error,
) -> PublishFailureDecision {
    if phase != PublishPhase::PreSend && is_transport_lifecycle_lost(source) {
        return PublishFailureDecision::RetireAmbiguous { generation };
    }
    let kind = classify_publish_kind(source);
    if is_transport_lifecycle_lost(source) || is_protocol_close(source) {
        PublishFailureDecision::RetireDefinitive { generation, kind }
    } else {
        PublishFailureDecision::KeepDefinitive(kind)
    }
}

fn is_transport_lifecycle_lost(error: &lapin::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::InvalidChannel(_)
            | ErrorKind::InvalidChannelState(..)
            | ErrorKind::InvalidConnectionState(_)
            | ErrorKind::IOError(_)
            | ErrorKind::RuntimeShutdownError(_)
            | ErrorKind::MissingHeartbeatError
    ) || matches!(
        error.kind(),
        ErrorKind::ProtocolError(amqp) if matches!(amqp.kind(), AMQPErrorKind::Hard(_))
    )
}

fn is_protocol_close(error: &lapin::Error) -> bool {
    matches!(error.kind(), ErrorKind::ProtocolError(_))
}

/// Ready type-state之外的底层 lapin 状态二次 admission 防线。Connection/channel 在 snapshot 之后、
/// `basic_publish` 之前已关闭时明确尚未发送，故必须以 PreSend definitive failure 退休，而非误标 Ambiguous。
fn validate_transport_admission(
    connection_connected: bool,
    channel_connected: bool,
) -> Result<(), lapin::Error> {
    if !connection_connected {
        return Err(ErrorKind::InvalidConnectionState(lapin::ConnectionState::Closed).into());
    }
    if !channel_connected {
        return Err(ErrorKind::InvalidChannelState(
            lapin::ChannelState::Closed,
            "publisher admission",
        )
        .into());
    }
    Ok(())
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
fn classify_publish_kind(error: &lapin::Error) -> DefinitivePublishKind {
    if is_permanent_lapin(error) {
        DefinitivePublishKind::Permanent
    } else {
        DefinitivePublishKind::Transient
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
/// RESOURCELOCKED 锁释放）——后者归 transient，由 [`classify_publish_kind`] 的 `can_be_recovered()` 兜底（review
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
    connection_config: PublisherConnectionConfig,
    transports: Arc<Mutex<PublisherTransportLifecycle>>,
    name: String,
    publish_timeout: Duration,
    #[cfg(feature = "integration-test-support")]
    post_send_connection_close_once: AtomicBool,
}

#[derive(Clone)]
struct PublisherConnectionConfig {
    endpoint: secure::AmqpEndpoint,
    trust: conn::AmqpTlsTrust,
}

impl AmqpPublisher {
    pub(crate) fn readiness_snapshot(&self) -> bool {
        self.lock_transports()
            .is_ok_and(|lifecycle| lifecycle.is_ready())
    }

    /// 从单个 per-domain AMQP URL 连接（URL 含 `user:pass@host/vhost`）。`name` 是 `ManagedResource`
    /// 可读名（kebab/snake 稳定标识）。`publish_timeout` 在任何网络连接前再次校验非零、整毫秒且可由
    /// 数据库/审计 `i64` 表示；连接失败日志只经 redaction funnel，URL 原文绝不进日志。
    pub async fn connect(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
        publish_timeout: Duration,
    ) -> Result<Self, conn::AmqpConnectError> {
        Self::connect_with_trust(endpoint, name, publish_timeout, conn::AmqpTlsTrust::WebPki).await
    }

    pub(crate) async fn connect_with_private_ca(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
        publish_timeout: Duration,
        ca: &conn::AmqpPrivateCa,
    ) -> Result<Self, conn::AmqpConnectError> {
        Self::connect_with_trust(
            endpoint,
            name,
            publish_timeout,
            conn::AmqpTlsTrust::PrivateCa(ca.clone()),
        )
        .await
    }

    async fn connect_with_trust(
        endpoint: &secure::AmqpEndpoint,
        name: impl Into<String>,
        publish_timeout: Duration,
        trust: conn::AmqpTlsTrust,
    ) -> Result<Self, conn::AmqpConnectError> {
        validate_publish_timeout(publish_timeout).map_err(|_| conn::invalid_publisher_timeout())?;
        let name = name.into();
        // confirm=true：启用 publisher confirms，使 publish 能检测 broker ack/nack（durable publish-ok）。
        let (conn, channel) = match &trust {
            conn::AmqpTlsTrust::WebPki => conn::connect(endpoint, &name, true).await?,
            conn::AmqpTlsTrust::PrivateCa(ca) => {
                conn::connect_with_private_ca(endpoint, &name, true, ca).await?
            }
        };
        Ok(Self {
            connection_config: PublisherConnectionConfig {
                endpoint: endpoint.clone(),
                trust,
            },
            transports: Arc::new(Mutex::new(PublisherTransportLifecycle::new(
                PublisherTransport::new(conn, channel),
            ))),
            name,
            publish_timeout,
            #[cfg(feature = "integration-test-support")]
            post_send_connection_close_once: AtomicBool::new(false),
        })
    }

    fn lock_transports(
        &self,
    ) -> Result<MutexGuard<'_, PublisherTransportLifecycle>, PublisherTransportError> {
        self.transports
            .lock()
            .map_err(|_| PublisherTransportError::StatePoisoned)
    }

    /// 正常路径只在 std mutex 下 clone 当前 `(generation, PublisherTransport)`，不跨 broker await 持锁，
    /// 故并发 publish 不会被整次串行化。Unavailable 的首次 caller 只触发 single-flight reconnect，
    /// 自身仍 fail-fast。
    fn transport_snapshot(
        &self,
    ) -> Result<TransportSnapshot<LapinPublisherTransport>, PublisherTransportError> {
        let mut lifecycle = self.lock_transports()?;
        match lifecycle.slot.snapshot() {
            Ok(snapshot) => Ok(snapshot),
            Err(PublisherTransportError::Unavailable) => {
                if let Some(recovery) = lifecycle.slot.begin_unavailable_recovery() {
                    self.spawn_transport_recovery(&mut lifecycle, recovery);
                }
                Err(PublisherTransportError::Unavailable)
            }
            Err(error) => Err(error),
        }
    }

    /// client error/deadline 以 snapshot generation 做 CAS；只有首个失败能把 Ready 转为 Recovering 并
    /// spawn owned cleanup。所有调用点都收口在 private decision applicator（名字非载体）。
    fn retire_transport(&self, generation: u64) {
        let Ok(mut lifecycle) = self.lock_transports() else {
            tracing::error!(target: "amqp", resource = %self.name, "amqp publisher transport state poisoned");
            return;
        };
        if let Some(recovery) = lifecycle.slot.begin_recovery(generation) {
            self.spawn_transport_recovery(&mut lifecycle, recovery);
        }
    }

    #[allow(clippy::disallowed_methods)]
    // reason: adapter-private monotonic recovery deadline; not business time and shared by every recovery stage.
    fn spawn_transport_recovery(
        &self,
        lifecycle: &mut PublisherTransportLifecycle,
        recovery: TransportRecovery<LapinPublisherTransport>,
    ) {
        if let Some(previous) = lifecycle.recovery.take()
            && !previous.task.is_finished()
        {
            // 只能命中「上一 task 已把状态落为 Unavailable、尚未 return」的窄窗口。合作取消避免
            // detached task 在新 generation 已开始恢复后继续发起 authenticated reconnect。
            previous.cancellation.cancel();
        }
        let started = tokio::time::Instant::now();
        let deadline = started + self.publish_timeout;
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_transport_recovery(
            self.connection_config.clone(),
            Arc::clone(&self.transports),
            self.name.clone(),
            started,
            deadline,
            cancellation.clone(),
            recovery,
        ));
        lifecycle.recovery = Some(OwnedTransportRecovery {
            cancellation,
            deadline,
            task,
        });
    }

    /// 将 [`PublishFailureDecision`] 落到 generation retirement 与三态 [`PublisherError`]。
    ///
    /// Ownership 分界（不向后兼容；无旧 funnel shape 要求）：
    /// - **Hard**：private closed [`PublishFailureDecision`] / [`DefinitivePublishKind`] 使非法
    ///   Keep/Retire-Ambiguous 混态不可构造；本 helper 只是 decision → wire 的私有 applicator，名字可改。
    /// - **Provider behavior**：budget / fencing / ambiguity 的 publish pipeline 行为由 enrolled AMQP
    ///   capability 与真实 broker behavior 拥有，不由 Medium AST 锁 pipeline 函数名或局部调用顺序。
    ///   `OUTBOX-RELAY-BUDGET-01` 的 AMQP ambiguous audit 按唯一 production tracing marker
    ///   （ambiguous publish outcome 文案）+ required/forbidden fields 定位，不锁本 helper ident。
    /// - **Medium residual**（`AMQP-PUBLISH-BYPASS-01`）：仅禁止 production
    ///   `impl Publisher for AmqpPublisher::publish`（含 reachable nested local 与 live async/closure
    ///   敏感面）直接构造 `PublisherError::{transient,permanent,ambiguous}`、直接 `retire_transport`、
    ///   外层 `?` 或 macro 隐藏上述敏感调用。
    fn handle_publish_failure(&self, failure: PublishAttemptFailure) -> PublisherError {
        let phase = failure.phase();
        let applied = apply_publish_failure_decision(failure.decision(), failure);
        if let Some(generation) = applied.retirement_generation {
            self.retire_transport(generation);
        }
        if applied.needs_ambiguous_audit
            && let Some(generation) = applied.retirement_generation
        {
            tracing::warn!(
                target: "amqp",
                resource = %self.name,
                transport_generation = generation,
                phase = phase.as_str(),
                publish_timeout_ms = self.publish_timeout.as_millis() as i64,
                delivery_outcome = "unknown",
                broker_may_have_received = true,
                "amqp publish outcome is ambiguous",
            );
        }
        applied.error
    }

    #[allow(clippy::disallowed_methods)]
    // reason: one adapter-private monotonic deadline bounds recovery join plus admission drain during shutdown.
    async fn shutdown_channels(&self) -> Result<(), PublisherTransportError> {
        let shutdown_deadline = tokio::time::Instant::now() + self.publish_timeout;
        let (recovery, retiring) = {
            let mut lifecycle = self.lock_transports()?;
            let retiring = lifecycle.slot.begin_port_shutdown();
            (lifecycle.recovery.take(), retiring)
        };
        let recovery_result = if let Some(recovery) = recovery {
            // ShuttingDown type-state and cancellation are established before joining. A pending
            // connect is dropped; a simultaneously-ready connection wins the biased select and is
            // then fenced by CAS and closed as an orphan within the original recovery deadline.
            join_cancelled_recovery(recovery).await
        } else {
            Ok(())
        };
        let transport_result = if let Some(retiring) = retiring {
            let admission_drained =
                wait_for_shutdown_admission(&retiring.admission, shutdown_deadline).await;
            let close_result = if retiring.transport.confirm_channel.status().connected() {
                retiring
                    .transport
                    .confirm_channel
                    .close(REPLY_SUCCESS, "publisher shutdown".into())
                    .await
                    .map_err(PublisherTransportError::Close)
            } else {
                Ok(())
            };
            close_result.and(admission_drained)
        } else {
            Ok(())
        };
        recovery_result.and(transport_result)
    }

    #[allow(clippy::disallowed_methods)]
    // reason: one adapter-private monotonic deadline bounds recovery join plus admission drain during shutdown.
    async fn shutdown_resource_transport(&self) -> Result<(), PublisherTransportError> {
        let shutdown_deadline = tokio::time::Instant::now() + self.publish_timeout;
        let (recovery, retiring) = {
            let mut lifecycle = self.lock_transports()?;
            let retiring = lifecycle.slot.take_for_resource_shutdown();
            (lifecycle.recovery.take(), retiring)
        };
        let recovery_result = if let Some(recovery) = recovery {
            join_cancelled_recovery(recovery).await
        } else {
            Ok(())
        };
        let transport_result = if let Some(retiring) = retiring {
            let admission_drained =
                wait_for_shutdown_admission(&retiring.admission, shutdown_deadline).await;
            let close_result = if retiring.transport.connection.status().connected() {
                retiring
                    .transport
                    .connection
                    .close(REPLY_SUCCESS, "publisher resource shutdown".into())
                    .await
                    .map_err(PublisherTransportError::Close)
            } else {
                Ok(())
            };
            close_result.and(admission_drained)
        } else {
            Ok(())
        };
        recovery_result.and(transport_result)
    }

    /// Integration-only deterministic fault barrier. The next publish closes the exact snapshot connection after
    /// lapin has written `basic.publish` and before its confirm is polled, then routes the synthetic lifecycle loss
    /// through the normal PostSend [`PublishFailureDecision`] path.
    #[cfg(feature = "integration-test-support")]
    pub fn inject_post_send_connection_close_once(&self) {
        self.post_send_connection_close_once
            .store(true, Ordering::Release);
    }

    #[cfg(feature = "integration-test-support")]
    fn take_post_send_connection_close_fault(&self) -> bool {
        self.post_send_connection_close_once
            .swap(false, Ordering::AcqRel)
    }

    #[cfg(not(feature = "integration-test-support"))]
    fn take_post_send_connection_close_fault(&self) -> bool {
        false
    }

    /// Integration-only high-level recovery barrier. It proves only that a publish can take a
    /// fresh ready snapshot before the publisher's bounded recovery budget expires; generation,
    /// connection, channel, and any constructible recovery evidence remain adapter-private.
    ///
    /// Poll backoff uses `interval`（非裸 `sleep`）——本方法在 lib + `integration-test-support`
    /// 路径编译，不能依赖 testkit（LAYER-DEPS-08：testkit 仅限 dev-dep）。
    #[cfg(feature = "integration-test-support")]
    pub async fn wait_until_publish_ready_for_test(&self) -> bool {
        tokio::time::timeout(self.publish_timeout, async {
            let mut ticker = tokio::time::interval(Duration::from_millis(10));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Consume the immediate first tick so subsequent Recovering waits are spaced.
            ticker.tick().await;
            loop {
                match self.transport_snapshot() {
                    Ok(snapshot) => {
                        drop(snapshot);
                        return true;
                    }
                    Err(
                        PublisherTransportError::Recovering | PublisherTransportError::Unavailable,
                    ) => {
                        ticker.tick().await;
                    }
                    Err(_) => return false,
                }
            }
        })
        .await
        .unwrap_or(false)
    }
}

async fn wait_for_shutdown_admission(
    admission: &TransportAdmission,
    deadline: tokio::time::Instant,
) -> Result<(), PublisherTransportError> {
    tokio::time::timeout_at(deadline, admission.wait_until_idle())
        .await
        .map_err(|_| PublisherTransportError::AdmissionDrainDeadline)
}

async fn join_cancelled_recovery(
    mut recovery: OwnedTransportRecovery,
) -> Result<(), PublisherTransportError> {
    recovery.cancellation.cancel();
    tokio::select! {
        biased;
        joined = &mut recovery.task => classify_recovery_join(joined),
        _ = tokio::time::sleep_until(recovery.deadline) => {
            // Cooperative stages are deadline-bound; abort is only a hard backstop for code between
            // awaits once the shared budget is already exhausted.
            recovery.task.abort();
            let _ = recovery.task.await;
            Err(PublisherTransportError::RecoveryJoinDeadline)
        }
    }
}

fn classify_recovery_join(
    joined: Result<(), tokio::task::JoinError>,
) -> Result<(), PublisherTransportError> {
    joined.map_err(|error| {
        if error.is_panic() {
            PublisherTransportError::RecoveryTaskPanicked
        } else if error.is_cancelled() {
            PublisherTransportError::RecoveryTaskCancelled
        } else {
            PublisherTransportError::RecoveryTaskUnknown
        }
    })
}

/// ambiguous/client failure 后的资源恢复在 owned task 中执行，避免 Postgres 外层 publisher watchdog drop
/// caller 时把 cleanup 一并取消。一个 lifecycle 同时至多保存一个 task；Recovering 期间 caller fail-fast，
/// 不会继续向 retiring connection/channel 注册 publish 或 confirm。
#[allow(clippy::cognitive_complexity)]
// reason: 实际分支仅 replacement 成功/失败与 lifecycle lock 成功/失败；tracing 宏展开抬高认知复杂度。
async fn run_transport_recovery(
    connection_config: PublisherConnectionConfig,
    transports: Arc<Mutex<PublisherTransportLifecycle>>,
    name: String,
    started: tokio::time::Instant,
    recovery_deadline: tokio::time::Instant,
    cancellation: CancellationToken,
    recovery: TransportRecovery<LapinPublisherTransport>,
) {
    let generation = recovery.generation;
    let Some(replacement) = recover_publisher_transport(
        &connection_config,
        recovery.retiring,
        &name,
        generation,
        started,
        recovery_deadline,
        cancellation,
    )
    .await
    else {
        match transports.lock() {
            Ok(mut lifecycle) => lifecycle.slot.fail_recovery(generation),
            Err(_) => {
                tracing::error!(
                    target: "amqp",
                    resource = %name,
                    transport_generation = generation,
                    phase = "transport_recovery",
                    result = "state_poisoned",
                    "amqp publisher transport state poisoned",
                )
            }
        }
        return;
    };

    let installed = match transports.lock() {
        Ok(mut lifecycle) => lifecycle
            .slot
            .install_replacement(generation, replacement.clone()),
        Err(_) => {
            tracing::error!(
                target: "amqp",
                resource = %name,
                transport_generation = generation,
                phase = "transport_install",
                result = "state_poisoned",
                "amqp publisher transport state poisoned",
            );
            false
        }
    };
    if installed {
        tracing::info!(
            target: "amqp",
            resource = %name,
            transport_generation = generation.saturating_add(1),
            phase = "transport_install",
            result = "installed",
            "amqp publisher transport replaced",
        );
    } else {
        // shutdown 或另一代 recovery 已先完成：replacement 不能成为无主可发布 transport。
        close_transport_bounded_at(
            &replacement,
            recovery_deadline,
            &name,
            generation.saturating_add(1),
            "orphan_replacement",
        )
        .await;
    }
}

#[derive(Debug, thiserror::Error)]
enum TransportRecoveryClientError {
    #[error("amqp retiring transport operation failed")]
    Lapin(#[source] lapin::Error),
    #[error("amqp replacement transport connect failed")]
    Connect(#[source] conn::AmqpConnectError),
}

#[derive(Debug)]
enum RecoveryStageError<E> {
    Client(E),
    Deadline,
    Cancelled,
}

struct PublisherTransportRecoveryResult<T, E> {
    drain: Option<Result<(), RecoveryStageError<E>>>,
    close: Option<Result<(), RecoveryStageError<E>>>,
    replacement: Result<T, RecoveryStageError<E>>,
}

/// 用一个 absolute recovery deadline 覆盖 confirm drain → connection close → replacement connect。
///
/// 有 retiring transport 时，前 1/3 给 drain、第二个 1/3 给整条 connection close、最后 1/3 给 fresh
/// connection+confirm channel；每个阶段使用从同一 start 派生的 `timeout_at`，前一阶段耗时会从后续可用
/// wall-clock 中扣除。无 retiring transport 时，reconnect 可使用完整 budget。
#[allow(clippy::disallowed_methods)]
// reason: adapter-private Tokio I/O absolute deadline；不表达业务时间，且必须与 timeout_at 使用同一 monotonic clock。
async fn run_publisher_transport_recovery_pipeline<
    Drain,
    DrainOutput,
    Close,
    CloseOutput,
    Create,
    T,
    E,
>(
    started: tokio::time::Instant,
    recovery_deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    has_retiring: bool,
    drain: Drain,
    close: Close,
    create: Create,
) -> PublisherTransportRecoveryResult<T, E>
where
    Drain: Future<Output = Result<DrainOutput, E>>,
    Close: Future<Output = Result<CloseOutput, E>>,
    Create: Future<Output = Result<T, E>>,
{
    if cancellation.is_cancelled() {
        return PublisherTransportRecoveryResult {
            drain: has_retiring.then_some(Err(RecoveryStageError::Cancelled)),
            close: None,
            replacement: Err(RecoveryStageError::Cancelled),
        };
    }
    let operation_timeout = recovery_deadline.saturating_duration_since(started);
    let (drain, close) = if has_retiring {
        let cleanup_stage = operation_timeout / 3;
        let drain_deadline = started + cleanup_stage;
        let close_deadline = drain_deadline + cleanup_stage;
        let drain = run_recovery_cleanup_stage_at(drain_deadline, cancellation, drain)
            .await
            .map(|_| ());
        if matches!(drain, Err(RecoveryStageError::Cancelled)) {
            return PublisherTransportRecoveryResult {
                drain: Some(drain),
                close: None,
                replacement: Err(RecoveryStageError::Cancelled),
            };
        }
        let close = run_recovery_cleanup_stage_at(close_deadline, cancellation, close)
            .await
            .map(|_| ());
        if matches!(close, Err(RecoveryStageError::Cancelled)) {
            return PublisherTransportRecoveryResult {
                drain: Some(drain),
                close: Some(close),
                replacement: Err(RecoveryStageError::Cancelled),
            };
        }
        (Some(drain), Some(close))
    } else {
        (None, None)
    };
    let replacement = run_recovery_connect_stage_at(recovery_deadline, cancellation, create).await;
    PublisherTransportRecoveryResult {
        drain,
        close,
        replacement,
    }
}

async fn run_recovery_cleanup_stage_at<F, T, E>(
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    future: F,
) -> Result<T, RecoveryStageError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(RecoveryStageError::Cancelled),
        result = tokio::time::timeout_at(deadline, &mut future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(RecoveryStageError::Client(error)),
            Err(_) => Err(RecoveryStageError::Deadline),
        },
    }
}

async fn run_recovery_connect_stage_at<F, T, E>(
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
    future: F,
) -> Result<T, RecoveryStageError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::pin!(future);
    tokio::select! {
        // If connect completion and shutdown cancellation become ready together, retain the
        // connection so lifecycle CAS can reject it and bounded orphan close can run.
        biased;
        result = tokio::time::timeout_at(deadline, &mut future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(RecoveryStageError::Client(error)),
            Err(_) => Err(RecoveryStageError::Deadline),
        },
        _ = cancellation.cancelled() => Err(RecoveryStageError::Cancelled),
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: drain/close/create 三阶段各自需安全审计；复杂度主要来自 tracing 宏展开。
async fn recover_publisher_transport(
    connection_config: &PublisherConnectionConfig,
    retiring: Option<RetiringTransport<LapinPublisherTransport>>,
    name: &str,
    generation: u64,
    started: tokio::time::Instant,
    recovery_deadline: tokio::time::Instant,
    cancellation: CancellationToken,
) -> Option<LapinPublisherTransport> {
    let has_retiring = retiring.is_some();
    let result = run_publisher_transport_recovery_pipeline(
        started,
        recovery_deadline,
        &cancellation,
        has_retiring,
        async {
            match retiring.as_ref() {
                Some(retiring) => {
                    retiring.admission.wait_until_idle().await;
                    retiring
                        .transport
                        .confirm_channel
                        .wait_for_confirms()
                        .await
                        .map(|_| ())
                        .map_err(TransportRecoveryClientError::Lapin)
                }
                None => Ok(()),
            }
        },
        async {
            match retiring.as_ref().map(|value| &value.transport.connection) {
                Some(connection) if connection.status().connected() => connection
                    .close(REPLY_SUCCESS, "publisher transport retirement".into())
                    .await
                    .map_err(TransportRecoveryClientError::Lapin),
                Some(_) | None => Ok(()),
            }
        },
        async {
            conn::reconnect_publisher(
                &connection_config.endpoint,
                name,
                generation,
                &connection_config.trust,
            )
            .await
            .map(|(connection, confirm_channel)| {
                PublisherTransport::new(connection, confirm_channel)
            })
            .map_err(TransportRecoveryClientError::Connect)
        },
    )
    .await;

    match result.drain {
        None | Some(Ok(())) => {}
        Some(Err(RecoveryStageError::Client(_))) => tracing::warn!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase = "confirm_cleanup",
            result = "client_error",
            "amqp retiring transport confirm drain failed",
        ),
        Some(Err(RecoveryStageError::Deadline)) => tracing::warn!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase = "confirm_cleanup",
            result = "deadline",
            "amqp retiring transport confirm drain deadline elapsed",
        ),
        Some(Err(RecoveryStageError::Cancelled)) => tracing::info!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase = "confirm_cleanup",
            result = "cancelled",
            "amqp retiring transport confirm drain cancelled",
        ),
    }
    match result.close {
        None | Some(Ok(())) => {}
        Some(Err(RecoveryStageError::Client(_))) => tracing::warn!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase = "retiring_connection",
            result = "client_error",
            "amqp publisher retiring connection close failed",
        ),
        Some(Err(RecoveryStageError::Deadline)) => tracing::warn!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase = "retiring_connection",
            result = "deadline",
            "amqp publisher retiring connection close deadline elapsed",
        ),
        Some(Err(RecoveryStageError::Cancelled)) => tracing::info!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase = "retiring_connection",
            result = "cancelled",
            "amqp publisher retiring connection close cancelled",
        ),
    }
    match result.replacement {
        Ok(transport) => Some(transport),
        // The conn context already emitted the closed recovery result vocabulary without endpoint.
        Err(RecoveryStageError::Client(_)) => None,
        Err(RecoveryStageError::Deadline) => {
            tracing::warn!(
                target: "amqp",
                resource = %name,
                transport_generation = generation.saturating_add(1),
                phase = "transport_reconnect",
                result = "deadline",
                "amqp publisher transport reconnect deadline elapsed",
            );
            None
        }
        Err(RecoveryStageError::Cancelled) => {
            tracing::info!(
                target: "amqp",
                resource = %name,
                transport_generation = generation.saturating_add(1),
                phase = "transport_reconnect",
                result = "cancelled",
                "amqp publisher transport reconnect cancelled",
            );
            None
        }
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: close 成功/client error/deadline 三态需独立安全审计；复杂度主要来自 tracing 宏展开。
#[allow(clippy::disallowed_methods)]
// reason: orphan transport close 的 Tokio I/O absolute deadline；不表达业务时间。
async fn close_transport_bounded_at(
    transport: &LapinPublisherTransport,
    deadline: tokio::time::Instant,
    name: &str,
    generation: u64,
    phase: &'static str,
) {
    if !transport.connection.status().connected() {
        return;
    }
    match tokio::time::timeout_at(
        deadline,
        transport
            .connection
            .close(REPLY_SUCCESS, "publisher transport retirement".into()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => tracing::warn!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase,
            result = "client_error",
            "amqp publisher transport close failed",
        ),
        Err(_) => tracing::warn!(
            target: "amqp",
            resource = %name,
            transport_generation = generation,
            phase,
            result = "deadline",
            "amqp publisher transport close deadline elapsed",
        ),
    }
}

impl Publisher for AmqpPublisher {
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
        let snapshot = match self.transport_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Err(self.handle_publish_failure(PublishAttemptFailure::Admission(error)));
            }
        };
        if let Err(source) = validate_transport_admission(
            snapshot.transport.connection.status().connected(),
            snapshot.transport.confirm_channel.status().connected(),
        ) {
            return Err(self.handle_publish_failure(PublishAttemptFailure::Client {
                generation: snapshot.generation,
                phase: PublishPhase::PreSend,
                source,
            }));
        }
        // Broker-owned topic exchange + routing key = topic：subscriber 声明同名 queue 并绑定 exact
        // key。per-domain 隔离仍经 vhost，broker topic permission 额外封闭契约 routing key。
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
        let inject_post_send_close = self.take_post_send_connection_close_fault();
        let transport = snapshot.transport.clone();
        let confirmation = run_publish_pipeline(
            self.publish_timeout,
            async {
                let pending = transport
                    .confirm_channel
                    .basic_publish(
                        crate::EVENT_EXCHANGE.into(),
                        topic.into(),
                        BasicPublishOptions {
                            mandatory: true,
                            ..Default::default()
                        },
                        &payload,
                        properties,
                    )
                    .await?;
                if inject_post_send_close {
                    if transport.connection.status().connected() {
                        transport
                            .connection
                            .close(REPLY_SUCCESS, "integration post-send fault".into())
                            .await?;
                    }
                    return Err(lapin::Error::from(ErrorKind::InvalidConnectionState(
                        lapin::ConnectionState::Closed,
                    )));
                }
                Ok(pending)
            },
            // confirm_select 已启用 ⇒ await PublisherConfirm 拿到真实 Ack/Nack/返回消息。
            |pending| pending,
        )
        .await;
        let confirmation = match confirmation {
            Ok(confirmation) => confirmation,
            Err(error) => {
                return Err(
                    self.handle_publish_failure(PublishAttemptFailure::from_pipeline(
                        snapshot.generation,
                        error,
                    )),
                );
            }
        };
        if confirmation.is_nack() {
            // broker nack（队列错误 / 资源压力等）→ transient：退避后可能恢复，不首投即 DLX。
            return Err(self.handle_publish_failure(PublishRejected::Nack.into()));
        }
        // unroutable（mandatory 退回，无绑定 queue）→ transient（review #278 F1）：queue 由
        // AmqpSubscriber::subscribe_ackable 声明、无组合根级硬屏障保证 relay 发布前队列已就绪，启动/重启窗口
        // 「当前无绑定 queue」可经退避重试等订阅完成收敛。判永久会跳过 outbox 自愈、破坏 L2 最终送达——「路由
        // 目标当前不存在」≠ 永久非法（RabbitMQ basic.return 语义；与 NOROUTE/NOTFOUND 一致归 transient）。
        if confirmation.take_message().is_some() {
            return Err(self.handle_publish_failure(PublishRejected::Unroutable.into()));
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        // port-local 先停止 owned recovery，再关当前/retiring confirm channel；latest connection 保留在
        // lifecycle 中，随后由 ManagedResource 单源取得并关闭。
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
        match self.shutdown_resource_transport().await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::warn!(target: "amqp", resource = %self.name, error = %secure::redact_error(&error), "amqp publisher transport close error");
                Err(publisher_transport_shutdown_error(error))
            }
        }
    }
}

fn publisher_transport_shutdown_error(error: PublisherTransportError) -> ShutdownError {
    match error {
        PublisherTransportError::RecoveryTaskPanicked => ShutdownError::task_panicked(error),
        PublisherTransportError::RecoveryTaskCancelled => ShutdownError::task_cancelled(error),
        PublisherTransportError::RecoveryTaskUnknown => ShutdownError::task_unknown(error),
        PublisherTransportError::RecoveryJoinDeadline
        | PublisherTransportError::AdmissionDrainDeadline => {
            ShutdownError::deadline_exceeded(error)
        }
        _ => ShutdownError::new(error),
    }
}

#[cfg(all(test, feature = "integration"))]
type ProviderConformanceError = testkit::FixtureError;

#[cfg(all(test, feature = "integration"))]
testkit::provider_conformance_catalog! {
    provider: amqp,
    error: ProviderConformanceError,
    capabilities: {
        identity => {
            #[tokio::test(flavor = "multi_thread")]
            integration_broker_roundtrip_preserves_message_identity
                => publisher_transport_replacement_integration_tests::broker_roundtrip_preserves_message_identity_behavior
        },
        fencing => {
            #[tokio::test]
            publish_pipeline_transport_recovery_is_single_flight_and_generation_fenced
                => publish_pipeline_red_tests::transport_recovery_is_single_flight_and_generation_fenced_behavior
        },
        budget => {
            #[tokio::test(start_paused = true)]
            basic_publish_elapsed_time_is_deducted_from_confirm_budget
                => publish_deadline_tests::elapsed_time_is_deducted_from_confirm_budget_behavior
        },
        ambiguity => {
            #[tokio::test(flavor = "multi_thread")]
            integration_post_send_close_is_ambiguous_and_allows_same_id_retry
                => publisher_transport_replacement_integration_tests::post_send_close_is_ambiguous_and_allows_same_id_retry_behavior
        },
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

    use super::{
        DefinitivePublishKind, PublishRejected, classify_publish_kind, is_permanent_lapin,
    };

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
                DefinitivePublishKind::Permanent
            } else {
                DefinitivePublishKind::Transient
            };
            assert_eq!(
                classify_publish_kind(&err),
                want,
                "classify_publish_kind: {label}"
            );
        }
    }

    // 我方 PublishRejected 在 publish() 调用点直接分类（不经 classify_publish）——锁定 disposition 接线意图：
    // Nack（资源压力）→ transient 退避；Unroutable（无绑定 queue，路由目标尚未声明）→ transient 退避等订阅
    // 完成收敛（review #278 F1：不首投即 DLX，保 L2 最终送达）。
    #[test]
    fn publish_rejected_dispositions() {
        assert_eq!(
            diport::PublisherError::transient(PublishRejected::Nack).kind(),
            PublishErrorKind::Transient
        );
        assert_eq!(
            diport::PublisherError::transient(PublishRejected::Unroutable).kind(),
            PublishErrorKind::Transient
        );
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
    fn empty_metadata_sets_message_id_and_persistent_delivery() {
        let md = EnvelopeMetadata::empty();
        let props = build_properties("evt-1", &md);
        assert_eq!(
            props.message_id().as_ref().map(|s| s.as_str()),
            Some("evt-1")
        );
        assert_eq!(props.delivery_mode(), &Some(2));
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
    fn deadline_error_is_static_and_ambiguous() {
        let elapsed = PublishDeadlineElapsed {
            phase: PublishPhase::Confirm,
        };
        assert_eq!(elapsed.to_string(), "amqp publish deadline elapsed");
        assert!(diport::PublisherError::ambiguous(elapsed).is_ambiguous());
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

        assert_eq!(err.timeout_phase(), Some(PublishPhase::PostSend));
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

    // reason: 若 confirm 错获完整 10s，此 case 会成功；expect_err 锁定第一阶段耗时已扣减。
    #[allow(clippy::expect_used)]
    pub(super) async fn elapsed_time_is_deducted_from_confirm_budget_behavior() -> anyhow::Result<()>
    {
        let err = run_publish_pipeline(
            Duration::from_secs(10),
            async {
                testkit::await_delay(Duration::from_secs(7)).await;
                Ok::<(), Infallible>(())
            },
            |()| async {
                testkit::await_delay(Duration::from_secs(4)).await;
                Ok::<(), Infallible>(())
            },
        )
        .await
        .expect_err("confirm must only receive the remaining three seconds");

        assert_eq!(err.timeout_phase(), Some(PublishPhase::Confirm));
        Ok(())
    }
}

#[cfg(test)]
mod publish_pipeline_red_tests {
    use std::convert::Infallible;
    use std::future;
    use std::sync::Arc;
    use std::time::Duration;

    use lapin::{ChannelState, ConnectionState, ErrorKind};
    use tokio_util::sync::CancellationToken;

    use super::{
        DefinitivePublishKind, PublishDeadlineElapsed, PublishFailureDecision, PublishPhase,
        PublishPipelineError, RecoveryStageError, TransportSlot, decide_publish_failure,
        run_publish_pipeline, run_publisher_transport_recovery_pipeline,
        validate_transport_admission,
    };

    const GENERATION: u64 = 7;

    fn io_reset() -> lapin::Error {
        lapin::Error::from(ErrorKind::IOError(Arc::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ))))
    }

    fn closed_channel() -> lapin::Error {
        lapin::Error::from(ErrorKind::InvalidChannelState(
            ChannelState::Closed,
            "publisher confirm",
        ))
    }

    fn unavailable_connection() -> lapin::Error {
        lapin::Error::from(ErrorKind::InvalidConnectionState(ConnectionState::Error))
    }

    #[test]
    fn publish_pipeline_phase_vocabulary_is_closed() {
        let cases = [
            (PublishPhase::PreSend, "pre_send"),
            (PublishPhase::PostSend, "post_send"),
            (PublishPhase::Confirm, "confirm"),
        ];

        for (phase, expected) in cases {
            assert_eq!(phase.as_str(), expected);
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: the test must name which publish phase lost its client error.
    async fn publish_pipeline_client_error_carries_the_observed_phase() {
        let post_send = run_publish_pipeline(
            Duration::from_secs(1),
            future::ready(Err::<(), _>(io_reset())),
            |()| future::ready(Ok::<(), lapin::Error>(())),
        )
        .await
        .expect_err("basic_publish client failure must retain the post-send phase");
        assert!(matches!(
            post_send,
            PublishPipelineError::Client {
                phase: PublishPhase::PostSend,
                ..
            }
        ));

        let confirm = run_publish_pipeline(
            Duration::from_secs(1),
            future::ready(Ok::<(), lapin::Error>(())),
            |()| future::ready(Err::<(), _>(closed_channel())),
        )
        .await
        .expect_err("confirm client failure must retain the confirm phase");
        assert!(matches!(
            confirm,
            PublishPipelineError::Client {
                phase: PublishPhase::Confirm,
                ..
            }
        ));
    }

    #[test]
    fn publish_pipeline_failure_decision_table() {
        let cases = [
            (
                PublishPipelineError::Client {
                    phase: PublishPhase::PostSend,
                    source: io_reset(),
                },
                PublishFailureDecision::RetireAmbiguous {
                    generation: GENERATION,
                },
                "post-send reset may have reached the broker",
            ),
            (
                PublishPipelineError::Client {
                    phase: PublishPhase::Confirm,
                    source: closed_channel(),
                },
                PublishFailureDecision::RetireAmbiguous {
                    generation: GENERATION,
                },
                "confirm lifecycle close loses the delivery outcome",
            ),
            (
                PublishPipelineError::Client {
                    phase: PublishPhase::PreSend,
                    source: closed_channel(),
                },
                PublishFailureDecision::RetireDefinitive {
                    generation: GENERATION,
                    kind: DefinitivePublishKind::Transient,
                },
                "closed before send is definitive but the transport is unusable",
            ),
            (
                PublishPipelineError::Client {
                    phase: PublishPhase::PreSend,
                    source: unavailable_connection(),
                },
                PublishFailureDecision::RetireDefinitive {
                    generation: GENERATION,
                    kind: DefinitivePublishKind::Transient,
                },
                "unavailable before send is definitive but the transport is unusable",
            ),
            (
                PublishPipelineError::Deadline(PublishDeadlineElapsed {
                    phase: PublishPhase::PostSend,
                }),
                PublishFailureDecision::RetireAmbiguous {
                    generation: GENERATION,
                },
                "post-send deadline is ambiguous",
            ),
            (
                PublishPipelineError::Deadline(PublishDeadlineElapsed {
                    phase: PublishPhase::Confirm,
                }),
                PublishFailureDecision::RetireAmbiguous {
                    generation: GENERATION,
                },
                "confirm deadline is ambiguous",
            ),
        ];

        for (error, expected, label) in cases {
            assert_eq!(
                decide_publish_failure(GENERATION, &error),
                expected,
                "{label}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: the test must identify a pre-send admission classification failure.
    fn publish_pipeline_admission_rejects_disconnected_transport_before_send() {
        for (connection_connected, channel_connected) in [(false, true), (true, false)] {
            let source = validate_transport_admission(connection_connected, channel_connected)
                .expect_err("disconnected transport must fail before basic_publish");
            let error = PublishPipelineError::Client {
                phase: PublishPhase::PreSend,
                source,
            };
            assert_eq!(
                decide_publish_failure(GENERATION, &error),
                PublishFailureDecision::RetireDefinitive {
                    generation: GENERATION,
                    kind: DefinitivePublishKind::Transient,
                }
            );
        }
        assert!(validate_transport_admission(true, true).is_ok());
    }

    #[test]
    fn publish_attempt_failure_decision_covers_every_closed_variant() {
        let cases = [
            (
                super::PublishAttemptFailure::Admission(
                    super::PublisherTransportError::Unavailable,
                ),
                PublishFailureDecision::KeepDefinitive(DefinitivePublishKind::Transient),
            ),
            (
                super::PublishAttemptFailure::Client {
                    generation: GENERATION,
                    phase: PublishPhase::PreSend,
                    source: lapin::Error::from(ErrorKind::AuthProviderError("denied".into())),
                },
                PublishFailureDecision::KeepDefinitive(DefinitivePublishKind::Permanent),
            ),
            (
                super::PublishAttemptFailure::Deadline {
                    generation: GENERATION,
                    elapsed: PublishDeadlineElapsed {
                        phase: PublishPhase::Confirm,
                    },
                },
                PublishFailureDecision::RetireAmbiguous {
                    generation: GENERATION,
                },
            ),
            (
                super::PublishAttemptFailure::Rejected(super::PublishRejected::Nack),
                PublishFailureDecision::KeepDefinitive(DefinitivePublishKind::Transient),
            ),
        ];

        for (failure, expected) in cases {
            assert_eq!(failure.decision(), expected);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: table labels name which production decision/wire pairing failed.
    fn publish_failure_decision_applicator_locks_retire_and_wire_disposition() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum ExpectedWire {
            Transient,
            Permanent,
            Ambiguous,
        }

        let mut slot = TransportSlot::ready("applicator-transport");
        let ready_generation = slot.snapshot().expect("ready transport").generation;

        let cases = [
            (
                super::PublishAttemptFailure::Deadline {
                    generation: ready_generation,
                    elapsed: PublishDeadlineElapsed {
                        phase: PublishPhase::Confirm,
                    },
                },
                Some(ready_generation),
                ExpectedWire::Ambiguous,
                "RetireAmbiguous must retire generation and wire ambiguous",
            ),
            (
                super::PublishAttemptFailure::Admission(
                    super::PublisherTransportError::Unavailable,
                ),
                None,
                ExpectedWire::Transient,
                "KeepDefinitive transient must keep transport and wire transient",
            ),
            (
                super::PublishAttemptFailure::Client {
                    generation: ready_generation,
                    phase: PublishPhase::PreSend,
                    source: lapin::Error::from(ErrorKind::AuthProviderError("denied".into())),
                },
                None,
                ExpectedWire::Permanent,
                "KeepDefinitive permanent must keep transport and wire permanent",
            ),
            (
                super::PublishAttemptFailure::Rejected(super::PublishRejected::Nack),
                None,
                ExpectedWire::Transient,
                "KeepDefinitive nack must keep transport and wire transient",
            ),
        ];

        for (failure, expected_retirement, expected_wire, label) in cases {
            let decision = failure.decision();
            let applied = super::apply_publish_failure_decision(decision, failure);
            assert_eq!(
                applied.retirement_generation, expected_retirement,
                "{label}: retirement"
            );
            match expected_wire {
                ExpectedWire::Ambiguous => {
                    assert!(applied.error.is_ambiguous(), "{label}: wire");
                }
                ExpectedWire::Transient => {
                    assert!(
                        applied.error.is_retryable()
                            && !applied.error.is_ambiguous()
                            && !applied.error.is_permanent(),
                        "{label}: wire"
                    );
                }
                ExpectedWire::Permanent => {
                    assert!(applied.error.is_permanent(), "{label}: wire");
                }
            }
        }

        // Observe retirement CAS only for RetireAmbiguous: KeepDefinitive leaves Ready intact.
        assert!(
            slot.snapshot().is_ok(),
            "KeepDefinitive cases must not have retired the shared Ready slot"
        );
        let ambiguous = super::apply_publish_failure_decision(
            super::PublishAttemptFailure::Deadline {
                generation: ready_generation,
                elapsed: PublishDeadlineElapsed {
                    phase: PublishPhase::Confirm,
                },
            }
            .decision(),
            super::PublishAttemptFailure::Deadline {
                generation: ready_generation,
                elapsed: PublishDeadlineElapsed {
                    phase: PublishPhase::Confirm,
                },
            },
        );
        let recovery = slot
            .begin_recovery(
                ambiguous
                    .retirement_generation
                    .expect("RetireAmbiguous must publish a retirement generation"),
            )
            .expect("RetireAmbiguous retirement must CAS the Ready generation");
        assert_eq!(recovery.generation, ready_generation);
        assert!(
            slot.snapshot().is_err(),
            "retired transport must leave Ready"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: the test must identify the exact lifecycle transition that stopped being available.
    fn publish_deadline_decision_retires_its_exact_slot_generation() {
        let mut slot = TransportSlot::ready("transport-7");
        let generation = slot.snapshot().expect("transport must be ready").generation;
        let failure = super::PublishAttemptFailure::Deadline {
            generation,
            elapsed: PublishDeadlineElapsed {
                phase: PublishPhase::PostSend,
            },
        };
        let decision = failure.decision();
        let retirement = decision
            .retirement_generation()
            .expect("deadline must carry a retirement generation");

        let recovery = slot
            .begin_recovery(retirement)
            .expect("deadline decision must retire the matching ready generation");
        assert_eq!(recovery.generation, generation);
        assert!(slot.snapshot().is_err());
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockTransport {
        connection: &'static str,
        confirm_channel: &'static str,
    }

    fn transport(connection: &'static str, confirm_channel: &'static str) -> MockTransport {
        MockTransport {
            connection,
            confirm_channel,
        }
    }

    #[allow(clippy::expect_used)]
    // reason: the test must identify the exact generation transition that violated fencing.
    pub(super) async fn transport_recovery_is_single_flight_and_generation_fenced_behavior()
    -> anyhow::Result<()> {
        let retired = transport("connection-0", "confirm-0");
        let replacement = transport("connection-1", "confirm-1");
        let mut slot = TransportSlot::ready(retired.clone());
        let snapshot = slot.snapshot().expect("initial transport must be ready");

        let recovery = slot
            .begin_recovery(snapshot.generation)
            .expect("first failure must own recovery");
        assert_eq!(
            recovery
                .retiring
                .as_ref()
                .expect("ready recovery owns retiring transport")
                .transport,
            retired
        );
        assert!(
            slot.snapshot().is_err(),
            "Recovering must never admit a new publish snapshot"
        );
        assert!(
            slot.begin_recovery(snapshot.generation).is_none(),
            "one generation must have only one recovery owner"
        );

        assert!(slot.install_replacement(snapshot.generation, replacement.clone()));
        assert!(
            slot.begin_recovery(snapshot.generation).is_none(),
            "a stale generation must not retire its replacement"
        );
        let current = slot
            .snapshot()
            .expect("replacement transport must remain ready");
        assert_eq!(current.generation, snapshot.generation + 1);
        assert_eq!(current.transport, replacement);
        drop(snapshot);
        assert_eq!(
            current._admission.admission.in_flight(),
            1,
            "dropping a stale-generation permit must not affect replacement admission"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::disallowed_methods)]
    // reason: paused Tokio time observes the adapter-private monotonic shared recovery deadline.
    async fn publish_pipeline_recovery_replaces_connection_and_confirm_with_one_deadline() {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(9);
        let cancellation = CancellationToken::new();
        let replacement = transport("connection-1", "confirm-1");
        let result = run_publisher_transport_recovery_pipeline(
            started,
            deadline,
            &cancellation,
            true,
            future::pending::<Result<(), Infallible>>(),
            future::pending::<Result<(), Infallible>>(),
            future::ready(Ok::<MockTransport, Infallible>(replacement.clone())),
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
        assert!(matches!(result.replacement, Ok(value) if value == replacement));
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(6),
            "drain and connection close consume two thirds of the one absolute deadline"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: the concurrency test must identify the exact admission or drain transition that stalled.
    async fn two_callers_fence_stale_admission_before_confirm_drain() {
        let mut slot = TransportSlot::ready("transport-0");
        let stale_caller = slot.snapshot().expect("first caller admission");
        let failing_caller = slot.snapshot().expect("second caller admission");
        let recovery = slot
            .begin_recovery(failing_caller.generation)
            .expect("second caller retires the generation");
        assert_eq!(
            recovery
                .retiring
                .as_ref()
                .expect("ready recovery owns admission")
                .admission
                .in_flight(),
            2
        );
        drop(failing_caller);
        assert_eq!(
            recovery
                .retiring
                .as_ref()
                .expect("ready recovery owns admission")
                .admission
                .in_flight(),
            1
        );

        assert!(
            slot.snapshot().is_err(),
            "retirement must atomically close new admission"
        );
        let confirms_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&confirms_started);
        let retiring = recovery
            .retiring
            .expect("ready recovery owns its closed admission gate");
        let drain = tokio::spawn(async move {
            retiring.admission.wait_until_idle().await;
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        tokio::task::yield_now().await;
        assert!(
            !confirms_started.load(std::sync::atomic::Ordering::SeqCst),
            "confirm drain must not start while an admitted stale caller can still basic_publish"
        );

        drop(stale_caller);
        drain.await.expect("admission drain task must complete");
        assert!(confirms_started.load(std::sync::atomic::Ordering::SeqCst));
    }
}

#[cfg(test)]
mod publisher_channel_state_tests {
    #![allow(clippy::expect_used)]
    // reason: 状态机单测用 expect 把 invariant 失败定位到精确 transition。

    use super::TransportSlot;

    #[test]
    fn consecutive_timeouts_retire_a_generation_once() {
        let mut slot = TransportSlot::ready("channel-0");
        let snapshot = slot.snapshot().expect("initial channel must be ready");

        let recovery = slot
            .begin_recovery(snapshot.generation)
            .expect("first timeout must own recovery");
        assert_eq!(recovery.generation, snapshot.generation);
        assert_eq!(
            recovery
                .retiring
                .as_ref()
                .expect("ready recovery owns retiring channel")
                .transport,
            "channel-0"
        );
        assert!(
            slot.begin_recovery(snapshot.generation).is_none(),
            "concurrent timeout must not retire the same generation twice"
        );
    }

    #[test]
    fn recovering_channel_fails_snapshot_closed() {
        let mut slot = TransportSlot::ready("channel-0");
        let generation = slot
            .snapshot()
            .expect("initial channel must be ready")
            .generation;
        slot.begin_recovery(generation)
            .expect("timeout must start recovery");

        assert!(
            slot.snapshot().is_err(),
            "retiring channel must never be handed to another publish"
        );
    }

    #[test]
    fn replacement_advances_generation_without_reusing_retired_channel() {
        let mut slot = TransportSlot::ready("channel-0");
        let generation = slot
            .snapshot()
            .expect("initial channel must be ready")
            .generation;
        slot.begin_recovery(generation)
            .expect("timeout must start recovery");

        assert!(slot.install_replacement(generation, "channel-1"));
        let replacement = slot.snapshot().expect("replacement must be ready");
        assert_eq!(replacement.generation, generation + 1);
        assert_eq!(replacement.transport, "channel-1");
    }

    #[test]
    fn shutdown_between_reconnect_and_install_fences_replacement_as_orphan() {
        let mut slot = TransportSlot::ready("transport-0");
        let generation = slot
            .snapshot()
            .expect("initial transport must be ready")
            .generation;
        slot.begin_recovery(generation)
            .expect("failure must start recovery");

        assert_eq!(
            slot.begin_port_shutdown()
                .as_ref()
                .map(|retiring| retiring.transport),
            Some("transport-0")
        );
        assert!(
            !slot.install_replacement(generation, "transport-orphan"),
            "ShuttingDown must force the recovery task into bounded orphan close"
        );
        assert_eq!(
            slot.take_for_resource_shutdown()
                .as_ref()
                .map(|retiring| retiring.transport),
            Some("transport-0"),
            "runtime shutdown must still own the retiring connection"
        );
    }

    #[test]
    fn unavailable_first_caller_owns_single_flight_and_install_advances_once() {
        let mut slot = TransportSlot::ready("transport-0");
        let generation = slot.snapshot().expect("ready").generation;
        slot.begin_recovery(generation).expect("initial recovery");
        slot.fail_recovery(generation);

        let recovery = slot
            .begin_unavailable_recovery()
            .expect("first unavailable caller must own recovery");
        assert!(
            slot.begin_unavailable_recovery().is_none(),
            "subsequent caller must observe Recovering and never spawn another task"
        );
        assert!(slot.snapshot().is_err(), "Recovering rejects admission");
        assert!(slot.install_replacement(recovery.generation, "transport-1"));
        let ready = slot.snapshot().expect("replacement must become ready");
        assert_eq!(ready.generation, generation + 1);
        assert_eq!(ready.transport, "transport-1");
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    use super::{
        OwnedTransportRecovery, PublisherTransportError, RecoveryStageError, TransportAdmission,
        TransportSlot, join_cancelled_recovery, publisher_transport_shutdown_error,
        run_publisher_transport_recovery_pipeline, wait_for_shutdown_admission,
    };

    #[tokio::test(start_paused = true)]
    async fn shutdown_admission_wait_is_bounded_by_publish_timeout() {
        let started = tokio::time::Instant::now();
        let admission = TransportAdmission::open();
        let permit = admission.acquire().expect("synthetic caller admission");
        admission.close();

        let result =
            wait_for_shutdown_admission(&admission, started + Duration::from_secs(9)).await;

        assert!(matches!(
            result,
            Err(PublisherTransportError::AdmissionDrainDeadline)
        ));
        assert_eq!(started.elapsed(), Duration::from_secs(9));
        drop(permit);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_join_cancels_and_waits_for_owned_recovery() {
        let started = tokio::time::Instant::now();
        let cancellation = CancellationToken::new();
        let observed = Arc::new(AtomicBool::new(false));
        let task_token = cancellation.clone();
        let task_observed = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            task_token.cancelled().await;
            task_observed.store(true, Ordering::SeqCst);
        });

        join_cancelled_recovery(OwnedTransportRecovery {
            cancellation,
            deadline: started + Duration::from_secs(9),
            task,
        })
        .await
        .expect("cooperative recovery stops cleanly");

        assert!(observed.load(Ordering::SeqCst));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::panic)]
    async fn shutdown_join_reports_panic_and_deadline_as_closed_reasons() {
        let panic_result = join_cancelled_recovery(OwnedTransportRecovery {
            cancellation: CancellationToken::new(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(9),
            task: tokio::spawn(async { panic!("amqp-recovery-plain-panic-secret") }),
        })
        .await;
        assert!(matches!(
            panic_result,
            Err(PublisherTransportError::RecoveryTaskPanicked)
        ));
        assert_eq!(
            publisher_transport_shutdown_error(PublisherTransportError::RecoveryTaskPanicked)
                .kind(),
            diport::ShutdownErrorKind::TaskPanicked
        );

        let started = tokio::time::Instant::now();
        let deadline_result = join_cancelled_recovery(OwnedTransportRecovery {
            cancellation: CancellationToken::new(),
            deadline: started + Duration::from_secs(9),
            task: tokio::spawn(std::future::pending::<()>()),
        })
        .await;
        assert!(matches!(
            deadline_result,
            Err(PublisherTransportError::RecoveryJoinDeadline)
        ));
        assert_eq!(started.elapsed(), Duration::from_secs(9));
        assert_eq!(
            publisher_transport_shutdown_error(PublisherTransportError::RecoveryJoinDeadline)
                .kind(),
            diport::ShutdownErrorKind::DeadlineExceeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_create_hang_exits_within_total_recovery_budget() {
        let mut slot = TransportSlot::ready("channel-0");
        let generation = slot
            .snapshot()
            .expect("initial channel must be ready")
            .generation;
        slot.begin_recovery(generation)
            .expect("timeout must enter recovery");
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(9);
        let cancellation = CancellationToken::new();
        let result = run_publisher_transport_recovery_pipeline(
            started,
            deadline,
            &cancellation,
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
            Err(PublisherTransportError::Unavailable)
        ));
        assert_eq!(started.elapsed(), Duration::from_secs(9));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_close_and_create_share_one_absolute_recovery_deadline() {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(9);
        let cancellation = CancellationToken::new();
        let result = run_publisher_transport_recovery_pipeline(
            started,
            deadline,
            &cancellation,
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

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancellation_before_recovery_start_never_polls_connect() {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(9);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let connect_polled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&connect_polled);

        let result = run_publisher_transport_recovery_pipeline(
            started,
            deadline,
            &cancellation,
            false,
            future::ready(Ok::<(), Infallible>(())),
            future::ready(Ok::<(), Infallible>(())),
            async move {
                observed.store(true, Ordering::SeqCst);
                Ok::<_, Infallible>("must-not-connect")
            },
        )
        .await;

        assert!(matches!(
            result.replacement,
            Err(RecoveryStageError::Cancelled)
        ));
        assert!(!connect_polled.load(Ordering::SeqCst));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_connect_is_cooperatively_cancelled_without_new_deadline() {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(9);
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            trigger.cancel();
        });

        let result = run_publisher_transport_recovery_pipeline(
            started,
            deadline,
            &cancellation,
            false,
            future::ready(Ok::<(), Infallible>(())),
            future::ready(Ok::<(), Infallible>(())),
            future::pending::<Result<&'static str, Infallible>>(),
        )
        .await;

        assert!(matches!(
            result.replacement,
            Err(RecoveryStageError::Cancelled)
        ));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_ready_with_cancellation_is_returned_for_orphan_fencing() {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(9);
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();

        let result = run_publisher_transport_recovery_pipeline(
            started,
            deadline,
            &cancellation,
            false,
            future::ready(Ok::<(), Infallible>(())),
            future::ready(Ok::<(), Infallible>(())),
            async move {
                trigger.cancel();
                Ok::<_, Infallible>("orphan-replacement")
            },
        )
        .await;

        assert!(matches!(result.replacement, Ok("orphan-replacement")));
        assert!(cancellation.is_cancelled());
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}

#[cfg(all(test, feature = "integration"))]
mod publisher_transport_replacement_integration_tests {
    use std::time::Duration;

    use anyhow::{Context as _, anyhow};
    use diport::{
        AckAction, AckableSubscriber, Acker, ManagedResource, MessageId, PublishErrorKind,
        PublishRequest, Publisher, Topic,
    };
    use futures::StreamExt;
    use lapin::options::{BasicGetOptions, QueueDeclareOptions};
    use lapin::types::FieldTable;
    use testkit::{FixtureError, await_map, await_try};
    use tokio_util::sync::CancellationToken;

    use super::{AmqpPublisher, PublisherTransportError};
    use crate::AmqpSubscriber;

    pub(super) async fn broker_roundtrip_preserves_message_identity_behavior()
    -> Result<(), FixtureError> {
        let rmq = testkit::env_or_rabbitmq().await?;
        let url = rmq.vhost_url("rss_publisher_identity_roundtrip").await?;
        let endpoint =
            secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
        let publisher =
            AmqpPublisher::connect(&endpoint, "amqp-it-identity-pub", Duration::from_secs(6))
                .await?;
        let subscriber = AmqpSubscriber::connect(&endpoint, "amqp-it-identity-sub").await?;
        let topic = Topic::new("rss.it.publisher.identity");
        let token = CancellationToken::new();
        let mut deliveries = subscriber
            .subscribe_ackable(topic.clone(), token.clone())
            .await?;
        let event_id = MessageId::new("evt-publisher-identity-roundtrip-1");

        publisher
            .publish(PublishRequest::new(
                topic,
                event_id.clone(),
                b"identity-roundtrip".to_vec(),
            ))
            .await?;
        let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
            .await?
            .ok_or_else(|| anyhow!("identity roundtrip delivery missing"))?;
        assert_eq!(delivery.message.id, event_id);
        delivery
            .acker
            .settle(AckAction::Ack)
            .await
            .map_err(|error| anyhow!("identity roundtrip ack failed: {error}"))?;

        token.cancel();
        AckableSubscriber::shutdown(&subscriber).await?;
        Publisher::shutdown(&publisher).await?;
        ManagedResource::shutdown(&publisher).await?;
        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    pub(super) async fn post_send_close_is_ambiguous_and_allows_same_id_retry_behavior()
    -> Result<(), FixtureError> {
        let rmq = testkit::env_or_rabbitmq().await?;
        let url = rmq.vhost_url("rss_confirm_rotation").await?;
        let endpoint =
            secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
        let publisher =
            AmqpPublisher::connect(&endpoint, "amqp-it-rotation", Duration::from_secs(6)).await?;
        let topic = Topic::new("rss.it.confirm.rotation");
        let subscriber = AmqpSubscriber::connect(&endpoint, "amqp-it-rotation-sub").await?;
        let token = CancellationToken::new();
        let mut deliveries = subscriber
            .subscribe_ackable(topic.clone(), token.clone())
            .await?;

        let before = publisher
            .transport_snapshot()
            .map_err(|error| anyhow!(error))?;
        let before_generation = before.generation;
        let before_transport = before.transport.clone();
        drop(before);
        let event_id = MessageId::new("evt-confirm-timeout-retry-1");
        publisher.inject_post_send_connection_close_once();
        let error = publisher
            .publish(PublishRequest::new(
                topic.clone(),
                event_id.clone(),
                b"same-id".to_vec(),
            ))
            .await
            .err()
            .ok_or_else(|| anyhow!("post-send barrier must return an ambiguous outcome"))?;
        assert!(error.is_ambiguous());

        let replacement = await_try(Duration::from_secs(10), async || {
            match publisher.transport_snapshot() {
                Ok(snapshot) if snapshot.generation > before_generation => Ok(Some(snapshot)),
                Ok(_) => Ok(None),
                Err(PublisherTransportError::Recovering | PublisherTransportError::Unavailable) => {
                    Ok(None)
                }
                Err(error) => Err(anyhow!(error)),
            }
        })
        .await
        .context("publisher transport replacement wait failed")?;
        assert!(
            !before_transport.connection.status().connected(),
            "retired connection must be closed before replacement becomes ready"
        );
        assert!(
            replacement.transport.connection.status().connected()
                && replacement.transport.confirm_channel.status().connected(),
            "replacement connection and confirm channel must both be connected"
        );
        let replacement_generation = replacement.generation;
        drop(replacement);

        publisher
            .publish(PublishRequest::new(
                topic,
                event_id.clone(),
                b"same-id".to_vec(),
            ))
            .await?;

        let mut delivered_ids = Vec::with_capacity(2);
        for _ in 0..2 {
            let delivery = tokio::time::timeout(Duration::from_secs(5), deliveries.next())
                .await?
                .ok_or_else(|| anyhow!("same-ID retry delivery missing"))?;
            delivered_ids.push(delivery.message.id.as_str().to_string());
            delivery
                .acker
                .settle(AckAction::Ack)
                .await
                .map_err(|error| anyhow!("same-ID delivery ack failed: {error}"))?;
        }
        assert_eq!(
            delivered_ids,
            vec![event_id.as_str().to_string(), event_id.as_str().to_string()],
            "ambiguous attempt and retry must produce two broker-visible deliveries with the original message id"
        );
        assert!(
            replacement_generation > before_generation,
            "ambiguous generation must be retired before same-id retry"
        );

        token.cancel();
        AckableSubscriber::shutdown(&subscriber).await?;
        Publisher::shutdown(&publisher).await?;
        ManagedResource::shutdown(&publisher).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn integration_broker_forced_close_reconnects_fresh_transport() -> Result<(), FixtureError>
    {
        let rmq = testkit::env_or_rabbitmq().await?;
        let vhost = "rss_forced_transport_close";
        let url = rmq.vhost_url(vhost).await?;
        let endpoint =
            secure::AmqpEndpoint::parse(&url, secure::PlaintextEndpointPolicy::AllowLoopback)?;
        let topic = Topic::new("rss.it.forced.transport.close");

        // Provision the queue, then fully close the setup connection. At the forced-close instant
        // the vhost has exactly one AMQP connection: the publisher transport under test.
        let (setup_connection, setup_channel) =
            crate::conn::connect(&endpoint, "amqp-it-forced-close-setup", false).await?;
        setup_channel
            .queue_declare(
                topic.as_str().into(),
                QueueDeclareOptions::default(),
                FieldTable::default(),
            )
            .await?;
        setup_channel
            .close(super::REPLY_SUCCESS, "forced close setup shutdown".into())
            .await?;
        setup_connection
            .close(
                super::REPLY_SUCCESS,
                "forced close setup resource shutdown".into(),
            )
            .await?;

        let publisher =
            AmqpPublisher::connect(&endpoint, "amqp-it-forced-close", Duration::from_secs(6))
                .await?;

        let before = publisher
            .transport_snapshot()
            .map_err(|error| anyhow!(error))?;
        let before_generation = before.generation;
        let before_transport = before.transport.clone();
        drop(before);
        rmq.broker_force_close_one_connection(vhost, "rss integration forced close")
            .await?;
        await_map(Duration::from_secs(5), async || {
            (!before_transport.connection.status().connected()).then_some(())
        })
        .await
        .map_err(|_| anyhow!("broker forced close did not disconnect the publisher"))?;
        let error = publisher
            .publish(PublishRequest::new(
                topic.clone(),
                MessageId::new("evt-forced-close-pre-send"),
                b"must-not-send".to_vec(),
            ))
            .await
            .err()
            .ok_or_else(|| anyhow!("closed Ready transport must fail before send"))?;
        assert_eq!(error.kind(), PublishErrorKind::Transient);
        assert!(!error.is_ambiguous());

        let replacement = await_try(Duration::from_secs(10), async || {
            match publisher.transport_snapshot() {
                Ok(snapshot) if snapshot.generation > before_generation => Ok(Some(snapshot)),
                Ok(_) => Ok(None),
                Err(PublisherTransportError::Recovering | PublisherTransportError::Unavailable) => {
                    Ok(None)
                }
                Err(error) => Err(anyhow!(error)),
            }
        })
        .await
        .context("publisher transport reconnect wait failed")?;
        assert!(replacement.transport.connection.status().connected());
        assert!(replacement.transport.confirm_channel.status().connected());
        assert_eq!(replacement.generation, before_generation + 1);
        drop(replacement);

        let (probe_connection, probe) =
            crate::conn::connect(&endpoint, "amqp-it-forced-close-probe", false).await?;

        publisher
            .publish(PublishRequest::new(
                topic,
                MessageId::new("evt-forced-close-retry"),
                b"fresh-transport".to_vec(),
            ))
            .await?;
        let delivery = tokio::time::timeout(
            Duration::from_secs(5),
            probe.basic_get(
                "rss.it.forced.transport.close".into(),
                BasicGetOptions { no_ack: true },
            ),
        )
        .await??
        .ok_or_else(|| anyhow!("fresh transport delivery missing"))?;
        assert_eq!(
            delivery
                .properties
                .message_id()
                .as_ref()
                .map(|value| value.as_str()),
            Some("evt-forced-close-retry")
        );

        probe
            .close(super::REPLY_SUCCESS, "forced close probe shutdown".into())
            .await?;
        probe_connection
            .close(
                super::REPLY_SUCCESS,
                "forced close probe resource shutdown".into(),
            )
            .await?;
        Publisher::shutdown(&publisher).await?;
        ManagedResource::shutdown(&publisher).await?;
        Ok(())
    }
}
