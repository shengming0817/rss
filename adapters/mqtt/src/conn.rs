//! MQTT 连接接缝（rumqttc v5）——publisher / subscriber 共用：URL 解析 + 连接（poll 至 ConnAck 的
//! fail-fast）+ 凭据 redaction + driver 共享常量 / 优雅断连 / teardown。
//!
//! rumqttc 与 lapin 的关键差异：lapin 自驱 I/O，rumqttc 须调用方持续 poll `EventLoop` 才收发。故
//! [`connect`] 内联 poll 直到 `ConnAck`（连接 fail-fast），随后把已连接的 `EventLoop` 交回调用方
//! spawn 的 driver task 持续泵；关停时 driver 自身经 [`graceful_disconnect`] 发 DISCONNECT 再退出
//! （eventloop 由同一 task 拥有 ⇒ DISCONNECT 能真正发出，不会因停 poll 而只剩 TCP 关闭）。
//! ref: bytebeamio/rumqtt rumqttc/examples/asyncpubsub_v5.rs@main。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rumqttc::v5::mqttbytes::v5::{Packet, PubAckReason, SubscribeReasonCode};
use rumqttc::v5::{AsyncClient, ConnectionError, Event, EventLoop, MqttOptions};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// AsyncClient → EventLoop 请求通道容量（出站 publish/subscribe 缓冲；driver poll 驱动消费）。
const REQUEST_CHANNEL_CAP: usize = 100;
/// keep-alive ping 周期（broker 据此探活；rumqttc 自动发 PINGREQ）。
const KEEP_ALIVE: Duration = Duration::from_secs(30);
/// 连接 fail-fast 上限——poll 至 ConnAck 的有界等待，防黑洞 broker 永久挂起 `connect().await`
/// （Option 范式 §强依赖 fail-fast）。连接拒绝（如不可达端口）由 rumqttc 立即返回 `ConnectionError`，
/// 不依赖本超时；本超时只兜底 TCP 黑洞。**v1 不可配置**——生产需可调超时时开放 `connect` 参数 = follow-up。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// driver poll 错误后的退避——防 broker 永久不可达时 busy-loop（rumqttc 下次 poll 自动重连）。
/// publisher / subscriber driver 经 [`note_poll_health`] 共用（避免两处重复定义同义常量）。
const DRIVER_ERROR_BACKOFF: Duration = Duration::from_secs(1);
/// 优雅断连有界泵——driver 关停时发 DISCONNECT 后泵 eventloop 至连接关闭的上限，防 broker 异常时挂死。
const GRACEFUL_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// publish/subscribe 等 broker ACK（PUBACK/SUBACK）的上限——fail-fast，不让调用方因 broker 静默永久挂起。
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// 进程内 client-id 序号——MQTT 同 client-id 重连会互踢，故每条连接派生唯一 id。
/// `Relaxed` 足够：单一 atomic 的 fetch_add 有全局 modification order，唯一性（不重复）天然成立；
/// 跨实例唯一性另靠 client-id 内的 `process::id()`（见 [`connect`]）。
static CLIENT_SEQ: AtomicU64 = AtomicU64::new(0);

/// 解析后的连接坐标（[`parse_mqtt_url`] 产出）——具名字段而非裸 tuple（可读 + 消除 type_complexity carve-out）。
/// **v1 无 credentials 字段**：明文 mqtt:// 禁止携带凭据（见 [`MqttUrlError::CredentialsRequireTls`]）；
/// per-domain 凭据 / mTLS 须 `mqtts://`（follow-up #1264）。
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MqttEndpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// MQTT URL 解析失败（纯函数 [`parse_mqtt_url`] 产出，无 broker 可单测）。
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MqttUrlError {
    /// 缺 `mqtt://` scheme（`mqtts://` TLS 本 PR 未支持，= follow-up）。
    #[error("mqtt url must start with mqtt://")]
    Scheme,
    /// 明文 mqtt:// 携带 userinfo 凭据——fail-closed 拒绝：凭据走明文 = 泄露，须 mqtts:// + mTLS（#1264）。
    #[error("plaintext mqtt:// must not carry credentials (use mqtts:// once available)")]
    CredentialsRequireTls,
    /// 缺 host 段。
    #[error("mqtt url missing host")]
    Host,
    /// port 段非法 u16。
    #[error("mqtt url has invalid port")]
    Port,
}

/// 连接失败内层成因（不进 Display 凭据边界——仅作 [`MqttConnectError`] 的 internal source）。
#[derive(Debug, thiserror::Error)]
enum ConnectFault {
    /// URL 解析失败。
    #[error("invalid mqtt url")]
    Url(#[source] MqttUrlError),
    /// rumqttc 连接错误（TCP 拒绝 / 协议错误等）。
    #[error("mqtt connection error")]
    Connection(#[source] ConnectionError),
    /// poll 至 ConnAck 超时（黑洞 broker 兜底）。
    #[error("mqtt connect timed out")]
    Timeout,
}

/// MQTT 连接 / 握手失败。
///
/// **PII 边界**（同 `diport::PublisherError` / `amqp::conn::AmqpConnectError` 范式）：`Display` 仅安全
/// 摘要常量 `"mqtt connect failed"`，**绝不含 URL / 凭据**；内层成因仅作 [`std::error::Error::source`]
/// 保留，不进默认日志。`Debug` 手写（不 derive）——隐藏 source：rumqttc error 的 `Debug` 可能含
/// host/连接上下文，故 `{:?}` 也只输出安全摘要。连接诊断经 [`connect`] 内 `tracing::warn!` 以
/// `secure::redact_url_credentials`（抹 userinfo）+ `secure::redact_error`（顶层 Display）记录。
#[derive(thiserror::Error)]
#[error("mqtt connect failed")]
pub struct MqttConnectError {
    #[source]
    source: ConnectFault,
}

impl std::fmt::Debug for MqttConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 不展开 source（rumqttc error Debug 可能含连接上下文）；{:?} 仅安全摘要（PII 边界）。
        f.write_str("MqttConnectError(\"mqtt connect failed\")")
    }
}

/// 解析 `mqtt://host[:port]` → [`MqttEndpoint`]。**纯函数**（无 broker 可单测）。
///
/// - 仅接受 `mqtt://`（明文）；`mqtts://`（TLS）本 PR 未支持（= follow-up，依赖 softca #1266 + #1264）。
/// - **fail-closed 拒绝 userinfo**：明文携凭据会把 user:pass 走明文传输（泄露），须 mqtts:// + mTLS。
/// - 缺 port 段默认 1883（MQTT 标准端口）。
/// - 仅精确 host:port（不解析 IPv6 字面量 / query 段）——v1 transport 边界足够。
pub(crate) fn parse_mqtt_url(url: &str) -> Result<MqttEndpoint, MqttUrlError> {
    let rest = url.strip_prefix("mqtt://").ok_or(MqttUrlError::Scheme)?;
    // 明文 mqtt:// 禁止 userinfo（任意 `@` 即视为携凭据）→ fail-closed（凭据须经 mqtts:// + mTLS）。
    if rest.contains('@') {
        return Err(MqttUrlError::CredentialsRequireTls);
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| MqttUrlError::Port)?;
            (h, port)
        }
        None => (rest, 1883),
    };
    if host.is_empty() {
        return Err(MqttUrlError::Host);
    }
    Ok(MqttEndpoint {
        host: host.to_string(),
        port,
    })
}

/// 从 per-domain MQTT URL 建连接并 poll 至 `ConnAck`（连接 fail-fast）。`role` 用于派生唯一 client-id
/// 前缀 + 日志 resource 名。返回已连接的 `(AsyncClient, EventLoop)`，由调用方 spawn driver 持续 poll。
/// 失败经 redaction funnel 记日志，URL 原文绝不进日志。
pub(crate) async fn connect(
    url: &str,
    role: &str,
) -> Result<(AsyncClient, EventLoop), MqttConnectError> {
    let endpoint = parse_mqtt_url(url).map_err(|e| connect_err(ConnectFault::Url(e), url, role))?;
    // 唯一 client-id：role + 进程 pid + 进程内序号（pid 防多实例/多进程同 seq 碰撞互踢，seq 防进程内碰撞）。
    let seq = CLIENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let client_id = format!("rss-{role}-{}-{seq}", std::process::id());
    let mut options = MqttOptions::new(client_id, endpoint.host, endpoint.port);
    options.set_keep_alive(KEEP_ALIVE);
    // clean_start：每次连接全新 session（v1 transport 边界——auto-ack、不做持久 session/手工 ack）。
    // 影响：断连期间 broker 侧 QoS1 pending 消息于重连后丢弃（持久 session = follow-up，与 DLT 一并处理）。
    options.set_clean_start(true);
    // v1 无凭据：明文 mqtt:// 禁 userinfo（parse 已 fail-closed）；mqtts:// + mTLS = follow-up #1264。
    let (client, mut eventloop) = AsyncClient::new(options, REQUEST_CHANNEL_CAP);
    // poll 至 ConnAck（有界）——连接拒绝立即冒泡，黑洞由 CONNECT_TIMEOUT 兜底。
    let handshake = tokio::time::timeout(CONNECT_TIMEOUT, await_connack(&mut eventloop)).await;
    match handshake {
        Ok(Ok(())) => {
            tracing::info!(
                target: "mqtt",
                resource = role,
                endpoint = %secure::redact_url_credentials(url),
                "mqtt connected",
            );
            Ok((client, eventloop))
        }
        Ok(Err(e)) => Err(connect_err(ConnectFault::Connection(e), url, role)),
        Err(_elapsed) => Err(connect_err(ConnectFault::Timeout, url, role)),
    }
}

/// poll eventloop 直到收到 `ConnAck`（成功）或连接错误。
async fn await_connack(eventloop: &mut EventLoop) -> Result<(), ConnectionError> {
    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Packet::ConnAck(_))) => return Ok(()),
            Ok(_) => continue,
            Err(e) => return Err(e),
        }
    }
}

fn connect_err(source: ConnectFault, url: &str, role: &str) -> MqttConnectError {
    tracing::warn!(
        target: "mqtt",
        resource = role,
        // user:pass -> <redacted>；保留 scheme/host/port 供诊断。
        endpoint = %secure::redact_url_credentials(url),
        // 顶层 Display，不展开 source 链（杜绝第三方 error 链泄 PII）。
        error = %secure::redact_error(&source),
        "mqtt connect failed",
    );
    MqttConnectError { source }
}

/// driver poll 后的健康状态机（publisher / subscriber driver 共用）：Err → 记 warn + 退避（防 busy-loop，
/// rumqttc 下次 poll 自动重连）；从 degraded 恢复的首个 Ok → 记 info（断连恢复可观测）。借 `&polled`，
/// caller 在其后仍可按需消费 `Ok(event)`。
#[allow(clippy::cognitive_complexity)]
// reason: 复杂度由 tracing!（info/warn）宏展开撑高，非真实分支复杂——逻辑仅「Ok 恢复 / Err 退避」二分。
// 同 bootstrap/shutdown.rs 的 select!/tracing 宏膨胀 carve-out 范式。
pub(crate) async fn note_poll_health(
    polled: &std::result::Result<Event, ConnectionError>,
    degraded: &mut bool,
    role: &str,
) {
    match polled {
        Ok(_) => {
            if *degraded {
                tracing::info!(target: "mqtt", resource = role, "mqtt eventloop reconnected");
                *degraded = false;
            }
        }
        Err(e) => {
            *degraded = true;
            tracing::warn!(target: "mqtt", resource = role, error = %secure::redact_error(e), "mqtt eventloop error; retrying");
            tokio::time::sleep(DRIVER_ERROR_BACKOFF).await;
        }
    }
}

/// driver 关停前的**优雅断连**：发 DISCONNECT 后有界泵 eventloop，让 DISCONNECT 包真正写出（避免只剩
/// TCP 关闭触发 broker LWT）。由 driver task 自身调用（同一 task 拥有 eventloop ⇒ poll 能推进出站）。
pub(crate) async fn graceful_disconnect(
    role: &str,
    client: &AsyncClient,
    eventloop: &mut EventLoop,
) {
    if client.disconnect().await.is_err() {
        // 入队失败（连接已断）：无需再泵。
        return;
    }
    // 有界泵：poll 直到连接关闭（Err，含我方 DISCONNECT 后 broker/我方关闭）或超时。
    let drained = tokio::time::timeout(GRACEFUL_DISCONNECT_TIMEOUT, async {
        while eventloop.poll().await.is_ok() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(target: "mqtt", resource = role, "mqtt graceful disconnect drain timed out");
    }
}

/// driver teardown（publisher / subscriber 的 port-local + `ManagedResource::shutdown` 共用）：cancel
/// driver token（driver select 命中 break → 自身 `graceful_disconnect` → 退出）→ await driver 退出。
/// **幂等**：只有取到 `JoinHandle` 的首个调用方执行（取走后 `None` ⇒ 第二次 no-op），故 port-local 与
/// ManagedResource 两条 shutdown 路径都调它也不会重复断连（断连归 driver 唯一执行）。
pub(crate) async fn teardown(
    role: &str,
    token: &CancellationToken,
    driver: &Mutex<Option<JoinHandle<()>>>,
) {
    let Some(handle) = take_driver(role, driver) else {
        return;
    };
    token.cancel();
    let _ = handle.await;
}

/// 取出 driver `JoinHandle`（锁中毒只记日志——无 handle 可 await，driver 已被 token 通知退出）。
fn take_driver(role: &str, driver: &Mutex<Option<JoinHandle<()>>>) -> Option<JoinHandle<()>> {
    match driver.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => {
            tracing::error!(target: "mqtt", resource = role, "mqtt driver handle mutex poisoned");
            None
        }
    }
}

// ── broker ACK 确认（publish→PUBACK / subscribe→SUBACK，FIFO-pkid 关联）──────────

/// broker ACK 失败成因（不暴露 broker 细节——PII / 安全边界，统一 redacted 摘要）。
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfirmError {
    /// broker 以**永久** reason 拒绝（PUBACK NotAuthorized / TopicNameInvalid / PayloadFormatInvalid、
    /// SUBACK 失败码等，重试无意义）→ [`classify_confirm`](crate::publisher) 判 permanent，首投即 DLX。
    #[error("broker rejected the request (permanent)")]
    Rejected,
    /// broker 以**瞬态** reason 拒绝（PUBACK QuotaExceeded 等资源压力 / broker 端未知错误，可退避重试）
    /// → 判 transient，退避至预算耗尽（#1212：瞬态误判永久会破坏 L2 最终送达，故未知 reason 默认归此）。
    #[error("broker rejected the request (transient)")]
    RejectedTransient,
    /// 连接在 ACK 前断开（driver fail_all fanout）。
    #[error("connection lost before broker ack")]
    Disconnected,
    /// ACK 超时（broker 静默兜底）。
    #[error("broker ack timed out")]
    Timeout,
}

/// broker ACK 结果（`Ok` = broker 确认；`Err` = 拒绝 / 断连 / 超时）。
pub(crate) type ConfirmResult = Result<(), ConfirmError>;

/// PUBACK reason → 结果：`Success` / `NoMatchingSubscribers`（broker 已接收）视为成功；
/// **已知永久**拒绝因（NotAuthorized / TopicNameInvalid / PayloadFormatInvalid，重试同一消息必然再失败）
/// → [`ConfirmError::Rejected`]；其余（QuotaExceeded 等资源压力 / broker 端未知错误）默认
/// [`ConfirmError::RejectedTransient`]（退避重试，不过早 DLX——瞬态误判永久比反向代价高，破坏 L2 最终送达，
/// 与 amqp 侧 `can_be_recovered()` default-transient 对称，#1212）。
pub(crate) fn puback_result(reason: &PubAckReason) -> ConfirmResult {
    match reason {
        PubAckReason::Success | PubAckReason::NoMatchingSubscribers => Ok(()),
        PubAckReason::NotAuthorized
        | PubAckReason::TopicNameInvalid
        | PubAckReason::PayloadFormatInvalid => Err(ConfirmError::Rejected),
        _ => Err(ConfirmError::RejectedTransient),
    }
}

/// SUBACK return codes → 结果：全部 `Success(_)` 成功，任一失败码（NotAuthorized 等）即拒绝。
pub(crate) fn suback_result(return_codes: &[SubscribeReasonCode]) -> ConfirmResult {
    if return_codes
        .iter()
        .all(|c| matches!(c, SubscribeReasonCode::Success(_)))
    {
        Ok(())
    } else {
        Err(ConfirmError::Rejected)
    }
}

/// broker ACK 确认簿（publish→PUBACK / subscribe→SUBACK 共用）。
///
/// rumqttc 高层 API **不回传 pkid**，故经「请求入队顺序 == eventloop 出站顺序（单 FIFO 请求通道）」关联：
/// [`submit`](Self::submit) 在 `send_gate` 下 push oneshot 进 `awaiting_send` 再入队（串行化保 FIFO 不乱序）；
/// driver 见 `Outgoing::{Publish,Subscribe}(pkid)` 调 [`on_sent`](Self::on_sent) 出队 → `awaiting_ack[pkid]`，
/// 见 `Incoming::{PubAck,SubAck}` 调 [`on_ack`](Self::on_ack) 结算；连接断开调 [`fail_all`](Self::fail_all)。
pub(crate) struct Confirmations {
    awaiting_send: Mutex<VecDeque<oneshot::Sender<ConfirmResult>>>,
    awaiting_ack: Mutex<HashMap<u16, oneshot::Sender<ConfirmResult>>>,
    send_gate: tokio::sync::Mutex<()>,
}

impl Confirmations {
    pub(crate) fn new() -> Self {
        Self {
            awaiting_send: Mutex::new(VecDeque::new()),
            awaiting_ack: Mutex::new(HashMap::new()),
            send_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// 串行入队 + 等 broker ACK：`send_gate` 下 push oneshot 再跑 `enqueue`（client.publish/subscribe），
    /// 保 `awaiting_send` 顺序 == eventloop 出站顺序；随后有界等 driver 结算（[`ACK_TIMEOUT`]）。
    pub(crate) async fn submit<Fut, E>(&self, enqueue: Fut) -> ConfirmResult
    where
        Fut: std::future::Future<Output = Result<(), E>>,
    {
        let (tx, rx) = oneshot::channel();
        {
            let _gate = self.send_gate.lock().await;
            if let Ok(mut q) = self.awaiting_send.lock() {
                q.push_back(tx);
            } else {
                return Err(ConfirmError::Disconnected);
            }
            if enqueue.await.is_err() {
                // 入队失败：弹回刚 push 的 oneshot（永不会有 Outgoing 关联它）。
                if let Ok(mut q) = self.awaiting_send.lock() {
                    q.pop_back();
                }
                return Err(ConfirmError::Disconnected);
            }
        }
        match tokio::time::timeout(ACK_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ConfirmError::Disconnected), // sender dropped（driver 退出）
            Err(_) => Err(ConfirmError::Timeout),
        }
    }

    /// driver: `Outgoing::{Publish,Subscribe}(pkid)` → `awaiting_send` 出队 → `awaiting_ack[pkid]`。
    pub(crate) fn on_sent(&self, pkid: u16) {
        let tx = self
            .awaiting_send
            .lock()
            .ok()
            .and_then(|mut q| q.pop_front());
        if let Some(tx) = tx
            && let Ok(mut m) = self.awaiting_ack.lock()
        {
            m.insert(pkid, tx);
        }
    }

    /// driver: `Incoming::{PubAck,SubAck}` → 结算 `awaiting_ack[pkid]`。
    pub(crate) fn on_ack(&self, pkid: u16, result: ConfirmResult) {
        let tx = self
            .awaiting_ack
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&pkid));
        if let Some(tx) = tx {
            let _ = tx.send(result);
        }
    }

    /// driver: 连接错误 → 全部 pending（send + ack）以 `Disconnected` fanout，不让调用方挂到超时。
    pub(crate) fn fail_all(&self) {
        if let Ok(mut q) = self.awaiting_send.lock() {
            for tx in q.drain(..) {
                let _ = tx.send(Err(ConfirmError::Disconnected));
            }
        }
        if let Ok(mut m) = self.awaiting_ack.lock() {
            for (_, tx) in m.drain() {
                let _ = tx.send(Err(ConfirmError::Disconnected));
            }
        }
    }

    /// 待 `Outgoing` 关联的 pending 请求数（测试用）。
    #[cfg(test)]
    pub(crate) fn pending_send_len(&self) -> usize {
        self.awaiting_send.lock().map(|q| q.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rumqttc::v5::mqttbytes::QoS;
    use rumqttc::v5::mqttbytes::v5::{PubAckReason, SubscribeReasonCode};

    use super::{
        ConfirmError, Confirmations, MqttEndpoint, MqttUrlError, parse_mqtt_url, puback_result,
        suback_result,
    };

    fn endpoint(host: &str, port: u16) -> MqttEndpoint {
        MqttEndpoint {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn parses_host_and_port() {
        assert_eq!(
            parse_mqtt_url("mqtt://broker.example:1884"),
            Ok(endpoint("broker.example", 1884))
        );
    }

    #[test]
    fn defaults_port_1883_when_absent() {
        assert_eq!(
            parse_mqtt_url("mqtt://localhost"),
            Ok(endpoint("localhost", 1883))
        );
    }

    #[test]
    fn rejects_userinfo_on_plaintext() {
        // 明文 mqtt:// 携凭据 fail-closed（凭据走明文 = 泄露；须 mqtts:// + mTLS）。
        assert_eq!(
            parse_mqtt_url("mqtt://alice:s3cr3t@h:1885"),
            Err(MqttUrlError::CredentialsRequireTls)
        );
        assert_eq!(
            parse_mqtt_url("mqtt://alice@h:1883"),
            Err(MqttUrlError::CredentialsRequireTls)
        );
    }

    #[test]
    fn rejects_non_mqtt_scheme() {
        assert_eq!(parse_mqtt_url("amqp://h:1883"), Err(MqttUrlError::Scheme));
        // mqtts:// (TLS) 本 PR 未支持——亦走 Scheme 拒绝（strip mqtt:// 失败）。
        assert_eq!(parse_mqtt_url("mqtts://h:8883"), Err(MqttUrlError::Scheme));
    }

    #[test]
    fn rejects_empty_host() {
        assert_eq!(parse_mqtt_url("mqtt://:1883"), Err(MqttUrlError::Host));
    }

    #[test]
    fn rejects_invalid_port() {
        assert_eq!(parse_mqtt_url("mqtt://h:notaport"), Err(MqttUrlError::Port));
    }

    #[test]
    fn rejects_port_overflow() {
        // 65536 > u16::MAX ⇒ parse 失败 → Port。
        assert_eq!(parse_mqtt_url("mqtt://h:65536"), Err(MqttUrlError::Port));
    }

    // #1212：PUBACK reason → 永久/瞬态分类。已知永久因（NotAuthorized 等）→ Rejected；资源压力
    // （QuotaExceeded）+ broker 端未知错误 → RejectedTransient（退避重试，不过早 DLX）。
    #[test]
    fn puback_success_reasons_ok_permanent_vs_transient_rejected() {
        assert!(puback_result(&PubAckReason::Success).is_ok());
        assert!(puback_result(&PubAckReason::NoMatchingSubscribers).is_ok());
        // 已知永久拒绝因 → Rejected。
        for reason in [
            PubAckReason::NotAuthorized,
            PubAckReason::TopicNameInvalid,
            PubAckReason::PayloadFormatInvalid,
        ] {
            assert!(
                matches!(puback_result(&reason), Err(ConfirmError::Rejected)),
                "{reason:?} should be permanent Rejected"
            );
        }
        // 资源压力 / broker 端未知错误 → RejectedTransient（保 L2 最终送达）。
        for reason in [
            PubAckReason::QuotaExceeded,
            PubAckReason::UnspecifiedError,
            PubAckReason::ImplementationSpecificError,
        ] {
            assert!(
                matches!(puback_result(&reason), Err(ConfirmError::RejectedTransient)),
                "{reason:?} should be transient"
            );
        }
    }

    #[test]
    fn suback_all_success_ok_any_failure_rejected() {
        assert!(suback_result(&[SubscribeReasonCode::Success(QoS::AtLeastOnce)]).is_ok());
        assert!(
            suback_result(&[
                SubscribeReasonCode::Success(QoS::AtLeastOnce),
                SubscribeReasonCode::NotAuthorized,
            ])
            .is_err()
        );
        assert!(suback_result(&[SubscribeReasonCode::Failure]).is_err());
    }

    /// submit 注册后，driver on_sent→on_ack 结算成功。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)] // 测试断言：item-level carve-out（workspace lints 约定）
    async fn submit_resolves_when_driver_acks() {
        let confirm = Arc::new(Confirmations::new());
        let c2 = Arc::clone(&confirm);
        let task =
            tokio::spawn(async move { c2.submit(async { Ok::<(), std::io::Error>(()) }).await });
        // 轮询直到 submit 已 push（pending_send==1），最多 ~1s。
        for _ in 0..100 {
            if confirm.pending_send_len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            confirm.pending_send_len(),
            1,
            "submit 应已 push 一条 pending"
        );
        confirm.on_sent(7);
        confirm.on_ack(7, Ok(()));
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("task 未超时")
            .expect("task join");
        assert!(result.is_ok(), "broker ACK 成功 ⇒ submit Ok");
    }

    /// 连接断开 → fail_all fanout，submit 立即得 Disconnected（不挂到超时）。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)] // 测试断言：item-level carve-out（workspace lints 约定）
    async fn submit_fails_when_connection_lost() {
        let confirm = Arc::new(Confirmations::new());
        let c2 = Arc::clone(&confirm);
        let task =
            tokio::spawn(async move { c2.submit(async { Ok::<(), std::io::Error>(()) }).await });
        for _ in 0..100 {
            if confirm.pending_send_len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        confirm.fail_all();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("task 未超时")
            .expect("task join");
        assert!(result.is_err(), "连接断开 ⇒ submit Err（非挂起）");
    }
}
