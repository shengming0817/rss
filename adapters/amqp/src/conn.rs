//! AMQP 连接接缝（lapin）——publisher / subscriber 共用：连接 + 建 channel + 凭据 redaction。

use std::sync::Arc;

use lapin::options::ConfirmSelectOptions;
use lapin::{Channel, Connection, ConnectionProperties};

use crate::conn_events::{
    RecoveryConnectResult, RecoveryFailureReason, RecoveryFailureStage, emit_connect_failed,
    emit_connected, emit_recovery_connect_result,
};

/// AMQP `channel.close` / `connection.close` 的成功 reply code（AMQP `REPLY_SUCCESS` = 200）。
pub(crate) const REPLY_SUCCESS: u16 = 200;

/// AMQP 连接 / 建 channel 失败。
///
/// **PII 边界**（同 `diport::PublisherError` 范式）：`Display` 仅安全摘要常量 `"amqp connect failed"`，
/// **绝不含 URL / 凭据**；原始 lapin error 仅作 [`std::error::Error::source`] 内部保留，不进默认日志。
/// `Debug` 手写（不 derive）——隐藏 `source`：lapin error 的 `Debug` 可能含 host/连接上下文，故 `{:?}`
/// 也只输出安全摘要（与 `AmqpUrl` 同范式）。连接诊断经 `crate::conn_events`：`AmqpEndpoint` Display
/// （Hard）+ `secure::redact_error`（顶层 Display）。
#[derive(thiserror::Error)]
#[error("amqp connect failed")]
pub struct AmqpConnectError {
    #[source]
    source: AmqpConnectErrorSource,
}

#[derive(Debug, thiserror::Error)]
enum AmqpConnectErrorSource {
    #[error(transparent)]
    Transport(#[from] lapin::Error),
    #[error("invalid amqp publisher timeout")]
    InvalidPublisherTimeout,
}

impl std::fmt::Debug for AmqpConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 不展开 source（lapin::Error Debug 可能含连接上下文）；{:?} 仅安全摘要（PII 边界）。
        f.write_str("AmqpConnectError(\"amqp connect failed\")")
    }
}

/// 从单个 per-domain AMQP URL 连接并开一个 channel（URL 含 `user:pass@host/vhost`——per-domain
/// vhost/credential 隔离 seam）。`confirm=true` 时启用 publisher confirms（`confirm_select`），让
/// publish 的 broker ack/nack 可被检测（durable publish-ok 语义，见 publisher）；subscriber 传 false。
/// 失败经 redaction funnel 记日志，URL 原文绝不进日志。
pub(crate) async fn connect(
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    confirm: bool,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    connect_with_context(endpoint, name, confirm, ConnectContext::Initial).await
}

/// RSS-owned publisher replacement entry point. Recovery deliberately uses a different closed
/// logging context from initial assembly: endpoint identity is needed to authenticate the socket,
/// but it is not admitted to recovery events.
pub(crate) async fn reconnect_publisher(
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    retiring_generation: u64,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    connect_with_context(
        endpoint,
        name,
        true,
        ConnectContext::Recovery {
            replacement_generation: retiring_generation.saturating_add(1),
        },
    )
    .await
}

#[derive(Clone, Copy)]
enum ConnectContext {
    Initial,
    Recovery { replacement_generation: u64 },
}

async fn connect_with_context(
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    confirm: bool,
    context: ConnectContext,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    #[allow(clippy::disallowed_methods)]
    // reason: 唯一 AMQP driver connect callsite；endpoint 已在组合根经 secure::AmqpEndpoint 校验。
    let url = endpoint.expose();
    // Intentionally keep lapin auto-recovery disabled (`ConnectionProperties::default()` has zero retries and
    // `auto_recover=false`). Publisher transport replacement is RSS-owned and bounded by one absolute deadline;
    // enabling lapin recovery here would create an uncancellable second reconnect owner.
    let conn = Arc::new(
        Connection::connect(url, ConnectionProperties::default())
            .await
            .map_err(|source| {
                connect_err(
                    source,
                    endpoint,
                    name,
                    context,
                    RecoveryFailureStage::Connect,
                )
            })?,
    );
    let channel = conn.create_channel().await.map_err(|source| {
        connect_err(
            source,
            endpoint,
            name,
            context,
            RecoveryFailureStage::CreateChannel,
        )
    })?;
    if confirm {
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|source| {
                connect_err(
                    source,
                    endpoint,
                    name,
                    context,
                    RecoveryFailureStage::ConfirmSelect,
                )
            })?;
    }
    match context {
        ConnectContext::Initial => emit_connected(name, endpoint),
        ConnectContext::Recovery {
            replacement_generation,
        } => emit_recovery_connect_result(
            name,
            replacement_generation,
            RecoveryConnectResult::Connected,
        ),
    }
    Ok((conn, channel))
}

fn connect_err(
    source: lapin::Error,
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    context: ConnectContext,
    recovery_stage: RecoveryFailureStage,
) -> AmqpConnectError {
    match context {
        ConnectContext::Initial => emit_connect_failed(name, endpoint, &source),
        ConnectContext::Recovery {
            replacement_generation,
        } => emit_recovery_connect_result(
            name,
            replacement_generation,
            RecoveryConnectResult::Failed {
                stage: recovery_stage,
                reason: recovery_failure_reason(&source),
            },
        ),
    }
    AmqpConnectError {
        source: source.into(),
    }
}

fn recovery_failure_reason(error: &lapin::Error) -> RecoveryFailureReason {
    match error.kind() {
        lapin::ErrorKind::IOError(_) => RecoveryFailureReason::Io,
        lapin::ErrorKind::ProtocolError(_) => RecoveryFailureReason::Protocol,
        lapin::ErrorKind::InvalidChannel(_)
        | lapin::ErrorKind::InvalidChannelState(..)
        | lapin::ErrorKind::InvalidConnectionState(_) => RecoveryFailureReason::State,
        lapin::ErrorKind::RuntimeShutdownError(_) | lapin::ErrorKind::NoDefaultRuntime => {
            RecoveryFailureReason::Runtime
        }
        lapin::ErrorKind::MissingHeartbeatError => RecoveryFailureReason::Heartbeat,
        _ => RecoveryFailureReason::Client,
    }
}

/// 构造 publisher timeout 配置错误。仅供 publisher 在任何 endpoint 暴露/网络连接前 fail-closed；
/// 对外错误面仍是固定安全摘要，避免把配置细节与连接信息拼接进日志。
pub(crate) fn invalid_publisher_timeout() -> AmqpConnectError {
    AmqpConnectError {
        source: AmqpConnectErrorSource::InvalidPublisherTimeout,
    }
}

#[cfg(test)]
mod recovery_failure_reason_tests {
    use std::sync::Arc;

    use lapin::ErrorKind;
    use lapin::protocol::{AMQPError, AMQPErrorKind, AMQPHardError};

    use super::{RecoveryFailureReason, recovery_failure_reason};

    #[test]
    fn lapin_errors_map_to_closed_low_cardinality_recovery_reasons() {
        let cases = [
            (
                ErrorKind::IOError(Arc::new(std::io::Error::other("secret raw io"))).into(),
                RecoveryFailureReason::Io,
            ),
            (
                ErrorKind::ProtocolError(AMQPError::new(
                    AMQPErrorKind::Hard(AMQPHardError::CONNECTIONFORCED),
                    "secret raw protocol".into(),
                ))
                .into(),
                RecoveryFailureReason::Protocol,
            ),
            (
                ErrorKind::InvalidConnectionState(lapin::ConnectionState::Error).into(),
                RecoveryFailureReason::State,
            ),
            (
                ErrorKind::RuntimeShutdownError(Arc::new(std::io::Error::other(
                    "secret raw runtime",
                )))
                .into(),
                RecoveryFailureReason::Runtime,
            ),
            (
                ErrorKind::MissingHeartbeatError.into(),
                RecoveryFailureReason::Heartbeat,
            ),
            (
                ErrorKind::AuthProviderError("secret raw client".into()).into(),
                RecoveryFailureReason::Client,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(recovery_failure_reason(&error), expected);
        }
    }
}
