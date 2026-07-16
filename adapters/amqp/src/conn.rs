//! AMQP 连接接缝（lapin）——publisher / subscriber 共用：连接 + 建 channel + 凭据 redaction。

use std::sync::Arc;

use lapin::options::ConfirmSelectOptions;
use lapin::{Channel, Connection, ConnectionProperties};

use crate::conn_events::{emit_connect_failed, emit_connected};

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
    #[allow(clippy::disallowed_methods)]
    // reason: 唯一 AMQP driver connect callsite；endpoint 已在组合根经 secure::AmqpEndpoint 校验。
    let url = endpoint.expose();
    let conn = Arc::new(
        Connection::connect(url, ConnectionProperties::default())
            .await
            .map_err(|source| connect_err(source, endpoint, name))?,
    );
    let channel = if confirm {
        confirmed_channel(conn.as_ref())
            .await
            .map_err(|source| connect_err(source, endpoint, name))?
    } else {
        conn.create_channel()
            .await
            .map_err(|source| connect_err(source, endpoint, name))?
    };
    emit_connected(name, endpoint);
    Ok((conn, channel))
}

/// 在既有 publisher connection 上创建一个全新的 confirm channel。
///
/// 初始连接和 timeout 后的 channel rotation 共用这一接缝，避免 replacement 忘记
/// `confirm_select` 而把 [`lapin::Confirmation::NotRequested`] 误当 durable publish 成功。
pub(crate) async fn confirmed_channel(conn: &Connection) -> lapin::Result<Channel> {
    let channel = conn.create_channel().await?;
    channel
        .confirm_select(ConfirmSelectOptions::default())
        .await?;
    Ok(channel)
}

fn connect_err(
    source: lapin::Error,
    endpoint: &secure::AmqpEndpoint,
    name: &str,
) -> AmqpConnectError {
    emit_connect_failed(name, endpoint, &source);
    AmqpConnectError {
        source: source.into(),
    }
}

/// 构造 publisher timeout 配置错误。仅供 publisher 在任何 endpoint 暴露/网络连接前 fail-closed；
/// 对外错误面仍是固定安全摘要，避免把配置细节与连接信息拼接进日志。
pub(crate) fn invalid_publisher_timeout() -> AmqpConnectError {
    AmqpConnectError {
        source: AmqpConnectErrorSource::InvalidPublisherTimeout,
    }
}
