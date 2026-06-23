//! AMQP 连接接缝（lapin）——publisher / subscriber 共用：连接 + 建 channel + 凭据 redaction。

use std::sync::Arc;

use lapin::options::ConfirmSelectOptions;
use lapin::{Channel, Connection, ConnectionProperties};

/// AMQP `channel.close` / `connection.close` 的成功 reply code（AMQP `REPLY_SUCCESS` = 200）。
pub(crate) const REPLY_SUCCESS: u16 = 200;

/// AMQP 连接 / 建 channel 失败。
///
/// **PII 边界**（同 `diport::PublisherError` 范式）：`Display` 仅安全摘要常量 `"amqp connect failed"`，
/// **绝不含 URL / 凭据**；原始 lapin error 仅作 [`std::error::Error::source`] 内部保留，不进默认日志。
/// `Debug` 手写（不 derive）——隐藏 `source`：lapin error 的 `Debug` 可能含 host/连接上下文，故 `{:?}`
/// 也只输出安全摘要（与 `AmqpUrl` 同范式）。连接诊断经 [`connect`] 内 `tracing::warn!` 以
/// `secure::redact_url_credentials`（抹 userinfo）+ `secure::redact_error`（顶层 Display）记录。
#[derive(thiserror::Error)]
#[error("amqp connect failed")]
pub struct AmqpConnectError {
    #[source]
    source: lapin::Error,
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
    url: &str,
    name: &str,
    confirm: bool,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    let conn = Connection::connect(url, ConnectionProperties::default())
        .await
        .map_err(|source| connect_err(source, url, name))?;
    let channel = conn
        .create_channel()
        .await
        .map_err(|source| connect_err(source, url, name))?;
    if confirm {
        // publisher confirms：publish 后 await PublisherConfirm 才能拿到真实 Ack/Nack（否则 NotRequested）。
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await
            .map_err(|source| connect_err(source, url, name))?;
    }
    tracing::info!(
        target: "amqp",
        resource = name,
        endpoint = %secure::redact_url_credentials(url),
        "amqp connected",
    );
    Ok((Arc::new(conn), channel))
}

fn connect_err(source: lapin::Error, url: &str, name: &str) -> AmqpConnectError {
    tracing::warn!(
        target: "amqp",
        resource = name,
        // user:pass -> <redacted>；保留 scheme/host/port/vhost 供诊断。
        endpoint = %secure::redact_url_credentials(url),
        // 顶层 Display，不展开 source 链（杜绝第三方 error 链泄 PII）。
        error = %secure::redact_error(&source),
        "amqp connect failed",
    );
    AmqpConnectError { source }
}
