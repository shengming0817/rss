//! AMQP 连接接缝（lapin）——publisher / subscriber 共用：连接 + 建 channel + 凭据 redaction。

use std::sync::Arc;

#[cfg(any(test, feature = "integration-test-support"))]
use lapin::DefaultConnectionBuilder;
use lapin::options::ConfirmSelectOptions;
use lapin::tcp::{AsyncTcpStream, RustlsConnector, RustlsConnectorConfig};
use lapin::uri::{AMQPScheme, AMQPUri};
use lapin::{Channel, Connection, ConnectionProperties};
use rustls_pki_types::{CertificateDer, pem::PemObject};

use crate::conn_events::{
    RecoveryConnectResult, RecoveryFailureReason, RecoveryFailureStage, emit_connect_failed,
    emit_connected, emit_recovery_connect_result,
};

/// AMQP `channel.close` / `connection.close` 的成功 reply code（AMQP `REPLY_SUCCESS` = 200）。
pub(crate) const REPLY_SUCCESS: u16 = 200;

/// AMQP 连接 / 建 channel 失败。
///
/// **PII 边界**（同 transactional messaging `MessagingError` 范式）：`Display` 仅安全摘要常量 `"amqp connect failed"`，
/// **绝不含 URL / 凭据**；原始 lapin error 仅作 [`std::error::Error::source`] 内部保留，不进默认日志。
/// `Debug` 手写（不 derive）——隐藏 `source`：lapin error 的 `Debug` 可能含 host/连接上下文，故 `{:?}`
/// 也只输出安全摘要（与 `AmqpUrl` 同范式）。连接诊断经 `crate::conn_events`：`AmqpEndpoint` Display
/// （Hard）+ `rss_redact::redact_error`（顶层 Display）。
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

/// Explicit private trust anchor for an AMQPS connection.
///
/// The field is private so production composition cannot substitute an empty/default TLS policy.
#[derive(Clone)]
pub struct AmqpPrivateCa {
    connector: RustlsConnector,
}

/// Invalid explicit AMQPS trust anchor. The message is intentionally fixed and never contains PEM.
#[derive(Debug, thiserror::Error)]
#[error("invalid AMQP private CA PEM")]
pub struct AmqpPrivateCaError;

impl AmqpPrivateCa {
    /// Build a non-empty PEM trust anchor and an exclusive rustls verifier. The verifier starts
    /// from an empty root store; WebPKI/platform roots are never appended to this constructor.
    pub fn from_pem(pem: Vec<u8>) -> Result<Self, AmqpPrivateCaError> {
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AmqpPrivateCaError)?;
        if certificates.is_empty() {
            return Err(AmqpPrivateCaError);
        }
        let connector = RustlsConnectorConfig::default()
            .with_parsable_certificates(certificates)
            .connector_with_no_client_auth()
            .map_err(|_| AmqpPrivateCaError)?;
        Ok(Self { connector })
    }
}

#[derive(Clone)]
pub(crate) enum AmqpTlsTrust {
    #[cfg(any(test, feature = "integration-test-support"))]
    WebPki,
    PrivateCa(AmqpPrivateCa),
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
#[cfg(any(test, feature = "integration-test-support"))]
pub(crate) async fn connect_with_webpki_for_test(
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    confirm: bool,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    connect_with_context(
        endpoint,
        name,
        confirm,
        &AmqpTlsTrust::WebPki,
        ConnectContext::Initial,
    )
    .await
}

pub(crate) async fn connect_with_private_ca(
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    confirm: bool,
    ca: &AmqpPrivateCa,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    connect_with_context(
        endpoint,
        name,
        confirm,
        &AmqpTlsTrust::PrivateCa(ca.clone()),
        ConnectContext::Initial,
    )
    .await
}

/// RSS-owned publisher replacement entry point. Recovery deliberately uses a different closed
/// logging context from initial assembly: endpoint identity is needed to authenticate the socket,
/// but it is not admitted to recovery events.
pub(crate) async fn reconnect_publisher(
    endpoint: &secure::AmqpEndpoint,
    name: &str,
    retiring_generation: u64,
    trust: &AmqpTlsTrust,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    connect_with_context(
        endpoint,
        name,
        true,
        trust,
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
    trust: &AmqpTlsTrust,
    context: ConnectContext,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    #[allow(clippy::disallowed_methods)]
    // reason: 唯一 AMQP driver connect callsite；endpoint 已在组合根经 secure::AmqpEndpoint 校验。
    let url = endpoint.expose();
    // Intentionally keep lapin auto-recovery disabled (`ConnectionProperties::default()` has zero retries and
    // `auto_recover=false`). Publisher transport replacement is RSS-owned and bounded by one absolute deadline;
    // enabling lapin recovery here would create an uncancellable second reconnect owner.
    let connection = match trust {
        #[cfg(any(test, feature = "integration-test-support"))]
        AmqpTlsTrust::WebPki => {
            DefaultConnectionBuilder::new()
                .map_err(|source| {
                    connect_err(
                        source,
                        endpoint,
                        name,
                        context,
                        RecoveryFailureStage::Connect,
                    )
                })?
                .with_uri_str(url.to_owned())
                .with_properties(ConnectionProperties::default())
                .connect()
                .await
        }
        AmqpTlsTrust::PrivateCa(ca) => connect_with_exclusive_private_ca(url, ca).await,
    }
    .map_err(|source| {
        connect_err(
            source,
            endpoint,
            name,
            context,
            RecoveryFailureStage::Connect,
        )
    })?;
    let conn = Arc::new(connection);
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

async fn connect_with_exclusive_private_ca(
    url: &str,
    ca: &AmqpPrivateCa,
) -> lapin::Result<Connection> {
    let uri = url
        .parse::<AMQPUri>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let runtime = lapin::runtime::default_runtime()?;
    let connector = ca.connector.clone();
    Connection::connector(
        uri,
        runtime,
        async move |uri, runtime| {
            if uri.scheme != AMQPScheme::AMQPS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "private AMQP trust requires AMQPS",
                )
                .into());
            }
            let host = uri.authority.host.clone();
            let address = runtime.to_socket_addrs((host.clone(), uri.authority.port));
            let stream = AsyncTcpStream::connect(&runtime, address)
                .await
                .map_err(lapin::Error::from)?;
            stream
                .into_rustls(&connector, &host)
                .await
                .map_err(lapin::Error::from)
        },
        ConnectionProperties::default(),
    )
    .await
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

#[cfg(test)]
mod tests {
    use super::{
        AmqpConnectError, AmqpConnectErrorSource, AmqpPrivateCa, connect_with_webpki_for_test,
    };

    #[test]
    fn private_ca_rejects_empty_and_malformed_pem() {
        assert!(AmqpPrivateCa::from_pem(Vec::new()).is_err());
        assert!(AmqpPrivateCa::from_pem(b"not a certificate".to_vec()).is_err());
    }

    #[test]
    fn connect_error_surface_redacts_transport_source() {
        let error = AmqpConnectError {
            source: AmqpConnectErrorSource::Transport(
                std::io::Error::other("user:secretpass@broker.internal").into(),
            ),
        };

        assert_eq!(error.to_string(), "amqp connect failed");
        assert_eq!(
            format!("{error:?}"),
            "AmqpConnectError(\"amqp connect failed\")"
        );
        assert!(!error.to_string().contains("secretpass"));
        assert!(!format!("{error:?}").contains("secretpass"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)] // fixed literal fixture and required error path
    async fn connect_failure_returns_safe_error_with_source() {
        let endpoint = secure::AmqpEndpoint::parse(
            "amqp://user:secretpass@127.0.0.1:1/%2f",
            secure::PlaintextEndpointPolicy::AllowLoopback,
        )
        .expect("loopback AMQP fixture must parse");
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connect_with_webpki_for_test(&endpoint, "amqp-unit", true),
        )
        .await
        .expect("loopback connect failure must remain bounded")
        .err();

        assert_eq!(
            error.as_ref().map(ToString::to_string).as_deref(),
            Some("amqp connect failed")
        );
        assert!(!format!("{error:?}").contains("secretpass"));
        assert!(
            error
                .as_ref()
                .and_then(|error| std::error::Error::source(error))
                .is_some()
        );
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
