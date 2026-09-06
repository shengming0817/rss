//! AMQP 连接接缝（lapin）——publisher / subscriber 共用：连接 + 建 channel + 凭据 redaction。

use rss_transactional_messaging::error::MessagingErrorKind;
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(test, feature = "test-support"))]
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

/// Connection/setup failures with closed configuration and transport variants.
/// Provider errors terminate at the shared redacted source boundary, including recursive reports.
#[derive(Debug, thiserror::Error)]
pub enum AmqpConnectError {
    /// The broker connection or channel setup failed; the provider source stays opaque.
    #[error("amqp connect failed")]
    Transport {
        /// Closed retry/authority classification; provider text stays opaque.
        kind: MessagingErrorKind,
        /// Redacted provider source, safe for recursive error reports.
        #[source]
        source: rss_redact::RedactedSource,
    },
    /// Recovery requires a positive integral millisecond duration within the adapter limit.
    #[error("invalid amqp recovery timeout")]
    InvalidRecoveryTimeout,
}

impl AmqpConnectError {
    /// Distinguish retryable transport faults from authority/configuration failures safely.
    pub const fn kind(&self) -> MessagingErrorKind {
        match self {
            Self::Transport { kind, .. } => *kind,
            Self::InvalidRecoveryTimeout => MessagingErrorKind::Permanent,
        }
    }
}

pub(crate) fn transport_error_kind(error: &lapin::Error) -> MessagingErrorKind {
    if let lapin::ErrorKind::ProtocolError(protocol) = error.kind() {
        match protocol.get_id() {
            406 => return MessagingErrorKind::Conflict,
            403 | 311 => return MessagingErrorKind::Permanent,
            _ => {}
        }
    }
    if error.can_be_recovered() {
        MessagingErrorKind::Transient
    } else {
        MessagingErrorKind::Permanent
    }
}

pub(crate) const MAX_RECOVERY_TIMEOUT_MILLIS: u64 = 86_400_000;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RecoveryTimeoutConfigError {
    #[error("recovery timeout must be non-zero")]
    Zero,
    #[error("recovery timeout must be an integral number of milliseconds")]
    NonIntegralMilliseconds,
    #[error("recovery timeout exceeds operational maximum {max_millis}ms")]
    OperationalRangeExceeded { max_millis: u64 },
}

pub(crate) fn validate_recovery_timeout(
    timeout: Duration,
) -> Result<(), RecoveryTimeoutConfigError> {
    if timeout.is_zero() {
        return Err(RecoveryTimeoutConfigError::Zero);
    }
    if !timeout.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(RecoveryTimeoutConfigError::NonIntegralMilliseconds);
    }
    if timeout.as_millis() > u128::from(MAX_RECOVERY_TIMEOUT_MILLIS) {
        return Err(RecoveryTimeoutConfigError::OperationalRangeExceeded {
            max_millis: MAX_RECOVERY_TIMEOUT_MILLIS,
        });
    }
    Ok(())
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
    #[cfg(any(test, feature = "test-support"))]
    WebPki,
    PrivateCa(AmqpPrivateCa),
}

/// 从单个 per-domain AMQP URL 连接并开一个 channel（URL 含 `user:pass@host/vhost`——per-domain
/// vhost/credential 隔离 seam）。`confirm=true` 时启用 publisher confirms（`confirm_select`），让
/// publish 的 broker ack/nack 可被检测（durable publish-ok 语义，见 publisher）；subscriber 传 false。
/// 失败经 redaction funnel 记日志，URL 原文绝不进日志。
#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn connect_with_webpki_for_test(
    endpoint: &crate::endpoint::Endpoint,
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
    endpoint: &crate::endpoint::Endpoint,
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
    endpoint: &crate::endpoint::Endpoint,
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

/// Subscriber replacement uses the same TLS owner and closed recovery diagnostics.
pub(crate) async fn reconnect_subscriber(
    endpoint: &crate::endpoint::Endpoint,
    name: &str,
    generation: u64,
    trust: &AmqpTlsTrust,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    connect_with_context(
        endpoint,
        name,
        false,
        trust,
        ConnectContext::Recovery {
            replacement_generation: generation.saturating_add(1),
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
    endpoint: &crate::endpoint::Endpoint,
    name: &str,
    confirm: bool,
    trust: &AmqpTlsTrust,
    context: ConnectContext,
) -> Result<(Arc<Connection>, Channel), AmqpConnectError> {
    // The raw URL is private to this adapter and consumed only at the driver boundary.
    let url = endpoint.expose();
    // Intentionally keep lapin auto-recovery disabled (`ConnectionProperties::default()` has zero retries and
    // `auto_recover=false`). Publisher transport replacement is RSS-owned and bounded by one absolute deadline;
    // enabling lapin recovery here would create an uncancellable second reconnect owner.
    let connection = match trust {
        #[cfg(any(test, feature = "test-support"))]
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
    let cleanup = OnDrop::new(|| close_connection_now(&conn));
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
    cleanup.disarm();
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
    endpoint: &crate::endpoint::Endpoint,
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
    AmqpConnectError::Transport {
        kind: transport_error_kind(&source),
        source: rss_redact::RedactedSource::new(source),
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
    use super::{AmqpConnectError, AmqpPrivateCa, connect_with_webpki_for_test};

    #[test]
    fn private_ca_rejects_empty_and_malformed_pem() {
        assert!(AmqpPrivateCa::from_pem(Vec::new()).is_err());
        assert!(AmqpPrivateCa::from_pem(b"not a certificate".to_vec()).is_err());
    }

    #[test]
    fn connect_error_surface_redacts_transport_source() {
        let error = AmqpConnectError::Transport {
            kind: rss_transactional_messaging::error::MessagingErrorKind::Transient,
            source: rss_redact::RedactedSource::new(lapin::Error::from(std::io::Error::other(
                "user:secretpass@broker.internal",
            ))),
        };

        assert_eq!(error.to_string(), "amqp connect failed");
        assert!(!error.to_string().contains("secretpass"));
        assert!(!format!("{error:?}").contains("secretpass"));
        let mut source = std::error::Error::source(&error);
        while let Some(error) = source {
            assert!(!format!("{error:?}: {error}").contains("secretpass"));
            source = error.source();
        }
        assert!(!format!("{:?}", anyhow::Error::new(error)).contains("secretpass"));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::expect_used)] // fixed literal fixture and required error path
    async fn connect_failure_returns_safe_error_with_source() {
        let endpoint =
            crate::endpoint::Endpoint::parse("amqp://user:secretpass@127.0.0.1:1/%2f", true)
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
pub(crate) fn invalid_recovery_timeout() -> AmqpConnectError {
    AmqpConnectError::InvalidRecoveryTimeout
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

/// Scope-bound fallback for cancelled initialization, publication, settlement, or shutdown.
pub(crate) struct OnDrop<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> OnDrop<F> {
    pub(crate) fn new(action: F) -> Self {
        Self(Some(action))
    }
    pub(crate) fn disarm(mut self) {
        self.0.take();
    }
    /// Failed graceful cleanup must still run the forced-retirement fallback.
    pub(crate) fn disarm_on_success<T, E>(self, result: &Result<T, E>) {
        if result.is_ok() {
            self.disarm();
        }
    }
}
impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(action) = self.0.take() {
            action();
        }
    }
}

/// Poll the lapin close request once: its first poll fences the session and enqueues Close.
/// Waiting for Close-Ok is optional on cancellation; never spawn an unowned cleanup task.
/// ref: amqp-rs/lapin src/generated/channel.rs@v4.10.0 and src/connection.rs@v4.10.0.
pub(crate) fn close_connection_now(connection: &Connection) {
    use futures::FutureExt as _;
    if connection.status().connected() {
        let _ = connection
            .close(REPLY_SUCCESS, "resource ownership ended".into())
            .now_or_never();
    }
}
pub(crate) fn close_channel_now(channel: &Channel) {
    use futures::FutureExt as _;
    if channel.status().connected() {
        let _ = channel
            .close(REPLY_SUCCESS, "delivery ownership ended".into())
            .now_or_never();
    }
}

/// Deterministic test-only barrier at a real transport boundary.
#[cfg(feature = "test-support")]
pub(crate) struct TestPause {
    entered: tokio::sync::oneshot::Sender<()>,
    resume: tokio::sync::oneshot::Receiver<()>,
}
#[cfg(feature = "test-support")]
impl TestPause {
    pub(crate) fn new() -> (
        Self,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, resume) = tokio::sync::oneshot::channel();
        (Self { entered, resume }, observed, release)
    }
    pub(crate) async fn wait(self) {
        let _ = self.entered.send(());
        let _ = self.resume.await;
    }
}

#[cfg(test)]
mod cleanup_guard_tests {
    use super::OnDrop;
    use std::cell::Cell;

    #[test]
    fn close_error_keeps_forced_retirement_armed() {
        for close_result in [Ok(()), Err("injected close failure")] {
            let forced = Cell::new(false);
            let cleanup = OnDrop::new(|| forced.set(true));
            cleanup.disarm_on_success(&close_result);
            assert_eq!(forced.get(), close_result.is_err());
        }
    }
}
