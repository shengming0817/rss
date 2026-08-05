//! Shared offline/live harness for Vault T2 proofs（env parser、warm proxy、anti-vacuity）。
//! 无 vault/secure/tracing production helper——默认 offline target 不拉 backend optional deps。

use std::fmt;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

pub(crate) const ENV_ADDR: &str = "RSS_VAULT_TEST_ADDR";
pub(crate) const ENV_TOKEN: &str = "RSS_VAULT_TEST_TOKEN";
pub(crate) const ENV_MOUNT: &str = "RSS_VAULT_TEST_MOUNT";
pub(crate) const ENV_SIGNING_KEY: &str = "RSS_VAULT_TEST_SIGNING_KEY";
pub(crate) const ENV_ENCRYPTION_KEY: &str = "RSS_VAULT_TEST_ENCRYPTION_KEY";
pub(crate) const ENV_NAMES: [&str; 5] = [
    ENV_ADDR,
    ENV_TOKEN,
    ENV_MOUNT,
    ENV_SIGNING_KEY,
    ENV_ENCRYPTION_KEY,
];

pub(crate) const REDACTED: &str = "<redacted>";

pub(crate) const ERR_PROXY_INVALID_ADDR: &str =
    "warm outage proxy requires a valid plaintext http Vault address";
pub(crate) const ERR_PROXY_HTTPS: &str =
    "warm outage proxy requires plaintext http Vault address; https is unsupported";
pub(crate) const ERR_PROXY_BIND: &str = "warm outage proxy failed to bind local listener";
pub(crate) const ERR_PROXY_LOCAL_ADDR: &str = "warm outage proxy failed to read local address";
pub(crate) const ERR_PROXY_CUT_STOP: &str = "warm outage proxy accept loop did not stop after cut";
pub(crate) const ERR_PROXY_CUT_TIMEOUT: &str = "warm outage proxy cut timed out";

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const PROXY_CUT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const HARNESS_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Test-local live Vault 坐标薄 harness（非 production config）。
/// `Debug` 全坐标脱敏，避免断言/失败输出把凭据写进 report。
pub(crate) struct LiveVaultInputs {
    pub(crate) addr: String,
    pub(crate) token: String,
    pub(crate) mount: String,
    pub(crate) signing_key: String,
    pub(crate) encryption_key: String,
}

impl fmt::Debug for LiveVaultInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveVaultInputs")
            .field("addr", &REDACTED)
            .field("token", &REDACTED)
            .field("mount", &REDACTED)
            .field("signing_key", &REDACTED)
            .field("encryption_key", &REDACTED)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct LiveVaultInputsError {
    name: &'static str,
    kind: LiveVaultInputsErrorKind,
}

#[derive(Debug)]
enum LiveVaultInputsErrorKind {
    Missing,
    Blank,
}

impl fmt::Display for LiveVaultInputsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            LiveVaultInputsErrorKind::Missing => {
                write!(
                    f,
                    "{name} must be set to run live vault integration tests",
                    name = self.name
                )
            }
            LiveVaultInputsErrorKind::Blank => {
                write!(
                    f,
                    "{name} must be non-empty to run live vault integration tests",
                    name = self.name
                )
            }
        }
    }
}

impl std::error::Error for LiveVaultInputsError {}

impl LiveVaultInputs {
    pub(crate) fn from_get(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, LiveVaultInputsError> {
        let [addr, token, mount, signing_key, encryption_key] =
            ENV_NAMES.map(|name| required_live_input(&get, name));
        Ok(Self {
            addr: addr?,
            token: token?,
            mount: mount?,
            signing_key: signing_key?,
            encryption_key: encryption_key?,
        })
    }
}

fn required_live_input(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, LiveVaultInputsError> {
    match get(name) {
        None => Err(LiveVaultInputsError {
            name,
            kind: LiveVaultInputsErrorKind::Missing,
        }),
        Some(raw) if raw.trim().is_empty() => Err(LiveVaultInputsError {
            name,
            kind: LiveVaultInputsErrorKind::Blank,
        }),
        Some(raw) => Ok(raw.trim().to_string()),
    }
}

/// 字节窗口 contains：非 UTF-8 plaintext 也不得静默跳过；空 needle fail-loud 防空绿。
pub(crate) fn assert_bytes_absent(haystack: &[u8], needle: &[u8], what: &str) {
    assert!(!needle.is_empty(), "{what} must be non-empty");
    let found = haystack
        .windows(needle.len())
        .any(|window| window == needle);
    assert!(
        !found,
        "{what} must be absent from diagnostic bytes (needle len {})",
        needle.len()
    );
}

pub(crate) fn assert_sensitive_text_absent(
    haystack: &str,
    inputs: &LiveVaultInputs,
    request_endpoint: &str,
    plaintext_marker: &[u8],
) {
    let bytes = haystack.as_bytes();
    assert_bytes_absent(bytes, inputs.token.as_bytes(), "sensitive token");
    assert_bytes_absent(bytes, inputs.addr.as_bytes(), "upstream endpoint");
    assert_bytes_absent(bytes, request_endpoint.as_bytes(), "request endpoint");
    assert_bytes_absent(bytes, plaintext_marker, "plaintext marker");
}

/// Anti-vacuity：负向脱敏前先证明 recorder 捕获了 outage 诊断闭集字段。
/// 不锁 `category=connect`（classify 闭集由 production T1 表驱动 owner）。
/// 失败消息故意不嵌入完整 trace，避免把敏感片段写进断言输出。
pub(crate) fn assert_warm_outage_trace_anti_vacuity(trace: &str) {
    assert!(
        trace.contains("span=vault.transit.encrypt"),
        "warm-outage recorder must capture vault.transit.encrypt span before redaction checks"
    );
    assert!(
        trace.contains("target=vault"),
        "warm-outage recorder must capture target=vault before redaction checks"
    );
    assert!(
        trace.contains("operation=encrypt"),
        "warm-outage recorder must capture operation=encrypt before redaction checks"
    );
    assert!(
        trace.contains("phase=key-provider-send"),
        "warm-outage recorder must capture phase=key-provider-send before redaction checks"
    );
}

#[derive(Debug)]
pub(crate) struct WarmOutageProxyError(pub(crate) &'static str);

impl fmt::Display for WarmOutageProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for WarmOutageProxyError {}

/// 单用途 TCP forwarder：先把同一 provider 接到真 Vault（warm），再确定性切断 listener + relays。
/// accept loop 内用 [`JoinSet`] 拥有 relay；显式 [`Self::cut`] / [`Drop`] 均发 cut 并收口。
/// ref: tokio-rs/tokio tokio/src/task/join_set.rs（`shutdown()` abort+join；Drop abort all）。
pub(crate) struct WarmOutageProxy {
    endpoint: String,
    cut_tx: watch::Sender<bool>,
    accept_task: Option<JoinHandle<()>>,
}

impl WarmOutageProxy {
    pub(crate) async fn start(addr: &str) -> Result<Self, WarmOutageProxyError> {
        let upstream = parse_http_upstream(addr)?;
        let listener = timeout(HARNESS_IO_TIMEOUT, TcpListener::bind("127.0.0.1:0"))
            .await
            .map_err(|_| WarmOutageProxyError(ERR_PROXY_BIND))?
            .map_err(|_| WarmOutageProxyError(ERR_PROXY_BIND))?;
        let local = listener
            .local_addr()
            .map_err(|_| WarmOutageProxyError(ERR_PROXY_LOCAL_ADDR))?;
        let endpoint = format!("http://127.0.0.1:{}", local.port());

        let (cut_tx, cut_rx) = watch::channel(false);

        let accept_task = tokio::spawn(async move {
            run_forward_accept_loop(listener, upstream, cut_rx).await;
        });

        Ok(Self {
            endpoint,
            cut_tx,
            accept_task: Some(accept_task),
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) async fn cut(mut self) -> Result<(), WarmOutageProxyError> {
        let _ = self.cut_tx.send(true);
        let Some(mut accept_task) = self.accept_task.take() else {
            return Ok(());
        };
        match timeout(PROXY_CUT_TIMEOUT, &mut accept_task).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(WarmOutageProxyError(ERR_PROXY_CUT_STOP));
            }
            Err(_) => {
                accept_task.abort();
                let _ = timeout(PROXY_CUT_TIMEOUT, accept_task).await;
                return Err(WarmOutageProxyError(ERR_PROXY_CUT_TIMEOUT));
            }
        }
        Ok(())
    }
}

impl Drop for WarmOutageProxy {
    fn drop(&mut self) {
        let _ = self.cut_tx.send(true);
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
    }
}

pub(crate) fn parse_http_upstream(addr: &str) -> Result<(String, u16), WarmOutageProxyError> {
    let url = reqwest::Url::parse(addr.trim())
        .map_err(|_| WarmOutageProxyError(ERR_PROXY_INVALID_ADDR))?;
    if url.scheme() != "http" {
        // Fail-closed static diagnosis（非 skip）：本 harness 只对本地 HTTP Vault 做明文 TCP cut。
        return Err(WarmOutageProxyError(ERR_PROXY_HTTPS));
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(WarmOutageProxyError(ERR_PROXY_INVALID_ADDR))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or(WarmOutageProxyError(ERR_PROXY_INVALID_ADDR))?;
    Ok((host, port))
}

async fn run_forward_accept_loop(
    listener: TcpListener,
    upstream: (String, u16),
    mut cut_rx: watch::Receiver<bool>,
) {
    let mut relays = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = cut_rx.changed() => {
                if changed.is_err() || *cut_rx.borrow() {
                    break;
                }
            }
            // Reap finished relays so JoinSet does not retain completed tasks indefinitely.
            Some(_) = relays.join_next() => {}
            accepted = listener.accept() => {
                let Ok((mut inbound, _)) = accepted else {
                    break;
                };
                let upstream = upstream.clone();
                relays.spawn(async move {
                    let connect = timeout(
                        PROXY_CONNECT_TIMEOUT,
                        TcpStream::connect(upstream),
                    )
                    .await;
                    let Ok(Ok(mut outbound)) = connect else {
                        let _ = inbound.shutdown().await;
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    let _ = inbound.shutdown().await;
                    let _ = outbound.shutdown().await;
                });
            }
        }
    }
    // ref: tokio-rs/tokio tokio/src/task/join_set.rs — shutdown aborts all + awaits join.
    relays.shutdown().await;
}
