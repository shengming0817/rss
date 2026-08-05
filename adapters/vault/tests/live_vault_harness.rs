//! Offline Vault live-harness proofs（无真 Vault、无 `integration` feature）。
//!
//! Canonical runbook 在 `tests/live_vault.rs`；本 target 默认可跑且不进 shard catalog。

#[path = "live_vault_support.rs"]
mod live_vault_support;

use std::net::SocketAddr;

use live_vault_support::{
    ENV_NAMES, ERR_PROXY_HTTPS, ERR_PROXY_INVALID_ADDR, HARNESS_IO_TIMEOUT, LiveVaultInputs,
    REDACTED, WarmOutageProxy, assert_sensitive_text_absent, assert_warm_outage_trace_anti_vacuity,
    parse_http_upstream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const MARKER_PREFIX: &str = "marker-for-";

#[test]
#[should_panic(
    expected = "warm-outage recorder must capture vault.transit.encrypt span before redaction checks"
)]
fn warm_outage_anti_vacuity_rejects_empty_trace() {
    assert_warm_outage_trace_anti_vacuity("");
}

#[test]
#[should_panic(
    expected = "warm-outage recorder must capture phase=key-provider-send before redaction checks"
)]
fn warm_outage_anti_vacuity_rejects_missing_phase() {
    assert_warm_outage_trace_anti_vacuity(
        "span=vault.transit.encrypt\ntarget=vault operation=encrypt\n",
    );
}

#[test]
fn warm_outage_anti_vacuity_accepts_closed_outage_markers() {
    assert_warm_outage_trace_anti_vacuity(
        "span=vault.transit.encrypt\ntarget=vault operation=encrypt phase=key-provider-send\n",
    );
}

#[test]
#[allow(clippy::expect_used)]
fn live_inputs_reject_each_missing_or_blank_coordinate() {
    for missing in ENV_NAMES {
        let result = LiveVaultInputs::from_get(|name| {
            (name != missing).then(|| format!("{MARKER_PREFIX}{name}"))
        });
        let error = result.expect_err("missing coordinate must fail closed");
        assert!(error.to_string().contains(missing));
        assert!(!error.to_string().contains(MARKER_PREFIX));
    }

    for blank in ENV_NAMES {
        let result = LiveVaultInputs::from_get(|name| {
            Some(if name == blank {
                "  ".to_string()
            } else {
                format!("{MARKER_PREFIX}{name}")
            })
        });
        let error = result.expect_err("blank coordinate must fail closed");
        assert!(error.to_string().contains(blank));
        assert!(!error.to_string().contains(MARKER_PREFIX));
    }

    let inputs = LiveVaultInputs::from_get(|name| Some(format!("{MARKER_PREFIX}{name}")))
        .expect("all live coordinates are present");
    let debug = format!("{inputs:?}");
    assert!(
        !debug.contains(MARKER_PREFIX),
        "live input Debug must redact every coordinate"
    );
    assert!(
        debug.matches(REDACTED).count() >= 5,
        "live input Debug must redact all five coordinates"
    );
    assert_eq!(inputs.mount, format!("{MARKER_PREFIX}RSS_VAULT_TEST_MOUNT"));
    assert_eq!(
        inputs.signing_key,
        format!("{MARKER_PREFIX}RSS_VAULT_TEST_SIGNING_KEY")
    );
    assert_eq!(
        inputs.encryption_key,
        format!("{MARKER_PREFIX}RSS_VAULT_TEST_ENCRYPTION_KEY")
    );
}

#[test]
#[allow(clippy::expect_used)]
fn parse_http_upstream_accepts_http_and_rejects_https_or_invalid() {
    #[allow(clippy::type_complexity)]
    let cases: [(&str, Result<(&str, u16), &str>); 6] = [
        ("http://127.0.0.1:8200", Ok(("127.0.0.1", 8200))),
        ("http://localhost:8200", Ok(("localhost", 8200))),
        ("https://127.0.0.1:8200", Err(ERR_PROXY_HTTPS)),
        ("not a url", Err(ERR_PROXY_INVALID_ADDR)),
        ("ftp://127.0.0.1:8200", Err(ERR_PROXY_HTTPS)),
        ("http://", Err(ERR_PROXY_INVALID_ADDR)),
    ];
    for (input, expected) in cases {
        let actual = parse_http_upstream(input);
        match expected {
            Ok((host, port)) => {
                let (got_host, got_port) = actual.expect("expected accept");
                assert_eq!((got_host.as_str(), got_port), (host, port));
            }
            Err(want) => {
                let err = actual.expect_err("expected reject");
                assert_eq!(err.0, want);
            }
        }
    }
}

#[test]
#[allow(clippy::expect_used)]
fn sensitive_absent_checks_non_utf8_plaintext_via_byte_windows() {
    let inputs = LiveVaultInputs::from_get(|name| Some(format!("{MARKER_PREFIX}{name}")))
        .expect("fixture inputs");
    let marker = b"plain\xfftext";
    assert_sensitive_text_absent(
        "no-sensitive-payload",
        &inputs,
        "http://127.0.0.1:9",
        marker,
    );
    live_vault_support::assert_bytes_absent(b"safe-prefix", marker, "plaintext marker");
}

#[test]
#[should_panic(expected = "plaintext marker must be absent")]
fn sensitive_absent_panics_when_non_utf8_plaintext_leaks_in_bytes() {
    let marker = b"plain\xfftext";
    let mut haystack = Vec::from(b"diag-".as_slice());
    haystack.extend_from_slice(marker);
    live_vault_support::assert_bytes_absent(&haystack, marker, "plaintext marker");
}

#[test]
#[should_panic(expected = "plaintext marker must be non-empty")]
fn sensitive_absent_rejects_empty_marker() {
    live_vault_support::assert_bytes_absent(b"safe", b"", "plaintext marker");
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used)]
async fn warm_outage_proxy_forwards_then_rejects_new_connections_after_cut() {
    let upstream = timeout(HARNESS_IO_TIMEOUT, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("bind timeout")
        .expect("bind loopback");
    let upstream_addr = upstream.local_addr().expect("upstream local addr");
    let echo = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = upstream.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let Ok(Ok(n)) = timeout(HARNESS_IO_TIMEOUT, stream.read(&mut buf)).await else {
                    return;
                };
                let _ = timeout(HARNESS_IO_TIMEOUT, stream.write_all(&buf[..n])).await;
            });
        }
    });

    let upstream_url = format!("http://127.0.0.1:{}", upstream_addr.port());
    let proxy = WarmOutageProxy::start(&upstream_url)
        .await
        .expect("start proxy");
    let proxy_endpoint = proxy.endpoint().to_string();
    let proxy_addr = proxy_socket_addr(&proxy_endpoint);

    let payload = b"warm-proxy-echo";
    {
        let mut client = timeout(HARNESS_IO_TIMEOUT, TcpStream::connect(proxy_addr))
            .await
            .expect("connect timeout")
            .expect("connect proxy");
        timeout(HARNESS_IO_TIMEOUT, client.write_all(payload))
            .await
            .expect("write timeout")
            .expect("write");
        let mut buf = [0u8; 64];
        let n = timeout(HARNESS_IO_TIMEOUT, client.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(&buf[..n], payload);
    }

    proxy.cut().await.expect("cut proxy");

    let refused = timeout(HARNESS_IO_TIMEOUT, TcpStream::connect(proxy_addr)).await;
    assert!(
        matches!(refused, Ok(Err(_))),
        "proxy must refuse new connections after cut without hanging"
    );

    echo.abort();
}

#[allow(clippy::expect_used)]
fn proxy_socket_addr(endpoint: &str) -> SocketAddr {
    let (host, port) = parse_http_upstream(endpoint).expect("proxy endpoint");
    format!("{host}:{port}").parse().expect("proxy socket addr")
}
