//! AMQP connect 成功 / 失败 tracing emit（feature-agnostic，无 lapin）。
//!
//! **Hard funnel**：[`emit_connected`] / [`emit_connect_failed`] 的 `endpoint` 入参类型为
//! [`secure::AmqpEndpoint`]——明文 URL / `expose()` 结果无法经本 API 进入日志字段；字段值经
//! `AmqpEndpoint: Display`（内部 `render_redacted_url` → `redact_url_credentials`）输出。
//!
//! **Medium 门**：下方 synthetic CaptureLayer 负向测试闭合 EVENTTRANSPORT-CRED-REDACT-01
//! （research.md：字段值无 userinfo；类型系统管不到字符串内容，故保留 Medium 执行体）。
//!
//! `cfg(any(test, feature = "backend"))`：默认 `cargo test` 可跑（进 verify）；backend 供
//! [`crate::conn`] 调用；纯 lib build 无消费方不编译（同 [`crate::settle`]）。

/// 记录 AMQP 连接成功事件。`endpoint` 只接受 typed [`secure::AmqpEndpoint`]（Display 已脱敏）。
pub(crate) fn emit_connected(resource: &str, endpoint: &secure::AmqpEndpoint) {
    tracing::info!(
        target: "amqp",
        resource,
        endpoint = %endpoint,
        "amqp connected",
    );
}

/// 记录 AMQP 连接失败事件。`endpoint` 经 typed Display；`error` 经 [`secure::redact_error`]。
pub(crate) fn emit_connect_failed(
    resource: &str,
    endpoint: &secure::AmqpEndpoint,
    err: &dyn std::error::Error,
) {
    tracing::warn!(
        target: "amqp",
        resource,
        endpoint = %endpoint,
        error = %secure::redact_error(err),
        "amqp connect failed",
    );
}

#[cfg(test)]
mod cred_redact_tests {
    //! INVARIANT: EVENTTRANSPORT-CRED-REDACT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "cred_redact_tests::n1_ok_and_fail_redact_userinfo", anti_vacuity = "cred_redact_tests::b1_no_userinfo_preserves_endpoint" } ——
    //! mock tracing subscriber 断言 amqp URI userinfo 不出现在任何 event 字段；有 userinfo 时
    //! `endpoint` 必须含 `<redacted>`（防空绿）。非 integration feature。默认 `cargo test -p amqp --lib`
    //! 进 verify nextest；ArchRules `source_file_gate` 精确绑定 verify（#543 F1 最小修；系统性
    //! plan→registry 见 #1818）。
    //!
    //! Hard 入参 funnel 见模块 rustdoc；本测试是字段值 Medium 执行体。
    //!
    //! ref: vectordotdev/vector src/sinks/util/uri.rs@74173af63a84
    //! ref: assemblies/runtime phase_result_redacts_error_field（CaptureLayer 形态）

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use secure::{AmqpEndpoint, PlaintextEndpointPolicy};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::{emit_connect_failed, emit_connected};

    const SENTINEL: &str = "s3cr3t";
    const RESOURCE: &str = "amqp-cred-redact";

    #[derive(Clone, Default)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<HashMap<String, String>>>>,
    }

    struct CapVisit {
        fields: HashMap<String, String>,
    }

    impl Visit for CapVisit {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = CapVisit {
                fields: HashMap::new(),
            };
            event.record(&mut visitor);
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(visitor.fields);
        }
    }

    fn capture(f: impl FnOnce()) -> Vec<HashMap<String, String>> {
        let layer = CaptureLayer::default();
        let events = Arc::clone(&layer.events);
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[allow(clippy::expect_used)]
    // reason: 测试辅助；parse Err 即失败。
    fn parse_loopback(url: &str) -> AmqpEndpoint {
        AmqpEndpoint::parse(url, PlaintextEndpointPolicy::AllowLoopback)
            .expect("loopback amqp endpoint must parse")
    }

    #[allow(clippy::expect_used)]
    // reason: 测试辅助；parse Err 即失败。
    fn parse_amqps(url: &str) -> AmqpEndpoint {
        AmqpEndpoint::parse(url, PlaintextEndpointPolicy::Deny).expect("amqps endpoint must parse")
    }

    fn assert_no_cred_leak(fields: &HashMap<String, String>, raw_url: &str) {
        for (name, value) in fields {
            assert!(
                !value.contains(SENTINEL),
                "field {name} must not contain sentinel: {value}"
            );
            assert!(
                !value.contains(raw_url),
                "field {name} must not contain raw URI: {value}"
            );
            assert!(
                !value.contains(&format!("user:{SENTINEL}")),
                "field {name} must not contain user:pass: {value}"
            );
        }
    }

    #[allow(clippy::expect_used)]
    // reason: 测试辅助；缺 endpoint 字段即失败。
    fn endpoint_field(fields: &HashMap<String, String>) -> &str {
        fields
            .get("endpoint")
            .map(String::as_str)
            .expect("endpoint field missing")
    }

    #[derive(Debug)]
    struct EmbeddedUriError(&'static str);

    impl std::fmt::Display for EmbeddedUriError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "connect {} refused", self.0)
        }
    }

    impl std::error::Error for EmbeddedUriError {}

    /// N1 + A1：有 userinfo 的成功 / 失败路径；anti-vacuity 要求 `<redacted>`。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试断言 error 字段存在。
    fn n1_ok_and_fail_redact_userinfo() {
        let raw = "amqp://user:s3cr3t@127.0.0.1:5672/app";
        let endpoint = parse_loopback(raw);

        let ok_events = capture(|| emit_connected(RESOURCE, &endpoint));
        assert_eq!(ok_events.len(), 1);
        let ok = &ok_events[0];
        assert_eq!(
            ok.get("message").map(String::as_str),
            Some("amqp connected")
        );
        assert_no_cred_leak(ok, raw);
        let ok_endpoint = endpoint_field(ok);
        assert!(
            ok_endpoint.contains("<redacted>"),
            "anti-vacuity: endpoint must contain <redacted>: {ok_endpoint}"
        );
        assert_eq!(ok_endpoint, "amqp://<redacted>@127.0.0.1:5672/app");
        assert!(!ok.contains_key("error"));

        let fail_events = capture(|| {
            emit_connect_failed(RESOURCE, &endpoint, &EmbeddedUriError(raw));
        });
        assert_eq!(fail_events.len(), 1);
        let fail = &fail_events[0];
        assert_eq!(
            fail.get("message").map(String::as_str),
            Some("amqp connect failed")
        );
        assert_no_cred_leak(fail, raw);
        let fail_endpoint = endpoint_field(fail);
        assert!(
            fail_endpoint.contains("<redacted>"),
            "anti-vacuity: endpoint must contain <redacted>: {fail_endpoint}"
        );
        assert_eq!(fail_endpoint, "amqp://<redacted>@127.0.0.1:5672/app");
        let error = fail
            .get("error")
            .map(String::as_str)
            .expect("error field missing");
        assert!(
            !error.contains(SENTINEL),
            "error must redact sentinel: {error}"
        );
        assert!(
            error.contains("amqp://<redacted>@127.0.0.1:5672/app"),
            "error must retain redacted shape: {error}"
        );
    }

    /// N2：amqps + percent-encoded vhost。
    #[test]
    fn n2_amqps_percent_vhost_redacts_userinfo() {
        let raw = "amqps://u:p@broker.example/%2fvhost";
        let endpoint = parse_amqps(raw);

        let ok = capture(|| emit_connected(RESOURCE, &endpoint));
        assert_eq!(ok.len(), 1);
        assert!(!ok[0].values().any(|v| v.contains("u:p")));
        let ok_ep = endpoint_field(&ok[0]);
        assert!(ok_ep.contains("<redacted>"), "endpoint: {ok_ep}");
        assert!(ok_ep.contains("broker.example"), "endpoint: {ok_ep}");
        assert!(
            ok_ep.contains("%2fvhost"),
            "endpoint must retain encoded vhost: {ok_ep}"
        );

        let fail = capture(|| {
            emit_connect_failed(RESOURCE, &endpoint, &std::io::Error::other("refused"));
        });
        assert_eq!(fail.len(), 1);
        assert!(!fail[0].values().any(|v| v.contains("u:p")));
        let fail_ep = endpoint_field(&fail[0]);
        assert!(fail_ep.contains("<redacted>"), "endpoint: {fail_ep}");
        assert!(fail_ep.contains("broker.example"), "endpoint: {fail_ep}");
        assert!(
            fail_ep.contains("%2fvhost"),
            "endpoint must retain encoded vhost: {fail_ep}"
        );
    }

    /// B1：无 userinfo → endpoint 原样。
    #[test]
    fn b1_no_userinfo_preserves_endpoint() {
        let raw = "amqp://127.0.0.1:5672/vh";
        let endpoint = parse_loopback(raw);
        let events = capture(|| emit_connected(RESOURCE, &endpoint));
        let ep = endpoint_field(&events[0]);
        assert_eq!(ep, raw);
        assert!(!ep.contains("<redacted>"));
    }

    /// B2：仅 username。
    #[test]
    fn b2_username_only_redacts_userinfo() {
        let raw = "amqp://alice@127.0.0.1/vh";
        let endpoint = parse_loopback(raw);
        let events = capture(|| emit_connected(RESOURCE, &endpoint));
        let ep = endpoint_field(&events[0]);
        assert_eq!(ep, "amqp://<redacted>@127.0.0.1/vh");
        assert!(!ep.contains("alice"));
    }

    /// B2b：仅 password（空 username）。
    #[test]
    fn b2b_password_only_redacts_userinfo() {
        let raw = "amqp://:s3cr3t@127.0.0.1/vh";
        let endpoint = parse_loopback(raw);
        let events = capture(|| emit_connected(RESOURCE, &endpoint));
        assert_no_cred_leak(&events[0], raw);
        let ep = endpoint_field(&events[0]);
        assert_eq!(ep, "amqp://<redacted>@127.0.0.1/vh");
    }

    /// B3：IPv6 loopback + sentinel password。
    #[test]
    fn b3_ipv6_loopback_redacts_userinfo() {
        let raw = "amqp://user:s3cr3t@[::1]:5672/vhost";
        let endpoint = parse_loopback(raw);
        let events = capture(|| emit_connected(RESOURCE, &endpoint));
        assert_no_cred_leak(&events[0], raw);
        let ep = endpoint_field(&events[0]);
        assert!(ep.contains("<redacted>"), "endpoint: {ep}");
        assert!(ep.contains("[::1]"), "endpoint: {ep}");
        assert!(ep.contains("vhost"), "endpoint: {ep}");
    }

    /// E1：error Display 内嵌含 sentinel 的 URI（与 endpoint 字段分离）。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试断言 error 字段存在。
    fn e1_error_display_embedded_uri_redacted() {
        let endpoint = parse_loopback("amqp://probe:other@127.0.0.1:5672/app");
        let leak_url = "amqp://user:s3cr3t@127.0.0.1:5672/app";
        let events = capture(|| {
            emit_connect_failed(RESOURCE, &endpoint, &EmbeddedUriError(leak_url));
        });
        let fields = &events[0];
        assert_no_cred_leak(fields, leak_url);
        let error = fields
            .get("error")
            .map(String::as_str)
            .expect("error field missing");
        assert!(
            error.contains("amqp://<redacted>@127.0.0.1:5672/app"),
            "error: {error}"
        );
    }

    /// E2：成功 / 失败 message 与 error 字段存在性。
    #[test]
    fn e2_ok_vs_fail_message_and_error_presence() {
        let endpoint = parse_loopback("amqp://127.0.0.1:5672/app");
        let ok = capture(|| emit_connected(RESOURCE, &endpoint));
        assert_eq!(
            ok[0].get("message").map(String::as_str),
            Some("amqp connected")
        );
        assert!(!ok[0].contains_key("error"));

        let fail = capture(|| {
            emit_connect_failed(RESOURCE, &endpoint, &std::io::Error::other("refused"));
        });
        assert_eq!(
            fail[0].get("message").map(String::as_str),
            Some("amqp connect failed")
        );
        assert!(fail[0].contains_key("error"));
    }
}
