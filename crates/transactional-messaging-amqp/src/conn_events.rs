//! Connection observations accept closed failure reasons, never raw error text or endpoints.
//! Resource names are caller-selected diagnostic identifiers and must not contain secrets.

pub(crate) fn emit_connected(resource: &str) {
    tracing::info!(target: "amqp", resource, "amqp connected");
}

pub(crate) fn emit_connect_failed(resource: &str, reason: AmqpFailureReason) {
    tracing::warn!(target: "amqp", resource, error = %reason.summary(), "amqp connect failed");
}

pub(crate) fn emit_subscription_cancel_failed(resource: &str, reason: AmqpFailureReason) {
    tracing::warn!(target: "amqp", resource, error = %reason.summary(), "amqp delivery source basic.cancel error");
}

pub(crate) fn emit_delivery_failed(resource: &str, topic: &str, reason: AmqpFailureReason) {
    tracing::warn!(target: "amqp", resource, topic, error = %reason.summary(), "amqp delivery source error; skipping");
}

/// RSS-owned transport recovery connection result. Unlike initial connection events this funnel
/// deliberately has no endpoint parameter, so recovery cannot accidentally disclose or even record
/// broker coordinates. Generation and the closed result vocabulary are sufficient to correlate it
/// with the lifecycle event that initiated replacement.
#[derive(Clone, Copy)]
pub(crate) enum RecoveryConnectResult {
    Connected,
    Failed {
        stage: RecoveryFailureStage,
        reason: AmqpFailureReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryFailureStage {
    Connect,
    CreateChannel,
    ConfirmSelect,
}

impl RecoveryFailureStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::CreateChannel => "create_channel",
            Self::ConfirmSelect => "confirm_select",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AmqpFailureReason {
    Io,
    Protocol,
    State,
    Runtime,
    Heartbeat,
    Client,
}

impl AmqpFailureReason {
    /// Output-only projection; AMQP retains ownership of its failure classification.
    pub(crate) const fn summary(self) -> rss_redact::ErrorSummary {
        use rss_redact::ErrorSummary;
        match self {
            Self::Io => ErrorSummary::Io,
            Self::Protocol => ErrorSummary::Protocol,
            Self::State => ErrorSummary::State,
            Self::Runtime => ErrorSummary::Runtime,
            Self::Heartbeat => ErrorSummary::Heartbeat,
            Self::Client => ErrorSummary::Client,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Protocol => "protocol",
            Self::State => "state",
            Self::Runtime => "runtime",
            Self::Heartbeat => "heartbeat",
            Self::Client => "client",
        }
    }
}

impl RecoveryConnectResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Failed { .. } => "failed",
        }
    }
}

#[allow(clippy::cognitive_complexity)]
// reason: two closed result variants select only tracing level; macro expansion exceeds the lint threshold.
pub(crate) fn emit_recovery_connect_result(
    resource: &str,
    generation: u64,
    result: RecoveryConnectResult,
) {
    match result {
        RecoveryConnectResult::Connected => tracing::info!(
            target: "amqp",
            resource,
            transport_generation = generation,
            phase = "transport_reconnect",
            result = result.as_str(),
            "amqp transport recovery connection completed",
        ),
        RecoveryConnectResult::Failed { stage, reason } => tracing::warn!(
            target: "amqp",
            resource,
            transport_generation = generation,
            phase = "transport_reconnect",
            result = result.as_str(),
            failure_stage = stage.as_str(),
            failure_reason = reason.as_str(),
            "amqp transport recovery connection failed",
        ),
    }
}

#[cfg(test)]
mod cred_redact_tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::{
        AmqpFailureReason, RecoveryConnectResult, RecoveryFailureStage, emit_connect_failed,
        emit_connected, emit_recovery_connect_result,
    };

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

    #[test]
    fn recovery_connection_events_have_no_endpoint_or_error_field() {
        let events = capture(|| {
            emit_recovery_connect_result("amqp-recovery", 41, RecoveryConnectResult::Connected);
            for stage in [
                RecoveryFailureStage::Connect,
                RecoveryFailureStage::CreateChannel,
                RecoveryFailureStage::ConfirmSelect,
            ] {
                emit_recovery_connect_result(
                    "amqp-recovery",
                    41,
                    RecoveryConnectResult::Failed {
                        stage,
                        reason: AmqpFailureReason::Io,
                    },
                );
            }
        });

        assert_eq!(events.len(), 4);
        for (index, fields) in events.iter().enumerate() {
            assert_eq!(
                fields.get("resource").map(String::as_str),
                Some("amqp-recovery")
            );
            assert_eq!(
                fields.get("transport_generation").map(String::as_str),
                Some("41")
            );
            assert_eq!(
                fields.get("phase").map(String::as_str),
                Some("transport_reconnect")
            );
            assert!(fields.contains_key("result"));
            assert!(!fields.contains_key("endpoint"));
            assert!(!fields.contains_key("error"));
            if index == 0 {
                assert!(!fields.contains_key("failure_stage"));
                assert!(!fields.contains_key("failure_reason"));
            } else {
                assert!(matches!(
                    fields.get("failure_stage").map(String::as_str),
                    Some("connect" | "create_channel" | "confirm_select")
                ));
                assert_eq!(fields.get("failure_reason").map(String::as_str), Some("io"));
            }
        }
    }

    #[test]
    fn recovery_failure_stage_and_reason_vocabularies_are_closed() {
        assert_eq!(
            [
                RecoveryFailureStage::Connect,
                RecoveryFailureStage::CreateChannel,
                RecoveryFailureStage::ConfirmSelect,
            ]
            .map(RecoveryFailureStage::as_str),
            ["connect", "create_channel", "confirm_select"]
        );
        assert_eq!(
            [
                AmqpFailureReason::Io,
                AmqpFailureReason::Protocol,
                AmqpFailureReason::State,
                AmqpFailureReason::Runtime,
                AmqpFailureReason::Heartbeat,
                AmqpFailureReason::Client,
            ]
            .map(AmqpFailureReason::as_str),
            ["io", "protocol", "state", "runtime", "heartbeat", "client"]
        );
    }

    #[test]
    fn initial_connection_events_only_publish_closed_diagnostics() {
        let events = capture(|| {
            emit_connected(RESOURCE);
            for text in [
                "https://broker/SENSITIVE_2326",
                "https://broker/?token=SENSITIVE_2326",
                "https://broker/#SENSITIVE_2326",
                "Bearer SENSITIVE_2326",
                "email SENSITIVE_2326@example.com free text",
            ] {
                let error = lapin::Error::from(std::io::Error::other(text));
                emit_connect_failed(RESOURCE, crate::conn::amqp_failure_reason(&error));
            }
        });
        assert_eq!(events.len(), 6);
        for (index, fields) in events.iter().enumerate() {
            assert!(!fields.contains_key("endpoint"));
            assert!(
                !fields
                    .values()
                    .any(|v| v.contains("SENSITIVE_2326") || v.contains("broker"))
            );
            assert_eq!(fields.get("resource").map(String::as_str), Some(RESOURCE));
            if index == 0 {
                assert!(!fields.contains_key("error"));
                assert_eq!(
                    fields.get("message").map(String::as_str),
                    Some("amqp connected")
                );
            } else {
                assert_eq!(fields.get("error").map(String::as_str), Some("io"));
                assert_eq!(
                    fields.get("message").map(String::as_str),
                    Some("amqp connect failed")
                );
            }
        }
    }

    #[test]
    fn subscription_failures_retain_identity_without_provider_text() {
        use super::{emit_delivery_failed, emit_subscription_cancel_failed};
        let error = lapin::Error::from(std::io::Error::other("Bearer SENSITIVE_2326"));
        let reason = crate::conn::amqp_failure_reason(&error);
        let events = capture(|| {
            emit_subscription_cancel_failed("subscriber-a", reason);
            emit_delivery_failed("subscriber-b", "topic-b", reason);
        });
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].get("resource").map(String::as_str),
            Some("subscriber-a")
        );
        assert_eq!(
            events[1].get("resource").map(String::as_str),
            Some("subscriber-b")
        );
        assert_eq!(events[1].get("topic").map(String::as_str), Some("topic-b"));
        for fields in events {
            assert_eq!(fields.get("error").map(String::as_str), Some("io"));
            assert!(
                !fields
                    .values()
                    .any(|value| value.contains("SENSITIVE_2326"))
            );
        }
    }

    #[derive(Debug)]
    struct MustNotFormat;
    impl std::fmt::Display for MustNotFormat {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            unreachable!("diagnostic boundary must never format the provider error")
        }
    }
    impl std::error::Error for MustNotFormat {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            unreachable!("diagnostic boundary must never traverse the provider error")
        }
    }

    #[test]
    fn classification_does_not_format_or_traverse_provider_errors() {
        let error = lapin::Error::from(std::io::Error::other(MustNotFormat));
        let reason = crate::conn::amqp_failure_reason(&error);
        let events = capture(|| emit_connect_failed(RESOURCE, reason));
        assert_eq!(events[0].get("error").map(String::as_str), Some("io"));
    }
}
