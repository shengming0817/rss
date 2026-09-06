use bytes::Bytes;
use rumqttc::mqttbytes::v5::PublishProperties;
use rumqttc::{AckMode, Broker, MqttOptions, SessionMode, Transport};
use std::{fmt, sync::Arc, time::Duration};

/// Closed diagnostics; provider strings and wire data never cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum MqttError {
    /// Invalid MQTT configuration.
    #[error("invalid MQTT configuration")]
    InvalidConfig,
    /// Invalid MQTT message.
    #[error("invalid MQTT message")]
    InvalidMessage,
    /// MQTT resource closed.
    #[error("MQTT resource closed")]
    Closed,
    /// MQTT operation deadline elapsed.
    #[error("MQTT operation deadline elapsed")]
    DeadlineElapsed,
    /// MQTT transport unavailable.
    #[error("MQTT transport unavailable")]
    Unavailable,
    /// MQTT connection lost.
    #[error("MQTT connection lost")]
    ConnectionLost,
    /// MQTT broker temporarily busy.
    #[error("MQTT broker temporarily busy")]
    BrokerBusy,
    /// MQTT authentication rejected.
    #[error("MQTT authentication rejected")]
    Authentication,
    /// MQTT protocol failure.
    #[error("MQTT protocol failure")]
    Protocol,
    /// MQTT delivery belongs to a retired connection.
    #[error("MQTT delivery belongs to a retired connection")]
    StaleDelivery,
    /// MQTT settlement outcome unknown.
    #[error("MQTT settlement outcome unknown")]
    SettlementUnknown,
    /// MQTT broker rejected subscription.
    #[error("MQTT broker rejected subscription")]
    SubscriptionRejected,
    /// MQTT session state cannot be restored.
    #[error("MQTT session state cannot be restored")]
    SessionState,
    /// MQTT session storage failed.
    #[error("MQTT session storage failed")]
    SessionStore,
    /// Incoming MQTT QoS is unsupported.
    #[error("incoming MQTT QoS is unsupported")]
    UnsupportedQos,
    /// MQTT receive capacity exceeded.
    #[error("MQTT receive capacity exceeded")]
    ReceiveCapacity,
}

/// Permanent failure to encode an authored Outbox message, before protocol admission.
/// Transport, storage and other retryable work must not run inside the mapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid authored MQTT message")]
pub struct EncodeError;

/// Queue, in-flight and wire limits. All queues are bounded independently.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub(crate) commands: usize,
    pub(crate) deliveries: u16,
    pub(crate) inflight: u16,
    pub(crate) packet_bytes: u32,
}
impl Limits {
    /// Validate explicit bounds, including the MQTT maximum packet size.
    pub fn new(
        commands: usize,
        deliveries: u16,
        inflight: u16,
        packet_bytes: u32,
    ) -> Result<Self, MqttError> {
        if commands == 0
            || commands > u16::MAX as usize
            || deliveries == 0
            || inflight == 0
            || !(8..=268_435_455).contains(&packet_bytes)
        {
            return Err(MqttError::InvalidConfig);
        }
        Ok(Self {
            commands,
            deliveries,
            inflight,
            packet_bytes,
        })
    }
}

/// TLS connection and fixed subscription configuration. Debug deliberately omits all endpoint data.
pub struct MqttConfig {
    pub(crate) options: MqttOptions,
    pub(crate) subscriptions: Vec<String>,
    pub(crate) limits: Limits,
    pub(crate) reconnect: crate::ReconnectPolicy,
}
impl fmt::Debug for MqttConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttConfig")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
impl MqttConfig {
    /// Configure a persistent, manually acknowledged, TLS-only connection.
    ///
    /// The caller must exclusively own `(scope, client_id)` in its session store and broker.
    /// A subscription-set change requires a new identity or an explicitly reset broker session.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        client_id: impl Into<String>,
        scope: impl Into<String>,
        tls: Arc<rustls::ClientConfig>,
        limits: Limits,
    ) -> Result<Self, MqttError> {
        let host = host.into();
        let client_id = client_id.into();
        let scope = scope.into();
        if host.is_empty()
            || port == 0
            || client_id.is_empty()
            || client_id.len() > u16::MAX as usize
            || client_id.contains('\0')
            || scope.is_empty()
        {
            return Err(MqttError::InvalidConfig);
        }
        let mut options = MqttOptions::new(client_id, Broker::tcp(host, port));
        options.set_transport(Transport::tls_with_config(
            rumqttc::TlsConfiguration::Rustls(tls),
        ));
        options.set_session_mode(SessionMode::Persistent);
        options.set_ack_mode(AckMode::Manual);
        options.set_session_store_scope(scope);
        options.set_receive_maximum(Some(limits.deliveries));
        options.set_outgoing_inflight_upper_limit(limits.inflight);
        options.set_max_packet_size(Some(limits.packet_bytes));
        // Single-packet batches make each outgoing ACK event a precise flush boundary.
        options.set_max_request_batch(1).set_read_batch_size(1);
        options.set_keep_alive(10);
        options.set_connect_timeout(Duration::from_secs(10));
        Ok(Self {
            options,
            subscriptions: Vec::new(),
            limits,
            reconnect: crate::ReconnectPolicy::default(),
        })
    }
    /// Exponential reconnect delays with jitter; reset only after validated readiness.
    #[must_use]
    pub fn reconnect_policy(mut self, policy: crate::ReconnectPolicy) -> Self {
        self.reconnect = policy;
        self
    }
    /// Credentials come from the caller; no device identity or authorization is inferred.
    pub fn credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<Bytes>,
    ) -> Result<Self, MqttError> {
        let username = username.into();
        let password = password.into();
        if username.contains('\0')
            || username.len() > u16::MAX as usize
            || password.len() > u16::MAX as usize
        {
            return Err(MqttError::InvalidConfig);
        }
        self.options.set_credentials(username, password);
        Ok(self)
    }
    /// Fixed desired filters. The protocol validator owns MQTT filter syntax.
    pub fn subscriptions(
        mut self,
        filters: impl IntoIterator<Item = String>,
    ) -> Result<Self, MqttError> {
        let filters: Vec<_> = filters.into_iter().collect();
        if filters.len() > self.limits.commands
            || filters.iter().any(|v| {
                v.len() > u16::MAX as usize || v.contains('\0') || !rumqttc::valid_filter(v)
            })
        {
            return Err(MqttError::InvalidConfig);
        }
        if filters.iter().map(|v| v.len() + 3).sum::<usize>() + 8
            > self.limits.packet_bytes as usize
        {
            return Err(MqttError::InvalidConfig);
        }
        self.subscriptions = filters;
        Ok(self)
    }
    /// Broker session retention, with no product-level expiry interpretation.
    pub fn session_expiry(mut self, seconds: u32) -> Result<Self, MqttError> {
        if seconds == 0 {
            return Err(MqttError::InvalidConfig);
        }
        self.options.set_session_expiry_interval(Some(seconds));
        Ok(self)
    }
}

/// Immutable authored MQTT content. No message identity is generated by the adapter.
#[derive(Clone)]
pub struct PublishRequest {
    pub(crate) topic: String,
    pub(crate) payload: Bytes,
    pub(crate) retain: bool,
    pub(crate) properties: PublishProperties,
}
impl fmt::Debug for PublishRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishRequest")
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}
impl PublishRequest {
    /// Validate the authored topic without exposing it in errors.
    pub fn new(topic: impl Into<String>, payload: impl Into<Bytes>) -> Result<Self, MqttError> {
        let topic = topic.into();
        if topic.is_empty()
            || topic.contains('\0')
            || topic.len() > u16::MAX as usize
            || !rumqttc::valid_topic(&topic)
        {
            return Err(MqttError::InvalidMessage);
        }
        Ok(Self {
            topic,
            payload: payload.into(),
            retain: false,
            properties: PublishProperties::default(),
        })
    }
    #[must_use]
    /// Whether the broker retains the publication.
    pub fn retain(mut self, retain: bool) -> Self {
        self.retain = retain;
        self
    }
    #[must_use]
    /// Caller-authored MQTT expiry interval in seconds.
    pub fn message_expiry_interval(mut self, seconds: u32) -> Self {
        self.properties.message_expiry_interval = Some(seconds);
        self
    }
    #[must_use]
    /// Opaque caller-authored correlation bytes.
    pub fn correlation_data(mut self, data: impl Into<Bytes>) -> Self {
        self.properties.correlation_data = Some(data.into());
        self
    }
    #[must_use]
    /// Caller-authored MQTT user properties, preserved across protocol retries.
    pub fn user_properties(mut self, properties: Vec<(String, String)>) -> Self {
        self.properties.user_properties = properties;
        self
    }
    pub(crate) fn valid_size(&self, max: u32) -> bool {
        if self
            .properties
            .correlation_data
            .as_ref()
            .is_some_and(|v| v.len() > u16::MAX as usize)
            || self.properties.user_properties.iter().any(|(k, v)| {
                k.len() > u16::MAX as usize
                    || v.len() > u16::MAX as usize
                    || k.contains('\0')
                    || v.contains('\0')
            })
        {
            return false;
        }
        let mut packet = rumqttc::mqttbytes::v5::Publish::new(
            self.topic.clone(),
            rumqttc::QoS::AtLeastOnce,
            self.payload.clone(),
            Some(self.properties.clone()),
        );
        packet.pkid = 1; // QoS 1 always writes a nonzero two-byte packet identifier.
        packet.size() <= max as usize
    }
}

/// Observable lifecycle. A fresh broker session may have lost offline incoming messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// Initial connection or local checkpoint restoration is pending.
    Connecting,
    /// Connection and fixed subscriptions have been validated.
    Ready {
        /// Current settlement authority generation.
        generation: u64,
        /// Whether the broker resumed its persisted session.
        session_present: bool,
    },
    /// A retryable failure retired the previous connection.
    Reconnecting {
        /// Sanitized reason for retiring the previous connection.
        cause: MqttError,
        /// Current settlement authority generation.
        generation: u64,
    },
    /// Terminal failure; the resource will admit no more operations.
    Failed(MqttError),
    /// The resource has stopped.
    Closed,
}

/// Explicit terminal MQTT rejection reasons; none requests requeue.
#[derive(Clone, Copy, Debug)]
pub enum RejectReason {
    /// Terminal rejection without a more specific protocol reason.
    Unspecified,
    /// Caller rejects authorization; this does not authenticate the message.
    NotAuthorized,
    /// Caller rejects the payload format.
    PayloadFormatInvalid,
}
impl RejectReason {
    pub(crate) fn wire(self) -> rumqttc::mqttbytes::v5::PubAckReason {
        use rumqttc::mqttbytes::v5::PubAckReason;
        match self {
            Self::Unspecified => PubAckReason::UnspecifiedError,
            Self::NotAuthorized => PubAckReason::NotAuthorized,
            Self::PayloadFormatInvalid => PubAckReason::PayloadFormatInvalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qos_one_size_matches_encoded_packets_including_length_rollover() -> anyhow::Result<()> {
        for payload_len in [0, 1, 117, 118, 119, 120, 121, 122, 123, 127, 16370, 16380] {
            let request = PublishRequest::new("abc", vec![0; payload_len])?;
            let mut publish = rumqttc::mqttbytes::v5::Publish::new(
                "abc",
                rumqttc::QoS::AtLeastOnce,
                vec![0; payload_len],
                Some(PublishProperties::default()),
            );
            publish.pkid = 42;
            let mut bytes = bytes::BytesMut::new();
            rumqttc::mqttbytes::v5::Packet::Publish(publish).write(&mut bytes, None)?;
            let size = u32::try_from(bytes.len())?;
            assert!(!request.valid_size(size - 1));
            assert!(request.valid_size(size));
            assert!(request.valid_size(size + 1));
        }
        Ok(())
    }
}
