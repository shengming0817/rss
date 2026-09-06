//! Bounded MQTT v5 QoS 1 delivery, durable protocol recovery, and RSS Outbox publication.
//!
//! Protocol acceptance is not business authentication or an application receipt.
//! Callers own encoding, routing, TLS/credentials, durable handoff and the upstream session store.
//! INVARIANT: MQTT-SETTLEMENT-OWNER-01: only the driver issues connection-bound settlement values.
#![warn(missing_docs)]
#![forbid(unsafe_code)]
mod driver;
mod handles;
mod model;
mod outcome;
mod reconnect;
pub use driver::connect;
pub use handles::{
    Delivery, MqttOutboxPublisher, MqttPublisher, MqttReceiver, MqttResource, Settlement,
};
pub use model::{
    ConnectionState, EncodeError, Limits, MqttConfig, MqttError, PublishRequest, RejectReason,
};
pub use reconnect::ReconnectPolicy;
