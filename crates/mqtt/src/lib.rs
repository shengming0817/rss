//! Bounded MQTT v5 QoS 1 delivery, durable protocol recovery, and RSS Outbox publication.
//!
//! Protocol acceptance is not business authentication or an application receipt.
//! Callers encode payloads before Outbox append and own routing, TLS and the session store.
//! The optional consumer adapter reuses core transaction evidence; raw MQTT handoff remains caller-owned.
//! INVARIANT: MQTT-SETTLEMENT-OWNER-01: only the driver issues connection-bound settlement values.
#![warn(missing_docs)]
#![forbid(unsafe_code)]
mod codec;
mod driver;
mod handles;
mod model;
mod outbox;
mod outcome;
mod reconnect;
pub use driver::connect;
pub use handles::{Delivery, MqttPublisher, MqttReceiver, MqttResource, Settlement};
pub use model::{ConnectionState, Limits, MqttConfig, MqttError, PublishRequest, RejectReason};
pub use reconnect::ReconnectPolicy;

pub use outbox::{MqttOutboxPlan, MqttOutboxPublisher, MqttOutboxTopic};

#[cfg(feature = "consumer")]
mod transactional;
#[cfg(feature = "consumer")]
pub use transactional::{MqttDeliveries, MqttDeliverySource, MqttTransactionSettlement};
