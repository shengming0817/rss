//! AMQP publisher confirms, generation-scoped recovery, and one-shot delivery settlement.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod conn;
mod conn_events;
mod endpoint;
mod handles;
#[cfg(feature = "managed-runtime")]
mod managed;
mod publisher;
mod settle;
mod shutdown;
mod subscriber;

pub(crate) const EVENT_EXCHANGE: &str = "amq.topic";
pub use conn::{AmqpConnectError, AmqpPrivateCa, AmqpPrivateCaError};
pub use endpoint::{AmqpEndpointError, AmqpPublisherEndpoint, AmqpSubscriberEndpoint};
pub use handles::{AmqpPublisher, AmqpPublisherResource, AmqpSubscriber, AmqpSubscriberResource};
pub use subscriber::{AmqpDeliveries, AmqpSettlement};

pub use shutdown::{AmqpShutdownError, AmqpShutdownErrorKind};
