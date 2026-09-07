//! Internal provider fixtures and bounded waits for component integration tests.
//!
//! The Make launcher owns shared brokers across test processes. Exclusive scenarios retain
//! their own guards; private descriptors carry explicit connection material for shared clients.
//! Transactional messaging conformance belongs to `rss-transactional-messaging-testkit`.

#![forbid(unsafe_code)]

mod wait;
pub use wait::{await_delay, await_try};

#[cfg(feature = "containers")]
mod containers;
#[cfg(feature = "containers")]
pub use containers::{
    BridgeNetwork, FixtureError, KafkaTlsFixture, KafkaTlsServerIdentity, MinioTlsFixture,
    MqttTlsFixture, NetworkAttachment, PgConnParams, PgTlsFixture, PgTlsServerIdentity,
    RabbitFixture, RabbitTlsFixture, RedisFixture, bridge_network, exclusive_kafka_tls,
    exclusive_mqtt_tls, exclusive_rabbitmq, launch, managed_redis, minio_tls_archive, postgres_tls,
    rabbitmq_tls, shared_kafka_tls, shared_mqtt_tls, shared_rabbitmq,
};

/// A bounded readiness probe exhausted its total deadline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TestkitError {
    /// Wrap with context naming the expected ready condition.
    #[error(
        "wait timed out after {waited_ms}ms (wrap with context naming the expected ready condition)"
    )]
    WaitTimeout { waited_ms: u64 },
}
