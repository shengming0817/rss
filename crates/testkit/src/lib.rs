//! Internal provider fixtures and bounded waits for component integration tests.
//!
//! Fixtures own temporary PostgreSQL, RabbitMQ and Redis containers. Consumers keep their guards
//! alive for the whole scenario; network and TLS material are explicit fixture outputs.
//! Transactional messaging conformance belongs to `rss-transactional-messaging-testkit`.

#![forbid(unsafe_code)]

mod wait;
pub use wait::{await_delay, await_try};

#[cfg(feature = "containers")]
mod containers;
#[cfg(feature = "containers")]
pub use containers::{
    BridgeNetwork, FixtureError, NetworkAttachment, PgConnParams, PgTlsFixture,
    PgTlsServerIdentity, RabbitFixture, RabbitTlsFixture, RedisFixture, bridge_network,
    managed_rabbitmq, managed_redis, postgres_tls, rabbitmq_tls,
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
