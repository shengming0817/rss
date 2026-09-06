//! Kafka publication with explicit acceptance evidence and a unique native resource owner.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod config;
mod engine;
mod publisher;
mod record;
pub use config::{KafkaClientId, KafkaConfig, KafkaCredentials, KafkaLimits};
pub use publisher::{KafkaPublisher, KafkaPublisherResource};

/// Safe component diagnostic; provider text and credentials never enter its source chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KafkaError {
    #[error("invalid Kafka resource limits")]
    InvalidLimits,
    #[error("invalid Kafka lifecycle timeout")]
    InvalidLifecycleTimeout,
    #[error("invalid Kafka configuration")]
    InvalidConfiguration,
    #[error("invalid Kafka client identity")]
    InvalidClientId,
    #[error("invalid Kafka route mapping")]
    InvalidRoute,
    #[error("Kafka initialization failed")]
    Initialization,
    #[error("Kafka owner thread could not start")]
    ThreadStart,
    #[error("Kafka lifecycle deadline elapsed")]
    DeadlineElapsed,
    #[error("Kafka owner failed")]
    OwnerFailed,
    #[error("Kafka shutdown failed")]
    Shutdown,
}
/// Broker acknowledgement coordinates. This proves acceptance, not consumer execution.
pub struct KafkaPublishReceipt {
    pub(crate) topic: String,
    pub(crate) partition: i32,
    pub(crate) offset: i64,
}
impl KafkaPublishReceipt {
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
    #[must_use]
    pub const fn partition(&self) -> i32 {
        self.partition
    }
    #[must_use]
    pub const fn offset(&self) -> i64 {
        self.offset
    }
}
impl std::fmt::Debug for KafkaPublishReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KafkaPublishReceipt(<redacted>)")
    }
}

#[cfg(test)]
mod tests;
