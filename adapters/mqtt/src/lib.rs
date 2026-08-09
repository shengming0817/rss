//! RSS broker-facing MQTT v5 transport.
//!
//! The production surface is deliberately one [`MqttSession`]: one mTLS identity, one eventloop,
//! one persistent broker session and one exact typed topic policy. It never accepts plaintext
//! endpoints or caller-provided topic strings. Device uplinks become
//! [`AuthenticatedDeviceDelivery`] only after the broker's Ed25519 assertion is verified.

mod assertion;
mod config;
mod session;
mod topic;

pub use assertion::{
    BrokerAssertionError, BrokerAssertionVerifier, BrokerPublishFrame, VerifiedBrokerAssertion,
};
#[cfg(feature = "test-support")]
pub use config::NegativeAckPollBarrier;
pub use config::{
    CredentialRevision, MqttConfigError, MqttSessionConfig, MqttTlsMaterial, MqttsEndpoint,
    SessionExpiry,
};
pub use diport::BrokerAccepted;
pub use session::{AuthenticatedDeviceDelivery, MqttReadiness, MqttSession, MqttSessionError};
pub use topic::{
    CredentialGeneration, DeviceScope, ExactMqttTopic, MqttTopicPolicy, MqttUplinkContract,
    TopicPolicyError,
};
