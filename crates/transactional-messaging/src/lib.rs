#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Closed error vocabulary shared by transactional messaging ports.
pub mod error;
#[cfg(feature = "consumer")]
/// Inbox ownership, lease, and idempotency contracts.
pub mod inbox;
/// Authored message identity, envelope, metadata, and fingerprint types.
pub mod message;
/// Stable telemetry vocabulary and observation emission ports.
pub mod observability;
#[cfg(feature = "producer")]
/// Transactional outbox admission, lease, and settlement contracts.
pub mod outbox;
/// Deadline, retry, delivery-budget, and monotonic-time policies.
pub mod policy;
/// Local transaction outcomes and, with `consumer`, opaque consumer capabilities.
pub mod transaction;
/// Narrow publisher and delivery-source transport ports.
pub mod transport;
