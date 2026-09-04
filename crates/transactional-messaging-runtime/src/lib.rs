#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "consumer")]
/// Provider-neutral transactional consumer execution and lifecycle.
pub mod consumer;

#[cfg(feature = "producer")]
/// Provider-neutral outbox relay execution and lifecycle.
pub mod relay;
