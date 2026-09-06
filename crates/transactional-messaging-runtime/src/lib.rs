#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "consumer")]
/// Provider-neutral transactional consumer execution and caller-driven loops.
pub mod consumer;

#[cfg(feature = "producer")]
/// Provider-neutral outbox relay execution and caller-driven loops.
pub mod relay;

#[cfg(all(
    feature = "managed-runtime",
    any(feature = "consumer", feature = "producer")
))]
mod managed;
