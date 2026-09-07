#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod fence;
#[cfg(feature = "consumer")]
pub mod inbox;
pub mod message;
pub mod observability;
#[cfg(feature = "producer")]
pub mod outbox;
pub mod policy;
pub mod transaction;
pub mod transport;
