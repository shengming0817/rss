//! Executable public-API scenarios shared with the fixture-owning integration tests.
#[cfg(feature = "providers")]
pub mod providers;

#[cfg(feature = "device-command-pg")]
pub mod device_command;
#[cfg(any(feature = "execution-pg", feature = "outbox-writer"))]
pub mod pg;
#[cfg(feature = "projection-pg")]
pub mod projection;
#[cfg(feature = "reconcile-pg")]
pub mod reconcile;
#[cfg(feature = "saga-pg")]
pub mod saga;

#[cfg(feature = "outbox-writer")]
pub mod outbox_writer;
