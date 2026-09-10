//! Executable public-API scenarios shared with the fixture-owning integration tests.
#[cfg(feature = "providers")]
pub mod providers;

#[cfg(feature = "device-command-pg")]
pub mod device_command;
#[cfg(any(feature = "execution-pg", feature = "outbox-writer", feature = "mqtt"))]
pub mod pg;
#[cfg(feature = "projection-pg")]
pub mod projection;
#[cfg(feature = "reconcile-pg")]
pub mod reconcile;
#[cfg(feature = "saga-pg")]
pub mod saga;

#[cfg(feature = "outbox-writer")]
pub mod outbox_writer;

#[cfg(feature = "observation-handoff")]
pub mod observation;

#[cfg(feature = "mqtt")]
pub mod mqtt;

#[cfg(feature = "ledger-pg")]
pub mod ledger;

#[cfg(feature = "recovery-pg")]
pub mod recovery;

#[cfg(any(
    feature = "mqtt",
    feature = "ledger-messaging",
    feature = "recovery-pg"
))]
pub mod sample_message;

#[cfg(any(
    feature = "protection",
    feature = "recovery-pg",
    feature = "recovery-s3"
))]
pub mod ephemeral;

#[cfg(feature = "recovery-archive")]
pub mod recovery_archive;
