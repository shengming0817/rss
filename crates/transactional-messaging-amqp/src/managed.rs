//! Explicit RSS integration; the shutdown stack owns the only timeout here.
use crate::{
    AmqpPublisherResource, AmqpShutdownError, AmqpShutdownErrorKind, AmqpSubscriberResource,
};
use rss_runtime::{ManagedResource, ShutdownError};

fn into_runtime(error: AmqpShutdownError) -> ShutdownError {
    match error.kind() {
        AmqpShutdownErrorKind::TaskPanicked => ShutdownError::task_panicked(error),
        AmqpShutdownErrorKind::TaskCancelled => ShutdownError::task_cancelled(error),
        AmqpShutdownErrorKind::DeadlineExceeded => ShutdownError::deadline_exceeded(error),
        AmqpShutdownErrorKind::Operation
        | AmqpShutdownErrorKind::InvalidBudget
        | AmqpShutdownErrorKind::AlreadyStarted => ShutdownError::new(error),
    }
}

impl ManagedResource for AmqpPublisherResource {
    fn name(&self) -> &str {
        self.name()
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.shutdown_managed().await.map_err(into_runtime)
    }
}
impl ManagedResource for AmqpSubscriberResource {
    fn name(&self) -> &str {
        self.name()
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.shutdown_managed().await.map_err(into_runtime)
    }
}
