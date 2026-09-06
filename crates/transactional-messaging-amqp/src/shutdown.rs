//! Adapter shutdown errors and the standalone owner's single total budget.
use std::{future::Future, time::Duration};

use rss_redact::RedactedSource;

/// Payload-free failure classification for resource shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmqpShutdownErrorKind {
    /// The duration cannot be represented as a Tokio deadline.
    InvalidBudget,
    /// Cleanup exceeded the caller's total budget; remaining tasks were aborted.
    DeadlineExceeded,
    /// Closing the transport failed.
    Operation,
    /// A resource-owned task panicked.
    TaskPanicked,
    /// A resource-owned task was unexpectedly cancelled.
    TaskCancelled,
    /// The resource has already entered shutdown.
    AlreadyStarted,
}

/// A safe classification and redacted source; never exposes provider or panic payloads.
#[derive(Debug, thiserror::Error)]
#[error("AMQP resource shutdown failed")]
pub struct AmqpShutdownError {
    kind: AmqpShutdownErrorKind,
    #[source]
    source: Option<RedactedSource>,
}

impl AmqpShutdownError {
    /// Read the payload-free reason for shutdown failure.
    pub const fn kind(&self) -> AmqpShutdownErrorKind {
        self.kind
    }
    pub(crate) const fn classified(kind: AmqpShutdownErrorKind) -> Self {
        Self { kind, source: None }
    }
    pub(crate) fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            kind: AmqpShutdownErrorKind::Operation,
            source: Some(RedactedSource::new(source)),
        }
    }
    pub(crate) fn task(source: tokio::task::JoinError) -> Self {
        Self {
            kind: if source.is_panic() {
                AmqpShutdownErrorKind::TaskPanicked
            } else {
                AmqpShutdownErrorKind::TaskCancelled
            },
            source: Some(RedactedSource::new(source)),
        }
    }
}

#[allow(clippy::disallowed_methods)]
// reason: adapter cleanup uses a monotonic I/O deadline, not business time.
pub(crate) async fn within_budget(
    timeout: Duration,
    cleanup: impl Future<Output = Result<(), AmqpShutdownError>>,
) -> Result<(), AmqpShutdownError> {
    if timeout.is_zero() {
        return Err(AmqpShutdownError::classified(
            AmqpShutdownErrorKind::DeadlineExceeded,
        ));
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| AmqpShutdownError::classified(AmqpShutdownErrorKind::InvalidBudget))?;
    tokio::time::timeout_at(deadline, cleanup)
        .await
        .map_err(|_| AmqpShutdownError::classified(AmqpShutdownErrorKind::DeadlineExceeded))?
}

#[derive(Clone, Copy)]
pub(crate) enum ShutdownStage {
    PublisherRecovery,
    SubscriberCancellation,
    TransportClose,
}

#[derive(Default)]
pub(crate) struct ShutdownFailures {
    primary: Option<AmqpShutdownError>,
}
impl ShutdownFailures {
    /// Log every failure immediately, including those followed by a pending cleanup stage.
    pub(crate) fn record(
        &mut self,
        resource: &str,
        stage: ShutdownStage,
        result: Result<(), AmqpShutdownError>,
    ) {
        let Err(error) = result else {
            return;
        };
        let (phase, task_kind) = match stage {
            ShutdownStage::PublisherRecovery => ("task_join", "publisher_recovery"),
            ShutdownStage::SubscriberCancellation => ("task_join", "subscription_cancel"),
            ShutdownStage::TransportClose => ("connection_close", "none"),
        };
        tracing::warn!(target: "amqp", resource, phase, task_kind, error_kind = ?error.kind(),
            "amqp shutdown stage failed");
        if self.primary.as_ref().is_none_or(|previous| {
            shutdown_priority(error.kind()) > shutdown_priority(previous.kind())
        }) {
            self.primary = Some(error);
        }
    }
    pub(crate) fn finish(self) -> Result<(), AmqpShutdownError> {
        self.primary.map_or(Ok(()), Err)
    }
}

// Stage failure priority is independent of iteration/completion order; equal kinds retain the first.
// Budget and admission errors are returned at the entry point, outside stage aggregation.
fn shutdown_priority(kind: AmqpShutdownErrorKind) -> u8 {
    match kind {
        AmqpShutdownErrorKind::TaskPanicked => 3,
        AmqpShutdownErrorKind::TaskCancelled => 2,
        AmqpShutdownErrorKind::Operation => 1,
        AmqpShutdownErrorKind::InvalidBudget
        | AmqpShutdownErrorKind::DeadlineExceeded
        | AmqpShutdownErrorKind::AlreadyStarted => 0,
    }
}

/// Observe completed tasks before pruning their handles; unfinished tasks remain awaitable.
/// No terminal cache is needed: reported tasks are removed, retained tasks are joined at shutdown.
pub(crate) fn observe_finished_task(
    task: &mut tokio_util::task::AbortOnDropHandle<()>,
    task_kind: &'static str,
) -> bool {
    use futures::FutureExt as _;
    if !task.is_finished() {
        return false;
    }
    match task.now_or_never() {
        Some(Err(error)) => {
            let error = AmqpShutdownError::task(error);
            tracing::warn!(target: "amqp", task_kind, error_kind = ?error.kind(),
                "amqp owned task terminated abnormally");
            true
        }
        Some(Ok(())) => true,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::OnDrop;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio_util::task::AbortOnDropHandle;

    #[derive(Clone)]
    struct Writer(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn shutdown_primary_failure_is_independent_of_stage_completion_order() {
        use AmqpShutdownErrorKind::{Operation, TaskCancelled, TaskPanicked};
        for kinds in [
            [Operation, TaskPanicked, TaskCancelled],
            [TaskCancelled, Operation, TaskPanicked],
            [TaskPanicked, TaskCancelled, Operation],
        ] {
            let mut failures = ShutdownFailures::default();
            for kind in kinds {
                failures.record(
                    "test",
                    ShutdownStage::SubscriberCancellation,
                    Err(AmqpShutdownError::classified(kind)),
                );
            }
            assert_eq!(failures.finish().map_err(|e| e.kind()), Err(TaskPanicked));
        }
        assert!(ShutdownFailures::default().finish().is_ok());
    }

    #[test]
    fn shutdown_reports_every_failure_with_its_actual_stage()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Writer(Arc::clone(&bytes));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let primary = tracing::subscriber::with_default(subscriber, || {
            let mut failures = ShutdownFailures::default();
            failures.record(
                "test",
                ShutdownStage::PublisherRecovery,
                Err(AmqpShutdownError::classified(
                    AmqpShutdownErrorKind::TaskPanicked,
                )),
            );
            failures.record(
                "test",
                ShutdownStage::TransportClose,
                Err(AmqpShutdownError::operation(std::io::Error::other(
                    "secret credential",
                ))),
            );
            for kind in [
                AmqpShutdownErrorKind::TaskCancelled,
                AmqpShutdownErrorKind::TaskPanicked,
            ] {
                failures.record(
                    "test",
                    ShutdownStage::SubscriberCancellation,
                    Err(AmqpShutdownError::classified(kind)),
                );
            }
            failures.finish().map_err(|e| e.kind())
        });
        assert_eq!(primary, Err(AmqpShutdownErrorKind::TaskPanicked));
        let capture = String::from_utf8(
            bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .clone(),
        )?;
        assert_eq!(capture.matches("amqp shutdown stage failed").count(), 4);
        assert!(capture.contains("publisher_recovery") && capture.contains("subscription_cancel"));
        assert!(capture.contains("connection_close") && capture.contains("task_join"));
        assert!(
            capture.contains("TaskPanicked")
                && capture.contains("TaskCancelled")
                && capture.contains("Operation")
        );
        assert!(!capture.contains("secret credential"));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn one_budget_covers_all_tasks_and_aborts_the_remainder() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = [75, 150]
            .into_iter()
            .map(|delay| {
                let dropped = Arc::clone(&dropped);
                let cleanup = OnDrop::new(move || {
                    dropped.fetch_add(1, Ordering::SeqCst);
                });
                AbortOnDropHandle::new(tokio::spawn(async move {
                    let _cleanup = cleanup;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }))
            })
            .collect();
        let result = within_budget(Duration::from_millis(100), async move {
            for task in tasks {
                task.await.map_err(AmqpShutdownError::task)?;
            }
            Ok(())
        })
        .await;
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(AmqpShutdownErrorKind::DeadlineExceeded)
        );
        tokio::task::yield_now().await;
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_and_unrepresentable_budgets_never_poll_cleanup() {
        for (timeout, expected) in [
            (Duration::ZERO, AmqpShutdownErrorKind::DeadlineExceeded),
            (Duration::MAX, AmqpShutdownErrorKind::InvalidBudget),
        ] {
            let polled = std::sync::atomic::AtomicBool::new(false);
            let result = within_budget(timeout, async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await;
            assert_eq!(result.map_err(|e| e.kind()), Err(expected));
            assert!(!polled.load(Ordering::SeqCst));
        }
    }

    #[tokio::test]
    async fn pruning_observes_task_failures_without_losing_pending_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Writer(Arc::clone(&bytes));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        for task_kind in ["publisher_recovery", "subscription_cancel"] {
            let mut pending = AbortOnDropHandle::new(tokio::spawn(std::future::pending::<()>()));
            assert!(!observe_finished_task(&mut pending, task_kind));
            pending.abort();
            let mut panicked = AbortOnDropHandle::new(tokio::spawn(async {
                std::panic::resume_unwind(Box::new("secret credential"));
            }));
            tokio::task::yield_now().await;
            tracing::dispatcher::with_default(&dispatch, || {
                assert!(observe_finished_task(&mut pending, task_kind));
                assert!(observe_finished_task(&mut panicked, task_kind));
            });
        }
        let capture = String::from_utf8(
            bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .clone(),
        )?;
        assert!(capture.contains("TaskPanicked") && capture.contains("TaskCancelled"));
        assert!(capture.contains("publisher_recovery") && capture.contains("subscription_cancel"));
        assert!(!capture.contains("secret credential"));
        Ok(())
    }

    #[tokio::test]
    async fn task_errors_redact_panic_payloads() {
        let result =
            tokio::spawn(async { std::panic::resume_unwind(Box::new("secret credential")) }).await;
        let error = AmqpShutdownError::task(result.expect_err("task must panic"));
        assert_eq!(error.kind(), AmqpShutdownErrorKind::TaskPanicked);
        assert!(!format!("{error:?} {error}").contains("secret credential"));
        let mut source = std::error::Error::source(&error);
        while let Some(error) = source {
            assert!(!format!("{error:?} {error}").contains("secret credential"));
            source = error.source();
        }
    }
}
