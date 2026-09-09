//! Local lifecycle execution and cancellation-safe result handoff.

use std::future::Future;
use std::panic::AssertUnwindSafe;

use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered};

use crate::{
    ShutdownDrain, ShutdownReceipt, ShutdownStack, ShutdownStackError, StartupTransaction,
    TotalDrainBudget,
};

/// Why local execution ended. This is not a business-effect rollback receipt.
pub enum ScopeExit<T, E, S> {
    /// The execution callback returned its original value or error.
    Completed(Result<T, E>),
    /// The caller's prepared stop future completed, possibly with its own error.
    StopRequested(Result<(), S>),
    /// An explicitly critical registered task terminated before the scope stopped.
    CriticalTaskExited(CriticalTaskExit),
    /// The drive future was dropped before observing execution completion.
    DriveCancelled,
    /// Construction or polling panicked; no panic payload is exposed here.
    ExecutionPanicked,
    /// Execution returned successfully without sealing registration; retains the original value.
    RegistrationIncomplete(T),
}

/// Same-registration terminal observation. It does not replace the resource owner's shutdown join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriticalTaskExit {
    name: String,
    reason: crate::TaskExit,
}

impl CriticalTaskExit {
    /// Operator-controlled identity from the canonical registration.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Closed terminal reason; cancellation does not imply business effects were rolled back.
    pub const fn reason(&self) -> crate::TaskExit {
        self.reason
    }
}

/// Read-only, same-stack critical task observations. It owns no tasks or cancellation authority.
/// A scope evaluates these observations automatically; bare stack consumers can select on this view.
#[derive(Clone)]
pub struct CriticalTasks {
    receiver: tokio::sync::watch::Receiver<Vec<crate::TaskStatus>>,
}

impl CriticalTasks {
    pub(crate) fn new(receiver: tokio::sync::watch::Receiver<Vec<crate::TaskStatus>>) -> Self {
        Self { receiver }
    }

    /// Observe the first terminal critical task, including tasks registered while waiting.
    ///
    /// Cancellation is safe and terminal observations are sticky. Returns None only when the stack
    /// publisher has gone away with no critical tasks. A live empty set remains pending. This is a
    /// task fact, not an early-exit policy: a bare consumer decides whether shutdown was expected.
    pub async fn wait(&self) -> Option<CriticalTaskExit> {
        let mut receiver = self.receiver.clone();
        let mut watch_open = true;
        loop {
            let statuses = receiver.borrow_and_update().clone();
            let mut waits: FuturesUnordered<_> = statuses
                .into_iter()
                .map(|status| async move {
                    let reason = status.wait_stopped().await;
                    CriticalTaskExit {
                        name: status.name().to_owned(),
                        reason,
                    }
                })
                .collect();
            tokio::select! {
                biased;
                changed = receiver.changed(), if watch_open => { watch_open = changed.is_ok(); },
                Some(exit) = waits.next(), if !waits.is_empty() => return Some(exit),
                else => return None,
            }
        }
    }
}

/// Original execution outcome and shutdown result, retained independently.
/// Generic application values are intentionally not formatted by this library.
pub struct LifecycleOutcome<T, E, S> {
    exit: ScopeExit<T, E, S>,
    shutdown: Result<ShutdownReceipt, ShutdownStackError>,
}

impl<T, E, S> LifecycleOutcome<T, E, S> {
    /// Read the original execution outcome.
    pub const fn exit(&self) -> &ScopeExit<T, E, S> {
        &self.exit
    }
    /// Read the independent shutdown result, including driver unavailability.
    pub const fn shutdown(&self) -> &Result<ShutdownReceipt, ShutdownStackError> {
        &self.shutdown
    }
    /// Transfer both results without requiring application values or errors to be Clone.
    pub fn into_parts(
        self,
    ) -> (
        ScopeExit<T, E, S>,
        Result<ShutdownReceipt, ShutdownStackError>,
    ) {
        (self.exit, self.shutdown)
    }
}

/// Invalid reuse of the single-shot scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ScopeStateError {
    /// A scope can only be driven once.
    #[error("lifecycle scope has already been driven")]
    AlreadyDriven,
    /// No drive has been polled yet.
    #[error("lifecycle scope has not been driven")]
    NotStarted,
}

/// Sole local owner of execution and its bounded cleanup.
///
/// Dropping a drive after its first poll starts cleanup. An unpolled drive has not started work
/// and leaves this scope ready. Retaining a driven scope allows another wait to recover the result.
/// Dropping the scope abandons result delivery, but its originating runtime still drives cleanup.
#[must_use = "retain the scope to recover execution and shutdown outcomes"]
pub struct LifecycleScope<T, E, S> {
    state: ScopeState<T, E, S>,
}

enum ScopeState<T, E, S> {
    Ready(ShutdownStack),
    Draining {
        exit: ScopeExit<T, E, S>,
        drain: ShutdownDrain,
    },
    Complete(LifecycleOutcome<T, E, S>),
    // Used only while synchronously moving state; no cancellation point observes this variant.
    Moving,
}

impl<T, E, S> LifecycleScope<T, E, S> {
    /// Create a local owner on the currently driven Tokio runtime.
    pub fn try_new(
        budget: TotalDrainBudget,
        timer: std::sync::Arc<impl rss_request_context::ExecutionTimer + 'static>,
    ) -> Result<Self, ShutdownStackError> {
        Ok(Self {
            state: ScopeState::Ready(ShutdownStack::try_new(budget, timer)?),
        })
    }

    /// Execute startup, launch and running work within one cancellation boundary.
    ///
    /// The callback owns the transaction borrow and can commit/finish it. Stage completed resources
    /// before the next cancellable await. Prepare the stop source before calling this method; the
    /// library installs no signals. A ready stop wins over execution on the same poll.
    pub async fn drive<Run, Stop>(
        &mut self,
        run: Run,
        stop: Stop,
    ) -> Result<&LifecycleOutcome<T, E, S>, ScopeStateError>
    where
        Run: for<'a> FnOnce(StartupTransaction<'a>) -> BoxFuture<'a, Result<T, E>>,
        Stop: Future<Output = Result<(), S>>,
    {
        if !matches!(self.state, ScopeState::Ready(_)) {
            return Err(ScopeStateError::AlreadyDriven);
        }
        let ScopeState::Ready(stack) = std::mem::replace(&mut self.state, ScopeState::Moving)
        else {
            unreachable!("ready state was checked without a cancellation point");
        };
        let mut guard = DriveGuard {
            stack: Some(stack),
            state: &mut self.state,
        };
        let stack = guard
            .stack
            .as_mut()
            .unwrap_or_else(|| unreachable!("drive owns the stack"));
        let monitor = stack.critical_tasks();
        let critical = monitor.wait();
        let exit = {
            // Keep callback construction inside catch_unwind as well as future polling.
            let execution = AssertUnwindSafe(async {
                let startup = stack
                    .startup()
                    .unwrap_or_else(|_| unreachable!("fresh scope startup"));
                run(startup).await
            })
            .catch_unwind();
            tokio::pin!(execution);
            tokio::pin!(stop);
            tokio::pin!(critical);
            tokio::select! {
                biased;
                result = &mut stop => ScopeExit::StopRequested(result),
                Some(exit) = &mut critical => ScopeExit::CriticalTaskExited(exit),
                result = &mut execution => match result {
                    Ok(result) => ScopeExit::Completed(result),
                    Err(_) => ScopeExit::ExecutionPanicked,
                },
            }
        };
        let exit = match exit {
            ScopeExit::Completed(Ok(value)) if !stack.registration_is_sealed() => {
                ScopeExit::RegistrationIncomplete(value)
            }
            exit => exit,
        };
        guard.finish(exit);
        drop(guard);
        self.wait().await
    }

    /// Wait without consuming the result. Cancellation can be retried on the same scope.
    pub async fn wait(&mut self) -> Result<&LifecycleOutcome<T, E, S>, ScopeStateError> {
        if matches!(self.state, ScopeState::Ready(_)) {
            return Err(ScopeStateError::NotStarted);
        }
        if let ScopeState::Draining { drain, .. } = &mut self.state {
            drain.wait().await;
            let ScopeState::Draining { exit, drain } =
                std::mem::replace(&mut self.state, ScopeState::Moving)
            else {
                unreachable!("drain state remains owned while waiting");
            };
            self.state = ScopeState::Complete(LifecycleOutcome {
                exit,
                shutdown: drain
                    .into_result()
                    .unwrap_or_else(|| unreachable!("wait cached the receipt")),
            });
        }
        match &self.state {
            ScopeState::Complete(outcome) => Ok(outcome),
            _ => unreachable!("wait ends in a terminal outcome"),
        }
    }

    /// Consume a completed outcome; dropping an unfinished scope still submits cleanup.
    pub fn into_outcome(self) -> Option<LifecycleOutcome<T, E, S>> {
        match self.state {
            ScopeState::Complete(outcome) => Some(outcome),
            _ => None,
        }
    }
}

struct DriveGuard<'a, T, E, S> {
    stack: Option<ShutdownStack>,
    state: &'a mut ScopeState<T, E, S>,
}

impl<T, E, S> DriveGuard<'_, T, E, S> {
    fn finish(&mut self, exit: ScopeExit<T, E, S>) {
        if let Some(stack) = self.stack.take() {
            *self.state = ScopeState::Draining {
                exit,
                drain: stack.shutdown(),
            };
        }
    }
}

impl<T, E, S> Drop for DriveGuard<'_, T, E, S> {
    fn drop(&mut self) {
        self.finish(ScopeExit::DriveCancelled);
    }
}
