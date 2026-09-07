//! Local in-flight leases. Product authorization and readiness remain outside this module.
//!
//! ref: tokio-rs/tokio tokio-util/src/task/task_tracker.rs@tokio-util-0.7.16

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::task::{TaskTracker, task_tracker::TaskTrackerToken};

use crate::{ManagedResource, ShutdownError};

#[derive(Clone, Copy)]
enum Phase {
    BeforeOpen,
    Open,
    Closed,
}

pub(crate) struct AdmissionInner {
    phase: Mutex<Phase>,
    tracker: TaskTracker,
}

impl AdmissionInner {
    pub(crate) fn close(&self) {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *phase = Phase::Closed;
        self.tracker.close();
    }
}

/// Local gate rejection, unrelated to authentication or product readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmissionError {
    /// Product code has not opened this gate.
    #[error("local admission has not opened")]
    NotOpen,
    /// Closure is permanent for this lifecycle.
    #[error("local admission is closed")]
    Closed,
    /// A gate can only be opened once.
    #[error("local admission has already opened")]
    AlreadyOpen,
}

/// Move-only authority to open the local gate. Dropping it closes admission.
#[must_use = "dropping admission control permanently closes the gate"]
pub struct AdmissionControl {
    inner: Arc<AdmissionInner>,
}

impl AdmissionControl {
    /// Open once, after product-owned readiness/authorization prerequisites are satisfied.
    pub fn open(&self) -> Result<(), AdmissionError> {
        let mut phase = self
            .inner
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            Phase::BeforeOpen => {
                *phase = Phase::Open;
                Ok(())
            }
            Phase::Open => Err(AdmissionError::AlreadyOpen),
            Phase::Closed => Err(AdmissionError::Closed),
        }
    }
    /// Permanently reject new work. Existing permits must still be released by their owners.
    pub fn close(&self) {
        self.inner.close();
    }
}

impl Drop for AdmissionControl {
    fn drop(&mut self) {
        self.close();
    }
}

/// Cloneable admission view without open/close authority.
#[derive(Clone)]
pub struct AdmissionGate {
    inner: Arc<AdmissionInner>,
}

impl AdmissionGate {
    /// Acquire one in-flight lease. The phase check and token mint share the close lock.
    pub fn try_admit(&self) -> Result<AdmissionPermit, AdmissionError> {
        let phase = self
            .inner
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            Phase::Open => Ok(AdmissionPermit {
                _token: self.inner.tracker.token(),
            }),
            Phase::BeforeOpen => Err(AdmissionError::NotOpen),
            Phase::Closed => Err(AdmissionError::Closed),
        }
    }
}

/// Non-copyable in-flight lease. Hold until work has released its dependency access.
///
/// INVARIANT: RUNTIME-ADMISSION-LEASE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private token with no Clone or public constructor" }
#[must_use = "dropping the permit removes this work from the drain count"]
pub struct AdmissionPermit {
    _token: TaskTrackerToken,
}

pub(crate) struct AdmissionDrain {
    name: String,
    timeout: Duration,
    inner: Arc<AdmissionInner>,
}

impl ManagedResource for AdmissionDrain {
    fn name(&self) -> &str {
        &self.name
    }
    fn shutdown_timeout(&self) -> Duration {
        self.timeout
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.inner.close();
        self.inner.tracker.wait().await;
        Ok(())
    }
}

pub(crate) fn admission(
    name: String,
    timeout: Duration,
) -> (
    AdmissionControl,
    AdmissionGate,
    AdmissionDrain,
    Arc<AdmissionInner>,
) {
    let inner = Arc::new(AdmissionInner {
        phase: Mutex::new(Phase::BeforeOpen),
        tracker: TaskTracker::new(),
    });
    (
        AdmissionControl {
            inner: Arc::clone(&inner),
        },
        AdmissionGate {
            inner: Arc::clone(&inner),
        },
        AdmissionDrain {
            name,
            timeout,
            inner: Arc::clone(&inner),
        },
        inner,
    )
}
