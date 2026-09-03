//! Read-only Platform projection of RuntimeExec-owned lifecycle and live inventory truth.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use rss_platform::{AdmissionState, ConditionStatus, HostView};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

use crate::inventory::InventoryReader;

#[derive(Clone)]
pub struct RuntimeHostView {
    inner: Arc<HostTruth>,
}

struct HostTruth {
    state: AtomicU8,
    inventory: Option<InventoryReader>,
    admission_gate: Arc<RwLock<()>>,
}

impl RuntimeHostView {
    /// Create the projection in `Starting`; only the RuntimeExec launch funnel can advance it.
    #[must_use]
    pub fn starting(inventory: InventoryReader) -> Self {
        Self {
            inner: Arc::new(HostTruth {
                state: AtomicU8::new(0),
                inventory: Some(inventory),
                admission_gate: Arc::new(RwLock::new(())),
            }),
        }
    }

    /// Build a ready projection for integration journeys without exposing a production state
    /// transition authority.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn ready_for_test(inventory: InventoryReader) -> Self {
        let host = Self::starting(inventory);
        host.mark_ready();
        host
    }

    pub(crate) fn mark_ready(&self) {
        self.inner.state.store(1, Ordering::Release);
    }
    pub(crate) fn begin_drain(&self) {
        self.inner.state.store(2, Ordering::Release);
    }
    pub(crate) fn mark_stopped(&self) {
        self.inner.state.store(3, Ordering::Release);
    }

    pub(crate) fn managed_resource(&self) -> Box<diport::DynManagedResource<'static>> {
        diport::DynManagedResource::new_box(AdmissionDrain(self.clone()))
    }
}

struct RuntimeAdmissionPermit(#[allow(dead_code)] OwnedRwLockReadGuard<()>);
impl rss_platform::AdmissionPermit for RuntimeAdmissionPermit {}

struct AdmissionDrain(RuntimeHostView);

impl diport::ManagedResource for AdmissionDrain {
    fn name(&self) -> &str {
        "platform-admission"
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.0.begin_drain();
        let _admitted = self.0.inner.admission_gate.clone().write_owned().await;
        Ok(())
    }
}

impl HostView for RuntimeHostView {
    fn admission_state(&self) -> AdmissionState {
        match self.inner.state.load(Ordering::Acquire) {
            0 => AdmissionState::Starting,
            1 => AdmissionState::Ready,
            2 => AdmissionState::Draining,
            _ => AdmissionState::Stopped,
        }
    }

    fn try_admit(&self) -> Result<Box<dyn rss_platform::AdmissionPermit>, AdmissionState> {
        let state = self.admission_state();
        if state != AdmissionState::Ready {
            return Err(state);
        }
        let permit = self
            .inner
            .admission_gate
            .clone()
            .try_read_owned()
            .map_err(|_| self.admission_state())?;
        let state = self.admission_state();
        if state != AdmissionState::Ready {
            return Err(state);
        }
        Ok(Box::new(RuntimeAdmissionPermit(permit)))
    }

    fn inventory_revision(&self) -> Option<String> {
        self.inner
            .inventory
            .as_ref()?
            .read()
            .ok()
            .map(|inventory| inventory.runtime_plan_fingerprint().as_str().to_owned())
    }

    fn condition(&self, name: &str) -> Option<ConditionStatus> {
        if name != "runtime.inventory" {
            return None;
        }
        Some(
            if self
                .inner
                .inventory
                .as_ref()
                .is_some_and(|reader| reader.read().is_ok())
            {
                ConditionStatus::True
            } else {
                ConditionStatus::Unknown
            },
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::Mutex;

    struct StateProbe {
        host: RuntimeHostView,
        seen: Arc<Mutex<Vec<AdmissionState>>>,
    }
    impl diport::ManagedResource for StateProbe {
        fn name(&self) -> &str {
            "listener-probe"
        }
        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            self.seen.lock().unwrap().push(self.host.admission_state());
            Ok(())
        }
    }

    #[test]
    fn lifecycle_projection_is_one_way_and_inventory_is_fail_closed() {
        let host = RuntimeHostView {
            inner: Arc::new(HostTruth {
                state: AtomicU8::new(0),
                inventory: None,
                admission_gate: Arc::new(RwLock::new(())),
            }),
        };
        assert_eq!(host.admission_state(), AdmissionState::Starting);
        assert_eq!(
            host.condition("runtime.inventory"),
            Some(ConditionStatus::Unknown)
        );
        assert_eq!(host.inventory_revision(), None);
        host.mark_ready();
        assert_eq!(host.admission_state(), AdmissionState::Ready);
        host.begin_drain();
        assert_eq!(host.admission_state(), AdmissionState::Draining);
        host.mark_stopped();
        assert_eq!(host.admission_state(), AdmissionState::Stopped);
    }

    #[tokio::test]
    async fn admission_is_closed_before_listener_resources() {
        let host = RuntimeHostView {
            inner: Arc::new(HostTruth {
                state: AtomicU8::new(1),
                inventory: None,
                admission_gate: Arc::new(RwLock::new(())),
            }),
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut stack =
            bootstrap::shutdown::ShutdownStack::new(tokio_util::sync::CancellationToken::new());
        stack.register_detached(diport::DynManagedResource::new_box(StateProbe {
            host: host.clone(),
            seen: Arc::clone(&seen),
        }));
        crate::register_platform_admission(&mut stack, &host);
        assert!(
            stack
                .shutdown_within(std::time::Duration::from_secs(1))
                .await
                .is_empty()
        );
        assert_eq!(*seen.lock().unwrap(), [AdmissionState::Draining]);
    }
}
