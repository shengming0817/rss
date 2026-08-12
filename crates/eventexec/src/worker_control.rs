use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionState {
    Running,
    Paused,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DrainSnapshot {
    admission: AdmissionState,
    in_flight: usize,
}

impl DrainSnapshot {
    const fn running() -> Self {
        Self {
            admission: AdmissionState::Running,
            in_flight: 0,
        }
    }

    const fn is_drained(self) -> bool {
        !matches!(self.admission, AdmissionState::Running) && self.in_flight == 0
    }
}

/// Reconcile-local observation state retained until that independent worker is migrated.
#[derive(Clone)]
pub(crate) struct WorkerDrainObservation {
    state: watch::Sender<DrainSnapshot>,
}

impl WorkerDrainObservation {
    pub(crate) fn new() -> Self {
        let (state, _receiver) = watch::channel(DrainSnapshot::running());
        Self { state }
    }

    pub(crate) fn mark_running(&self) {
        self.state.send_modify(|snapshot| {
            if snapshot.admission != AdmissionState::Stopped {
                snapshot.admission = AdmissionState::Running;
            }
        });
    }

    pub(crate) fn mark_paused(&self) {
        self.state.send_modify(|snapshot| {
            if snapshot.admission != AdmissionState::Stopped {
                snapshot.admission = AdmissionState::Paused;
            }
        });
    }

    pub(crate) fn set_in_flight(&self, in_flight: usize) {
        self.state.send_modify(|snapshot| {
            if snapshot.admission != AdmissionState::Stopped {
                snapshot.in_flight = in_flight;
            }
        });
    }

    pub(crate) fn mark_stopped(&self) {
        self.state.send_modify(|snapshot| {
            snapshot.admission = AdmissionState::Stopped;
            snapshot.in_flight = 0;
        });
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.state.borrow().in_flight
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.state.borrow().is_drained()
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.state.borrow().admission == AdmissionState::Stopped
    }

    pub(crate) async fn wait_drained(&self) {
        let mut state = self.state.subscribe();
        loop {
            if state.borrow().is_drained() {
                return;
            }
            if state.changed().await.is_err() {
                return;
            }
        }
    }
}
