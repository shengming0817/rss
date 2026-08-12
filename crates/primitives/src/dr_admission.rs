//! Process-local admission fencing for L2 disaster recovery.
//!
//! The control authority is move-only and the three lane handles are typed. All lane state is
//! changed under one mutex so a pause request is one linearization point across relay, consumer,
//! and serving writes. This module deliberately contains no transport, replica registry, or
//! operator protocol.
//!
//! ref: tower-rs/tower tower/src/builder/mod.rs@master (a request remains in flight until the
//! wrapped service future completes); kube-rs/kube kube-runtime/src/controller/mod.rs@main
//! (closed desired-state controller input with explicit retry/error observation).

use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::watch;

/// Stable identity of one admission attempt inside the current restored database lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdmissionEpochId(uuid::Uuid);

impl AdmissionEpochId {
    /// Build an admission epoch from a non-nil UUID.
    pub fn new(value: uuid::Uuid) -> Result<Self, AdmissionError> {
        if value.is_nil() {
            return Err(AdmissionError::InvalidEpoch);
        }
        Ok(Self(value))
    }

    /// Parse the canonical lowercase-hyphenated representation.
    pub fn parse(raw: &str) -> Result<Self, AdmissionError> {
        let value = uuid::Uuid::try_parse(raw).map_err(|_| AdmissionError::InvalidEpoch)?;
        if value.hyphenated().to_string() != raw {
            return Err(AdmissionError::InvalidEpoch);
        }
        Self::new(value)
    }

    /// Return the underlying UUID for durable adapters.
    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}

/// Process-local admission failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// The caller supplied nil or non-canonical epoch identity.
    #[error("admission epoch is invalid")]
    InvalidEpoch,
    /// The lane is closed for the active recovery epoch.
    #[error("admission is paused")]
    Paused,
    /// The process admission owner has terminated permanently.
    #[error("admission is stopped")]
    Stopped,
    /// A resume command does not name the locally active epoch.
    #[error("admission epoch is fenced")]
    EpochConflict,
    /// A lane was resumed before the previous lane reached its closed state.
    #[error("admission transition is out of order")]
    InvalidTransition,
    /// Resume was requested while admitted work remains in flight.
    #[error("admission has not drained")]
    NotDrained,
    /// The in-flight counter cannot represent another permit.
    #[error("admission in-flight counter overflow")]
    CounterOverflow,
}

/// Closed process-local phase. Durable, per-instance acknowledgement remains adapter-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAdmissionPhase {
    /// Startup has not yet established the durable database lineage; every lane is closed.
    Initializing,
    /// All three lanes admit work and no recovery epoch is active.
    Running,
    /// All three lanes are closed for the active epoch.
    Paused,
    /// Relay is open; consumer and writes remain closed.
    RelayRunning,
    /// Relay and consumer are open; writes remain closed.
    ConsumerRunning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LaneState {
    open: bool,
    in_flight: usize,
}

impl LaneState {
    const fn closed() -> Self {
        Self {
            open: false,
            in_flight: 0,
        }
    }
}

#[derive(Debug)]
struct ProcessState {
    active_epoch: Option<AdmissionEpochId>,
    phase: LocalAdmissionPhase,
    lanes: [LaneState; 3],
    stopped: bool,
}

impl ProcessState {
    const fn initializing() -> Self {
        Self {
            active_epoch: None,
            phase: LocalAdmissionPhase::Initializing,
            lanes: [LaneState::closed(); 3],
            stopped: false,
        }
    }

    fn close_all(&mut self, epoch: AdmissionEpochId) {
        self.active_epoch = Some(epoch);
        self.phase = LocalAdmissionPhase::Paused;
        for lane in &mut self.lanes {
            lane.open = false;
        }
    }

    fn all_drained(&self) -> bool {
        self.lanes
            .iter()
            .all(|lane| !lane.open && lane.in_flight == 0)
    }
}

#[derive(Debug)]
struct SharedAdmission {
    state: Mutex<ProcessState>,
    changed: watch::Sender<u64>,
}

impl SharedAdmission {
    fn lock(&self) -> MutexGuard<'_, ProcessState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn notify(&self) {
        self.changed.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }
}

mod lane_seal {
    pub trait Sealed {}
}

/// Marker for the outbox relay admission lane.
#[derive(Debug)]
pub struct RelayLane {
    _seal: (),
}

/// Marker for the event consumer admission lane.
#[derive(Debug)]
pub struct ConsumerLane {
    _seal: (),
}

/// Marker for generated serving writes and mutating maintenance workers.
#[derive(Debug)]
pub struct WriteLane {
    _seal: (),
}

impl lane_seal::Sealed for RelayLane {}
impl lane_seal::Sealed for ConsumerLane {}
impl lane_seal::Sealed for WriteLane {}

/// Closed lane marker implemented only by this module.
pub trait AdmissionLane: lane_seal::Sealed + Send + Sync + 'static {
    #[doc(hidden)]
    const INDEX: usize;
}

impl AdmissionLane for RelayLane {
    const INDEX: usize = 0;
}

impl AdmissionLane for ConsumerLane {
    const INDEX: usize = 1;
}

impl AdmissionLane for WriteLane {
    const INDEX: usize = 2;
}

/// Typed admission handle. Construction is restricted to [`PreparedAdmissionControls`].
pub struct AdmissionGate<L: AdmissionLane> {
    shared: Arc<SharedAdmission>,
    _lane: PhantomData<fn() -> L>,
}

impl<L: AdmissionLane> Clone for AdmissionGate<L> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            _lane: PhantomData,
        }
    }
}

impl<L: AdmissionLane> std::fmt::Debug for AdmissionGate<L> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionGate")
            .field("lane", &L::INDEX)
            .finish_non_exhaustive()
    }
}

impl<L: AdmissionLane> AdmissionGate<L> {
    fn new(shared: Arc<SharedAdmission>) -> Self {
        Self {
            shared,
            _lane: PhantomData,
        }
    }

    /// Admit one unit of work or fail closed. The returned permit spans the complete operation.
    pub fn try_enter(&self) -> Result<AdmissionPermit<L>, AdmissionError> {
        {
            let mut state = self.shared.lock();
            if state.stopped {
                return Err(AdmissionError::Stopped);
            }
            let lane = &mut state.lanes[L::INDEX];
            if !lane.open {
                return Err(AdmissionError::Paused);
            }
            lane.in_flight = lane
                .in_flight
                .checked_add(1)
                .ok_or(AdmissionError::CounterOverflow)?;
        }
        self.shared.notify();
        Ok(AdmissionPermit {
            shared: Arc::clone(&self.shared),
            _lane: PhantomData,
        })
    }

    /// Wait until this lane is open, or fail if the process has stopped.
    pub async fn wait_open(&self) -> Result<(), AdmissionError> {
        self.wait_for_lane_state(true).await
    }

    /// Wait until this lane is closed, or fail if the process has stopped.
    pub async fn wait_closed(&self) -> Result<(), AdmissionError> {
        self.wait_for_lane_state(false).await
    }

    async fn wait_for_lane_state(&self, open: bool) -> Result<(), AdmissionError> {
        let mut changed = self.shared.changed.subscribe();
        loop {
            {
                let state = self.shared.lock();
                if state.stopped {
                    return Err(AdmissionError::Stopped);
                }
                if state.lanes[L::INDEX].open == open {
                    return Ok(());
                }
            }
            if changed.changed().await.is_err() {
                return Err(AdmissionError::Stopped);
            }
        }
    }
}

/// Move-only in-flight capability. Dropping it is the only way to release admission.
pub struct AdmissionPermit<L: AdmissionLane> {
    shared: Arc<SharedAdmission>,
    _lane: PhantomData<fn() -> L>,
}

impl<L: AdmissionLane> std::fmt::Debug for AdmissionPermit<L> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionPermit")
            .field("lane", &L::INDEX)
            .finish_non_exhaustive()
    }
}

impl<L: AdmissionLane> Drop for AdmissionPermit<L> {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            let lane = &mut state.lanes[L::INDEX];
            debug_assert!(lane.in_flight > 0, "admission permit released twice");
            lane.in_flight = lane.in_flight.saturating_sub(1);
        }
        self.shared.notify();
    }
}

/// Relay admission handle.
pub type RelayAdmission = AdmissionGate<RelayLane>;
/// Consumer admission handle.
pub type ConsumerAdmission = AdmissionGate<ConsumerLane>;
/// Serving-write admission handle.
pub type WriteAdmission = AdmissionGate<WriteLane>;

/// Read-only local state for readiness and durable acknowledgement code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionSnapshot {
    active_epoch: Option<AdmissionEpochId>,
    phase: LocalAdmissionPhase,
    in_flight: [usize; 3],
    stopped: bool,
}

impl AdmissionSnapshot {
    /// Active epoch, if a pause has been observed.
    pub const fn active_epoch(self) -> Option<AdmissionEpochId> {
        self.active_epoch
    }

    /// Current local phase.
    pub const fn phase(self) -> LocalAdmissionPhase {
        self.phase
    }

    /// Relay, consumer, and write in-flight counts in that order.
    pub const fn in_flight(self) -> [usize; 3] {
        self.in_flight
    }

    /// Whether the process owner is terminal.
    pub const fn is_stopped(self) -> bool {
        self.stopped
    }
}

/// Sole move-only authority that changes all three lanes.
pub struct ProcessAdmissionControl {
    shared: Arc<SharedAdmission>,
}

impl std::fmt::Debug for ProcessAdmissionControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProcessAdmissionControl(<sealed>)")
    }
}

impl ProcessAdmissionControl {
    /// Close every lane while durable startup state is unavailable.
    pub fn fail_closed_initializing(&self) -> Result<(), AdmissionError> {
        {
            let mut state = self.shared.lock();
            if state.stopped {
                return Err(AdmissionError::Stopped);
            }
            state.active_epoch = None;
            state.phase = LocalAdmissionPhase::Initializing;
            for lane in &mut state.lanes {
                lane.open = false;
            }
        }
        self.shared.notify();
        Ok(())
    }

    /// Establish that no durable admission epoch exists and open every lane.
    ///
    /// This is the only transition out of the fail-closed startup state.
    pub fn start_running(&self) -> Result<(), AdmissionError> {
        {
            let mut state = self.shared.lock();
            if state.stopped {
                return Err(AdmissionError::Stopped);
            }
            if state.phase != LocalAdmissionPhase::Initializing || state.active_epoch.is_some() {
                return Err(AdmissionError::InvalidTransition);
            }
            for lane in &mut state.lanes {
                lane.open = true;
            }
            state.phase = LocalAdmissionPhase::Running;
        }
        self.shared.notify();
        Ok(())
    }

    /// Close all three lanes at one linearization point. A different epoch is a re-pause.
    pub fn pause_all(&self, epoch: AdmissionEpochId) -> Result<(), AdmissionError> {
        {
            let mut state = self.shared.lock();
            if state.stopped {
                return Err(AdmissionError::Stopped);
            }
            state.close_all(epoch);
        }
        self.shared.notify();
        Ok(())
    }

    /// Wait until all three closed lanes have no admitted work.
    pub async fn wait_drained(&self) -> Result<(), AdmissionError> {
        let mut changed = self.shared.changed.subscribe();
        loop {
            {
                let state = self.shared.lock();
                if state.stopped {
                    return Err(AdmissionError::Stopped);
                }
                if state.phase == LocalAdmissionPhase::Paused && state.all_drained() {
                    return Ok(());
                }
            }
            if changed.changed().await.is_err() {
                return Err(AdmissionError::Stopped);
            }
        }
    }

    /// Resume relay only for the active, fully drained epoch.
    pub fn resume_relay(&self, epoch: AdmissionEpochId) -> Result<(), AdmissionError> {
        self.transition(
            epoch,
            LocalAdmissionPhase::Paused,
            LocalAdmissionPhase::RelayRunning,
            0,
        )
    }

    /// Resume consumer after every relay worker has acknowledged the same epoch.
    pub fn resume_consumer(&self, epoch: AdmissionEpochId) -> Result<(), AdmissionError> {
        self.transition(
            epoch,
            LocalAdmissionPhase::RelayRunning,
            LocalAdmissionPhase::ConsumerRunning,
            1,
        )
    }

    /// Resume serving writes after every consumer worker has acknowledged the same epoch.
    pub fn resume_writes(&self, epoch: AdmissionEpochId) -> Result<(), AdmissionError> {
        self.transition(
            epoch,
            LocalAdmissionPhase::ConsumerRunning,
            LocalAdmissionPhase::Running,
            2,
        )
    }

    fn transition(
        &self,
        epoch: AdmissionEpochId,
        expected: LocalAdmissionPhase,
        next: LocalAdmissionPhase,
        lane_index: usize,
    ) -> Result<(), AdmissionError> {
        {
            let mut state = self.shared.lock();
            if state.stopped {
                return Err(AdmissionError::Stopped);
            }
            if state.active_epoch != Some(epoch) {
                return Err(AdmissionError::EpochConflict);
            }
            if state.phase != expected {
                return Err(AdmissionError::InvalidTransition);
            }
            if expected == LocalAdmissionPhase::Paused && !state.all_drained() {
                return Err(AdmissionError::NotDrained);
            }
            state.lanes[lane_index].open = true;
            state.phase = next;
            if next == LocalAdmissionPhase::Running {
                state.active_epoch = None;
            }
        }
        self.shared.notify();
        Ok(())
    }

    /// Inspect local state without granting admission or creating a receipt.
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let state = self.shared.lock();
        AdmissionSnapshot {
            active_epoch: state.active_epoch,
            phase: state.phase,
            in_flight: state.lanes.map(|lane| lane.in_flight),
            stopped: state.stopped,
        }
    }

    /// Permanently stop all lanes. A stopped process can never acknowledge a resumable phase.
    pub fn stop(&self) {
        {
            let mut state = self.shared.lock();
            state.stopped = true;
            for lane in &mut state.lanes {
                lane.open = false;
            }
        }
        self.shared.notify();
    }
}

/// Take-once bundle prepared by the process composition owner.
pub struct PreparedAdmissionControls {
    control: ProcessAdmissionControl,
    relay: RelayAdmission,
    consumer: ConsumerAdmission,
    writes: WriteAdmission,
}

impl PreparedAdmissionControls {
    /// Consume the bundle into the sole controller and its three typed lane handles.
    pub fn into_parts(
        self,
    ) -> (
        ProcessAdmissionControl,
        RelayAdmission,
        ConsumerAdmission,
        WriteAdmission,
    ) {
        (self.control, self.relay, self.consumer, self.writes)
    }
}

/// Prepare one process-local DR admission authority. There is no default or per-lane constructor.
pub fn prepare_dr_admission_controls() -> PreparedAdmissionControls {
    let (changed, _receiver) = watch::channel(0_u64);
    let shared = Arc::new(SharedAdmission {
        state: Mutex::new(ProcessState::initializing()),
        changed,
    });
    PreparedAdmissionControls {
        control: ProcessAdmissionControl {
            shared: Arc::clone(&shared),
        },
        relay: AdmissionGate::new(Arc::clone(&shared)),
        consumer: AdmissionGate::new(Arc::clone(&shared)),
        writes: AdmissionGate::new(shared),
    }
}
