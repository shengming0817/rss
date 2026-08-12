//! Durable-command driver for the process-local DR admission gates.
//!
//! The store reports only the current database lineage. Deployment membership and restore
//! orchestration deliberately remain outside this port.

use std::sync::Arc;
use std::time::Duration;

use primitives::{AdmissionEpochId, LocalAdmissionPhase, ProcessAdmissionControl};
use tokio_util::sync::CancellationToken;

use crate::WorkerHealth;

/// Boot-scoped process identity attached to every phase acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrAdmissionProcessIdentity {
    assembly_identity: String,
    runtime_plan_fingerprint: String,
    instance_id: uuid::Uuid,
    boot_id: uuid::Uuid,
    required_admission_epoch: Option<AdmissionEpochId>,
}

impl DrAdmissionProcessIdentity {
    pub fn new(
        assembly_identity: impl Into<String>,
        runtime_plan_fingerprint: impl Into<String>,
        instance_id: uuid::Uuid,
        boot_id: uuid::Uuid,
        required_admission_epoch: Option<AdmissionEpochId>,
    ) -> Result<Self, DrAdmissionRuntimeError> {
        let assembly_identity = assembly_identity.into();
        let runtime_plan_fingerprint = runtime_plan_fingerprint.into();
        if assembly_identity.is_empty()
            || assembly_identity.len() > 64
            || runtime_plan_fingerprint.len() < 8
            || runtime_plan_fingerprint.len() > 256
            || instance_id.is_nil()
            || boot_id.is_nil()
        {
            return Err(DrAdmissionRuntimeError::InvalidIdentity);
        }
        Ok(Self {
            assembly_identity,
            runtime_plan_fingerprint,
            instance_id,
            boot_id,
            required_admission_epoch,
        })
    }

    pub fn assembly_identity(&self) -> &str {
        &self.assembly_identity
    }

    pub fn runtime_plan_fingerprint(&self) -> &str {
        &self.runtime_plan_fingerprint
    }

    pub const fn instance_id(&self) -> uuid::Uuid {
        self.instance_id
    }

    pub const fn boot_id(&self) -> uuid::Uuid {
        self.boot_id
    }

    /// Post-restore bootstrap witness projected into this process before workers are constructed.
    pub const fn required_admission_epoch(&self) -> Option<AdmissionEpochId> {
        self.required_admission_epoch
    }
}

/// Closed durable command phases understood by serving binaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrAdmissionCommandPhase {
    PauseRequested,
    Drained,
    AppliedPaused,
    RelayResumeRequested,
    RelayRunning,
    ConsumerResumeRequested,
    ConsumerRunning,
    WritesResumeRequested,
    Running,
}

impl DrAdmissionCommandPhase {
    pub fn parse(raw: &str) -> Result<Self, DrAdmissionRuntimeError> {
        match raw {
            "pause_requested" => Ok(Self::PauseRequested),
            "drained" => Ok(Self::Drained),
            "applied_paused" => Ok(Self::AppliedPaused),
            "relay_resume_requested" => Ok(Self::RelayResumeRequested),
            "relay_running" => Ok(Self::RelayRunning),
            "consumer_resume_requested" => Ok(Self::ConsumerResumeRequested),
            "consumer_running" => Ok(Self::ConsumerRunning),
            "writes_resume_requested" => Ok(Self::WritesResumeRequested),
            "running" => Ok(Self::Running),
            _ => Err(DrAdmissionRuntimeError::UnknownPhase),
        }
    }
}

/// Minimal durable state consumed by one serving process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrAdmissionCommand {
    pub admission_epoch: AdmissionEpochId,
    pub phase: DrAdmissionCommandPhase,
    pub invalidated: bool,
    pub expired: bool,
}

/// Narrow store port implemented by the serving PostgreSQL adapter.
#[allow(async_fn_in_trait)]
pub trait DrAdmissionCommandStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn observe(&self) -> Result<Option<DrAdmissionCommand>, Self::Error>;

    async fn acknowledge(
        &self,
        command: &DrAdmissionCommand,
        identity: &DrAdmissionProcessIdentity,
        phase: &'static str,
    ) -> Result<bool, Self::Error>;

    async fn authorize_resume(
        &self,
        command: &DrAdmissionCommand,
        identity: &DrAdmissionProcessIdentity,
        phase: &'static str,
    ) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DrAdmissionRuntimeError {
    #[error("DR admission process identity is invalid")]
    InvalidIdentity,
    #[error("DR admission command phase is unknown")]
    UnknownPhase,
    #[error("DR admission command was durably fenced")]
    Fenced,
    #[error("DR admission durable store is unavailable")]
    StoreUnavailable,
    #[error("DR admission local transition failed")]
    LocalTransition,
}

/// Poll and apply the one closed durable phase machine until process shutdown.
pub async fn run_dr_admission_controller<S: DrAdmissionCommandStore>(
    store: S,
    control: ProcessAdmissionControl,
    identity: DrAdmissionProcessIdentity,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) {
    let required_epoch = identity.required_admission_epoch();
    let mut last_epoch = required_epoch;
    if let Some(epoch) = required_epoch
        && control.pause_all(epoch).is_err()
    {
        health.mark_invariant();
        return;
    }
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => {
                control.stop();
                return;
            }
            _ = ticker.tick() => {}
        }
        let observed = tokio::select! {
            biased;
            () = token.cancelled() => {
                control.stop();
                return;
            }
            result = store.observe() => result,
        };
        let Some(command) = handle_observation(
            observed,
            &control,
            required_epoch,
            last_epoch,
            health.as_ref(),
        ) else {
            continue;
        };
        if let Some(required) = required_epoch
            && required != command.admission_epoch
        {
            let _ = control.pause_all(required);
            health.mark_invariant();
            continue;
        }
        last_epoch = Some(command.admission_epoch);
        let result = tokio::select! {
            biased;
            () = token.cancelled() => {
                control.stop();
                return;
            }
            result = drive_command(&store, &control, &identity, &command) => result,
        };
        record_drive_result(result, &control, command.admission_epoch, health.as_ref());
    }
}

fn handle_observation<E: std::error::Error>(
    observed: Result<Option<DrAdmissionCommand>, E>,
    control: &ProcessAdmissionControl,
    required_epoch: Option<AdmissionEpochId>,
    last_epoch: Option<AdmissionEpochId>,
    health: &WorkerHealth,
) -> Option<DrAdmissionCommand> {
    match observed {
        Ok(Some(command)) if !command.invalidated && !command.expired => Some(command),
        Ok(Some(command)) => {
            let _ = control.pause_all(command.admission_epoch);
            health.mark_invariant();
            None
        }
        Ok(None) if required_epoch.is_none() && last_epoch.is_none() => {
            if control.snapshot().phase() == LocalAdmissionPhase::Initializing
                && control.start_running().is_err()
            {
                health.mark_invariant();
            } else {
                health.mark_healthy();
            }
            None
        }
        Ok(None) => {
            fail_closed(control, last_epoch);
            health.mark_invariant();
            None
        }
        Err(error) => {
            fail_closed(control, last_epoch);
            health.mark_degraded();
            tracing::warn!(
                error = %secure::redact_error(&error),
                "DR admission durable observation failed; controller remains fail-closed"
            );
            None
        }
    }
}

fn fail_closed(control: &ProcessAdmissionControl, epoch: Option<AdmissionEpochId>) {
    if let Some(epoch) = epoch {
        let _ = control.pause_all(epoch);
    } else {
        let _ = control.fail_closed_initializing();
    }
}

fn record_drive_result(
    result: Result<(), DrAdmissionRuntimeError>,
    control: &ProcessAdmissionControl,
    epoch: AdmissionEpochId,
    health: &WorkerHealth,
) {
    match result {
        Ok(()) => health.mark_healthy(),
        Err(DrAdmissionRuntimeError::StoreUnavailable) => {
            let _ = control.pause_all(epoch);
            health.mark_degraded();
            tracing::warn!(
                "DR admission durable command failed transiently; controller remains fail-closed"
            );
        }
        Err(_) => {
            let _ = control.pause_all(epoch);
            health.mark_invariant();
        }
    }
}

async fn drive_command<S: DrAdmissionCommandStore>(
    store: &S,
    control: &ProcessAdmissionControl,
    identity: &DrAdmissionProcessIdentity,
    command: &DrAdmissionCommand,
) -> Result<(), DrAdmissionRuntimeError> {
    let epoch = command.admission_epoch;
    match command.phase {
        DrAdmissionCommandPhase::PauseRequested | DrAdmissionCommandPhase::Drained => {
            control
                .pause_all(epoch)
                .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
            control
                .wait_drained()
                .await
                .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
            acknowledge(store, command, identity, "drained").await
        }
        DrAdmissionCommandPhase::AppliedPaused => match control.snapshot().active_epoch() {
            None => control
                .pause_all(epoch)
                .map_err(|_| DrAdmissionRuntimeError::LocalTransition),
            Some(active) if active == epoch => control
                .pause_all(epoch)
                .map_err(|_| DrAdmissionRuntimeError::LocalTransition),
            Some(_) => Err(DrAdmissionRuntimeError::LocalTransition),
        },
        DrAdmissionCommandPhase::RelayResumeRequested | DrAdmissionCommandPhase::RelayRunning => {
            advance_resume(store, control, identity, command, ResumeTarget::Relay).await
        }
        DrAdmissionCommandPhase::ConsumerResumeRequested
        | DrAdmissionCommandPhase::ConsumerRunning => {
            advance_resume(store, control, identity, command, ResumeTarget::Consumer).await
        }
        DrAdmissionCommandPhase::WritesResumeRequested | DrAdmissionCommandPhase::Running => {
            if command.phase == DrAdmissionCommandPhase::Running
                && control.snapshot().active_epoch().is_none()
            {
                if control.snapshot().phase() == LocalAdmissionPhase::Initializing {
                    control
                        .start_running()
                        .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
                }
                return Ok(());
            }
            advance_resume(store, control, identity, command, ResumeTarget::Writes).await
        }
    }
}

#[derive(Clone, Copy)]
enum ResumeTarget {
    Relay,
    Consumer,
    Writes,
}

impl ResumeTarget {
    const fn durable_phase(self) -> &'static str {
        match self {
            Self::Relay => "relay_running",
            Self::Consumer => "consumer_running",
            Self::Writes => "running",
        }
    }

    const fn local_phase(self) -> LocalAdmissionPhase {
        match self {
            Self::Relay => LocalAdmissionPhase::RelayRunning,
            Self::Consumer => LocalAdmissionPhase::ConsumerRunning,
            Self::Writes => LocalAdmissionPhase::Running,
        }
    }
}

async fn advance_resume<S: DrAdmissionCommandStore>(
    store: &S,
    control: &ProcessAdmissionControl,
    identity: &DrAdmissionProcessIdentity,
    command: &DrAdmissionCommand,
    target: ResumeTarget,
) -> Result<(), DrAdmissionRuntimeError> {
    authorize_resume(store, command, identity, target.durable_phase()).await?;
    establish_active_epoch(control, command.admission_epoch).await?;
    let epoch = command.admission_epoch;
    if control.snapshot().phase() == LocalAdmissionPhase::Paused {
        control
            .resume_relay(epoch)
            .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
    }
    if matches!(target, ResumeTarget::Consumer | ResumeTarget::Writes)
        && control.snapshot().phase() == LocalAdmissionPhase::RelayRunning
    {
        control
            .resume_consumer(epoch)
            .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
    }
    if matches!(target, ResumeTarget::Writes)
        && control.snapshot().phase() == LocalAdmissionPhase::ConsumerRunning
    {
        control
            .resume_writes(epoch)
            .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
    }
    if control.snapshot().phase() != target.local_phase() {
        return Err(DrAdmissionRuntimeError::LocalTransition);
    }
    acknowledge(store, command, identity, target.durable_phase()).await
}

async fn establish_active_epoch(
    control: &ProcessAdmissionControl,
    epoch: AdmissionEpochId,
) -> Result<(), DrAdmissionRuntimeError> {
    match control.snapshot().active_epoch() {
        None => {
            control
                .pause_all(epoch)
                .map_err(|_| DrAdmissionRuntimeError::LocalTransition)?;
            control
                .wait_drained()
                .await
                .map_err(|_| DrAdmissionRuntimeError::LocalTransition)
        }
        Some(active) if active == epoch => Ok(()),
        Some(_) => Err(DrAdmissionRuntimeError::LocalTransition),
    }
}

async fn authorize_resume<S: DrAdmissionCommandStore>(
    store: &S,
    command: &DrAdmissionCommand,
    identity: &DrAdmissionProcessIdentity,
    phase: &'static str,
) -> Result<(), DrAdmissionRuntimeError> {
    match store.authorize_resume(command, identity, phase).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(DrAdmissionRuntimeError::Fenced),
        Err(_) => Err(DrAdmissionRuntimeError::StoreUnavailable),
    }
}

async fn acknowledge<S: DrAdmissionCommandStore>(
    store: &S,
    command: &DrAdmissionCommand,
    identity: &DrAdmissionProcessIdentity,
    phase: &'static str,
) -> Result<(), DrAdmissionRuntimeError> {
    match store.acknowledge(command, identity, phase).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(DrAdmissionRuntimeError::Fenced),
        Err(_) => Err(DrAdmissionRuntimeError::StoreUnavailable),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeStore {
        acknowledgements: Mutex<Vec<&'static str>>,
    }

    #[derive(Default)]
    struct FencedResumeStore {
        acknowledged: std::sync::atomic::AtomicBool,
    }

    struct PendingStore {
        entered: Arc<tokio::sync::Notify>,
    }

    struct PauseStore {
        command: DrAdmissionCommand,
    }

    struct FlakyStore {
        observations: Arc<std::sync::atomic::AtomicUsize>,
        observed: Arc<tokio::sync::Notify>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("fake store failure")]
    struct FakeError;

    impl DrAdmissionCommandStore for FakeStore {
        type Error = FakeError;

        async fn observe(&self) -> Result<Option<DrAdmissionCommand>, Self::Error> {
            Ok(None)
        }

        async fn acknowledge(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            phase: &'static str,
        ) -> Result<bool, Self::Error> {
            self.acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(phase);
            Ok(true)
        }

        async fn authorize_resume(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    impl DrAdmissionCommandStore for FencedResumeStore {
        type Error = FakeError;

        async fn observe(&self) -> Result<Option<DrAdmissionCommand>, Self::Error> {
            Ok(None)
        }

        async fn acknowledge(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            self.acknowledged
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }

        async fn authorize_resume(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }
    }

    impl DrAdmissionCommandStore for PendingStore {
        type Error = FakeError;

        async fn observe(&self) -> Result<Option<DrAdmissionCommand>, Self::Error> {
            self.entered.notify_one();
            std::future::pending().await
        }

        async fn acknowledge(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn authorize_resume(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    impl DrAdmissionCommandStore for PauseStore {
        type Error = FakeError;

        async fn observe(&self) -> Result<Option<DrAdmissionCommand>, Self::Error> {
            Ok(Some(self.command.clone()))
        }

        async fn acknowledge(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn authorize_resume(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    impl DrAdmissionCommandStore for FlakyStore {
        type Error = FakeError;

        async fn observe(&self) -> Result<Option<DrAdmissionCommand>, Self::Error> {
            let observation = self
                .observations
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.observed.notify_one();
            if observation == 0 {
                Err(FakeError)
            } else {
                Ok(None)
            }
        }

        async fn acknowledge(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn authorize_resume(
            &self,
            _command: &DrAdmissionCommand,
            _identity: &DrAdmissionProcessIdentity,
            _phase: &'static str,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn epoch() -> AdmissionEpochId {
        AdmissionEpochId::new(uuid::Uuid::new_v4()).expect("non-nil epoch")
    }

    fn identity() -> DrAdmissionProcessIdentity {
        DrAdmissionProcessIdentity::new(
            "runtime",
            "sha256:test-runtime-plan",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            None,
        )
        .expect("valid identity")
    }

    #[tokio::test]
    async fn controller_acknowledges_only_after_drain_and_ordered_resume() {
        let store = FakeStore::default();
        let (control, relay, consumer, writes) =
            primitives::prepare_dr_admission_controls().into_parts();
        control.start_running().expect("durable lineage is clear");
        let relay_permit = relay.try_enter().expect("relay initially open");
        let admission_epoch = epoch();
        let pause = DrAdmissionCommand {
            admission_epoch,
            phase: DrAdmissionCommandPhase::PauseRequested,
            invalidated: false,
            expired: false,
        };
        let process_identity = identity();
        let pending = drive_command(&store, &control, &process_identity, &pause);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        drop(relay_permit);
        pending.await.expect("drain acknowledged");
        assert!(matches!(
            relay.try_enter(),
            Err(primitives::AdmissionError::Paused)
        ));
        assert!(matches!(
            consumer.try_enter(),
            Err(primitives::AdmissionError::Paused)
        ));
        assert!(matches!(
            writes.try_enter(),
            Err(primitives::AdmissionError::Paused)
        ));

        for (phase, expected_local) in [
            (
                DrAdmissionCommandPhase::RelayResumeRequested,
                LocalAdmissionPhase::RelayRunning,
            ),
            (
                DrAdmissionCommandPhase::ConsumerResumeRequested,
                LocalAdmissionPhase::ConsumerRunning,
            ),
            (
                DrAdmissionCommandPhase::WritesResumeRequested,
                LocalAdmissionPhase::Running,
            ),
        ] {
            drive_command(
                &store,
                &control,
                &identity(),
                &DrAdmissionCommand {
                    admission_epoch,
                    phase,
                    invalidated: false,
                    expired: false,
                },
            )
            .await
            .expect("ordered resume acknowledged");
            assert_eq!(control.snapshot().phase(), expected_local);
        }
        assert_eq!(
            *store
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["drained", "relay_running", "consumer_running", "running"]
        );
    }

    #[tokio::test]
    async fn stale_epoch_cannot_resume_a_paused_process() {
        let store = FakeStore::default();
        let (control, _, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        let active = epoch();
        control.pause_all(active).expect("pause active epoch");
        let stale = DrAdmissionCommand {
            admission_epoch: epoch(),
            phase: DrAdmissionCommandPhase::RelayResumeRequested,
            invalidated: false,
            expired: false,
        };
        assert_eq!(
            drive_command(&store, &control, &identity(), &stale).await,
            Err(DrAdmissionRuntimeError::LocalTransition)
        );
        assert_eq!(control.snapshot().active_epoch(), Some(active));
        assert_eq!(control.snapshot().phase(), LocalAdmissionPhase::Paused);
    }

    #[tokio::test]
    async fn durable_resume_authorization_precedes_local_lane_open() {
        let (control, relay, _consumer, _writes) =
            primitives::prepare_dr_admission_controls().into_parts();
        let admission_epoch = epoch();
        control
            .pause_all(admission_epoch)
            .expect("arm local paused epoch");
        let command = DrAdmissionCommand {
            admission_epoch,
            phase: DrAdmissionCommandPhase::RelayResumeRequested,
            invalidated: false,
            expired: false,
        };
        let store = FencedResumeStore::default();
        assert_eq!(
            drive_command(&store, &control, &identity(), &command).await,
            Err(DrAdmissionRuntimeError::Fenced)
        );
        assert!(!store.acknowledged.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(
            relay.try_enter(),
            Err(primitives::AdmissionError::Paused)
        ));
    }

    #[tokio::test]
    async fn durable_running_opens_initializing_lanes() {
        let store = FakeStore::default();
        let (control, relay, consumer, writes) =
            primitives::prepare_dr_admission_controls().into_parts();
        for paused in [
            relay.try_enter().is_err(),
            consumer.try_enter().is_err(),
            writes.try_enter().is_err(),
        ] {
            assert!(paused);
        }
        drive_command(
            &store,
            &control,
            &identity(),
            &DrAdmissionCommand {
                admission_epoch: epoch(),
                phase: DrAdmissionCommandPhase::Running,
                invalidated: false,
                expired: false,
            },
        )
        .await
        .expect("durable running opens startup gates");
        assert!(relay.try_enter().is_ok());
        assert!(consumer.try_enter().is_ok());
        assert!(writes.try_enter().is_ok());
    }

    #[tokio::test]
    async fn controller_shutdown_cancels_a_pending_observe() {
        let (control, _, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        let token = CancellationToken::new();
        let cancelled = token.clone();
        let health = Arc::new(WorkerHealth::starting());
        let entered = Arc::new(tokio::sync::Notify::new());
        let controller = run_dr_admission_controller(
            PendingStore {
                entered: Arc::clone(&entered),
            },
            control,
            identity(),
            token,
            health,
        );
        tokio::pin!(controller);
        let observing = tokio::select! {
            () = entered.notified() => true,
            () = &mut controller => false,
        };
        assert!(observing, "controller must enter the pending observe");
        cancelled.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), controller)
                .await
                .is_ok(),
            "pending observe must not block controller shutdown"
        );
    }

    #[tokio::test]
    async fn controller_shutdown_cancels_a_pending_drain() -> Result<(), primitives::AdmissionError>
    {
        let (control, relay, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        assert!(control.start_running().is_ok());
        let permit = relay.try_enter()?;
        let token = CancellationToken::new();
        let cancelled = token.clone();
        let health = Arc::new(WorkerHealth::starting());
        let controller = run_dr_admission_controller(
            PauseStore {
                command: DrAdmissionCommand {
                    admission_epoch: epoch(),
                    phase: DrAdmissionCommandPhase::PauseRequested,
                    invalidated: false,
                    expired: false,
                },
            },
            control,
            identity(),
            token,
            health,
        );
        tokio::pin!(controller);
        let draining = tokio::select! {
            result = relay.wait_closed() => result.is_ok(),
            () = &mut controller => false,
        };
        assert!(draining, "controller must close the relay before draining");
        cancelled.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), controller)
                .await
                .is_ok(),
            "held permits must not block controller shutdown"
        );
        drop(permit);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn transient_observe_failure_recovers_health_after_a_successful_observation() {
        let (control, _, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        let token = CancellationToken::new();
        let cancelled = token.clone();
        let health = Arc::new(WorkerHealth::starting());
        let observations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::new(tokio::sync::Notify::new());
        let controller = run_dr_admission_controller(
            FlakyStore {
                observations: Arc::clone(&observations),
                observed: Arc::clone(&observed),
            },
            control,
            identity(),
            token,
            Arc::clone(&health),
        );
        tokio::pin!(controller);
        while observations.load(std::sync::atomic::Ordering::SeqCst) < 2 {
            tokio::select! {
                () = observed.notified() => tokio::time::advance(Duration::from_millis(250)).await,
                () = &mut controller => break,
            }
        }
        assert_eq!(health.status(), primitives::healthz::HealthStatus::Healthy);
        cancelled.cancel();
        controller.await;
    }
}
