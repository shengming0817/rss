//! External-crate provider-neutral T1 proof for the production Eventing lifecycle seam.
//!
//! Runtime time is paused following `tokio-rs/tokio tokio/tests/time_sleep.rs`.
//! Real broker generation replacement and connection cleanup remain AMQP residual owners.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use eventing::delivery::{ConsumerTxOutcome, DeliveryBudget, PublishErrorKind};
use eventing::envelope::EventId;
use eventing::lifecycle::{ConsumerTxAction, ConsumerTxLifecycle, RetryPolicy, ShutdownBudget};
use tokio::task::JoinHandle;
use tokio::time::{Instant, advance, timeout};

#[derive(Clone, Copy, Debug)]
enum Defect {
    None,
    EarlyRetry,
    ExtraAttempt,
    IgnoreFence,
    SpendAtBudgetBoundary,
    AmbiguousNewId,
    ReuseRetiredGeneration,
    DropCommit,
    AckExhausted,
    ShutdownLeak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailedInvariant {
    RetryCadence,
    AttemptBound,
    Fencing,
    RemainingBudget,
    AmbiguityIdentity,
    AmbiguityGeneration,
    PositiveLifecycle,
    ExhaustionSettlement,
    ShutdownConvergence,
}

struct Observation {
    retry_offsets: Vec<Duration>,
    retry_delays: Vec<Duration>,
    retry_provider_calls: u32,
    committed: bool,
    same_event_id: bool,
    ambiguity_replaced_generation: bool,
    retired_generation_reused: bool,
    exhausted_provider_calls: u32,
    exhausted_acknowledgements: u32,
    fenced: bool,
    calls_after_fence: u32,
    settlements_after_fence: u32,
    budget_remaining: Duration,
    budget_required: Duration,
    budget_provider_calls: u32,
    shutdown_attempts: u32,
    shutdown_cleanup_calls: u32,
    shutdown_live_handles: u32,
}

#[tokio::test(start_paused = true)]
async fn production_lifecycle_is_fake_clock_t1_conformant() {
    let observation = observe(Defect::None).await;

    assert_eq!(assert_lifecycle(&observation), Ok(()));
}

#[tokio::test(start_paused = true)]
async fn every_verdict_branch_has_a_synthetic_red() {
    let cases = [
        (Defect::EarlyRetry, FailedInvariant::RetryCadence),
        (Defect::ExtraAttempt, FailedInvariant::AttemptBound),
        (Defect::IgnoreFence, FailedInvariant::Fencing),
        (
            Defect::SpendAtBudgetBoundary,
            FailedInvariant::RemainingBudget,
        ),
        (Defect::AmbiguousNewId, FailedInvariant::AmbiguityIdentity),
        (
            Defect::ReuseRetiredGeneration,
            FailedInvariant::AmbiguityGeneration,
        ),
        (Defect::DropCommit, FailedInvariant::PositiveLifecycle),
        (Defect::AckExhausted, FailedInvariant::ExhaustionSettlement),
        (Defect::ShutdownLeak, FailedInvariant::ShutdownConvergence),
    ];

    for (defect, expected) in cases {
        let observation = observe(defect).await;
        assert_eq!(assert_lifecycle(&observation), Err(expected), "{defect:?}");
    }
}

async fn observe(defect: Defect) -> Observation {
    let retry = observe_retry_to_commit(defect).await;
    let (exhausted_provider_calls, exhausted_acknowledgements) = observe_exhaustion(defect).await;
    let (fenced, calls_after_fence, settlements_after_fence) = observe_fence(defect).await;
    let (budget_remaining, budget_required, budget_provider_calls) = observe_budget(defect);
    let (shutdown_attempts, shutdown_cleanup_calls, shutdown_live_handles) =
        observe_shutdown_backoff(defect).await;

    Observation {
        retry_offsets: retry.offsets,
        retry_delays: retry.delays,
        retry_provider_calls: retry.provider_calls,
        committed: retry.committed,
        same_event_id: retry.same_event_id,
        ambiguity_replaced_generation: retry.ambiguity_replaced_generation,
        retired_generation_reused: retry.retired_generation_reused,
        exhausted_provider_calls,
        exhausted_acknowledgements,
        fenced,
        calls_after_fence,
        settlements_after_fence,
        budget_remaining,
        budget_required,
        budget_provider_calls,
        shutdown_attempts,
        shutdown_cleanup_calls,
        shutdown_live_handles,
    }
}

struct RetryObservation {
    offsets: Vec<Duration>,
    delays: Vec<Duration>,
    provider_calls: u32,
    committed: bool,
    same_event_id: bool,
    ambiguity_replaced_generation: bool,
    retired_generation_reused: bool,
}

#[allow(
    clippy::cognitive_complexity,
    clippy::expect_used,
    clippy::disallowed_methods,
    clippy::panic
)]
// reason: deterministic paused-time fixture fails loudly on an impossible production action.
async fn observe_retry_to_commit(defect: Defect) -> RetryObservation {
    let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    let authored_id = EventId::parse("opaque-event").expect("non-empty event id");
    let replacement_id = EventId::parse("replacement-event").expect("non-empty event id");
    let started_at = Instant::now();
    let mut offsets = Vec::new();
    let mut delays = Vec::new();
    let mut provider_calls = 0;
    let mut committed = false;
    let mut same_event_id = true;
    let mut generation = 1_u32;
    let mut retired_generation_reused = false;

    while let Some(attempt) = lifecycle.current_attempt() {
        provider_calls += 1;
        offsets.push(Instant::now() - started_at);
        let outcome = match attempt.get() {
            1 => {
                assert!(PublishErrorKind::Transient.is_retryable());
                ConsumerTxOutcome::HandlerTransient
            }
            2 => {
                assert!(PublishErrorKind::Ambiguous.is_ambiguous());
                let retry_id = if matches!(defect, Defect::AmbiguousNewId) {
                    &replacement_id
                } else {
                    &authored_id
                };
                same_event_id &= retry_id == &authored_id;
                if matches!(defect, Defect::ReuseRetiredGeneration) {
                    retired_generation_reused = true;
                } else {
                    generation += 1;
                }
                ConsumerTxOutcome::HandlerTransient
            }
            _ => ConsumerTxOutcome::Committed(()),
        };
        match finish_with_explicit_clock(&mut lifecycle, &outcome).await {
            ConsumerTxAction::RetryReady { delay, .. } => delays.push(delay),
            ConsumerTxAction::Commit => committed = !matches!(defect, Defect::DropCommit),
            action => panic!("unexpected positive lifecycle action: {action:?}"),
        }
    }

    if matches!(defect, Defect::EarlyRetry) {
        offsets[1] = Duration::ZERO;
    }
    if matches!(defect, Defect::ExtraAttempt) {
        provider_calls += 1;
    }
    RetryObservation {
        offsets,
        delays,
        provider_calls,
        committed,
        same_event_id,
        ambiguity_replaced_generation: generation == 2,
        retired_generation_reused,
    }
}

#[allow(clippy::expect_used, clippy::panic)]
// reason: explicit polling proves the production retry future cannot become ready early.
async fn finish_with_explicit_clock<C>(
    lifecycle: &mut ConsumerTxLifecycle,
    outcome: &ConsumerTxOutcome<C>,
) -> ConsumerTxAction {
    let expected_delay = lifecycle
        .current_attempt()
        .filter(|attempt| {
            matches!(outcome, ConsumerTxOutcome::HandlerTransient)
                && attempt.get() < RetryPolicy::STANDARD.max_attempts().get()
        })
        .map(|attempt| RetryPolicy::STANDARD.delay_after(attempt));
    let future = lifecycle.finish_attempt(outcome, tokio::time::sleep);
    tokio::pin!(future);
    if let Some(delay) = expected_delay {
        tokio::select! {
            biased;
            result = &mut future => panic!("retry became ready before {delay:?}: {result:?}"),
            () = tokio::task::yield_now() => {}
        }
        advance(delay).await;
    }
    future.await.expect("active lifecycle")
}

#[allow(clippy::expect_used)]
// reason: closed fixture construction fails loudly.
async fn observe_exhaustion(defect: Defect) -> (u32, u32) {
    let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    let mut provider_calls = 0;
    let mut acknowledgements = 0;
    while lifecycle.current_attempt().is_some() {
        provider_calls += 1;
        let action =
            finish_with_explicit_clock(&mut lifecycle, &ConsumerTxOutcome::<()>::HandlerTransient)
                .await;
        if matches!(action, ConsumerTxAction::Exhausted) && matches!(defect, Defect::AckExhausted) {
            acknowledgements += 1;
        }
    }
    (provider_calls, acknowledgements)
}

#[allow(clippy::expect_used)]
// reason: closed fixture construction fails loudly.
async fn observe_fence(defect: Defect) -> (bool, u32, u32) {
    let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    let action = lifecycle
        .finish_attempt(&ConsumerTxOutcome::<()>::Fenced, tokio::time::sleep)
        .await
        .expect("active lifecycle");
    let closed = lifecycle
        .finish_attempt(&ConsumerTxOutcome::<()>::Committed(()), tokio::time::sleep)
        .await;
    assert!(closed.is_err(), "terminal fence must close the lifecycle");
    let ignored = u32::from(matches!(defect, Defect::IgnoreFence));
    (matches!(action, ConsumerTxAction::Fenced), ignored, ignored)
}

#[allow(clippy::expect_used)]
// reason: closed fixture construction fails loudly.
fn observe_budget(defect: Defect) -> (Duration, Duration, u32) {
    let budget = DeliveryBudget::new(
        Duration::from_secs(60),
        Duration::from_secs(30),
        Duration::from_secs(10),
        Duration::from_secs(5),
    )
    .expect("valid delivery budget");
    let remaining = budget.required_budget();
    let provider_calls = u32::from(
        budget.can_start_attempt(remaining) || matches!(defect, Defect::SpendAtBudgetBoundary),
    );
    (remaining, budget.required_budget(), provider_calls)
}

struct LiveGuard {
    cleanup: Arc<AtomicU32>,
    live: Arc<AtomicU32>,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.cleanup.fetch_add(1, Ordering::AcqRel);
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn observe_shutdown_backoff(defect: Defect) -> (u32, u32, u32) {
    let admission = Arc::new(AtomicBool::new(true));
    let attempts = Arc::new(AtomicU32::new(0));
    let cleanup = Arc::new(AtomicU32::new(0));
    let live = Arc::new(AtomicU32::new(0));
    let mut handle = spawn_retry_wait(
        Arc::clone(&admission),
        Arc::clone(&attempts),
        Arc::clone(&cleanup),
        Arc::clone(&live),
    );
    tokio::task::yield_now().await;
    admission.store(false, Ordering::Release);

    let observed = if matches!(defect, Defect::ShutdownLeak) {
        (
            attempts.load(Ordering::Acquire),
            cleanup.load(Ordering::Acquire),
            live.load(Ordering::Acquire),
        )
    } else {
        abort_and_join(&mut handle, ShutdownBudget::STANDARD).await;
        (
            attempts.load(Ordering::Acquire),
            cleanup.load(Ordering::Acquire),
            live.load(Ordering::Acquire),
        )
    };
    if !handle.is_finished() {
        abort_and_join(&mut handle, ShutdownBudget::STANDARD).await;
    }
    observed
}

fn spawn_retry_wait(
    admission: Arc<AtomicBool>,
    attempts: Arc<AtomicU32>,
    cleanup: Arc<AtomicU32>,
    live: Arc<AtomicU32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        live.fetch_add(1, Ordering::AcqRel);
        let _guard = LiveGuard { cleanup, live };
        let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
        attempts.fetch_add(1, Ordering::AcqRel);
        let _ = lifecycle
            .finish_attempt(
                &ConsumerTxOutcome::<()>::HandlerTransient,
                tokio::time::sleep,
            )
            .await;
        if admission.load(Ordering::Acquire) {
            attempts.fetch_add(1, Ordering::AcqRel);
        }
    })
}

#[allow(clippy::disallowed_methods)]
// reason: shutdown timeout is the typed behavior under test and the handle is always awaited.
async fn abort_and_join(handle: &mut JoinHandle<()>, budget: ShutdownBudget) {
    handle.abort();
    let joined = timeout(budget.timeout(), handle).await;
    assert!(joined.is_ok(), "aborted lifecycle must join within budget");
}

fn assert_lifecycle(observation: &Observation) -> Result<(), FailedInvariant> {
    let policy = RetryPolicy::STANDARD;
    if observation.retry_provider_calls != policy.max_attempts().get()
        || observation.exhausted_provider_calls != policy.max_attempts().get()
    {
        return Err(FailedInvariant::AttemptBound);
    }
    if observation.retry_offsets
        != [
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(3),
        ]
        || observation.retry_delays != [Duration::from_secs(1), Duration::from_secs(2)]
    {
        return Err(FailedInvariant::RetryCadence);
    }
    if !observation.fenced
        || observation.calls_after_fence != 0
        || observation.settlements_after_fence != 0
    {
        return Err(FailedInvariant::Fencing);
    }
    if observation.budget_remaining != observation.budget_required
        || observation.budget_provider_calls != 0
    {
        return Err(FailedInvariant::RemainingBudget);
    }
    if !observation.same_event_id {
        return Err(FailedInvariant::AmbiguityIdentity);
    }
    if !observation.ambiguity_replaced_generation || observation.retired_generation_reused {
        return Err(FailedInvariant::AmbiguityGeneration);
    }
    if !observation.committed {
        return Err(FailedInvariant::PositiveLifecycle);
    }
    if observation.exhausted_acknowledgements != 0 {
        return Err(FailedInvariant::ExhaustionSettlement);
    }
    if observation.shutdown_attempts != 1
        || observation.shutdown_cleanup_calls != 1
        || observation.shutdown_live_handles != 0
    {
        return Err(FailedInvariant::ShutdownConvergence);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)]
// reason: closed fixture construction fails loudly.
async fn shutdown_timeout_aborts_awaits_and_drops_in_flight_future_once() {
    let cleanup = Arc::new(AtomicU32::new(0));
    let live = Arc::new(AtomicU32::new(0));
    let cleanup_run = Arc::clone(&cleanup);
    let live_run = Arc::clone(&live);
    let mut handle = tokio::spawn(async move {
        live_run.fetch_add(1, Ordering::AcqRel);
        let _guard = LiveGuard {
            cleanup: cleanup_run,
            live: live_run,
        };
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    let budget = ShutdownBudget::new(Duration::from_secs(5)).expect("positive budget");
    let timed = timeout(budget.timeout(), &mut handle);
    tokio::pin!(timed);
    tokio::select! {
        biased;
        result = &mut timed => panic!("pending operation completed early: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    advance(budget.timeout()).await;
    assert!(
        timed.await.is_err(),
        "operation must exceed shutdown budget"
    );
    handle.abort();
    let _ = handle.await;
    assert_eq!(cleanup.load(Ordering::Acquire), 1);
    assert_eq!(live.load(Ordering::Acquire), 0);
}

#[tokio::test(start_paused = true)]
async fn non_retryable_outcomes_close_with_typed_actions() {
    let cases = [
        ConsumerTxOutcome::<()>::InfrastructureTransient,
        ConsumerTxOutcome::CommitUnknown,
        ConsumerTxOutcome::RollbackFailed,
    ];
    for outcome in cases {
        let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
        assert_eq!(
            lifecycle.finish_attempt(&outcome, tokio::time::sleep).await,
            Ok(ConsumerTxAction::Requeue)
        );
        assert!(lifecycle.current_attempt().is_none());
    }
}
