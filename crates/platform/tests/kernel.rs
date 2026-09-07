#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use rss_contract::{Contract, ContractDescriptor};
use rss_platform::*;
use rss_request_context::{
    Cancellation, CancellationObserver, Clock, Deadline, ExecutionTimer, RequestContextView,
    RequestId,
};

struct Inventory;
impl Contract for Inventory {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "runtime.inventory",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}
struct InventoryHandler;
impl Handler<Inventory> for InventoryHandler {
    fn handle<'a>(
        &'a self,
        request: u32,
        _context: RequestContextView<'a>,
    ) -> HandlerFuture<'a, u32> {
        Box::pin(async move {
            if request == u32::MAX - 1 {
                Err(HandlerError::new(HandlerFailureClass::Internal))
            } else if request == u32::MAX {
                std::future::pending().await
            } else {
                Ok(request + 1)
            }
        })
    }
}

struct Host(AtomicU8);
impl Host {
    fn new(state: AdmissionState) -> Self {
        Self(AtomicU8::new(state as u8))
    }
    fn set(&self, state: AdmissionState) {
        self.0.store(state as u8, Ordering::SeqCst);
    }
}
impl HostView for Host {
    fn admission_state(&self) -> AdmissionState {
        match self.0.load(Ordering::SeqCst) {
            0 => AdmissionState::Starting,
            1 => AdmissionState::Ready,
            2 => AdmissionState::Draining,
            _ => AdmissionState::Stopped,
        }
    }
    fn try_admit(&self) -> Result<Box<dyn AdmissionPermit>, AdmissionState> {
        let state = self.admission_state();
        if state == AdmissionState::Ready {
            Ok(Box::new(Permit))
        } else {
            Err(state)
        }
    }
    fn inventory_revision(&self) -> Option<String> {
        Some("revision-1".to_owned())
    }
    fn condition(&self, _: &str) -> Option<ConditionStatus> {
        Some(ConditionStatus::True)
    }
}
struct Permit;
impl AdmissionPermit for Permit {}

struct Cancel {
    flag: AtomicBool,
    notify: tokio::sync::Notify,
}
impl Cancel {
    fn new(value: bool) -> Self {
        Self {
            flag: AtomicBool::new(value),
            notify: tokio::sync::Notify::new(),
        }
    }
    fn set(&self, value: bool) {
        self.flag.store(value, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}
impl CancellationObserver for Cancel {
    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
    fn cancelled(&self) -> rss_request_context::CancellationFuture<'_> {
        Box::pin(async move {
            loop {
                let notified = self.notify.notified();
                if self.is_cancelled() {
                    return;
                }
                notified.await;
            }
        })
    }
}

struct ImmediatelyCancelled;
impl CancellationObserver for ImmediatelyCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> rss_request_context::CancellationFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

fn application(host: Arc<Host>) -> (Dispatcher, TrustedContextMinter) {
    ApplicationBuilder::new(
        ApplicationName::parse("consumer").unwrap(),
        host,
        Arc::new(TokioTimer),
    )
    .module(
        ApplicationModule::new(ModuleName::parse("runtime").unwrap())
            .handler::<Inventory, _>(InventoryHandler),
    )
    .build()
    .unwrap()
    .into_parts()
}

fn context<'a>(
    request: &'a RequestId,
    cancel: &'a Cancel,
    deadline: Instant,
) -> RequestContextView<'a> {
    RequestContextView::new(
        None,
        request,
        Deadline::at(deadline),
        Cancellation::observe(cancel),
    )
}

#[tokio::test]
async fn dispatches_external_contract_and_closed_outcomes() {
    let host = Arc::new(Host::new(AdmissionState::Ready));
    let (dispatcher, minter) = application(host.clone());
    let request = RequestId::parse("request-1").unwrap();
    let cancel = Cancel::new(false);
    let output = dispatcher
        .dispatch::<Inventory>(
            &Inventory::DESCRIPTOR,
            minter.admit(
                41,
                context(&request, &cancel, Instant::now() + Duration::from_secs(1)),
            ),
        )
        .await
        .unwrap();
    assert_eq!(output, DispatchOutcome::Completed(42));

    cancel.set(true);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(
                    1,
                    context(&request, &cancel, Instant::now() + Duration::from_secs(1))
                )
            )
            .await
            .unwrap(),
        DispatchOutcome::Cancelled
    );
    cancel.set(false);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(
                    1,
                    context(&request, &cancel, Instant::now() - Duration::from_secs(1))
                )
            )
            .await
            .unwrap(),
        DispatchOutcome::DeadlineExceeded
    );

    let cancel_during = async {
        tokio::task::yield_now().await;
        cancel.set(true);
    };
    let running = dispatcher.dispatch::<Inventory>(
        &Inventory::DESCRIPTOR,
        minter.admit(
            u32::MAX,
            context(&request, &cancel, Instant::now() + Duration::from_secs(1)),
        ),
    );
    let (running, ()) = tokio::join!(running, cancel_during);
    assert_eq!(running.unwrap(), DispatchOutcome::Cancelled);

    cancel.set(false);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(
                    u32::MAX,
                    context(&request, &cancel, Instant::now() + Duration::from_millis(5),)
                ),
            )
            .await
            .unwrap(),
        DispatchOutcome::DeadlineExceeded
    );

    host.set(AdmissionState::Draining);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(
                    1,
                    context(&request, &cancel, Instant::now() + Duration::from_secs(1))
                )
            )
            .await
            .unwrap_err(),
        DispatchError::HostDraining
    );
    host.set(AdmissionState::Stopped);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(
                    1,
                    context(&request, &cancel, Instant::now() + Duration::from_secs(1))
                )
            )
            .await
            .unwrap_err(),
        DispatchError::HostStopped
    );
}

#[tokio::test]
async fn completed_operation_wins_when_termination_is_ready_in_the_same_poll() {
    let (dispatcher, minter) = application(Arc::new(Host::new(AdmissionState::Ready)));
    let request = RequestId::parse("request-race").unwrap();
    let context = RequestContextView::new(
        None,
        &request,
        Deadline::at(Instant::now() + Duration::from_secs(1)),
        Cancellation::observe(&ImmediatelyCancelled),
    );
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(&Inventory::DESCRIPTOR, minter.admit(1, context))
            .await
            .unwrap(),
        DispatchOutcome::Completed(2)
    );
}

#[tokio::test]
async fn admitted_request_is_bound_to_its_application_instance() {
    let host = Arc::new(Host::new(AdmissionState::Ready));
    let (dispatcher, _) = application(Arc::clone(&host));
    let (_, other_minter) = application(host);
    let request = RequestId::parse("request-seal").unwrap();
    let cancel = Cancel::new(false);
    let admitted = other_minter.admit(
        1,
        context(&request, &cancel, Instant::now() + Duration::from_secs(1)),
    );
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(&Inventory::DESCRIPTOR, admitted)
            .await
            .unwrap_err(),
        DispatchError::AdmissionCapabilityMismatch
    );
}

#[tokio::test]
async fn rejects_unknown_mismatch_and_handler_failure() {
    struct Unknown;
    impl Contract for Unknown {
        type Request = ();
        type Response = ();
        const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
            "unknown.contract",
            1,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
    }
    struct WrongTypes;
    impl Contract for WrongTypes {
        type Request = String;
        type Response = String;
        const DESCRIPTOR: ContractDescriptor = Inventory::DESCRIPTOR;
    }
    let host = Arc::new(Host::new(AdmissionState::Ready));
    let (dispatcher, minter) = application(host);
    let request = RequestId::parse("request-1").unwrap();
    let cancel = Cancel::new(false);
    let ctx = || context(&request, &cancel, Instant::now() + Duration::from_secs(1));
    assert_eq!(
        dispatcher
            .dispatch::<Unknown>(&Unknown::DESCRIPTOR, minter.admit((), ctx()))
            .await
            .unwrap_err(),
        DispatchError::UnknownContract
    );
    let mismatch = ContractDescriptor::from_static(
        "runtime.inventory",
        2,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(&mismatch, minter.admit(1, ctx()))
            .await
            .unwrap_err(),
        DispatchError::DescriptorMismatch
    );
    assert_eq!(
        dispatcher
            .dispatch::<WrongTypes>(&WrongTypes::DESCRIPTOR, minter.admit(String::new(), ctx()),)
            .await
            .unwrap_err(),
        DispatchError::DescriptorMismatch
    );
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(&Inventory::DESCRIPTOR, minter.admit(u32::MAX - 1, ctx()),)
            .await
            .unwrap(),
        DispatchOutcome::HandlerFailed(HandlerFailureClass::Internal)
    );
}

#[test]
fn duplicate_registration_fails_closed() {
    let host = Arc::new(Host::new(AdmissionState::Ready));
    let module = ApplicationModule::new(ModuleName::parse("runtime").unwrap())
        .handler::<Inventory, _>(InventoryHandler)
        .handler::<Inventory, _>(InventoryHandler);
    assert!(matches!(
        ApplicationBuilder::new(ApplicationName::parse("consumer").unwrap(), host, Arc::new(TokioTimer))
            .module(module)
            .build(),
        Err(BuildError::DuplicateContract(id)) if id == rss_contract::ContractId::from_static(Inventory::DESCRIPTOR.id())
    ));
}

struct NeverCancelled;
impl CancellationObserver for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> rss_request_context::CancellationFuture<'_> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn deadline_terminates_pending_handler_without_observer_wakeup() {
    let (dispatcher, minter) = application(Arc::new(Host::new(AdmissionState::Ready)));
    let request = RequestId::parse("independent-deadline").unwrap();
    let context = RequestContextView::new(
        None,
        &request,
        Deadline::at(Instant::now() + Duration::from_millis(5)),
        Cancellation::observe(&NeverCancelled),
    );
    let outcome = tokio::time::timeout(
        Duration::from_millis(100),
        dispatcher.dispatch::<Inventory>(&Inventory::DESCRIPTOR, minter.admit(u32::MAX, context)),
    )
    .await;
    assert!(
        matches!(outcome, Ok(Ok(DispatchOutcome::DeadlineExceeded))),
        "independent deadline did not terminate: {outcome:?}"
    );
}

struct TokioTimer;
impl Clock for TokioTimer {
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for TokioTimer {
    fn sleep_until(&self, deadline: Deadline) -> impl std::future::Future<Output = ()> + Send {
        // A handler may exhaust Tokio's cooperative budget before the timer is polled.
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into()))
    }
}

#[test]
fn duplicate_errors_preserve_safe_identity() {
    let name = ModuleName::parse("inventory").unwrap();
    let result = ApplicationBuilder::new(
        ApplicationName::parse("consumer").unwrap(),
        Arc::new(Host::new(AdmissionState::Ready)),
        Arc::new(TokioTimer),
    )
    .module(ApplicationModule::new(name.clone()))
    .module(ApplicationModule::new(name.clone()))
    .build();
    let error = result.err().unwrap();
    assert_eq!(error, BuildError::DuplicateModule(name));
    assert_eq!(error.to_string(), "duplicate platform module: inventory");
    let id = rss_contract::ContractId::from_static(Inventory::DESCRIPTOR.id());
    let error = ApplicationBuilder::new(
        ApplicationName::parse("consumer").unwrap(),
        Arc::new(Host::new(AdmissionState::Ready)),
        Arc::new(TokioTimer),
    )
    .module(
        ApplicationModule::new(ModuleName::parse("one").unwrap())
            .handler::<Inventory, _>(InventoryHandler),
    )
    .module(
        ApplicationModule::new(ModuleName::parse("two").unwrap())
            .handler::<Inventory, _>(InventoryHandler),
    )
    .build()
    .err()
    .unwrap();
    assert_eq!(error, BuildError::DuplicateContract(id));
    assert_eq!(
        error.to_string(),
        "duplicate platform contract: runtime.inventory"
    );
}

struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl AdmissionPermit for DropFlag {}
struct LeaseHost(Arc<AtomicBool>);
impl HostView for LeaseHost {
    fn admission_state(&self) -> AdmissionState {
        AdmissionState::Ready
    }
    fn try_admit(&self) -> Result<Box<dyn AdmissionPermit>, AdmissionState> {
        Ok(Box::new(DropFlag(self.0.clone())))
    }
    fn inventory_revision(&self) -> Option<String> {
        None
    }
    fn condition(&self, _: &str) -> Option<ConditionStatus> {
        None
    }
}
struct ControlledHandler {
    ready: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}
impl Handler<Inventory> for ControlledHandler {
    fn handle<'a>(&'a self, _: u32, _: RequestContextView<'a>) -> HandlerFuture<'a, u32> {
        Box::pin(async move {
            let _guard = DropFlag(self.dropped.clone());
            std::future::poll_fn(|_| {
                if self.ready.load(Ordering::SeqCst) {
                    std::task::Poll::Ready(Ok(42))
                } else {
                    std::task::Poll::Pending
                }
            })
            .await
        })
    }
}

// INVARIANT: PLATFORM-TERMINATION-01 — a timer wake drives a pending operation independently
// of cancellation, with deterministic ties and release of both user future and host lease.
#[tokio::test(start_paused = true)]
async fn deadline_wakeup_arbitrates_and_releases_owned_work() {
    use std::future::Future as _;
    use std::task::Poll;
    for (complete, cancel, expected) in [
        (false, false, DispatchOutcome::DeadlineExceeded),
        (false, true, DispatchOutcome::Cancelled),
        (true, true, DispatchOutcome::Completed(42)),
    ] {
        let ready = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let (dispatcher, minter) = ApplicationBuilder::new(
            ApplicationName::parse("consumer").unwrap(),
            Arc::new(LeaseHost(released.clone())),
            Arc::new(TokioTimer),
        )
        .module(
            ApplicationModule::new(ModuleName::parse("inventory").unwrap())
                .handler::<Inventory, _>(ControlledHandler {
                    ready: ready.clone(),
                    dropped: dropped.clone(),
                }),
        )
        .build()
        .unwrap()
        .into_parts();
        let id = RequestId::parse("race").unwrap();
        let cancellation = Cancel::new(false);
        let ctx = context(
            &id,
            &cancellation,
            TokioTimer.now() + Duration::from_secs(1),
        );
        let mut running = Box::pin(
            dispatcher.dispatch::<Inventory>(&Inventory::DESCRIPTOR, minter.admit(1, ctx)),
        );
        std::future::poll_fn(|cx| {
            assert!(running.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(!released.load(Ordering::SeqCst));
        ready.store(complete, Ordering::SeqCst);
        if cancel {
            cancellation.set(true);
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), running)
                .await
                .unwrap()
                .unwrap(),
            expected
        );
        assert!(dropped.load(Ordering::SeqCst));
        assert!(released.load(Ordering::SeqCst));
    }
}

#[tokio::test(start_paused = true)]
async fn pre_cancelled_and_expired_never_polls_handler() {
    let (dispatcher, minter) = application(Arc::new(Host::new(AdmissionState::Ready)));
    let request = RequestId::parse("pre-cancelled").unwrap();
    let cancel = Cancel::new(true);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(1, context(&request, &cancel, TokioTimer.now()))
            )
            .await
            .unwrap(),
        DispatchOutcome::Cancelled
    );
    cancel.set(false);
    assert_eq!(
        dispatcher
            .dispatch::<Inventory>(
                &Inventory::DESCRIPTOR,
                minter.admit(1, context(&request, &cancel, TokioTimer.now()))
            )
            .await
            .unwrap(),
        DispatchOutcome::DeadlineExceeded
    );
}

struct BudgetExhaustingHandler;
impl Handler<Inventory> for BudgetExhaustingHandler {
    fn handle<'a>(&'a self, _: u32, _: RequestContextView<'a>) -> HandlerFuture<'a, u32> {
        use std::future::Future as _;
        Box::pin(std::future::poll_fn(|cx| {
            // Even this cooperative handler must not consume the deadline branch's poll budget.
            for _ in 0..256 {
                let mut budget = std::pin::pin!(tokio::task::consume_budget());
                if budget.as_mut().poll(cx).is_pending() {
                    break;
                }
            }
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }))
    }
}

#[tokio::test(start_paused = true)]
async fn cooperative_handler_cannot_starve_the_timer() {
    use std::future::Future as _;
    let (dispatcher, minter) = ApplicationBuilder::new(
        ApplicationName::parse("budget").unwrap(),
        Arc::new(Host::new(AdmissionState::Ready)),
        Arc::new(TokioTimer),
    )
    .module(
        ApplicationModule::new(ModuleName::parse("inventory").unwrap())
            .handler::<Inventory, _>(BudgetExhaustingHandler),
    )
    .build()
    .unwrap()
    .into_parts();
    let id = RequestId::parse("cooperative-budget").unwrap();
    let context = RequestContextView::new(
        None,
        &id,
        Deadline::at(TokioTimer.now() + Duration::from_secs(1)),
        Cancellation::observe(&NeverCancelled),
    );
    let mut running = Box::pin(
        dispatcher.dispatch::<Inventory>(&Inventory::DESCRIPTOR, minter.admit(1, context)),
    );
    std::future::poll_fn(|cx| {
        assert!(running.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_secs(1)).await;
    // The request timer is already due: an outer watchdog must not be needed to terminate it.
    let outcome = tokio::time::timeout(Duration::ZERO, running).await;
    assert_eq!(outcome.unwrap().unwrap(), DispatchOutcome::DeadlineExceeded);
}
