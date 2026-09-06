#![allow(clippy::unwrap_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use rss_contract::{Contract, ContractDescriptor};
use rss_platform::*;
use rss_request_context::{
    Cancellation, CancellationObserver, Deadline, RequestContextView, RequestId,
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
    fn cancelled(&self, deadline: Deadline) -> rss_request_context::CancellationFuture<'_> {
        Box::pin(async move {
            tokio::select! {
                () = async {
                    loop {
                        let notified = self.notify.notified();
                        if self.is_cancelled() { break; }
                        notified.await;
                    }
                } => rss_request_context::CancellationReason::Cancelled,
                () = tokio::time::sleep_until(deadline.instant().into()) => {
                    rss_request_context::CancellationReason::DeadlineExceeded
                }
            }
        })
    }
}

struct ImmediatelyCancelled;
impl CancellationObserver for ImmediatelyCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self, _: Deadline) -> rss_request_context::CancellationFuture<'_> {
        Box::pin(std::future::ready(
            rss_request_context::CancellationReason::Cancelled,
        ))
    }
}

fn application(host: Arc<Host>) -> (Dispatcher, TrustedContextMinter) {
    ApplicationBuilder::new(ApplicationName::parse("consumer").unwrap(), host)
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
        ApplicationBuilder::new(ApplicationName::parse("consumer").unwrap(), host)
            .module(module)
            .build(),
        Err(BuildError::DuplicateContract)
    ));
}
