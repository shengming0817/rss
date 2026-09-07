#![allow(clippy::unwrap_used)]
// reason: the composition fixture must fail loudly on any construction or boundary regression.
use rss_contract::{Contract, ContractDescriptor};
use rss_platform::*;
use rss_request_context::{
    Cancellation, CancellationFuture, CancellationObserver, Clock, Deadline, ExecutionTimer,
    RequestContextView, RequestId,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

struct Inventory;
impl Contract for Inventory {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "shared.timer",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}
struct InventoryHandler;
impl Handler<Inventory> for InventoryHandler {
    fn handle<'a>(&'a self, _: u32, _: RequestContextView<'a>) -> HandlerFuture<'a, u32> {
        Box::pin(std::future::pending())
    }
}
struct Host;
struct Permit;
impl AdmissionPermit for Permit {}
impl HostView for Host {
    fn admission_state(&self) -> AdmissionState {
        AdmissionState::Ready
    }
    fn try_admit(&self) -> Result<Box<dyn AdmissionPermit>, AdmissionState> {
        Ok(Box::new(Permit))
    }
    // reason: the minimal test host has no product inventory or conditions.
    fn inventory_revision(&self) -> Option<String> {
        None
    }
    fn condition(&self, _: &str) -> Option<ConditionStatus> {
        None
    }
}
struct Cancel;
impl CancellationObserver for Cancel {
    // reason: only the shared cutoff may terminate this composition scenario.
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> CancellationFuture<'_> {
        Box::pin(std::future::pending())
    }
}
struct TokioTimer;
impl Clock for TokioTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "the injected adapter owns its monotonic source"
    )]
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for TokioTimer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}

#[tokio::test(start_paused = true)]
async fn one_timer_and_cutoff_drive_request_and_message_execution() {
    let timer = Arc::new(TokioTimer);
    let deadline = Deadline::from_timeout(timer.as_ref(), Duration::from_secs(1)).unwrap();
    let (dispatcher, minter) = ApplicationBuilder::new(
        ApplicationName::parse("shared-clock").unwrap(),
        Arc::new(Host),
        Arc::clone(&timer),
    )
    .module(
        ApplicationModule::new(ModuleName::parse("inventory").unwrap())
            .handler::<Inventory, _>(InventoryHandler),
    )
    .build()
    .unwrap()
    .into_parts();
    let request = RequestId::parse("shared-cutoff").unwrap();
    let cancel = Cancel;
    let request_work = dispatcher.dispatch::<Inventory>(
        &Inventory::DESCRIPTOR,
        minter.admit(
            u32::MAX,
            RequestContextView::new(None, &request, deadline, Cancellation::observe(&cancel)),
        ),
    );
    let message_work =
        rss_transactional_messaging::policy::within(timer.as_ref(), deadline, |_| {
            std::future::pending::<()>()
        });
    let (request_result, message_result) = tokio::join!(request_work, message_work);
    assert_eq!(request_result.unwrap(), DispatchOutcome::DeadlineExceeded);
    assert_eq!(
        message_result.unwrap_err().kind(),
        rss_transactional_messaging::error::MessagingErrorKind::DeadlineElapsed
    );
    assert!(deadline.is_expired(timer.now()));
}
