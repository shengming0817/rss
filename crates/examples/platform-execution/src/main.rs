use rss_contract::{Contract, ContractDescriptor, ContractId};
use rss_platform::{
    AdmissionPermit, AdmissionState, ApplicationBuilder, ApplicationModule, ApplicationName,
    BuildError, ConditionStatus, DispatchError, DispatchOutcome, Handler, HandlerFuture, HostView,
    ModuleName,
};
use rss_request_context::{
    Cancellation, CancellationFuture, CancellationObserver, Clock, Deadline, ExecutionTimer,
    RequestContextView, RequestId,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

struct Add;
impl Contract for Add {
    type Request = u32;
    type Response = u32;
    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "example.add",
        1,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}

struct AddHandler(Arc<AtomicBool>);
impl Handler<Add> for AddHandler {
    fn handle<'a>(&'a self, input: u32, _: RequestContextView<'a>) -> HandlerFuture<'a, u32> {
        Box::pin(async move {
            self.0.store(true, Ordering::SeqCst);
            if input == u32::MAX {
                // Stay pending while exhausting the executor budget on every poll. This checks
                // the real consumer timer adapter, not just the platform's test adapter.
                std::future::poll_fn(|cx| {
                    use std::future::Future as _;
                    for _ in 0..256 {
                        let mut budget = std::pin::pin!(tokio::task::consume_budget());
                        if budget.as_mut().poll(cx).is_pending() {
                            break;
                        }
                    }
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                })
                .await
            } else {
                Ok(input + 1)
            }
        })
    }
}

// The trusted composition supplies time, not dispatch arbitration.
struct TokioTimer;
impl Clock for TokioTimer {
    #[allow(
        clippy::disallowed_methods,
        reason = "the composition timer owns the monotonic clock"
    )]
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

struct NeverCancelled;
impl CancellationObserver for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
    fn cancelled(&self) -> CancellationFuture<'_> {
        // reason: this caller never cancels; the platform must still enforce its deadline.
        Box::pin(std::future::pending())
    }
}

// A minimal single-threaded composition gate. Production gate/leases belong to the host.
struct Host(AtomicBool);
struct Permit;
impl AdmissionPermit for Permit {}
impl HostView for Host {
    fn admission_state(&self) -> AdmissionState {
        if self.0.load(Ordering::SeqCst) {
            AdmissionState::Draining
        } else {
            AdmissionState::Ready
        }
    }
    fn try_admit(&self) -> Result<Box<dyn AdmissionPermit>, AdmissionState> {
        match self.admission_state() {
            AdmissionState::Ready => Ok(Box::new(Permit)),
            state => Err(state),
        }
    }
    fn inventory_revision(&self) -> Option<String> {
        // reason: this minimal host does not publish inventory.
        None
    }
    fn condition(&self, _: &str) -> Option<ConditionStatus> {
        // reason: this minimal host does not publish conditions.
        None
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = Arc::new(Host(AtomicBool::new(false)));
    let started = Arc::new(AtomicBool::new(false));
    let build = || {
        ApplicationBuilder::new(
            ApplicationName::parse("example")?,
            host.clone(),
            Arc::new(TokioTimer),
        )
        .module(
            ApplicationModule::new(ModuleName::parse("inventory")?)
                .handler::<Add, _>(AddHandler(started.clone())),
        )
        .build()
        .map_err(Box::<dyn std::error::Error>::from)
    };
    let (dispatcher, minter) = build()?.into_parts();
    let request_id = RequestId::parse("example-request")?;
    let cancellation = NeverCancelled;
    let context = |budget| {
        RequestContextView::new(
            None,
            &request_id,
            Deadline::at(TokioTimer.now() + budget),
            Cancellation::observe(&cancellation),
        )
    };
    let budget = Duration::from_secs(2);

    // No authentication policy lives here. A real integration validates identity and authority
    // before using its private, non-cloneable minter. A context alone grants no admission.
    let completed = match dispatcher
        .dispatch::<Add>(&Add::DESCRIPTOR, minter.admit(41, context(budget)))
        .await?
    {
        DispatchOutcome::Completed(value) => value,
        other => return Err(format!("unexpected success outcome: {other:?}").into()),
    };
    assert_eq!(completed, 42);

    started.store(false, Ordering::SeqCst);
    let deadline_exceeded = tokio::time::timeout(
        budget,
        dispatcher.dispatch::<Add>(
            &Add::DESCRIPTOR,
            minter.admit(u32::MAX, context(Duration::from_millis(100))),
        ),
    )
    .await??
        == DispatchOutcome::DeadlineExceeded;
    let handler_started = started.load(Ordering::SeqCst);
    assert!(handler_started && deadline_exceeded);

    let (_, foreign_minter) = build()?.into_parts();
    let foreign_admission_rejected = dispatcher
        .dispatch::<Add>(&Add::DESCRIPTOR, foreign_minter.admit(1, context(budget)))
        .await
        == Err(DispatchError::AdmissionCapabilityMismatch);
    assert!(foreign_admission_rejected);

    let mismatch =
        ContractDescriptor::from_static(Add::DESCRIPTOR.id(), 2, Add::DESCRIPTOR.schema_digest());
    let descriptor_mismatch_rejected = dispatcher
        .dispatch::<Add>(&mismatch, minter.admit(1, context(budget)))
        .await
        == Err(DispatchError::DescriptorMismatch);
    assert!(descriptor_mismatch_rejected);

    host.0.store(true, Ordering::SeqCst);
    let draining_rejected = dispatcher
        .dispatch::<Add>(&Add::DESCRIPTOR, minter.admit(1, context(budget)))
        .await
        == Err(DispatchError::HostDraining);
    assert!(draining_rejected);

    let duplicate_app = ApplicationName::parse("duplicates")?;
    let builder =
        || ApplicationBuilder::new(duplicate_app.clone(), host.clone(), Arc::new(TokioTimer));
    let module_name = ModuleName::parse("inventory")?;
    let duplicate_module = match builder()
        .module(ApplicationModule::new(module_name.clone()))
        .module(ApplicationModule::new(module_name.clone()))
        .build()
    {
        Err(BuildError::DuplicateModule(name)) => name,
        _ => return Err("missing duplicate module identity".into()),
    };
    assert_eq!(duplicate_module, module_name);
    let duplicate_contract = match builder()
        .module(
            ApplicationModule::new(module_name)
                .handler::<Add, _>(AddHandler(started.clone()))
                .handler::<Add, _>(AddHandler(started)),
        )
        .build()
    {
        Err(BuildError::DuplicateContract(id)) => id,
        _ => return Err("missing duplicate contract identity".into()),
    };
    assert_eq!(
        duplicate_contract,
        ContractId::from_static(Add::DESCRIPTOR.id())
    );

    println!(
        "{}",
        serde_json::json!({
            "completed": completed, "deadlineExceeded": deadline_exceeded, "handlerStarted": handler_started,
            "foreignAdmissionRejected": foreign_admission_rejected, "drainingRejected": draining_rejected,
            "descriptorMismatchRejected": descriptor_mismatch_rejected,
            "duplicateModule": duplicate_module.as_str(), "duplicateContract": duplicate_contract.as_str(),
        })
    );
    Ok(())
}
