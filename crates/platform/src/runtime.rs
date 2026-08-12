use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Instant;

use rss_contract::{ContractDescriptor, ContractId};
use rss_request_context::RequestContextView;

use crate::{ApplicationName, ModuleName};

static NEXT_APPLICATION_SEAL: AtomicU64 = AtomicU64::new(1);

pub type HandlerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, HandlerError>> + Send + 'a>>;

pub trait Contract: Send + Sync + 'static {
    type Request: Send + 'static;
    type Response: Send + 'static;
    const DESCRIPTOR: ContractDescriptor;
}

pub trait Handler<C: Contract>: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        request: C::Request,
        context: RequestContextView<'a>,
    ) -> HandlerFuture<'a, C::Response>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerFailureClass {
    Rejected,
    Unavailable,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerError {
    class: HandlerFailureClass,
}
impl HandlerError {
    #[must_use]
    pub const fn new(class: HandlerFailureClass) -> Self {
        Self { class }
    }
    #[must_use]
    pub const fn class(self) -> HandlerFailureClass {
        self.class
    }
}
impl fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("platform handler failed")
    }
}
impl Error for HandlerError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionState {
    Starting,
    Ready,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

/// Read-only projection of process truth. It contains no lifecycle authority.
pub trait HostView: Send + Sync + 'static {
    fn admission_state(&self) -> AdmissionState;
    fn try_admit(&self) -> Result<Box<dyn AdmissionPermit>, AdmissionState>;
    fn inventory_revision(&self) -> Option<String>;
    fn condition(&self, name: &str) -> Option<ConditionStatus>;
}

/// Move-only lease issued by the RuntimeExec-owned admission gate.
pub trait AdmissionPermit: Send {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchError {
    UnknownContract,
    DescriptorMismatch,
    HostNotReady,
    HostDraining,
    HostStopped,
    AdmissionCapabilityMismatch,
}
impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownContract => "unknown platform contract",
            Self::DescriptorMismatch => "platform contract descriptor mismatch",
            Self::HostNotReady => "platform host is not ready",
            Self::HostDraining => "platform host is draining",
            Self::HostStopped => "platform host is stopped",
            Self::AdmissionCapabilityMismatch => "platform admission capability mismatch",
        })
    }
}
impl Error for DispatchError {}

#[derive(Debug, Eq, PartialEq)]
pub enum DispatchOutcome<T> {
    Completed(T),
    HandlerFailed(HandlerFailureClass),
    Cancelled,
    DeadlineExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    DuplicateModule,
    DuplicateContract,
}
impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateModule => "duplicate platform module",
            Self::DuplicateContract => "duplicate platform contract",
        })
    }
}
impl Error for BuildError {}

pub struct ApplicationModule {
    name: ModuleName,
    registrations: Vec<Registration>,
}

impl ApplicationModule {
    #[must_use]
    pub fn new(name: ModuleName) -> Self {
        Self {
            name,
            registrations: Vec::new(),
        }
    }
    #[must_use]
    pub fn name(&self) -> &ModuleName {
        &self.name
    }
    #[must_use]
    pub fn handler<C, H>(mut self, handler: H) -> Self
    where
        C: Contract,
        H: Handler<C>,
    {
        self.registrations.push(Registration::new::<C, H>(handler));
        self
    }
}

pub struct ApplicationBuilder {
    name: ApplicationName,
    host: Arc<dyn HostView>,
    modules: Vec<ApplicationModule>,
}

impl ApplicationBuilder {
    #[must_use]
    pub fn new(name: ApplicationName, host: Arc<dyn HostView>) -> Self {
        Self {
            name,
            host,
            modules: Vec::new(),
        }
    }
    #[must_use]
    pub fn module(mut self, module: ApplicationModule) -> Self {
        self.modules.push(module);
        self
    }
    pub fn build(self) -> Result<Application, BuildError> {
        let mut module_names = HashSet::new();
        let mut handlers = HashMap::new();
        for module in self.modules {
            if !module_names.insert(module.name) {
                return Err(BuildError::DuplicateModule);
            }
            for registration in module.registrations {
                if handlers
                    .insert(
                        rss_contract::ContractId::from_static(registration.descriptor.id()),
                        registration,
                    )
                    .is_some()
                {
                    return Err(BuildError::DuplicateContract);
                }
            }
        }
        let seal = NEXT_APPLICATION_SEAL.fetch_add(1, Ordering::Relaxed);
        Ok(Application {
            dispatcher: Dispatcher {
                application: self.name,
                host: self.host,
                handlers: Arc::new(handlers),
                seal,
            },
            context_minter: TrustedContextMinter { seal },
        })
    }
}

/// Built application split into the public dispatcher and its private-integration mint authority.
pub struct Application {
    dispatcher: Dispatcher,
    context_minter: TrustedContextMinter,
}

impl Application {
    #[must_use]
    pub fn into_parts(self) -> (Dispatcher, TrustedContextMinter) {
        (self.dispatcher, self.context_minter)
    }
}

/// Instance-bound authority used by a private AuthN/AuthZ integration to admit request values.
///
/// This capability is intentionally not `Clone` and has no public constructor. Holding only a
/// [`Dispatcher`] and an authority-free [`RequestContextView`] is insufficient to dispatch.
pub struct TrustedContextMinter {
    seal: u64,
}

impl TrustedContextMinter {
    #[must_use]
    pub fn admit<'a, T>(
        &self,
        request: T,
        context: RequestContextView<'a>,
    ) -> AdmittedRequest<'a, T> {
        AdmittedRequest {
            seal: self.seal,
            request,
            context,
        }
    }
}

/// Move-only request capability minted after the owning integration has authenticated and
/// authorized the authority-free Foundation values.
pub struct AdmittedRequest<'a, T> {
    seal: u64,
    request: T,
    context: RequestContextView<'a>,
}

#[derive(Clone)]
pub struct Dispatcher {
    application: ApplicationName,
    host: Arc<dyn HostView>,
    handlers: Arc<HashMap<ContractId, Registration>>,
    seal: u64,
}

impl Dispatcher {
    #[must_use]
    pub fn application_name(&self) -> &ApplicationName {
        &self.application
    }
    #[must_use]
    pub fn host(&self) -> &dyn HostView {
        self.host.as_ref()
    }

    pub async fn dispatch<C: Contract>(
        &self,
        descriptor: &ContractDescriptor,
        admitted: AdmittedRequest<'_, C::Request>,
    ) -> Result<DispatchOutcome<C::Response>, DispatchError> {
        if admitted.seal != self.seal {
            return Err(DispatchError::AdmissionCapabilityMismatch);
        }
        let AdmittedRequest {
            request, context, ..
        } = admitted;
        let _admission = self.host.try_admit().map_err(dispatch_state_error)?;
        let contract_id = rss_contract::ContractId::from_static(descriptor.id());
        let Some(registration) = self.handlers.get(&contract_id) else {
            return Err(DispatchError::UnknownContract);
        };
        if descriptor != &C::DESCRIPTOR || descriptor != &registration.descriptor {
            return Err(DispatchError::DescriptorMismatch);
        }
        if registration.request_type != std::any::TypeId::of::<C::Request>()
            || registration.response_type != std::any::TypeId::of::<C::Response>()
        {
            return Err(DispatchError::DescriptorMismatch);
        }
        if context.cancellation().is_cancelled() {
            return Ok(DispatchOutcome::Cancelled);
        }
        if context.deadline().is_expired(Instant::now()) {
            return Ok(DispatchOutcome::DeadlineExceeded);
        }
        let mut operation = registration.handler.handle(Box::new(request), context);
        let mut termination = context.cancellation().cancelled(context.deadline());
        let output = std::future::poll_fn(move |cx| {
            if let Poll::Ready(output) = operation.as_mut().poll(cx) {
                return Poll::Ready(Ok(output));
            }
            termination.as_mut().poll(cx).map(Err)
        })
        .await;
        let output = match output {
            Ok(output) => output,
            Err(rss_request_context::CancellationReason::Cancelled) => {
                return Ok(DispatchOutcome::Cancelled);
            }
            Err(rss_request_context::CancellationReason::DeadlineExceeded) => {
                return Ok(DispatchOutcome::DeadlineExceeded);
            }
        };
        match output {
            Ok(value) => value
                .downcast::<C::Response>()
                .map(|value| DispatchOutcome::Completed(*value))
                .map_err(|_| DispatchError::DescriptorMismatch),
            Err(class) => Ok(DispatchOutcome::HandlerFailed(class)),
        }
    }
}

struct Registration {
    descriptor: ContractDescriptor,
    request_type: std::any::TypeId,
    response_type: std::any::TypeId,
    handler: Arc<dyn ErasedHandler>,
}
impl Registration {
    fn new<C: Contract, H: Handler<C>>(handler: H) -> Self {
        Self {
            descriptor: C::DESCRIPTOR.clone(),
            request_type: std::any::TypeId::of::<C::Request>(),
            response_type: std::any::TypeId::of::<C::Response>(),
            handler: Arc::new(TypedHandler::<C, H> {
                handler,
                marker: PhantomData,
            }),
        }
    }
}

fn dispatch_state_error(state: AdmissionState) -> DispatchError {
    match state {
        AdmissionState::Starting => DispatchError::HostNotReady,
        AdmissionState::Ready => DispatchError::HostNotReady,
        AdmissionState::Draining => DispatchError::HostDraining,
        AdmissionState::Stopped => DispatchError::HostStopped,
    }
}

trait ErasedHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        request: Box<dyn Any + Send>,
        context: RequestContextView<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Any + Send>, HandlerFailureClass>> + Send + 'a>>;
}
struct TypedHandler<C, H> {
    handler: H,
    marker: PhantomData<C>,
}
impl<C: Contract, H: Handler<C>> ErasedHandler for TypedHandler<C, H> {
    fn handle<'a>(
        &'a self,
        request: Box<dyn Any + Send>,
        context: RequestContextView<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Any + Send>, HandlerFailureClass>> + Send + 'a>>
    {
        Box::pin(async move {
            let request = request
                .downcast::<C::Request>()
                .map_err(|_| HandlerFailureClass::Internal)?;
            self.handler
                .handle(*request, context)
                .await
                .map(|value| Box::new(value) as Box<dyn Any + Send>)
                .map_err(HandlerError::class)
        })
    }
}
