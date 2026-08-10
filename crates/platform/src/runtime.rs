use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use crate::auth::{AccessToken, PrincipalKind, TrustedIssuer, VerifiedAccess};
use crate::diagnostics::{
    BuildError, Condition, ConditionCode, ConditionStatus, ConditionsSnapshot, Diagnostic,
    DiagnosticCode, DiagnosticsSnapshot, DispatchError, ShutdownError, VerifyError,
};
use crate::identity::{
    ApplicationName, ContractId, ContractVersion, ModuleName, RequestId, SchemaDigest, TenantId,
};

pub(crate) mod private {
    pub trait Sealed {}
}

pub trait Contract: private::Sealed + Send + Sync + 'static {
    type Request: Send + 'static;
    type Response: Send + 'static;
    const ID: ContractId;
    const VERSION: ContractVersion;
    const SCHEMA_DIGEST: SchemaDigest;
    const PERMISSION: &'static str;
}

pub trait Handler<C: Contract>: Send + Sync + 'static {
    fn handle(
        &self,
        request: C::Request,
        context: RequestContext<'_>,
    ) -> Result<C::Response, HandlerError>;
}

pub struct HandlerError;
impl HandlerError {
    pub const fn new() -> Self {
        Self
    }
}
impl Default for HandlerError {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Debug for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("platform handler failed")
    }
}
impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("platform handler failed")
    }
}
impl Error for HandlerError {}

pub struct RequestContext<'a> {
    access: &'a VerifiedAccess,
    request_id: &'a RequestId,
}

impl RequestContext<'_> {
    pub fn principal(&self) -> VerifiedPrincipal<'_> {
        VerifiedPrincipal {
            access: self.access,
        }
    }
    pub fn tenant(&self) -> Option<VerifiedTenant<'_>> {
        self.access.tenant.as_ref().map(|id| VerifiedTenant { id })
    }
    pub fn request_id(&self) -> &RequestId {
        self.request_id
    }
    pub fn allows_permission(&self, permission: &str) -> bool {
        self.access.allows_permission(permission)
    }
}

pub struct VerifiedPrincipal<'a> {
    access: &'a VerifiedAccess,
}
impl VerifiedPrincipal<'_> {
    pub fn kind(&self) -> PrincipalKind {
        self.access.kind
    }
    pub fn matches_subject(&self, candidate: &str) -> bool {
        self.access.matches_subject(candidate)
    }
}

pub struct VerifiedTenant<'a> {
    id: &'a TenantId,
}
impl VerifiedTenant<'_> {
    pub fn id(&self) -> &TenantId {
        self.id
    }
}

pub struct ApplicationModule {
    name: ModuleName,
    registrations: Vec<Registration>,
}

impl ApplicationModule {
    pub fn new(name: ModuleName) -> Self {
        Self {
            name,
            registrations: Vec::new(),
        }
    }
    pub fn name(&self) -> &ModuleName {
        &self.name
    }
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
    issuer: Option<TrustedIssuer>,
    modules: Vec<ApplicationModule>,
}

impl ApplicationBuilder {
    pub fn new(name: ApplicationName) -> Self {
        Self {
            name,
            issuer: None,
            modules: Vec::new(),
        }
    }
    pub fn trusted_issuer(mut self, issuer: TrustedIssuer) -> Self {
        self.issuer = Some(issuer);
        self
    }
    pub fn module(mut self, module: ApplicationModule) -> Self {
        self.modules.push(module);
        self
    }

    pub fn build(self) -> Result<Application, BuildError> {
        let issuer = self.issuer.ok_or_else(|| {
            BuildError::new(DiagnosticsSnapshot::one(Diagnostic::new(
                DiagnosticCode::MissingTrustedIssuer,
            )))
        })?;
        let mut module_names = HashSet::new();
        let mut handlers = HashMap::new();
        let mut duplicate_modules = 0;
        let mut duplicate_handlers = 0;
        for module in self.modules {
            if !module_names.insert(module.name.as_str().to_owned()) {
                duplicate_modules += 1;
            }
            for registration in module.registrations {
                if handlers
                    .insert(registration.id, registration.handler)
                    .is_some()
                {
                    duplicate_handlers += 1;
                }
            }
        }
        if duplicate_modules != 0 || duplicate_handlers != 0 {
            let mut diagnostics = Vec::new();
            if duplicate_modules != 0 {
                diagnostics.push(Diagnostic::count(
                    DiagnosticCode::DuplicateModule,
                    duplicate_modules,
                ));
            }
            if duplicate_handlers != 0 {
                diagnostics.push(Diagnostic::count(
                    DiagnosticCode::DuplicateHandler,
                    duplicate_handlers,
                ));
            }
            return Err(BuildError::new(DiagnosticsSnapshot::new(diagnostics)));
        }
        Ok(Application {
            _name: self.name,
            issuer,
            handlers,
        })
    }
}

pub struct Application {
    _name: ApplicationName,
    issuer: TrustedIssuer,
    handlers: HashMap<ContractId, Arc<dyn ErasedHandler>>,
}

impl Application {
    pub fn start(self) -> RuntimeHandle {
        let core = Arc::new(RuntimeCore {
            issuer: self.issuer,
            handlers: self.handlers,
            state: Mutex::new(RuntimeState {
                phase: Phase::Accepting,
                inflight: 0,
            }),
            diagnostics: Mutex::new(Vec::new()),
            idle: Condvar::new(),
        });
        RuntimeHandle { core }
    }
}

pub struct RuntimeHandle {
    core: Arc<RuntimeCore>,
}

impl RuntimeHandle {
    pub fn dispatcher(&self) -> Dispatcher {
        Dispatcher {
            core: Arc::clone(&self.core),
        }
    }
    pub fn conditions(&self) -> ConditionsSnapshot {
        self.core.conditions()
    }
    pub fn diagnostics(&self) -> DiagnosticsSnapshot {
        self.core.diagnostics()
    }

    pub fn shutdown(self, timeout: Duration) -> Result<ShutdownReport, ShutdownError> {
        let mut state = lock_state(&self.core.state);
        state.phase = Phase::Draining;
        let (next, timed_out) = wait_until_idle(&self.core.idle, state, timeout);
        state = next;
        if timed_out && state.inflight != 0 {
            self.core.record(DiagnosticCode::ShutdownTimedOut);
            return Err(shutdown_timeout(timeout));
        }
        state.phase = Phase::Stopped;
        drop(state);
        Ok(ShutdownReport {
            conditions: self.core.conditions(),
            diagnostics: DiagnosticsSnapshot::one(Diagnostic::new(
                DiagnosticCode::ShutdownComplete,
            )),
        })
    }
}

#[derive(Clone)]
pub struct Dispatcher {
    core: Arc<RuntimeCore>,
}

impl Dispatcher {
    pub fn verify(
        &self,
        token: &AccessToken,
        now: SystemTime,
    ) -> Result<VerifiedAccess, VerifyError> {
        if lock_state(&self.core.state).phase == Phase::Stopped {
            self.core.record(DiagnosticCode::RuntimeStopped);
            return Err(VerifyError::new(DiagnosticsSnapshot::one(Diagnostic::new(
                DiagnosticCode::RuntimeStopped,
            ))));
        }
        self.core.issuer.verify(token, now).inspect_err(|_| {
            self.core.record(DiagnosticCode::InvalidCredential);
        })
    }

    pub fn dispatch<C: Contract>(
        &self,
        access: &VerifiedAccess,
        request_id: RequestId,
        request: C::Request,
    ) -> Result<C::Response, DispatchError> {
        if !self.core.issuer.accepts(access)
            || !access.is_fresh_at(trusted_now())
            || !access.allows_permission(C::PERMISSION)
        {
            self.core.record(DiagnosticCode::PermissionDenied);
            return Err(dispatch_error(DiagnosticCode::PermissionDenied));
        }
        let guard = self.core.begin_dispatch().map_err(|code| {
            self.core.record(code);
            dispatch_error(code)
        })?;
        let handler = self.core.handlers.get(&C::ID).ok_or_else(|| {
            self.core.record(DiagnosticCode::MissingHandler);
            dispatch_error(DiagnosticCode::MissingHandler)
        })?;
        let response = handler
            .handle(access, &request_id, Box::new(request))
            .inspect_err(|_| self.core.record(DiagnosticCode::HandlerFailed))?;
        drop(guard);
        response
            .downcast::<C::Response>()
            .map(|value| *value)
            .map_err(|_| {
                self.core.record(DiagnosticCode::HandlerFailed);
                dispatch_error(DiagnosticCode::HandlerFailed)
            })
    }

    pub fn conditions(&self) -> ConditionsSnapshot {
        self.core.conditions()
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "Platform Public owns this private concrete wall-clock boundary; no caller-supplied clock can extend authority freshness"
)]
fn trusted_now() -> SystemTime {
    SystemTime::now()
}

pub struct ShutdownReport {
    conditions: ConditionsSnapshot,
    diagnostics: DiagnosticsSnapshot,
}
impl ShutdownReport {
    pub fn conditions(&self) -> &ConditionsSnapshot {
        &self.conditions
    }
    pub fn diagnostics(&self) -> &DiagnosticsSnapshot {
        &self.diagnostics
    }
}

struct RuntimeCore {
    issuer: TrustedIssuer,
    handlers: HashMap<ContractId, Arc<dyn ErasedHandler>>,
    state: Mutex<RuntimeState>,
    diagnostics: Mutex<Vec<DiagnosticCode>>,
    idle: Condvar,
}

impl RuntimeCore {
    fn begin_dispatch(self: &Arc<Self>) -> Result<InflightGuard, DiagnosticCode> {
        let mut state = lock_state(&self.state);
        match state.phase {
            Phase::Accepting => {
                state.inflight += 1;
                Ok(InflightGuard {
                    core: Arc::clone(self),
                })
            }
            Phase::Draining => Err(DiagnosticCode::RuntimeDraining),
            Phase::Stopped => Err(DiagnosticCode::RuntimeStopped),
        }
    }

    fn conditions(&self) -> ConditionsSnapshot {
        let state = lock_state(&self.state);
        let truth = |value| {
            if value {
                ConditionStatus::True
            } else {
                ConditionStatus::False
            }
        };
        ConditionsSnapshot::new(vec![
            Condition::new(
                ConditionCode::HandlersAdmitted,
                truth(!self.handlers.is_empty()),
            ),
            Condition::new(
                ConditionCode::AcceptingDispatch,
                truth(state.phase == Phase::Accepting),
            ),
            Condition::new(
                ConditionCode::Draining,
                truth(state.phase == Phase::Draining),
            ),
            Condition::new(ConditionCode::Stopped, truth(state.phase == Phase::Stopped)),
        ])
    }

    fn record(&self, code: DiagnosticCode) {
        const MAX_DIAGNOSTICS: usize = 64;
        let mut diagnostics = lock_diagnostics(&self.diagnostics);
        if diagnostics.len() == MAX_DIAGNOSTICS {
            diagnostics.remove(0);
        }
        diagnostics.push(code);
    }

    fn diagnostics(&self) -> DiagnosticsSnapshot {
        let diagnostics = lock_diagnostics(&self.diagnostics)
            .iter()
            .copied()
            .map(Diagnostic::new)
            .collect();
        DiagnosticsSnapshot::new(diagnostics)
    }
}

struct InflightGuard {
    core: Arc<RuntimeCore>,
}
impl Drop for InflightGuard {
    fn drop(&mut self) {
        let mut state = lock_state(&self.core.state);
        state.inflight = state.inflight.saturating_sub(1);
        if state.inflight == 0 {
            if state.phase == Phase::Draining {
                state.phase = Phase::Stopped;
            }
            self.core.idle.notify_all();
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Accepting,
    Draining,
    Stopped,
}
struct RuntimeState {
    phase: Phase,
    inflight: usize,
}

pub(crate) struct Registration {
    id: ContractId,
    handler: Arc<dyn ErasedHandler>,
}
impl Registration {
    fn new<C: Contract, H: Handler<C>>(handler: H) -> Self {
        Self {
            id: C::ID,
            handler: Arc::new(TypedHandler::<C, H> {
                handler,
                marker: PhantomData,
            }),
        }
    }
}

trait ErasedHandler: Send + Sync {
    fn handle(
        &self,
        access: &VerifiedAccess,
        request_id: &RequestId,
        request: Box<dyn Any + Send>,
    ) -> Result<Box<dyn Any + Send>, DispatchError>;
}

struct TypedHandler<C, H> {
    handler: H,
    marker: PhantomData<C>,
}
impl<C: Contract, H: Handler<C>> ErasedHandler for TypedHandler<C, H> {
    fn handle(
        &self,
        access: &VerifiedAccess,
        request_id: &RequestId,
        request: Box<dyn Any + Send>,
    ) -> Result<Box<dyn Any + Send>, DispatchError> {
        let request = request
            .downcast::<C::Request>()
            .map_err(|_| dispatch_error(DiagnosticCode::HandlerFailed))?;
        let context = RequestContext { access, request_id };
        self.handler
            .handle(*request, context)
            .map(|response| Box::new(response) as Box<dyn Any + Send>)
            .map_err(|_| dispatch_error(DiagnosticCode::HandlerFailed))
    }
}

fn dispatch_error(code: DiagnosticCode) -> DispatchError {
    DispatchError::new(DiagnosticsSnapshot::one(Diagnostic::new(code)))
}
fn shutdown_timeout(timeout: Duration) -> ShutdownError {
    ShutdownError::new(DiagnosticsSnapshot::one(Diagnostic::duration(
        DiagnosticCode::ShutdownTimedOut,
        timeout,
    )))
}
fn lock_state(mutex: &Mutex<RuntimeState>) -> MutexGuard<'_, RuntimeState> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
fn lock_diagnostics(mutex: &Mutex<Vec<DiagnosticCode>>) -> MutexGuard<'_, Vec<DiagnosticCode>> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
fn wait_until_idle<'a>(
    condvar: &Condvar,
    state: MutexGuard<'a, RuntimeState>,
    timeout: Duration,
) -> (MutexGuard<'a, RuntimeState>, bool) {
    match condvar.wait_timeout_while(state, timeout, |state| state.inflight != 0) {
        Ok((guard, result)) => (guard, result.timed_out()),
        Err(poisoned) => {
            let (guard, result) = poisoned.into_inner();
            (guard, result.timed_out())
        }
    }
}
