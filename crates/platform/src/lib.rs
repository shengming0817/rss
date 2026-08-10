#![deny(private_interfaces)]
#![allow(
    private_bounds,
    reason = "the private Contract supertrait is the public sealing boundary"
)]

//! Provider-free, typed in-process application kernel for RSS Platform Public.
//!
//! The crate owns the complete public authority path: canonical contract admission, static
//! federated ES256 verification, typed dispatch, and bounded shutdown. No workspace-internal type
//! or provider interface is part of this API.
//!
//! The required flow is `ApplicationBuilder` → `Application::start` → `Dispatcher::verify` →
//! `Dispatcher::dispatch` → `RuntimeHandle::shutdown`. Contracts are sealed generated markers;
//! successful verification is the only authority mint. Shutdown consumes the handle, rejects new
//! dispatches while draining, and leaves cloned dispatchers fail-closed after stop. Errors contain
//! only closed diagnostic codes and never retain a source chain or credential/identity text.
//!
//! See the packaged README for a complete flow.

mod auth;
mod diagnostics;
mod identity;
mod runtime;

pub mod contracts;

pub use auth::{AccessToken, PrincipalKind, TrustedIssuer, VerificationPolicy, VerifiedAccess};
pub use diagnostics::{
    BuildError, Condition, ConditionCode, ConditionStatus, ConditionsSnapshot, Diagnostic,
    DiagnosticCode, DiagnosticDetail, DiagnosticsSnapshot, DispatchError, ShutdownError,
    VerifyError,
};
pub use identity::{
    ApplicationName, ContractId, ContractVersion, IdentifierError, ModuleName, RequestId,
    SchemaDigest, TenantId, TenantIdError,
};
pub use runtime::{
    Application, ApplicationBuilder, ApplicationModule, Contract, Dispatcher, Handler,
    HandlerError, RequestContext, RuntimeHandle, ShutdownReport, VerifiedPrincipal, VerifiedTenant,
};
