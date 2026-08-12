//! Provider-free typed asynchronous application waist for RSS Platform Public.
//!
//! Contract identity and request context values come from the two public Foundation packages.
//! Authentication, process lifecycle, inventory minting, providers and composition remain outside
//! this crate. Public request values are deliberately not authentication evidence.

mod names;
mod runtime;
pub use names::{ApplicationName, ModuleName, NameError};
pub use runtime::{
    AdmissionPermit, AdmissionState, ApplicationBuilder, ApplicationModule, BuildError,
    ConditionStatus, Contract, DispatchError, DispatchOutcome, Dispatcher, Handler, HandlerError,
    HandlerFuture, HostView,
};
