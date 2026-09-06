#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod control;
mod error;

pub use control::{RequestBudget, RequestBudgetError, RequestControl, request_control};
pub use error::HttpError;
mod routes;
pub use routes::{ContractMarker, Endpoint, HttpContract};
#[cfg(feature = "managed-server")]
mod server;
#[cfg(feature = "managed-server")]
pub use server::serve_registration;
