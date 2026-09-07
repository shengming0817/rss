#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod control;
mod error;

pub use control::{RequestBudget, RequestBudgetError, RequestControl, request_control};
pub use error::HttpError;
mod routes;
pub use routes::{ContractMarker, Endpoint, HttpContract};
#[cfg(any(feature = "http1", feature = "http2"))]
mod server;
#[cfg(feature = "auto-protocol")]
pub use server::serve_auto_registration;
#[cfg(feature = "http1")]
pub use server::serve_http1_registration;
#[cfg(feature = "http2")]
pub use server::serve_http2_registration;
