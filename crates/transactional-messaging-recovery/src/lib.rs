#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod access;
mod model;
/// Authenticated, encrypted authored-message capsules.
pub mod protection;
mod store;
pub use access::*;
pub use model::*;
pub use store::*;
