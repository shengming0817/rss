//! Consumer dead-letter archive lifecycle. Providers report facts; this module alone mints proofs.
mod crypto;
mod lifecycle;
mod model;
pub use crypto::{ArchiveKey, HotKey, MAX_OBJECT_BYTES};
pub use lifecycle::*;
pub use model::*;
