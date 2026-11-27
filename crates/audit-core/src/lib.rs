#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod codec;
mod error;
mod identity;
#[cfg(feature = "ledger")]
mod ledger;
mod model;
mod prepared;

pub use codec::{
    MAX_HEADER_BYTES, MAX_RECORD_BYTES, canonical_len, decode_untrusted, inspect_canonical_header,
};
pub use error::{Error, Field};
pub use identity::{
    Action, ActorId, ActorKind, ActorRef, AuditPayload, EventId, OperationId, ResourceId,
    ResourceKind, ResourceRef, SourceContract, SourceId, SourceIdentity,
};
#[cfg(feature = "ledger")]
pub use ledger::{AUDIT_CHAIN_ID, DecodedAuditWindow, VerifiedAuditEntryV1, VerifiedAuditWindow};
pub use model::{
    AuditEventV1, Coordinates, DecodedAuditV1, EventContext, EventFacts, Outcome, RecordIdentity,
    RecordVersion,
};
pub use prepared::{PreparedAuditV1, prepare};
