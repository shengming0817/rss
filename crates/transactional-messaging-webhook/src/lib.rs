#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod binding;
mod config;
mod publisher;
mod signature;

pub use binding::{Publication, Target, TargetId, TargetVersion, pending_message};
pub use config::{
    AuthorizationFailure, AuthorizedTarget, Limits, NetworkAccess, TargetAuthorizer, TrustRoots,
};
pub use publisher::{WebhookPublishReceipt, WebhookPublisher};
pub use signature::{SigningKey, SigningKeys, WallClock};

/// Closed, redacted input failure. No URL, credential, payload or provider text is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// An authored binding or delivery identifier is invalid.
    #[error("invalid webhook message binding")]
    Binding,
    /// A limit, endpoint, trust root or network policy is invalid.
    #[error("invalid webhook configuration")]
    Config,
    /// Invalid signing material or wall-clock observation.
    #[error("invalid webhook signing input")]
    Signing,
}

#[cfg(test)]
mod tests;
