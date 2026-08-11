//! Isolated capability token for production DLQ operator authorization minting.
//!
//! Only `diport`, which owns the opaque authorization proof, and the production runtime
//! composition root may depend on this crate.
//!
//! INVARIANT: DLQ-OPERATOR-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "isolated capability crate + exact dependency wrappers" }

/// Opaque capability required to issue one action- and tenant-bound DLQ authorization.
#[derive(Clone, Copy, Debug)]
pub struct DlqOperatorMint(());

impl DlqOperatorMint {
    /// Mint the capability at the production DLQ operator composition boundary.
    #[must_use]
    pub const fn capability() -> Self {
        Self(())
    }
}
