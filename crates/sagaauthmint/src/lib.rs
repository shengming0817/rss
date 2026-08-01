//! Isolated capability token for production Saga operator authorization minting.
//!
//! This crate intentionally has no dependency on the ordinary authenticated-evidence mint. The
//! workspace dependency graph admits only `diport` (the opaque proof owner) and the production
//! runtime assembly, so HTTP and non-Saga assemblies cannot obtain operator authority merely by
//! holding `authmint`.
//!
//! INVARIANT: SAGA-OPERATOR-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "isolated capability crate + exact dependency wrappers" }

/// Opaque capability required to issue a target-bound Saga operator authorization.
#[derive(Clone, Copy, Debug)]
pub struct SagaOperatorMint(());

impl SagaOperatorMint {
    /// Mint the capability at the Saga operator composition boundary.
    #[must_use]
    pub const fn capability() -> Self {
        Self(())
    }
}
