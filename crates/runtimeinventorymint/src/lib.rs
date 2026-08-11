//! Capability required to mint one runtime-inventory live observation.
//!
//! `deny.toml` restricts this crate to `assembly-schema` (receipt signature owner) and
//! `runtimeexec` (full-plan receipt and live observation owner) plus the runtime assembly's closed
//! placement-projected provider transaction. Other assembly roots can consume opaque receipts but
//! cannot name or construct this capability.
//!
//! INVARIANT: RUNTIME-INVENTORY-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private token + crate graph wrapper allowlist" }

/// Opaque capability required by the runtime-inventory observation constructor.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeInventoryMint(());

impl RuntimeInventoryMint {
    /// Obtain the capability at the `runtimeexec` live-reader boundary.
    ///
    /// Dependency governance permits this call only from `runtimeexec`; `assembly-schema` names the
    /// token in its constructor signature but never obtains one.
    #[must_use]
    pub const fn capability() -> Self {
        Self(())
    }
}
