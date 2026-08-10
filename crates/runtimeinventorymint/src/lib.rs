//! Capability required to mint one runtime-inventory live observation.
//!
//! `deny.toml` restricts this crate to `assembly-schema` (receipt signature owner) and
//! `runtimeexec` (the only mint caller). Assembly roots can consume the opaque observation returned
//! by `runtimeexec`, but cannot name or construct this capability.
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
