//! Capability required to seal one production external-PKI provider closure.
//!
//! `diport` consumes the type only in its opaque seal signatures. Only the private Vault
//! provider-closure/evidence seals invoke [`ExternalPkiProviderMint::capability`]; identity and
//! composition receive move-only sealed values and cannot name this crate. `deny.toml` closes the
//! wrapper set and the layer-dependency callsite guard closes those constructor invocations.
//!
//! The `EXTERNAL-PKI-PROVIDER-MINT-01#production-callsite-exact-set` invariant is owned by the
//! canonical `layer-deps` check carrier; this marker crate does not duplicate that machine claim.

/// Move-only capability consumed when a validated provider/configuration pair is sealed.
pub struct ExternalPkiProviderMint(());

impl ExternalPkiProviderMint {
    /// Obtain the capability at the governed Vault production-construction boundary.
    #[must_use]
    pub const fn capability() -> Self {
        Self(())
    }
}

impl std::fmt::Debug for ExternalPkiProviderMint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExternalPkiProviderMint(<sealed>)")
    }
}
