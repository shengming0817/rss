//! Synthetic red: identityaudit SharedRuntimeDeps must not carry a domain service.

pub struct SharedRuntimeDeps {
    pub identity: identity::IdentityDomain<vault::VaultSigner>,
}
