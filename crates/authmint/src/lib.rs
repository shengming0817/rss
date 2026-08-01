//! Capability token for production [`httpserve::Authenticated`] evidence minting.
//!
//! Only crates that depend on `authmint` (deny.toml wrappers: `httpserve` + assembly roots) can
//! obtain [`AuthenticatedMint`] and pass it into `Authenticated::new_*`. Domain / journey crates
//! must use `Authenticated::new` under `test-util` instead.
//!
//! INVARIANT: AUTH-EVIDENCE-MINT-01 { level = "Hard", exec = "native-compile", source = "code", native = "capability token + crate graph" }
//!
//! ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs

/// Opaque capability required by production `httpserve::Authenticated::new_*` constructors.
///
/// The private unit field prevents struct-literal forgery outside this crate. Obtain a token only
/// via [`AuthenticatedMint::capability`].
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedMint(());

impl AuthenticatedMint {
    /// Mint the production evidence capability (assembly / httpserve trust boundary only).
    #[must_use]
    pub const fn capability() -> Self {
        Self(())
    }
}

/// Opaque capability required to issue one tenant/instance-bound Saga start authorization.
///
/// This is deliberately separate from operator authorization: a business adopter may start only
/// its assembly-selected Saga and cannot mint maintenance capabilities.
#[derive(Clone, Copy, Debug)]
pub struct SagaStartMint(());

impl SagaStartMint {
    /// Mint the Saga start capability at an authenticated, audited composition boundary.
    #[must_use]
    pub const fn capability() -> Self {
        Self(())
    }
}
