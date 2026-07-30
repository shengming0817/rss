//! AUTH-EVIDENCE-MINT-01：production `Authenticated::new_*` requires `authmint::AuthenticatedMint`.
//! An external crate without the `authmint` dependency cannot name that capability token, so it
//! cannot call the production mint constructors (distinct from `cannot_mint_authenticated.rs`,
//! which seals `AuthenticatedRoutes::new`).
//!
//! This fixture locks the arity / missing-token failure on `new_mtls`.
fn main() {
    let _ = httpserve::Authenticated::new_mtls("peer");
}
