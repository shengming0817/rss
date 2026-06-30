//! mTLS/SPIFFE identity model.
//!
//! `VerifiedMtlsPeer` mirrors the existing verified-token pattern: fields are
//! private, production minting goes through a verifier seam, and downstream code
//! only sees an already-authenticated service principal.

use std::collections::BTreeSet;

/// Canonical SPIFFE ID accepted by RSS mTLS.
///
/// RSS tightens the upstream SPIFFE parser: the URI must round-trip exactly to
/// canonical `spiffe://<trust-domain>/<path>`, and the path must be non-empty.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SpiffeId {
    canonical: String,
}

impl SpiffeId {
    /// Parse a canonical SPIFFE ID.
    pub fn parse(raw: &str) -> Result<Self, MtlsIdentityError> {
        if raw.contains('?') || raw.contains('#') || raw.contains('@') || raw.contains('*') {
            return Err(MtlsIdentityError::InvalidSpiffeId);
        }
        let parsed = spiffe::SpiffeId::new(raw).map_err(|_| MtlsIdentityError::InvalidSpiffeId)?;
        if parsed.path().is_empty() {
            return Err(MtlsIdentityError::EmptyPath);
        }
        let canonical = parsed.to_string();
        if canonical != raw {
            return Err(MtlsIdentityError::NonCanonicalSpiffeId);
        }
        Ok(Self { canonical })
    }

    /// Canonical `spiffe://...` string.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl std::fmt::Debug for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SpiffeId").field(&self.canonical).finish()
    }
}

impl std::fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl std::str::FromStr for SpiffeId {
    type Err = MtlsIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for SpiffeId {
    type Error = MtlsIdentityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Exact SPIFFE SAN allow-set.
#[derive(Clone, Debug)]
pub struct MtlsAllowSet {
    allowed: BTreeSet<SpiffeId>,
}

impl MtlsAllowSet {
    /// Build a non-empty exact allow-set.
    pub fn new<I, S>(ids: I) -> Result<Self, MtlsIdentityError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed: BTreeSet<SpiffeId> = ids
            .into_iter()
            .map(|id| SpiffeId::parse(id.as_ref()))
            .collect::<Result<_, _>>()?;
        if allowed.is_empty() {
            return Err(MtlsIdentityError::EmptyAllowSet);
        }
        Ok(Self { allowed })
    }

    /// Return true only for exact canonical identity matches.
    pub fn allows(&self, peer: &SpiffeId) -> bool {
        self.allowed.contains(peer)
    }

    /// Iterate canonical SPIFFE IDs for wiring exact upstream authorizers.
    pub fn iter(&self) -> impl Iterator<Item = &SpiffeId> {
        self.allowed.iter()
    }
}

/// Verified mTLS peer evidence.
///
/// The fields and `seal` are crate-private; external crates cannot mint this
/// type by struct literal or by calling the seal.
#[derive(Clone)]
pub struct VerifiedMtlsPeer {
    spiffe_id: SpiffeId,
}

impl std::fmt::Debug for VerifiedMtlsPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedMtlsPeer")
            .field("spiffe_id", &self.spiffe_id)
            .finish()
    }
}

impl VerifiedMtlsPeer {
    pub(crate) fn seal(spiffe_id: SpiffeId) -> Self {
        Self { spiffe_id }
    }

    /// Verified canonical peer SPIFFE ID.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }
}

/// Verify that a TLS-authenticated SPIFFE ID is allowed, then mint peer evidence.
pub fn verify_mtls_peer(
    spiffe_id: SpiffeId,
    allow_set: &MtlsAllowSet,
) -> Result<VerifiedMtlsPeer, MtlsIdentityError> {
    if !allow_set.allows(&spiffe_id) {
        return Err(MtlsIdentityError::PeerNotAllowed);
    }
    Ok(VerifiedMtlsPeer::seal(spiffe_id))
}

/// mTLS identity/allow-list failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MtlsIdentityError {
    /// SPIFFE ID is syntactically invalid or contains disallowed URI parts.
    #[error("spiffe id is invalid")]
    InvalidSpiffeId,
    /// SPIFFE ID is valid but not in canonical lowercase/string form.
    #[error("spiffe id is not canonical")]
    NonCanonicalSpiffeId,
    /// RSS service identities must include a non-empty path.
    #[error("spiffe id path is empty")]
    EmptyPath,
    /// Empty allow-set would authorize no peer ambiguously; reject at construction.
    #[error("mtls allow-set must not be empty")]
    EmptyAllowSet,
    /// Peer SPIFFE ID was authenticated by TLS but not authorized for this listener.
    #[error("mtls peer is not allowed")]
    PeerNotAllowed,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{MtlsAllowSet, MtlsIdentityError, SpiffeId, verify_mtls_peer};

    #[test]
    fn spiffe_id_accepts_only_canonical_with_path() {
        let id = SpiffeId::parse("spiffe://example.org/ns/rss/sa/api").expect("canonical");
        assert_eq!(id.as_str(), "spiffe://example.org/ns/rss/sa/api");
    }

    #[test]
    fn spiffe_id_rejects_noncanonical_and_unsafe_forms() {
        for raw in [
            "http://example.org/ns/rss",
            "SPIFFE://example.org/ns/rss",
            "spiffe://EXAMPLE.org/ns/rss",
            "spiffe://example.org",
            "spiffe://example.org/",
            "spiffe://example.org/ns/rss?x=1",
            "spiffe://example.org/ns/rss#frag",
            "spiffe://user@example.org/ns/rss",
            "spiffe://example.org/ns/*",
            "spiffe://example.org/ns/rss/",
            "spiffe://example.org/ns//rss",
        ] {
            assert!(SpiffeId::parse(raw).is_err(), "{raw} must be rejected");
        }
    }

    #[test]
    fn allow_set_is_exact_and_non_empty() {
        let allowed =
            MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"]).expect("allow-set");
        let exact = SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal").expect("exact");
        let prefix_child =
            SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal/child").expect("child");
        let sibling = SpiffeId::parse("spiffe://example.org/ns/rss/sa/other").expect("sibling");

        assert!(allowed.allows(&exact));
        assert!(!allowed.allows(&prefix_child));
        assert!(!allowed.allows(&sibling));
        assert!(matches!(
            MtlsAllowSet::new(Vec::<&str>::new()),
            Err(MtlsIdentityError::EmptyAllowSet)
        ));
    }

    #[test]
    fn verify_mtls_peer_mints_only_allowed_exact_peer() {
        let allowed =
            MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"]).expect("allow-set");
        let exact = SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal").expect("exact");
        let verified = verify_mtls_peer(exact, &allowed).expect("verified peer");
        assert_eq!(
            verified.spiffe_id().as_str(),
            "spiffe://example.org/ns/rss/sa/internal"
        );

        let other = SpiffeId::parse("spiffe://example.org/ns/rss/sa/other").expect("other");
        assert!(matches!(
            verify_mtls_peer(other, &allowed),
            Err(MtlsIdentityError::PeerNotAllowed)
        ));
    }
}
