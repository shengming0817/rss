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

    /// Canonical trust domain portion of this SPIFFE ID.
    pub fn trust_domain(&self) -> MtlsTrustDomain {
        MtlsTrustDomain::from_spiffe_id(self)
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

/// Canonical SPIFFE trust domain used by RSS mTLS policies.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MtlsTrustDomain {
    canonical: String,
}

impl MtlsTrustDomain {
    /// Parse a canonical trust domain name such as `example.org`.
    pub fn parse(raw: &str) -> Result<Self, MtlsIdentityError> {
        if raw.is_empty() {
            return Err(MtlsIdentityError::InvalidTrustDomain);
        }
        if raw.contains('/') || raw.contains("://") {
            return Err(MtlsIdentityError::InvalidTrustDomain);
        }
        let parsed =
            spiffe::TrustDomain::new(raw).map_err(|_| MtlsIdentityError::InvalidTrustDomain)?;
        if parsed.as_str() != raw {
            return Err(MtlsIdentityError::NonCanonicalTrustDomain);
        }
        Ok(Self {
            canonical: parsed.as_str().to_owned(),
        })
    }

    fn from_spiffe_id(id: &SpiffeId) -> Self {
        let raw = id
            .as_str()
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split_once('/').map(|(domain, _)| domain))
            .unwrap_or_default();
        Self {
            canonical: raw.to_owned(),
        }
    }

    /// Canonical trust domain string.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl std::fmt::Debug for MtlsTrustDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MtlsTrustDomain")
            .field(&self.canonical)
            .finish()
    }
}

impl std::fmt::Display for MtlsTrustDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical)
    }
}

impl std::str::FromStr for MtlsTrustDomain {
    type Err = MtlsIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for MtlsTrustDomain {
    type Error = MtlsIdentityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Non-empty trust domain allow-set for outbound mTLS peer verification.
#[derive(Clone, Debug)]
pub struct MtlsTrustDomainAllowSet {
    allowed: BTreeSet<MtlsTrustDomain>,
}

impl MtlsTrustDomainAllowSet {
    /// Build a non-empty trust-domain allow-set.
    pub fn new<I, S>(domains: I) -> Result<Self, MtlsIdentityError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed: BTreeSet<MtlsTrustDomain> = domains
            .into_iter()
            .map(|domain| MtlsTrustDomain::parse(domain.as_ref()))
            .collect::<Result<_, _>>()?;
        if allowed.is_empty() {
            return Err(MtlsIdentityError::EmptyTrustDomainAllowSet);
        }
        Ok(Self { allowed })
    }

    /// Return true only for exact canonical trust-domain matches.
    pub fn allows(&self, domain: &MtlsTrustDomain) -> bool {
        self.allowed.contains(domain)
    }

    /// Iterate canonical trust domains for upstream SPIFFE rustls policy conversion.
    pub fn iter(&self) -> impl Iterator<Item = &MtlsTrustDomain> {
        self.allowed.iter()
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

/// Outbound SPIFFE/mTLS policy for one remote domain transport target.
#[derive(Clone, Debug)]
pub struct OutboundMtlsPolicy {
    local_identity: SpiffeId,
    server_allow_set: MtlsAllowSet,
    trust_domains: MtlsTrustDomainAllowSet,
}

impl OutboundMtlsPolicy {
    /// Build a policy from local workload identity, exact server IDs, and trust domains.
    pub fn new(
        local_identity: SpiffeId,
        server_allow_set: MtlsAllowSet,
        trust_domains: MtlsTrustDomainAllowSet,
    ) -> Result<Self, MtlsIdentityError> {
        for server_id in server_allow_set.iter() {
            if !trust_domains.allows(&server_id.trust_domain()) {
                return Err(MtlsIdentityError::ServerTrustDomainNotAllowed);
            }
        }
        Ok(Self {
            local_identity,
            server_allow_set,
            trust_domains,
        })
    }

    /// Local workload identity expected from the SPIFFE source.
    pub fn local_identity(&self) -> &SpiffeId {
        &self.local_identity
    }

    /// Exact server SPIFFE IDs accepted for the remote target.
    pub fn server_allow_set(&self) -> &MtlsAllowSet {
        &self.server_allow_set
    }

    /// Trust domains accepted while verifying server bundles.
    pub fn trust_domains(&self) -> &MtlsTrustDomainAllowSet {
        &self.trust_domains
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
    /// Trust domain is syntactically invalid.
    #[error("mtls trust domain is invalid")]
    InvalidTrustDomain,
    /// Trust domain is valid but not canonical lowercase form.
    #[error("mtls trust domain is not canonical")]
    NonCanonicalTrustDomain,
    /// Empty trust-domain allow-set would ambiguously authorize no peer.
    #[error("mtls trust-domain allow-set must not be empty")]
    EmptyTrustDomainAllowSet,
    /// A configured server SPIFFE ID belongs to a trust domain not allowed by policy.
    #[error("mtls server trust domain is not allowed")]
    ServerTrustDomainNotAllowed,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        MtlsAllowSet, MtlsIdentityError, MtlsTrustDomain, MtlsTrustDomainAllowSet,
        OutboundMtlsPolicy, SpiffeId, verify_mtls_peer,
    };

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

    #[test]
    fn trust_domain_is_canonical_and_exact() {
        let domain = MtlsTrustDomain::parse("example.org").expect("trust domain");
        assert_eq!(domain.as_str(), "example.org");

        for raw in [
            "",
            "EXAMPLE.org",
            "spiffe://example.org/ns/rss/sa/server",
            "example.org/ns/rss",
            "example.org?x=1",
            "*",
        ] {
            assert!(
                MtlsTrustDomain::parse(raw).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn trust_domain_allow_set_is_non_empty_and_exact() {
        let allowed = MtlsTrustDomainAllowSet::new(["example.org"]).expect("trust domains");
        let exact = MtlsTrustDomain::parse("example.org").expect("exact");
        let other = MtlsTrustDomain::parse("other.example").expect("other");
        assert!(allowed.allows(&exact));
        assert!(!allowed.allows(&other));
        assert!(matches!(
            MtlsTrustDomainAllowSet::new(Vec::<&str>::new()),
            Err(MtlsIdentityError::EmptyTrustDomainAllowSet)
        ));
    }

    #[test]
    fn outbound_policy_requires_server_ids_within_allowed_trust_domains() {
        let local = SpiffeId::parse("spiffe://example.org/ns/rss/sa/runtime").expect("local");
        let servers = MtlsAllowSet::new([
            "spiffe://example.org/ns/rss/sa/identity",
            "spiffe://peer.example/ns/rss/sa/audit",
        ])
        .expect("server allow-set");
        let trust_domains =
            MtlsTrustDomainAllowSet::new(["example.org", "peer.example"]).expect("trust domains");
        let policy = OutboundMtlsPolicy::new(local.clone(), servers, trust_domains)
            .expect("outbound policy");
        assert_eq!(policy.local_identity(), &local);
        assert_eq!(
            policy
                .server_allow_set()
                .iter()
                .map(SpiffeId::as_str)
                .collect::<Vec<_>>(),
            vec![
                "spiffe://example.org/ns/rss/sa/identity",
                "spiffe://peer.example/ns/rss/sa/audit",
            ]
        );

        let rejected = OutboundMtlsPolicy::new(
            local,
            MtlsAllowSet::new(["spiffe://other.example/ns/rss/sa/identity"])
                .expect("server allow-set"),
            MtlsTrustDomainAllowSet::new(["example.org"]).expect("trust domains"),
        );
        assert!(matches!(
            rejected,
            Err(MtlsIdentityError::ServerTrustDomainNotAllowed)
        ));
    }
}
