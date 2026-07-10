//! Canonical HTTP route evidence shared by code generation and serving.
//!
//! Generated contracts mint one [`HttpRouteEvidence`] value from one manifest. Downstream code can
//! inspect that proof, but cannot split it into independently writable route-registration fields.
//!
//! INVARIANT: ROUTE-EVIDENCE-NONEMPTY-01 { level = "Hard", exec = "native-compile", source = "code", native = "const evaluation rejects empty or duplicate profiles; trybuild locks E0080" }

use crate::{ContractBinding, RoutePermissionId};
use core::marker::PhantomData;

/// Runtime consistency semantics declared by an HTTP contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpConsistencyLevel {
    /// Read-only or otherwise local work without a transaction boundary.
    LocalOnly,
    /// One tenant-scoped local transaction.
    LocalTx,
    /// Local commit followed by a durable outbox fact.
    OutboxFact,
    /// Durable workflow with eventual completion.
    WorkflowEventual,
    /// Device-side work whose observation is intentionally latent.
    DeviceLatent,
}

/// Closed vocabulary of effects performed by an HTTP contract.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpEffectKind {
    /// Read state.
    Read,
    /// Authenticate or authorize a request.
    Auth,
    /// Project fields according to authorization obligations.
    Projection,
    /// Write state.
    Write,
    /// Open a local transaction boundary.
    Transaction,
    /// Append a durable outbox fact.
    Outbox,
    /// Publish a message.
    Publish,
    /// Start or advance a workflow.
    Workflow,
    /// Start or advance a saga.
    Saga,
    /// Reconcile state.
    Reconcile,
    /// Enqueue or execute worker work.
    Worker,
    /// Record a cross-tenant audit fact.
    CrossTenantAudit,
}

/// A validated, non-empty set of distinct HTTP effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpEffectProfile {
    effects: &'static [HttpEffectKind],
}

impl HttpEffectProfile {
    /// Construct a profile for generated static metadata.
    ///
    /// # Panics
    ///
    /// Panics in const evaluation when `effects` is empty or contains a duplicate. This makes an
    /// invalid generated profile a compilation failure rather than a runtime registration error.
    #[must_use]
    pub const fn new(effects: &'static [HttpEffectKind]) -> Self {
        assert!(!effects.is_empty(), "HTTP effect profile must not be empty");

        let mut current = 0;
        while current < effects.len() {
            let mut candidate = current + 1;
            while candidate < effects.len() {
                assert!(
                    effects[current] as u8 != effects[candidate] as u8,
                    "HTTP effect profile must not contain duplicates"
                );
                candidate += 1;
            }
            current += 1;
        }

        Self { effects }
    }

    /// Borrow the ordered effect set emitted by code generation.
    #[must_use]
    pub const fn effects(&self) -> &'static [HttpEffectKind] {
        self.effects
    }
}

/// Authentication mode and, where required, its closed permission identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRouteAuth {
    /// A normal protected route requiring the given permission.
    Permission(RoutePermissionId),
    /// A deliberately unauthenticated route.
    Public,
    /// A bootstrap-only route.
    Bootstrap,
    /// A route accepting client identities only.
    ClientsOnly,
    /// A route accepting a service-owned identity only.
    ServiceOwned,
}

/// Atomic proof used to register one generated HTTP route.
///
/// All fields are private. Code generation constructs the complete value in one expression;
/// serving code receives that value together with the handler and can only read its accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRouteEvidence {
    contract: ContractBinding,
    path: &'static str,
    method: &'static str,
    auth: HttpRouteAuth,
    resource: Option<&'static str>,
    self_scoped: bool,
    consistency_level: HttpConsistencyLevel,
    effect_profile: HttpEffectProfile,
}

/// Contract-specific route binding emitted by code generation.
///
/// `M` is a unique generated marker for one HTTP contract. Serving code can only pair this
/// binding with a handler carrying the same marker, while runtime middleware receives the
/// enclosed [`HttpRouteEvidence`].
pub struct HttpRouteBinding<M> {
    evidence: HttpRouteEvidence,
    marker: PhantomData<fn() -> M>,
}

impl<M> Copy for HttpRouteBinding<M> {}

impl<M> Clone for HttpRouteBinding<M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M> HttpRouteBinding<M> {
    /// Construct a generated, contract-specific route binding from static manifest values.
    ///
    /// # Panics
    ///
    /// Applies the same validation as [`HttpRouteEvidence::from_static`].
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn from_static(
        contract: ContractBinding,
        path: &'static str,
        method: &'static str,
        auth: HttpRouteAuth,
        resource: Option<&'static str>,
        self_scoped: bool,
        consistency_level: HttpConsistencyLevel,
        effect_profile: HttpEffectProfile,
    ) -> Self {
        Self {
            evidence: HttpRouteEvidence::from_static(
                contract,
                path,
                method,
                auth,
                resource,
                self_scoped,
                consistency_level,
                effect_profile,
            ),
            marker: PhantomData,
        }
    }

    /// Erase the compile-time contract marker at the runtime middleware boundary.
    #[must_use]
    pub const fn evidence(&self) -> HttpRouteEvidence {
        self.evidence
    }
}

impl HttpRouteEvidence {
    /// Construct generated route evidence from static manifest values.
    ///
    /// # Panics
    ///
    /// Panics in const evaluation if the path is not absolute, the method is empty, resource and
    /// self scope are both present, or a non-permission route carries resource scope.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn from_static(
        contract: ContractBinding,
        path: &'static str,
        method: &'static str,
        auth: HttpRouteAuth,
        resource: Option<&'static str>,
        self_scoped: bool,
        consistency_level: HttpConsistencyLevel,
        effect_profile: HttpEffectProfile,
    ) -> Self {
        assert!(
            !path.is_empty() && path.as_bytes()[0] == b'/',
            "HTTP route path must be absolute"
        );
        assert!(!method.is_empty(), "HTTP route method must not be empty");
        assert!(
            !(resource.is_some() && self_scoped),
            "HTTP resource and self scope are mutually exclusive"
        );
        assert!(
            matches!(auth, HttpRouteAuth::Permission(_)) || (resource.is_none() && !self_scoped),
            "non-permission HTTP routes cannot carry resource scope"
        );

        Self {
            contract,
            path,
            method,
            auth,
            resource,
            self_scoped,
            consistency_level,
            effect_profile,
        }
    }

    /// Contract ownership and schema binding.
    #[must_use]
    pub const fn contract(&self) -> ContractBinding {
        self.contract
    }

    /// Stable contract identifier.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.contract.contract_id()
    }

    /// Absolute business HTTP path.
    #[must_use]
    pub const fn path(&self) -> &'static str {
        self.path
    }

    /// Canonical HTTP method token emitted by code generation.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }

    /// Closed authentication mode and permission.
    #[must_use]
    pub const fn auth(&self) -> HttpRouteAuth {
        self.auth
    }

    /// Named resource path parameter, when authorization is resource-scoped.
    #[must_use]
    pub const fn resource(&self) -> Option<&'static str> {
        self.resource
    }

    /// Whether authorization is scoped to the authenticated subject.
    #[must_use]
    pub const fn self_scoped(&self) -> bool {
        self.self_scoped
    }

    /// Declared consistency semantics.
    #[must_use]
    pub const fn consistency_level(&self) -> HttpConsistencyLevel {
        self.consistency_level
    }

    /// Validated, non-empty effect profile.
    #[must_use]
    pub const fn effect_profile(&self) -> HttpEffectProfile {
        self.effect_profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: ContractBinding = ContractBinding::from_static(
        "identity",
        "identity.profile",
        "v1",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    const EFFECTS: &[HttpEffectKind] = &[HttpEffectKind::Auth, HttpEffectKind::Read];
    const PROFILE: HttpEffectProfile = HttpEffectProfile::new(EFFECTS);
    const EVIDENCE: HttpRouteEvidence = HttpRouteEvidence::from_static(
        CONTRACT,
        "/v1/profile",
        "GET",
        HttpRouteAuth::Permission(RoutePermissionId::IdentityProfileRead),
        None,
        true,
        HttpConsistencyLevel::LocalOnly,
        PROFILE,
    );

    #[test]
    fn evidence_exposes_the_atomic_generated_values() {
        assert_eq!(EVIDENCE.contract(), CONTRACT);
        assert_eq!(EVIDENCE.contract_id(), "identity.profile");
        assert_eq!(EVIDENCE.path(), "/v1/profile");
        assert_eq!(EVIDENCE.method(), "GET");
        assert_eq!(
            EVIDENCE.auth(),
            HttpRouteAuth::Permission(RoutePermissionId::IdentityProfileRead)
        );
        assert_eq!(EVIDENCE.resource(), None);
        assert!(EVIDENCE.self_scoped());
        assert_eq!(
            EVIDENCE.consistency_level(),
            HttpConsistencyLevel::LocalOnly
        );
        assert_eq!(EVIDENCE.effect_profile().effects(), EFFECTS);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn empty_effect_profile_is_rejected() {
        let _ = HttpEffectProfile::new(&[]);
    }

    #[test]
    #[should_panic(expected = "must not contain duplicates")]
    fn duplicate_effect_is_rejected() {
        let _ = HttpEffectProfile::new(&[HttpEffectKind::Read, HttpEffectKind::Read]);
    }

    #[test]
    #[should_panic(expected = "must be absolute")]
    fn relative_path_is_rejected() {
        let _ = HttpRouteEvidence::from_static(
            CONTRACT,
            "v1/profile",
            "GET",
            HttpRouteAuth::Public,
            None,
            false,
            HttpConsistencyLevel::LocalOnly,
            PROFILE,
        );
    }

    #[test]
    #[should_panic(expected = "cannot carry resource scope")]
    fn public_resource_scope_is_rejected() {
        let _ = HttpRouteEvidence::from_static(
            CONTRACT,
            "/v1/profile",
            "GET",
            HttpRouteAuth::Public,
            Some("subject"),
            false,
            HttpConsistencyLevel::LocalOnly,
            PROFILE,
        );
    }
}
