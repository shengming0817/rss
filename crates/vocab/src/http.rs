//! Canonical HTTP route evidence shared by code generation and serving.
//!
//! Generated contracts mint one [`HttpRouteEvidence`] value from one manifest. Downstream code can
//! inspect that proof, but cannot split it into independently writable route-registration fields.
//!
//! INVARIANT: ROUTE-EVIDENCE-NONEMPTY-01 { level = "Hard", exec = "native-compile", source = "code", native = "const evaluation rejects empty or duplicate profiles; trybuild locks E0080" }
//! INVARIANT: LOCALTX-EVIDENCE-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "generated and consistency consume one closed vocab type identity; the macro emits variants, ALL, and exhaustive labels from one declaration" }

use crate::{ContractBinding, RoutePermissionId};
use core::marker::PhantomData;

macro_rules! closed_label_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $label:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Complete closed value set in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// Stable low-cardinality metrics/log label.
            #[must_use]
            pub const fn as_label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }
        }
    };
}

closed_label_enum! {
    /// LocalTx ownership boundary declared by a contract.
    pub enum LocalTxBoundary {
        /// One transaction may cover persistence owned by one bounded context only.
        SingleDomain => "single_domain",
    }
}

closed_label_enum! {
    /// LocalTx atomic execution model declared by a contract.
    pub enum LocalTxModel {
        /// Tenant scope is injected before opening the unit of work.
        TenantScopedUow => "tenant_scoped_uow",
        /// One repository operation atomically compares the expected version and inserts.
        RepoAtomicCas => "repo_atomic_cas",
    }
}

closed_label_enum! {
    /// LocalTx retry mode declared by a contract.
    pub enum LocalTxRetry {
        /// Only bounded retries of failures classified as transient are allowed.
        BoundedTransient => "bounded_transient",
    }
}

closed_label_enum! {
    /// LocalTx policy for an unknown commit outcome.
    pub enum LocalTxCommitUnknown {
        /// An unknown commit outcome must not replay the entire unit of work.
        NotRetryable => "not_retryable",
    }
}

mod consistency_sealed {
    pub trait HttpConsistencyClass {}
    pub trait NonLocalHttpConsistency {}
}

/// Sealed consistency class carried by generated HTTP route bindings.
pub trait HttpConsistencyClass: consistency_sealed::HttpConsistencyClass {
    /// Runtime evidence corresponding to this compile-time class.
    const LEVEL: HttpConsistencyLevel;
}

/// Sealed marker for consistency classes that may bind arbitrary Axum state.
pub trait NonLocalHttpConsistency:
    HttpConsistencyClass + consistency_sealed::NonLocalHttpConsistency
{
}

macro_rules! define_consistency_classes {
    ($($class:ident => $level:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Compile-time marker for `HttpConsistencyLevel::", stringify!($level), "`.")]
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $class;

            impl consistency_sealed::HttpConsistencyClass for $class {}
            impl HttpConsistencyClass for $class {
                const LEVEL: HttpConsistencyLevel = HttpConsistencyLevel::$level;
            }
        )+
    };
}

define_consistency_classes!(
    LocalOnly => LocalOnly,
    LocalTx => LocalTx,
    OutboxFact => OutboxFact,
    WorkflowEventual => WorkflowEventual,
    DeviceLatent => DeviceLatent,
);

macro_rules! impl_non_local_consistency {
    ($($class:ident),+ $(,)?) => {
        $(
            impl consistency_sealed::NonLocalHttpConsistency for $class {}
            impl NonLocalHttpConsistency for $class {}
        )+
    };
}

impl_non_local_consistency!(LocalTx, OutboxFact, WorkflowEventual, DeviceLatent);

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

/// Successful response status declared by an HTTP contract.
///
/// The inner value is private so generated metadata can only carry a validated 2xx status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpSuccessStatus(u16);

impl HttpSuccessStatus {
    /// Construct a status for generated static metadata.
    ///
    /// # Panics
    ///
    /// Panics in const evaluation unless `status` is in the inclusive HTTP success range.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        assert!(
            status >= 200 && status <= 299,
            "HTTP success status must be in 200..=299"
        );
        Self(status)
    }

    /// Validated numeric HTTP status.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Request replay semantics declared by an HTTP contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpIdempotency {
    /// Repeating the same request has the same intended effect.
    Idempotent,
    /// Repeating the same request may produce an additional effect.
    NonIdempotent,
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
    success_status: HttpSuccessStatus,
    idempotency: HttpIdempotency,
    auth: HttpRouteAuth,
    resource: Option<&'static str>,
    self_scoped: bool,
    consistency_level: HttpConsistencyLevel,
    effect_profile: HttpEffectProfile,
}

/// Contract-specific route binding emitted by code generation.
///
/// `M` is a unique generated marker for one HTTP contract. `C` is the sealed consistency marker
/// selected by code generation from that contract's manifest; callers cannot substitute a custom
/// consistency class. Serving code can only pair this binding with a handler carrying `M`, while
/// endpoint typestate uses `C` to expose the appropriate state-closing operation and runtime
/// middleware receives the enclosed [`HttpRouteEvidence`].
///
/// INVARIANT: LOCALTX-TEST-MARKER-TYPED-01 { level = "Hard", exec = "native-compile", source = "rustdoc", native = "an anonymous const typed as HttpRouteBinding<RouteMarker, ConsistencyMarker> rejects a mismatched generated ROUTE at compile time" }
pub struct HttpRouteBinding<M, C> {
    evidence: HttpRouteEvidence,
    marker: PhantomData<fn() -> (M, C)>,
}

impl<M, C> Copy for HttpRouteBinding<M, C> {}

impl<M, C> Clone for HttpRouteBinding<M, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M, C: HttpConsistencyClass> HttpRouteBinding<M, C> {
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
        success_status: HttpSuccessStatus,
        idempotency: HttpIdempotency,
        auth: HttpRouteAuth,
        resource: Option<&'static str>,
        self_scoped: bool,
        effect_profile: HttpEffectProfile,
    ) -> Self {
        Self {
            evidence: HttpRouteEvidence::from_static(
                contract,
                path,
                method,
                success_status,
                idempotency,
                auth,
                resource,
                self_scoped,
                C::LEVEL,
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
        success_status: HttpSuccessStatus,
        idempotency: HttpIdempotency,
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
            success_status,
            idempotency,
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

    /// Validated successful response status.
    #[must_use]
    pub const fn success_status(&self) -> HttpSuccessStatus {
        self.success_status
    }

    /// Declared request replay semantics.
    #[must_use]
    pub const fn idempotency(&self) -> HttpIdempotency {
        self.idempotency
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
        HttpSuccessStatus::new(200),
        HttpIdempotency::Idempotent,
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
        assert_eq!(EVIDENCE.success_status().get(), 200);
        assert_eq!(EVIDENCE.idempotency(), HttpIdempotency::Idempotent);
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
    fn binding_derives_runtime_consistency_from_its_marker() {
        enum Marker {}

        let binding = HttpRouteBinding::<Marker, OutboxFact>::from_static(
            CONTRACT,
            "/v1/profile",
            "GET",
            HttpSuccessStatus::new(202),
            HttpIdempotency::NonIdempotent,
            HttpRouteAuth::Public,
            None,
            false,
            PROFILE,
        );

        assert_eq!(
            binding.evidence().consistency_level(),
            HttpConsistencyLevel::OutboxFact
        );
        assert_eq!(binding.evidence().success_status().get(), 202);
        assert_eq!(
            binding.evidence().idempotency(),
            HttpIdempotency::NonIdempotent
        );
    }

    #[test]
    fn success_status_accepts_the_complete_success_range() {
        assert_eq!(HttpSuccessStatus::new(200).get(), 200);
        assert_eq!(HttpSuccessStatus::new(299).get(), 299);
    }

    #[test]
    #[should_panic(expected = "must be in 200..=299")]
    fn informational_status_is_rejected() {
        let _ = HttpSuccessStatus::new(199);
    }

    #[test]
    #[should_panic(expected = "must be in 200..=299")]
    fn redirect_status_is_rejected() {
        let _ = HttpSuccessStatus::new(300);
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
            HttpSuccessStatus::new(200),
            HttpIdempotency::Idempotent,
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
            HttpSuccessStatus::new(200),
            HttpIdempotency::Idempotent,
            HttpRouteAuth::Public,
            Some("subject"),
            false,
            HttpConsistencyLevel::LocalOnly,
            PROFILE,
        );
    }

    #[test]
    fn local_tx_evidence_labels_are_closed_stable_and_distinct() {
        fn assert_labels<T: Copy>(values: &[T], label: fn(T) -> &'static str, expected: &[&str]) {
            let labels: Vec<_> = values.iter().copied().map(label).collect();
            assert_eq!(labels, expected);
        }

        assert_labels(
            LocalTxBoundary::ALL,
            LocalTxBoundary::as_label,
            &["single_domain"],
        );
        assert_labels(
            LocalTxModel::ALL,
            LocalTxModel::as_label,
            &["tenant_scoped_uow", "repo_atomic_cas"],
        );
        assert_labels(
            LocalTxRetry::ALL,
            LocalTxRetry::as_label,
            &["bounded_transient"],
        );
        assert_labels(
            LocalTxCommitUnknown::ALL,
            LocalTxCommitUnknown::as_label,
            &["not_retryable"],
        );

        let labels = [
            LocalTxBoundary::SingleDomain.as_label(),
            LocalTxModel::TenantScopedUow.as_label(),
            LocalTxModel::RepoAtomicCas.as_label(),
            LocalTxRetry::BoundedTransient.as_label(),
            LocalTxCommitUnknown::NotRetryable.as_label(),
        ];
        for (index, label) in labels.iter().enumerate() {
            assert!(
                !labels[(index + 1)..].contains(label),
                "duplicate LocalTx evidence label: {label}"
            );
        }
    }
}
