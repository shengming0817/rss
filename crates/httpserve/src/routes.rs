//! routes — typed route lifecycle: listener-typed registration (#1103) + auth-finalize-before-bind funnel (#1113).
//!
//! 两条正交的类型层不变式收口在本模块（对标 axum `Router<S>` 用状态类型表达「缺状态不可 serve」的阶段约束）：
//! ref: tokio-rs/axum axum/src/routing/method_routing.rs@8762520da82cd99b78b35869069b36cfa305d4b9
//! ref: oxidecomputer/dropshot dropshot/src/api_description.rs@d802068f6dee979746d4000ec735e915df038259
//!
//! - **#1103 listener segregation（Medium→Hard）**：路由经 listener-typed [`ListenerRouter<L>`] 挂载，
//!   register 闭包绑定到具体 [`Listener`] marker；`mount` 按 listener 只接受
//!   [`GeneratedEndpoint`] 或 [`GeneratedPrimaryEndpoint`]，Health 只走固定 builder ⇒ 跨 listener 泄漏
//!   不可表达（typed function choice，Hard）。
//! - **#1113 auth-finalize-before-bind funnel（Hard）**：finalizer 函数是 [`AuthenticatedRoutes`] 的
//!   **唯一**生产者（构造 `pub(crate)`），[`AuthenticatedRoutes::into_server_service`] 是**唯一**
//!   transport core 出口；[`UnfinalizedRoutes`] 无 public service 出口 ⇒ 未跑 auth 装配的 router 无法进入
//!   transport adapter。
//!
//! 与兄弟 crate `bootstrap` 的协同：`bootstrap::Registry::finalize_routes` 经受控 `bootstrap → httpserve`
//! 编译期路由类型边（ADR-009）构造 [`UnfinalizedRoutes`]，再由组合根按 listener 选择
//! [`finalize_auth`] 或 [`finalize_primary_auth`] 产 [`AuthenticatedRoutes`]。

use crate::auth::{AuditSinkHandle, AuthAudit, RouteAuthorizer, enforce_layer};
use crate::{
    PrimaryRouteAuthz, RouteGroupError, RoutePermission, RouteResourceScope, RouteTenantBinding,
    ServiceCallerPolicy,
};
use axum::extract::FromRequestParts;
use axum::handler::Handler;
use core::any::TypeId;
use core::marker::PhantomData;
use diport::{AuthEffect, LocalPrivilege, PortEffectClass, PortPrivilegeClass, ReadEffect};
use primitives::{AuthPlan, ListenerKind};
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use vocab::http::{
    DeclaredHttpResponseMarker, HttpConsistencyClass, HttpProducerBinding, LocalOnly,
    NonLocalHttpConsistency, NonProducerHttpConsistency, OutboxFact,
};
use vocab::{ContractBinding, HttpRouteAuth, HttpRouteBinding, HttpRouteEvidence};

mod local_only_state_sealed {
    pub trait LocalOnlyAllowedEffect {}
}

/// Sealed effect set accepted by a `LocalOnly` route state.
pub trait LocalOnlyAllowedEffect:
    PortEffectClass + local_only_state_sealed::LocalOnlyAllowedEffect
{
}

impl local_only_state_sealed::LocalOnlyAllowedEffect for ReadEffect {}
impl LocalOnlyAllowedEffect for ReadEffect {}
impl local_only_state_sealed::LocalOnlyAllowedEffect for AuthEffect {}
impl LocalOnlyAllowedEffect for AuthEffect {}

/// Static effect and privilege proof attached to state injected into a `LocalOnly` route.
///
/// Domain state types implement this trait explicitly. The consistency gate verifies that this
/// declaration matches the strongest owner-sealed port held by the state.
pub trait ClassifiedRouteState {
    /// Strongest effect reachable through the state.
    type Effect: PortEffectClass;
    /// Strongest privilege reachable through the state.
    type Privilege: PortPrivilegeClass;
}

/// Opaque test-only proof that one generated `LocalOnly` route is mounted in a concrete
/// [`UnfinalizedRoutes`] value and uses classified state `S`.
///
/// The proof itself retains the route marker and state type. Cross-crate source analysis is still
/// responsible for proving that a receipt site consumes the proof returned beside the finalized
/// router; this type does not claim that source-level relationship as a native Hard guarantee.
#[cfg(any(test, feature = "test-util"))]
pub struct LocalOnlyMountedRouteProof<M, S>(PhantomData<fn() -> (M, S)>);

/// Opaque test-only proof that one generated stateless `LocalOnly` route is mounted.
#[cfg(any(test, feature = "test-util"))]
pub struct StatelessLocalOnlyMountedRouteProof<M>(PhantomData<fn() -> M>);

/// Failure to find the generated route binding in the exact pre-finalization route accumulator.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("generated LocalOnly route is not mounted in the supplied unfinalized routes")]
pub struct LocalOnlyRouteNotMounted;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MountedRouteState {
    Stateless,
    Stateful(TypeId),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GeneratedRouteIdentity {
    marker: TypeId,
    state: MountedRouteState,
}

impl GeneratedRouteIdentity {
    fn stateless<M: 'static>() -> Self {
        Self {
            marker: TypeId::of::<M>(),
            state: MountedRouteState::Stateless,
        }
    }

    fn with_state<S: 'static>(self) -> Self {
        Self {
            marker: self.marker,
            state: MountedRouteState::Stateful(TypeId::of::<S>()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MountedRouteIdentity {
    #[cfg(any(test, feature = "test-util"))]
    Raw,
    Generated(GeneratedRouteIdentity),
}

#[derive(Default)]
struct MountedRoutes {
    evidence: Vec<HttpRouteEvidence>,
    identity: Vec<MountedRouteIdentity>,
}

impl MountedRoutes {
    #[cfg(any(test, feature = "test-util"))]
    fn push_raw(&mut self, evidence: HttpRouteEvidence) {
        self.evidence.push(evidence);
        self.identity.push(MountedRouteIdentity::Raw);
    }

    fn push_generated(&mut self, evidence: HttpRouteEvidence, identity: GeneratedRouteIdentity) {
        self.evidence.push(evidence);
        self.identity
            .push(MountedRouteIdentity::Generated(identity));
    }

    fn append(&mut self, mut other: Self) {
        self.evidence.append(&mut other.evidence);
        self.identity.append(&mut other.identity);
    }

    fn evidence(&self) -> &[HttpRouteEvidence] {
        &self.evidence
    }

    #[cfg(any(test, feature = "test-util"))]
    fn contains_generated(
        &self,
        evidence: HttpRouteEvidence,
        identity: GeneratedRouteIdentity,
    ) -> bool {
        self.evidence
            .iter()
            .zip(&self.identity)
            .any(|(mounted_evidence, mounted_identity)| {
                mounted_evidence == &evidence
                    && mounted_identity == &MountedRouteIdentity::Generated(identity)
            })
    }
}

#[cfg(any(test, feature = "test-util"))]
fn route_is_mounted<M>(
    routes: &UnfinalizedRoutes,
    binding: &HttpRouteBinding<M, LocalOnly>,
    identity: GeneratedRouteIdentity,
) -> bool {
    routes
        .mounted
        .contains_generated(binding.evidence(), identity)
}

/// Proves that classified state and one generated `LocalOnly` route are mounted together.
///
/// The constructor checks the exact evidence stored in `routes` before auth finalization and
/// applies the same state bounds as [`GeneratedEndpoint::with_classified_state`] and
/// [`GeneratedPrimaryEndpoint::with_classified_state`].
#[cfg(any(test, feature = "test-util"))]
pub fn prove_local_only_mounted_route_state<S, M>(
    routes: &UnfinalizedRoutes,
    binding: &HttpRouteBinding<M, LocalOnly>,
) -> Result<LocalOnlyMountedRouteProof<M, S>, LocalOnlyRouteNotMounted>
where
    M: 'static,
    S: Clone + Send + Sync + 'static + ClassifiedRouteState<Privilege = LocalPrivilege>,
    S::Effect: LocalOnlyAllowedEffect,
{
    if route_is_mounted(
        routes,
        binding,
        GeneratedRouteIdentity::stateless::<M>().with_state::<S>(),
    ) {
        Ok(LocalOnlyMountedRouteProof(PhantomData))
    } else {
        Err(LocalOnlyRouteNotMounted)
    }
}

/// Proves that one generated stateless `LocalOnly` route is mounted before auth finalization.
#[cfg(any(test, feature = "test-util"))]
pub fn prove_stateless_local_only_mounted_route<M>(
    routes: &UnfinalizedRoutes,
    binding: &HttpRouteBinding<M, LocalOnly>,
) -> Result<StatelessLocalOnlyMountedRouteProof<M>, LocalOnlyRouteNotMounted>
where
    M: 'static,
{
    if route_is_mounted(routes, binding, GeneratedRouteIdentity::stateless::<M>()) {
        Ok(StatelessLocalOnlyMountedRouteProof(PhantomData))
    } else {
        Err(LocalOnlyRouteNotMounted)
    }
}

/// Zero-cost extractor carrying one generated HTTP contract identity into a handler signature.
///
/// A handler can only bind to [`HttpRouteBinding<M, C>`] when its first extractor is
/// `ContractMarker<M>`. Extraction is infallible and stores no request data.
pub struct ContractMarker<M>(PhantomData<fn() -> M>);

impl<M, S> FromRequestParts<S> for ContractMarker<M>
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(PhantomData))
    }
}

#[cfg(any(test, feature = "test-util"))]
impl<M> ContractMarker<M> {
    /// Construct a marker for direct handler unit tests.
    #[must_use]
    pub const fn for_test() -> Self {
        Self(PhantomData)
    }
}

struct ProducerRouteWitness<M>(HttpProducerBinding<M>);

impl<M> Copy for ProducerRouteWitness<M> {}

impl<M> Clone for ProducerRouteWitness<M> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Move-only extractor authorizing the generated HTTP producer route that mounted this request.
///
/// [`GeneratedPrimaryEndpoint::new_producer`] installs a private, route-bound witness in the
/// method router. Extraction fails closed when that witness is absent. The marker retains the
/// mounted producer binding, so production handlers cannot substitute another same-marker binding
/// while minting the receipt required by the service/UoW producer funnel.
pub struct ProducerMarker<M> {
    producer: HttpProducerBinding<M>,
}

impl<M, S> FromRequestParts<S> for ProducerMarker<M>
where
    M: 'static,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Some(witness) = parts.extensions.remove::<ProducerRouteWitness<M>>() else {
            tracing::error!(
                route_marker = core::any::type_name::<M>(),
                "producer route witness missing"
            );
            let request_id = crate::request_id_str(&parts.extensions).unwrap_or_default();
            return Err(crate::error::internal_error(request_id));
        };
        Ok(Self {
            producer: witness.0,
        })
    }
}

impl<M> ProducerMarker<M> {
    /// Consume the request marker into a receipt for the producer binding installed by the route.
    #[must_use]
    pub fn into_receipt(self) -> ProducerAssuranceReceipt<M> {
        ProducerAssuranceReceipt {
            producer: self.producer,
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl<M> ProducerMarker<M> {
    /// Construct a producer marker for direct handler/service tests.
    ///
    /// This explicit residual test surface is absent from the default production feature graph.
    /// Tests must still name the binding whose mounted-route witness they intend to model.
    #[must_use]
    pub const fn for_test(producer: HttpProducerBinding<M>) -> Self {
        Self { producer }
    }
}

/// Install the same route-bound producer witness used by
/// [`GeneratedPrimaryEndpoint::new_producer`] on a raw test method router.
///
/// This residual surface is available only with `test-util`. Callers must still name the exact
/// generated producer binding, so handler tests exercise the fail-closed extractor instead of
/// bypassing it with a directly constructed marker.
#[cfg(any(test, feature = "test-util"))]
pub fn with_producer_witness_for_test<M, S>(
    router: axum::routing::MethodRouter<S>,
    producer: HttpProducerBinding<M>,
) -> axum::routing::MethodRouter<S>
where
    M: Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::Extension(ProducerRouteWitness(producer)))
}

/// Move-only receipt proving a request passed through the matching generated producer route.
///
/// Its fields and constructor are private. Transaction orchestration consumes it while selecting
/// one emitted generated fact, yielding a copyable [`ProducerAuthorization`] for bounded retries.
pub struct ProducerAssuranceReceipt<M> {
    producer: HttpProducerBinding<M>,
}

impl<M> ProducerAssuranceReceipt<M> {
    /// Consume the one-shot request receipt and authorize one typed generated fact from its exact
    /// emitted set.
    ///
    /// The fact must come from the caller's typed event-entry boundary; the separately named
    /// contract keeps static producer assurance bound to the manifest alias.
    #[must_use]
    pub fn authorize(
        self,
        fact: vocab::EventFactBinding,
        expected_contract: ContractBinding,
    ) -> Option<ProducerAuthorization<M>> {
        (fact.contract() == expected_contract
            && self.producer.emitted_facts().contains(&expected_contract))
        .then_some(ProducerAuthorization {
            producer_contract: self.producer.route_evidence().contract(),
            fact,
            marker: PhantomData,
        })
    }
}

/// Copyable authorization for the exact generated facts permitted by one producer route.
///
/// This token has no public constructor. It may only be derived by consuming a
/// [`ProducerAssuranceReceipt`] minted from the matching request marker and generated binding.
pub struct ProducerAuthorization<M> {
    producer_contract: ContractBinding,
    fact: vocab::EventFactBinding,
    marker: PhantomData<fn() -> M>,
}

impl<M> Copy for ProducerAuthorization<M> {}

impl<M> Clone for ProducerAuthorization<M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M> ProducerAuthorization<M> {
    /// Producer HTTP contract carried by this authorization.
    #[must_use]
    pub const fn producer_contract(&self) -> ContractBinding {
        self.producer_contract
    }

    /// The exact generated fact selected from this producer's emitted-fact set.
    #[must_use]
    pub const fn fact_contract(&self) -> ContractBinding {
        self.fact.contract()
    }

    /// Complete generated fact identity selected by the payload type.
    #[must_use]
    pub const fn fact(&self) -> vocab::EventFactBinding {
        self.fact
    }
}

/// Sealed proof that an Axum handler argument tuple starts with the matching contract marker.
#[doc(hidden)]
pub trait ContractHandlerArgs<M>: sealed::ContractHandlerArgs<M> {}

/// Sealed proof that a declared-response handler preserves its generated output until mount.
#[doc(hidden)]
pub trait DeclaredContractHandler<M, T, S>:
    Handler<T, S> + sealed::DeclaredContractHandler<M, T, S>
where
    M: DeclaredHttpResponseMarker,
{
}

/// Sealed proof that a declared-response producer handler preserves its generated output.
#[doc(hidden)]
pub trait DeclaredProducerContractHandler<M, T, S>:
    Handler<T, S> + sealed::DeclaredProducerContractHandler<M, T, S>
where
    M: DeclaredHttpResponseMarker,
{
}

macro_rules! impl_declared_contract_handler {
    ($($ty:ident),*) => {
        impl<F, Fut, Mode, M, S, $($ty),*> sealed::DeclaredContractHandler<
            M,
            (Mode, ContractMarker<M>, $($ty,)*),
            S,
        > for F
        where
            M: DeclaredHttpResponseMarker,
            F: Handler<(Mode, ContractMarker<M>, $($ty,)*), S>
                + FnOnce(ContractMarker<M>, $($ty),*) -> Fut,
            Fut: Future<Output = M::HandlerOutput> + Send + 'static,
        {
        }

        impl<F, Fut, Mode, M, S, $($ty),*> DeclaredContractHandler<
            M,
            (Mode, ContractMarker<M>, $($ty,)*),
            S,
        > for F
        where
            M: DeclaredHttpResponseMarker,
            F: Handler<(Mode, ContractMarker<M>, $($ty,)*), S>
                + FnOnce(ContractMarker<M>, $($ty),*) -> Fut,
            Fut: Future<Output = M::HandlerOutput> + Send + 'static,
        {
        }
    };
}

impl_declared_contract_handler!();
impl_declared_contract_handler!(T1);
impl_declared_contract_handler!(T1, T2);
impl_declared_contract_handler!(T1, T2, T3);
impl_declared_contract_handler!(T1, T2, T3, T4);
impl_declared_contract_handler!(T1, T2, T3, T4, T5);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_declared_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
impl_declared_contract_handler!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15
);

macro_rules! impl_declared_producer_contract_handler {
    ($($ty:ident),*) => {
        impl<F, Fut, Mode, M, S, $($ty),*> sealed::DeclaredProducerContractHandler<
            M,
            (Mode, ProducerMarker<M>, $($ty,)*),
            S,
        > for F
        where
            M: DeclaredHttpResponseMarker,
            F: Handler<(Mode, ProducerMarker<M>, $($ty,)*), S>
                + FnOnce(ProducerMarker<M>, $($ty),*) -> Fut,
            Fut: Future<Output = M::HandlerOutput> + Send + 'static,
        {
        }

        impl<F, Fut, Mode, M, S, $($ty),*> DeclaredProducerContractHandler<
            M,
            (Mode, ProducerMarker<M>, $($ty,)*),
            S,
        > for F
        where
            M: DeclaredHttpResponseMarker,
            F: Handler<(Mode, ProducerMarker<M>, $($ty,)*), S>
                + FnOnce(ProducerMarker<M>, $($ty),*) -> Fut,
            Fut: Future<Output = M::HandlerOutput> + Send + 'static,
        {
        }
    };
}

impl_declared_producer_contract_handler!();
impl_declared_producer_contract_handler!(T1);
impl_declared_producer_contract_handler!(T1, T2);
impl_declared_producer_contract_handler!(T1, T2, T3);
impl_declared_producer_contract_handler!(T1, T2, T3, T4);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_declared_producer_contract_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_declared_producer_contract_handler!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14
);
impl_declared_producer_contract_handler!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15
);

macro_rules! impl_contract_handler_args {
    ($($ty:ident),*) => {
        impl<Mode, M, $($ty),*> sealed::ContractHandlerArgs<M>
            for (Mode, ContractMarker<M>, $($ty,)*)
        {
        }

        impl<Mode, M, $($ty),*> ContractHandlerArgs<M>
            for (Mode, ContractMarker<M>, $($ty,)*)
        {
        }
    };
}

impl_contract_handler_args!();
impl_contract_handler_args!(T1);
impl_contract_handler_args!(T1, T2);
impl_contract_handler_args!(T1, T2, T3);
impl_contract_handler_args!(T1, T2, T3, T4);
impl_contract_handler_args!(T1, T2, T3, T4, T5);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_contract_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
impl_contract_handler_args!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15
);

/// Sealed proof that an Axum handler argument tuple starts with the matching producer marker.
#[doc(hidden)]
pub trait ProducerHandlerArgs<M>: sealed::ProducerHandlerArgs<M> {}

macro_rules! impl_producer_handler_args {
    ($($ty:ident),*) => {
        impl<Mode, M, $($ty),*> sealed::ProducerHandlerArgs<M>
            for (Mode, ProducerMarker<M>, $($ty,)*)
        {
        }

        impl<Mode, M, $($ty),*> ProducerHandlerArgs<M>
            for (Mode, ProducerMarker<M>, $($ty,)*)
        {
        }
    };
}

impl_producer_handler_args!();
impl_producer_handler_args!(T1);
impl_producer_handler_args!(T1, T2);
impl_producer_handler_args!(T1, T2, T3);
impl_producer_handler_args!(T1, T2, T3, T4);
impl_producer_handler_args!(T1, T2, T3, T4, T5);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_producer_handler_args!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
impl_producer_handler_args!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15
);

struct Endpoint<S> {
    evidence: HttpRouteEvidence,
    identity: GeneratedRouteIdentity,
    method: axum::http::Method,
    handler: axum::routing::MethodRouter<S>,
}

/// INVARIANT: ROUTE-ENDPOINT-REQUIRED-01 { level = "Hard", exec = "native-compile", source = "code", native = "ordinary public endpoint constructors require a non-optional HttpRouteBinding<M, C> plus a handler whose argument tuple starts with ContractMarker<M>; trybuild omits each and rejects cross-contract markers" }
/// INVARIANT: ROUTE-ENDPOINT-ATOMIC-01 { level = "Hard", exec = "native-compile", source = "code", native = "private Endpoint owns evidence, typed route/state identity, parsed method, and MethodRouter as one move-only mount value" }
impl<S> Endpoint<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn new<M, H, T>(evidence: HttpRouteEvidence, handler: H) -> Result<Self, RouteGroupError>
    where
        M: 'static,
        H: Handler<T, S>,
        T: 'static,
    {
        let method = axum::http::Method::from_bytes(evidence.method().as_bytes())
            .map_err(|_| invalid_method(evidence))?;
        let filter = axum::routing::MethodFilter::try_from(method.clone())
            .map_err(|_| invalid_method(evidence))?;
        Ok(Self {
            evidence,
            identity: GeneratedRouteIdentity::stateless::<M>(),
            method,
            handler: axum::routing::on(filter, handler),
        })
    }

    fn with_state(self, state: S) -> Endpoint<()> {
        Endpoint {
            evidence: self.evidence,
            identity: self.identity.with_state::<S>(),
            method: self.method,
            handler: self.handler.with_state(state),
        }
    }
}

/// A generated endpoint for a non-Primary listener.
///
/// Construction atomically binds one generated [`HttpRouteBinding`] to a handler carrying the same
/// contract marker. The method router is private and derives its filter from the enclosed evidence;
/// stateful handlers must use the consistency-specific state binding method before mounting.
pub struct GeneratedEndpoint<S, C>(Endpoint<S>, PhantomData<fn() -> C>);

impl<S, C> GeneratedEndpoint<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: NonProducerHttpConsistency,
{
    /// Bind a contract-specific generated route to its matching handler and derive the method filter.
    pub fn new<M, H, T>(
        binding: HttpRouteBinding<M, C>,
        handler: H,
    ) -> Result<Self, RouteGroupError>
    where
        M: vocab::http::OpenHttpResponseMarker + 'static,
        H: Handler<T, S>,
        T: ContractHandlerArgs<M> + 'static,
    {
        Endpoint::new::<M, _, _>(binding.evidence(), handler)
            .map(|endpoint| Self(endpoint, PhantomData))
    }

    /// Bind a route with declared business responses to its exact generated handler output.
    pub fn new_declared<M, H, T>(
        binding: HttpRouteBinding<M, C>,
        handler: H,
    ) -> Result<Self, RouteGroupError>
    where
        M: DeclaredHttpResponseMarker + 'static,
        H: DeclaredContractHandler<M, T, S>,
        T: ContractHandlerArgs<M> + 'static,
    {
        Endpoint::new::<M, _, _>(binding.evidence(), handler)
            .map(|endpoint| Self(endpoint, PhantomData))
    }

    /// Borrow the atomic route proof.
    #[must_use]
    pub const fn evidence(&self) -> &HttpRouteEvidence {
        &self.0.evidence
    }
}

impl<S, C> GeneratedEndpoint<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: NonLocalHttpConsistency,
{
    /// Supply state to a transactional or asynchronous route.
    #[must_use]
    pub fn with_state(self, state: S) -> GeneratedEndpoint<(), C> {
        GeneratedEndpoint(self.0.with_state(state), PhantomData)
    }
}

impl<S> GeneratedEndpoint<S, LocalOnly>
where
    S: Clone + Send + Sync + 'static + ClassifiedRouteState<Privilege = LocalPrivilege>,
    S::Effect: LocalOnlyAllowedEffect,
{
    /// Supply explicitly classified local read/auth state to a `LocalOnly` route.
    #[must_use]
    pub fn with_classified_state(self, state: S) -> GeneratedEndpoint<(), LocalOnly> {
        GeneratedEndpoint(self.0.with_state(state), PhantomData)
    }
}

/// A generated endpoint for the Primary listener.
///
/// In addition to method and path, Primary authorization and resource scope are derived directly
/// from the same evidence when the endpoint is mounted.
pub struct GeneratedPrimaryEndpoint<S, C>(Endpoint<S>, PhantomData<fn() -> C>);

impl<S, C> GeneratedPrimaryEndpoint<S, C> {
    /// Borrow the atomic route proof for either an ordinary or producer endpoint.
    #[must_use]
    pub const fn evidence(&self) -> &HttpRouteEvidence {
        &self.0.evidence
    }
}

impl<S, C> GeneratedPrimaryEndpoint<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: NonProducerHttpConsistency,
{
    /// Bind a contract-specific generated route to its matching handler and derive the method filter.
    pub fn new<M, H, T>(
        binding: HttpRouteBinding<M, C>,
        handler: H,
    ) -> Result<Self, RouteGroupError>
    where
        M: vocab::http::OpenHttpResponseMarker + 'static,
        H: Handler<T, S>,
        T: ContractHandlerArgs<M> + 'static,
    {
        Endpoint::new::<M, _, _>(binding.evidence(), handler)
            .map(|endpoint| Self(endpoint, PhantomData))
    }

    /// Bind a Primary route with declared responses to its exact generated handler output.
    pub fn new_declared<M, H, T>(
        binding: HttpRouteBinding<M, C>,
        handler: H,
    ) -> Result<Self, RouteGroupError>
    where
        M: DeclaredHttpResponseMarker + 'static,
        H: DeclaredContractHandler<M, T, S>,
        T: ContractHandlerArgs<M> + 'static,
    {
        Endpoint::new::<M, _, _>(binding.evidence(), handler)
            .map(|endpoint| Self(endpoint, PhantomData))
    }
}

/// INVARIANT: HTTP-PRODUCER-MOUNT-01 { level = "Hard", exec = "native-compile", source = "code", native = "OutboxFact is excluded from ordinary endpoint constructors; new_producer requires HttpProducerBinding<M>, installs a private route-bound witness, and accepts only a handler beginning with ProducerMarker<M>; extraction without that witness fails closed and production receipt minting cannot substitute a caller-selected binding" }
impl<S> GeneratedPrimaryEndpoint<S, OutboxFact>
where
    S: Clone + Send + Sync + 'static,
{
    /// Bind one generated producer route to a handler carrying its matching move-only marker.
    pub fn new_producer<M, H, T>(
        producer: HttpProducerBinding<M>,
        handler: H,
    ) -> Result<Self, RouteGroupError>
    where
        M: vocab::http::OpenHttpResponseMarker + 'static,
        H: Handler<T, S>,
        T: ProducerHandlerArgs<M> + 'static,
    {
        Endpoint::new::<M, _, _>(producer.route_evidence(), handler).map(|mut endpoint| {
            endpoint.handler = endpoint
                .handler
                .layer(axum::Extension(ProducerRouteWitness(producer)));
            Self(endpoint, PhantomData)
        })
    }

    /// Bind a producer route with declared responses to its exact generated handler output.
    pub fn new_declared_producer<M, H, T>(
        producer: HttpProducerBinding<M>,
        handler: H,
    ) -> Result<Self, RouteGroupError>
    where
        M: DeclaredHttpResponseMarker + 'static,
        H: DeclaredProducerContractHandler<M, T, S>,
        T: ProducerHandlerArgs<M> + 'static,
    {
        Endpoint::new::<M, _, _>(producer.route_evidence(), handler).map(|mut endpoint| {
            endpoint.handler = endpoint
                .handler
                .layer(axum::Extension(ProducerRouteWitness(producer)));
            Self(endpoint, PhantomData)
        })
    }
}

impl<S, C> GeneratedPrimaryEndpoint<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: NonLocalHttpConsistency,
{
    /// Supply state to a transactional or asynchronous Primary route.
    #[must_use]
    pub fn with_state(self, state: S) -> GeneratedPrimaryEndpoint<(), C> {
        GeneratedPrimaryEndpoint(self.0.with_state(state), PhantomData)
    }
}

impl<S> GeneratedPrimaryEndpoint<S, LocalOnly>
where
    S: Clone + Send + Sync + 'static + ClassifiedRouteState<Privilege = LocalPrivilege>,
    S::Effect: LocalOnlyAllowedEffect,
{
    /// Supply explicitly classified local read/auth state to a `LocalOnly` Primary route.
    #[must_use]
    pub fn with_classified_state(self, state: S) -> GeneratedPrimaryEndpoint<(), LocalOnly> {
        GeneratedPrimaryEndpoint(self.0.with_state(state), PhantomData)
    }
}

/// Test-only raw route metadata. Production builds do not contain this type.
#[cfg(any(test, feature = "test-util"))]
pub struct TestRoute {
    pub method: axum::http::Method,
    pub path: &'static str,
    pub contract_id: &'static str,
}

/// Test-only permission metadata for raw router tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy)]
pub struct TestRoutePermission {
    pub permission: vocab::RoutePermissionId,
    pub scope: TestRouteResourceScope,
}

/// Test-only resource scope for raw router tests.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy)]
pub enum TestRouteResourceScope {
    None,
    PathParam(&'static str),
    SelfSubject,
}

/// Test-only Primary route metadata. Production builds do not contain this type.
#[cfg(any(test, feature = "test-util"))]
pub struct TestPrimaryRoute {
    evidence: HttpRouteEvidence,
    authz: PrimaryRouteAuthz,
}

#[cfg(any(test, feature = "test-util"))]
impl TestPrimaryRoute {
    pub fn permission(
        method: axum::http::Method,
        path: &'static str,
        contract_id: &'static str,
        permission: TestRoutePermission,
    ) -> Result<Self, RouteGroupError> {
        let scope = match permission.scope {
            TestRouteResourceScope::None => RouteResourceScope::None,
            TestRouteResourceScope::PathParam(name) => RouteResourceScope::PathParam(name),
            TestRouteResourceScope::SelfSubject => RouteResourceScope::SelfSubject,
        };
        let (resource, self_scoped) = match permission.scope {
            TestRouteResourceScope::None => (None, false),
            TestRouteResourceScope::PathParam(name) => (Some(name), false),
            TestRouteResourceScope::SelfSubject => (None, true),
        };
        Ok(Self {
            evidence: test_route_evidence(
                method,
                path,
                contract_id,
                HttpRouteAuth::Permission(permission.permission),
                resource,
                self_scoped,
            )?,
            authz: PrimaryRouteAuthz::Permission(RoutePermission {
                permission: permission.permission,
                scope,
                tenant_binding: RouteTenantBinding::Unrestricted,
            }),
        })
    }

    pub fn opt_out(
        method: axum::http::Method,
        path: &'static str,
        contract_id: &'static str,
        opt_out: primitives::RouteAuthOptOut,
    ) -> Result<Self, RouteGroupError> {
        Ok(Self {
            evidence: test_route_evidence(
                method,
                path,
                contract_id,
                HttpRouteAuth::Public,
                None,
                false,
            )?,
            authz: PrimaryRouteAuthz::OptOut(opt_out),
        })
    }
}

#[cfg(any(test, feature = "test-util"))]
fn test_route_evidence(
    method: axum::http::Method,
    path: &'static str,
    contract_id: &'static str,
    auth: HttpRouteAuth,
    resource: Option<&'static str>,
    self_scoped: bool,
) -> Result<HttpRouteEvidence, RouteGroupError> {
    let method = match method {
        axum::http::Method::CONNECT => "CONNECT",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::GET => "GET",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::POST => "POST",
        axum::http::Method::PUT => "PUT",
        axum::http::Method::TRACE => "TRACE",
        _ => {
            return Err(RouteGroupError::InvalidMethod {
                contract_id,
                method: method.as_str().to_owned(),
                path,
            });
        }
    };
    const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
    Ok(HttpRouteEvidence::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            contract_id,
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        path,
        method,
        &[],
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        auth,
        resource,
        self_scoped,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpConsistencyLevel::LocalOnly,
        vocab::HttpEffectProfile::new(EFFECTS),
    ))
}

/// 封闭 [`Listener`] / [`NonPrimaryListener`] 实现面：外部 crate 无法命名 [`sealed::Sealed`] ⇒ 无法新增
/// listener marker（type-layer Hard seal，对齐 `vocab::contract::owner` 私有内层封闭先例）。
mod sealed {
    pub trait Sealed {}
    pub trait ContractHandlerArgs<M> {}
    pub trait DeclaredContractHandler<M, T, S> {}
    pub trait DeclaredProducerContractHandler<M, T, S> {}
    pub trait ProducerHandlerArgs<M> {}
}

/// listener 类型层 marker（sealed）。`KIND` 把 marker 落到运行期 [`ListenerKind`] 值（fold 分组键）。
pub trait Listener: sealed::Sealed {
    /// 本 marker 对应的运行期 listener 值。
    const KIND: ListenerKind;
}

/// 非-`Primary` listener marker（sealed）：`ListenerRouter::mount`（无 opt-out 路由）仅这些 listener 可用。
pub trait NonPrimaryListener: Listener {}

/// 对外业务 listener marker。
pub struct Primary;
/// 服务间控制面 listener marker。
pub struct Internal;
/// operator / 管理面 listener marker。
pub struct Admin;
/// health / ready / metrics listener marker。
pub struct Health;

impl sealed::Sealed for Primary {}
impl sealed::Sealed for Internal {}
impl sealed::Sealed for Admin {}
impl sealed::Sealed for Health {}

impl Listener for Primary {
    const KIND: ListenerKind = ListenerKind::Primary;
}
impl Listener for Internal {
    const KIND: ListenerKind = ListenerKind::Internal;
}
impl Listener for Admin {
    const KIND: ListenerKind = ListenerKind::Admin;
}
impl Listener for Health {
    const KIND: ListenerKind = ListenerKind::Health;
}

impl NonPrimaryListener for Internal {}
impl NonPrimaryListener for Admin {}

/// register 闭包内构建本组路由的 listener-typed builder（`route_group::<L>` 注入）。
///
/// INVARIANT: ROUTE-LISTENER-TYPED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 路由经本 builder 挂载、随组 fold 进 `L::KIND` listener 的
/// Router；Internal/Admin generated endpoint 类型层不可能进 Primary Router（取代 SEGREGATION-01 Medium
/// runtime 守，#1103 Medium→Hard）。`mount` 按 listener 类型只接受对应 endpoint；Health 无业务 mount。
#[must_use = "ListenerRouter 须返回给 route_group register 闭包（否则路由未挂载）"]
pub struct ListenerRouter<L: Listener> {
    inner: axum::Router,
    prefix: &'static str,
    mounted: MountedRoutes,
    _l: PhantomData<fn() -> L>,
}

/// INVARIANT: ROUTE-MOUNT-NOBYPASS-01 { level = "Hard", exec = "native-compile", source = "code", native = "the isolated default production feature graph exports only closed generated endpoint mounts; default_feature_surface cargo-check proves all raw helpers absent" }
/// INVARIANT: ROUTE-MOUNT-TESTUTIL-RESIDUAL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `test-util` 显式开启后仍有 raw test helpers；它们只产/消费测试 router，不属于 production feature graph。
impl<L: Listener> ListenerRouter<L> {
    /// 在 fresh `axum::Router` 上起一个 listener-typed builder。**`pub(crate)`**：外部 crate 无法构造——
    /// 域 crate 只在 `route_group` register 闭包里**收到** builder，仅能 mount typed endpoint（无
    /// raw-bypass）。构造与裸 Router erase 只发生在 httpserve 内（[`UnfinalizedRoutes::nest_group`]），
    /// 故无任何 public API 交出可 bind 的裸 `axum::Router`（#1103/#1113 Hard 闭环）。
    pub(crate) fn new(router: axum::Router, prefix: &'static str) -> Self {
        Self {
            inner: router,
            prefix,
            mounted: MountedRoutes::default(),
            _l: PhantomData,
        }
    }

    fn into_parts(self) -> (axum::Router, MountedRoutes) {
        (self.inner, self.mounted)
    }

    /// Test-only raw framework router mount. Production builds do not contain this API.
    #[cfg(any(test, feature = "test-util"))]
    pub fn mount_raw_for_test(
        self,
        route: TestRoute,
        handler: axum::routing::MethodRouter,
    ) -> Result<Self, RouteGroupError> {
        let evidence = test_route_evidence(
            route.method,
            route.path,
            route.contract_id,
            HttpRouteAuth::ServiceOwned,
            None,
            false,
        )?;
        let method = axum::http::Method::from_bytes(evidence.method().as_bytes())
            .map_err(|_| invalid_method(evidence))?;
        let path = relative_path(evidence, self.prefix, L::KIND)?;
        let authz = if L::KIND == ListenerKind::Primary {
            Some(primary_authz(evidence)?)
        } else {
            None
        };
        let mut mounted = self.mounted;
        mounted.push_raw(evidence);
        Ok(Self {
            inner: self
                .inner
                .route(path, handler.layer(enforce_layer(authz, method, evidence))),
            prefix: self.prefix,
            mounted,
            _l: PhantomData,
        })
    }
}

#[cfg(any(test, feature = "test-util"))]
impl ListenerRouter<Primary> {
    pub fn mount_primary_raw_for_test(
        self,
        route: Result<TestPrimaryRoute, RouteGroupError>,
        handler: axum::routing::MethodRouter,
    ) -> Result<Self, RouteGroupError> {
        let route = route?;
        let method = axum::http::Method::from_bytes(route.evidence.method().as_bytes())
            .map_err(|_| invalid_method(route.evidence))?;
        let path = relative_path(route.evidence, self.prefix, ListenerKind::Primary)?;
        let mut mounted = self.mounted;
        mounted.push_raw(route.evidence);
        Ok(Self {
            inner: self.inner.route(
                path,
                handler.layer(enforce_layer(Some(route.authz), method, route.evidence)),
            ),
            prefix: self.prefix,
            mounted,
            _l: PhantomData,
        })
    }
}

#[cfg(any(test, feature = "test-util"))]
impl ListenerRouter<Internal> {
    /// Test-only raw Internal mount with the same exact caller-policy carrier as production.
    pub fn mount_internal_raw_for_test(
        self,
        route: TestRoute,
        policy: ServiceCallerPolicy,
        handler: axum::routing::MethodRouter,
    ) -> Result<Self, RouteGroupError> {
        let evidence = test_route_evidence(
            route.method,
            route.path,
            route.contract_id,
            HttpRouteAuth::ServiceOwned,
            None,
            false,
        )?;
        if !policy.matches_contract(evidence.contract_id()) {
            return Err(RouteGroupError::InvalidServiceCallerPolicy);
        }
        let method = axum::http::Method::from_bytes(evidence.method().as_bytes())
            .map_err(|_| invalid_method(evidence))?;
        let path = relative_path(evidence, self.prefix, ListenerKind::Internal)?;
        let mut mounted = self.mounted;
        mounted.push_raw(evidence);
        Ok(Self {
            inner: self.inner.route(
                path,
                handler.layer(enforce_layer(
                    Some(PrimaryRouteAuthz::ServiceCaller(policy)),
                    method,
                    evidence,
                )),
            ),
            prefix: self.prefix,
            mounted,
            _l: PhantomData,
        })
    }
}

impl ListenerRouter<Admin> {
    /// Mount one complete generated endpoint. Raw paths, method routers, and metadata are not
    /// accepted by the production API.
    pub fn mount<C: HttpConsistencyClass>(
        self,
        endpoint: GeneratedEndpoint<(), C>,
    ) -> Result<Self, RouteGroupError> {
        let Endpoint {
            evidence,
            identity,
            method,
            handler,
        } = endpoint.0;
        let authz = nonprimary_authz::<C>(evidence, ListenerKind::Admin)?;
        let path = relative_path(evidence, self.prefix, ListenerKind::Admin)?;
        let mut mounted = self.mounted;
        mounted.push_generated(evidence, identity);
        Ok(Self {
            inner: self
                .inner
                .route(path, handler.layer(enforce_layer(authz, method, evidence))),
            prefix: self.prefix,
            mounted,
            _l: PhantomData,
        })
    }
}

impl ListenerRouter<Internal> {
    /// Mount one generated Internal endpoint with an exact non-empty caller policy.
    pub fn mount<C: HttpConsistencyClass>(
        self,
        endpoint: GeneratedEndpoint<(), C>,
        policy: ServiceCallerPolicy,
    ) -> Result<Self, RouteGroupError> {
        let Endpoint {
            evidence,
            identity,
            method,
            handler,
        } = endpoint.0;
        nonprimary_auth(evidence, ListenerKind::Internal)?;
        if !policy.matches_contract(evidence.contract_id()) {
            return Err(RouteGroupError::InvalidServiceCallerPolicy);
        }
        let path = relative_path(evidence, self.prefix, ListenerKind::Internal)?;
        let mut mounted = self.mounted;
        mounted.push_generated(evidence, identity);
        Ok(Self {
            inner: self.inner.route(
                path,
                handler.layer(enforce_layer(
                    Some(PrimaryRouteAuthz::ServiceCaller(policy)),
                    method,
                    evidence,
                )),
            ),
            prefix: self.prefix,
            mounted,
            _l: PhantomData,
        })
    }
}

impl ListenerRouter<Primary> {
    /// Mount one complete generated Primary endpoint.
    pub fn mount<C: HttpConsistencyClass>(
        self,
        endpoint: GeneratedPrimaryEndpoint<(), C>,
    ) -> Result<Self, RouteGroupError> {
        let Endpoint {
            evidence,
            identity,
            method,
            handler,
        } = endpoint.0;
        let path = relative_path(evidence, self.prefix, ListenerKind::Primary)?;
        let authz = primary_authz(evidence)?;
        let mut mounted = self.mounted;
        mounted.push_generated(evidence, identity);
        Ok(Self {
            inner: self.inner.route(
                path,
                handler.layer(enforce_layer(Some(authz), method, evidence)),
            ),
            prefix: self.prefix,
            mounted,
            _l: PhantomData,
        })
    }
}

impl ListenerRouter<Health> {
    pub(crate) fn mount_framework(
        self,
        path: &'static str,
        handler: axum::routing::MethodRouter,
    ) -> Self {
        Self {
            inner: self.inner.route(path, handler),
            prefix: self.prefix,
            mounted: self.mounted,
            _l: PhantomData,
        }
    }
}

fn relative_path(
    evidence: HttpRouteEvidence,
    prefix: &'static str,
    listener: ListenerKind,
) -> Result<&'static str, RouteGroupError> {
    evidence
        .path()
        .strip_prefix(prefix)
        .filter(|path| path.starts_with('/') && path.len() > 1)
        .ok_or(RouteGroupError::PathOutsideGroup {
            contract_id: evidence.contract_id(),
            method: evidence.method(),
            path: evidence.path(),
            prefix,
            listener,
        })
}

fn invalid_method(evidence: HttpRouteEvidence) -> RouteGroupError {
    RouteGroupError::InvalidMethod {
        contract_id: evidence.contract_id(),
        method: evidence.method().to_owned(),
        path: evidence.path(),
    }
}

fn invalid_auth(evidence: HttpRouteEvidence, listener: ListenerKind) -> RouteGroupError {
    RouteGroupError::InvalidAuth {
        contract_id: evidence.contract_id(),
        method: evidence.method(),
        path: evidence.path(),
        listener,
        auth: evidence.auth(),
    }
}

fn nonprimary_auth(
    evidence: HttpRouteEvidence,
    listener: ListenerKind,
) -> Result<(), RouteGroupError> {
    if evidence.auth() == HttpRouteAuth::Public {
        return Err(invalid_auth(evidence, listener));
    }
    Ok(())
}

fn nonprimary_authz<C: HttpConsistencyClass>(
    evidence: HttpRouteEvidence,
    listener: ListenerKind,
) -> Result<Option<PrimaryRouteAuthz>, RouteGroupError> {
    nonprimary_auth(evidence, listener)?;
    if listener != ListenerKind::Admin || C::LEVEL != vocab::HttpConsistencyLevel::LocalOnly {
        return Ok(None);
    }
    match evidence.auth() {
        HttpRouteAuth::Permission(_) => {
            let tenant_binding = match evidence.resource_sharing() {
                vocab::http::HttpResourceSharing::TenantScoped => RouteTenantBinding::Ambient,
                vocab::http::HttpResourceSharing::Global => RouteTenantBinding::Unrestricted,
            };
            permission_authz(evidence, listener, tenant_binding).map(Some)
        }
        HttpRouteAuth::Bootstrap | HttpRouteAuth::ClientsOnly | HttpRouteAuth::ServiceOwned => {
            Ok(None)
        }
        HttpRouteAuth::Public => Err(invalid_auth(evidence, listener)),
    }
}

fn primary_authz(evidence: HttpRouteEvidence) -> Result<PrimaryRouteAuthz, RouteGroupError> {
    match evidence.auth() {
        HttpRouteAuth::Permission(_) => permission_authz(
            evidence,
            ListenerKind::Primary,
            RouteTenantBinding::Unrestricted,
        ),
        HttpRouteAuth::Public => Ok(PrimaryRouteAuthz::OptOut(
            primitives::RouteAuthOptOut::Public,
        )),
        HttpRouteAuth::Bootstrap | HttpRouteAuth::ClientsOnly | HttpRouteAuth::ServiceOwned => {
            Err(invalid_auth(evidence, ListenerKind::Primary))
        }
    }
}

fn permission_authz(
    evidence: HttpRouteEvidence,
    listener: ListenerKind,
    tenant_binding: RouteTenantBinding,
) -> Result<PrimaryRouteAuthz, RouteGroupError> {
    let HttpRouteAuth::Permission(permission) = evidence.auth() else {
        return Err(invalid_auth(evidence, listener));
    };
    let scope = match (
        evidence.resource_sharing(),
        evidence.resource(),
        evidence.self_scoped(),
    ) {
        (vocab::http::HttpResourceSharing::Global, Some(_), false) => RouteResourceScope::None,
        (vocab::http::HttpResourceSharing::Global, _, _) => {
            return Err(invalid_auth(evidence, listener));
        }
        (vocab::http::HttpResourceSharing::TenantScoped, Some(resource), false) => {
            RouteResourceScope::PathParam(resource)
        }
        (vocab::http::HttpResourceSharing::TenantScoped, None, true) => {
            RouteResourceScope::SelfSubject
        }
        (vocab::http::HttpResourceSharing::TenantScoped, None, false) => RouteResourceScope::None,
        (vocab::http::HttpResourceSharing::TenantScoped, Some(_), true) => {
            return Err(invalid_auth(evidence, listener));
        }
    };
    Ok(PrimaryRouteAuthz::Permission(RoutePermission {
        permission,
        scope,
        tenant_binding,
    }))
}

/// 单 listener 的 per-listener Router，**未** auth-finalize（#1113 funnel 入态），兼作 finalize 折叠的
/// per-listener **累加器**。
///
/// INVARIANT: ROUTE-AUTH-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 无 public bindable 出口（无 `into_server_service`）；唯一前进路径是
/// [`finalize_auth`]（同 crate 读私有字段）换 [`AuthenticatedRoutes`] ⇒ 未跑 auth 装配的 router 无法 bind。
/// 经 [`empty`](Self::empty) + [`nest_group`](Self::nest_group) 累加（裸 `axum::Router` 不出 httpserve），
/// 并原子保留 generated route marker 与 stateless/stateful identity；raw test mount 不具 generated identity。
/// 由 `bootstrap::finalize_routes` 经受控 `bootstrap → httpserve` 边驱动（ADR-009）。
#[must_use = "UnfinalizedRoutes 须经 finalize_auth 换 AuthenticatedRoutes 才能 bind"]
pub struct UnfinalizedRoutes {
    router: axum::Router,
    mounted: MountedRoutes,
    listener: Option<ListenerKind>,
    conflicting_listener: Option<ListenerKind>,
}

impl UnfinalizedRoutes {
    /// 起一个空的 per-listener 累加器（bootstrap finalize 每 listener 一个）。
    pub fn empty() -> Self {
        Self {
            router: axum::Router::new(),
            mounted: MountedRoutes::default(),
            listener: None,
            conflicting_listener: None,
        }
    }

    /// 跑 register 闭包构建本组路由（listener-typed [`ListenerRouter<L>`]），nest 到本累加器的 `prefix` 下。
    ///
    /// 裸 `axum::Router` 全程不出 httpserve（`ListenerRouter::{new, into_inner}` 均 `pub(crate)`）——域 crate
    /// 只能经收到的 builder mount typed endpoint，无法 raw-bypass（#1103 Medium→Hard）；产物仍是
    /// `UnfinalizedRoutes`（无 bindable 出口，#1113）。register 闭包 `Err` 原样冒泡（保留 bootstrap `KernelError` 变体）。
    pub fn nest_group<L, E>(
        self,
        prefix: &'static str,
        register: impl FnOnce(ListenerRouter<L>) -> Result<ListenerRouter<L>, E>,
    ) -> Result<Self, E>
    where
        L: Listener,
    {
        let (group, group_routes) =
            register(ListenerRouter::<L>::new(axum::Router::new(), prefix))?.into_parts();
        let listener = self.listener.or(Some(L::KIND));
        let conflicting_listener = self.conflicting_listener.or_else(|| {
            self.listener
                .filter(|registered| *registered != L::KIND)
                .map(|_| L::KIND)
        });
        let mut mounted = self.mounted;
        mounted.append(group_routes);
        Ok(Self {
            router: self.router.nest(prefix, group),
            mounted,
            listener,
            conflicting_listener,
        })
    }

    /// Exact generated route evidence mounted into this listener before auth finalization.
    #[must_use]
    pub fn route_evidence(&self) -> &[HttpRouteEvidence] {
        self.mounted.evidence()
    }

    /// 测试专用：取回裸 Router 做 `tower::ServiceExt::oneshot` listener 隔离断言。
    ///
    /// **`cfg(any(test, feature = "test-util"))` 门控（Medium）**：生产构建（无 `test-util` feature）里本入口
    /// **编译期不存在**——故不削弱 ROUTE-AUTH-FUNNEL-01（生产无 public bindable 出口）。跨 crate 测试消费方
    /// （bootstrap/audit/bins/httpserve 自身集成测试）经 dev-dependency 显式启用 `httpserve` 的 `test-util` feature。
    #[cfg(any(test, feature = "test-util"))]
    pub fn into_router_for_test(self) -> axum::Router {
        self.router
    }
}

/// Opaque, budget-sealed per-request HTTP transport core.
///
/// Only [`AuthenticatedRoutes::into_server_service`] constructs this production capability. It
/// implements only the per-request core. It emits no transport evidence: the `httpd` adapter owns
/// the sole official SERVER span/RED seam and selects scheme inside the actual bind branch.
#[derive(Clone)]
#[must_use = "ServerService must be consumed by the HTTP transport adapter"]
pub struct ServerService {
    router: axum::Router,
    observation_policy: crate::ServerObservationPolicy,
}

impl ServerService {
    /// Build a sealed service around a raw test router. Not present in production feature graphs.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_router_for_test(router: axum::Router, budget: crate::ServerRequestBudget) -> Self {
        let router = router.layer(axum::middleware::from_fn(crate::middleware::panic_recovery));
        Self {
            router: seal_server_router(
                router,
                crate::protect::EdgeHardening::default(),
                budget,
                crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Other),
            ),
            observation_policy: crate::ServerObservationPolicy::Enabled(
                crate::ServerObservationListener::Other,
            ),
        }
    }

    /// Build a Health-listener core for transport policy tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_health_router_for_test(router: axum::Router) -> Self {
        Self {
            router: seal_server_router(
                router,
                crate::protect::EdgeHardening::default(),
                crate::ServerRequestBudget::for_test(),
                crate::ServerObservationPolicy::Disabled,
            ),
            observation_policy: crate::ServerObservationPolicy::Disabled,
        }
    }

    /// Closed listener policy consumed by the transport-owned observation seam.
    #[must_use]
    pub const fn observation_policy(&self) -> crate::ServerObservationPolicy {
        self.observation_policy
    }
}

impl tower::Service<axum::extract::Request> for ServerService {
    type Response = crate::ServerResponse;
    type Error = core::convert::Infallible;
    type Future =
        ServerResponseFuture<<axum::Router as tower::Service<axum::extract::Request>>::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        <axum::Router as tower::Service<axum::extract::Request>>::poll_ready(&mut self.router, cx)
    }

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        ServerResponseFuture {
            inner: self.router.call(request),
        }
    }
}

/// Future returned by the sealed per-request core.
pub struct ServerResponseFuture<F> {
    inner: F,
}

impl<F> core::future::Future for ServerResponseFuture<F>
where
    F: core::future::Future<Output = Result<axum::response::Response, core::convert::Infallible>>
        + Unpin,
{
    type Output = Result<crate::ServerResponse, core::convert::Infallible>;

    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        match core::pin::Pin::new(&mut self.inner).poll(cx) {
            core::task::Poll::Ready(Ok(response)) => {
                core::task::Poll::Ready(Ok(crate::ServerResponse::from_response(response)))
            }
            core::task::Poll::Ready(Err(error)) => core::task::Poll::Ready(Err(error)),
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }
}

/// auth-finalize 后的 per-listener Router（#1113 funnel 出态，可进入 transport adapter）。
///
/// INVARIANT: ROUTE-AUTH-FUNNEL-02 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 唯一生产者 = finalizer 函数（构造 `pub(crate)`，外部 crate 无法
/// mint）；[`into_server_service`](Self::into_server_service) 是唯一 transport core 出口。验签桥（#1109）经
/// [`layer`](Self::layer) 叠在外层、保持封印（产物仍是 `AuthenticatedRoutes`，只能加层不能替换）。
///
/// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— body-limit **层**（CL 闸 + Limited wrap）叠在
/// [`sealed_router`](Self::sealed_router) 唯一 funnel ⇒ 每个 bindable router 必带且必 outer 于 auth：
/// CL-declared 超限 → before-auth clean 413；无声明/chunked → Limited read-time 字节硬顶（内存有界，
/// 未认证请求经 enforce 401 时 body 从不被读，无 pre-auth buffer）。详见 middleware.rs body_limit 注释。
#[must_use = "AuthenticatedRoutes 须经 into_server_service 交给 transport adapter"]
pub struct AuthenticatedRoutes {
    router: axum::Router,
    hardening: crate::protect::EdgeHardening,
    observation_policy: crate::ServerObservationPolicy,
}

impl AuthenticatedRoutes {
    /// 唯一生产入口（`pub(crate)`）——仅本模块 finalizer 可构造，外部 crate 无法 mint（ROUTE-AUTH-FUNNEL-02）。
    fn new(router: axum::Router, observation_policy: crate::ServerObservationPolicy) -> Self {
        Self {
            router,
            hardening: crate::protect::EdgeHardening::default(),
            observation_policy,
        }
    }

    /// 覆盖边缘防护配置（body-limit + security-headers）。
    ///
    /// 组合根在 `finalize_auth` 产物上调用，覆盖默认的 [`crate::protect::EdgeHardening`] 值
    /// （如调整 body 上限或显式关闭框架 CORP 策略）。`sealed_router` 将使用更新后的配置叠层；
    /// HSTS 的最终 wire 裁决由持有真实 transport scheme 的 `httpd` adapter 完成。
    pub fn with_edge_hardening(mut self, hardening: crate::protect::EdgeHardening) -> Self {
        self.hardening = hardening;
        self
    }

    /// 在已认证 router **外层**叠中间件（验签桥 #1109 的请求方向先于 `EnforceService`）。
    ///
    /// 镜像 axum `Router::layer` 的约束——只能**加层**、不能替换 router，故 funnel 封印不破（产物仍 `AuthenticatedRoutes`）。
    pub fn layer<L>(self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::extract::Request> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Error:
            Into<core::convert::Infallible> + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Future: Send + 'static,
    {
        Self {
            router: self.router.layer(layer),
            hardening: self.hardening,
            observation_policy: self.observation_policy,
        }
    }

    /// 在唯一 transport core 出口封全局防护中间件链（请求预算 + 请求 ID + correlation + security-headers + body-limit）。
    ///
    /// INVARIANT: ROUTE-REQUESTID-OUTERMOST-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `request_id` **不**在 [`finalize_auth`] 内挂（那会被组合根
    /// 后叠的验签桥包到内层 ⇒ 桥运行时读不到 `RequestId`，#1109 NOTE / #1320）；改由本出口统一注入 ⇒ 每个被
    /// bind 的 router 都带 request_id 且**不可遗漏**（can't-forget funnel）。
    ///
    /// INVARIANT: ROUTE-CORRELATION-INNER-REQUESTID-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `correlation` 封在 `request_id` 内侧、验签桥外侧：
    ///   · `request_id` 先行（外层）确保 `RequestId` extension 在场，`correlation` 可读回作回退值；
    ///   · `diagctx::scope` 包住验签桥 + handler + application + adapter emit ⇒ outbox emit 可经
    ///     [`diagctx::correlation`] 读回 correlation id（ADR-002 §D1-bis）。
    ///
    /// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— body-limit **层**（CL 闸 + Limited wrap）outer 于 auth 验签桥：
    ///   · **CL-declared 超限 → before-auth clean 413（`ERR_CORE_PAYLOAD_TOO_LARGE`）**：层1 CL fast-reject
    ///     在验签桥前拒，无 auth 开销；
    ///   · **无声明/chunked → `http_body_util::Limited` 字节硬顶（read-time，内存有界）**：未认证请求经
    ///     enforce 401 时 body 从不被读 ⇒ 无 pre-auth buffer（DoS 优姿态；见 middleware.rs body_limit reason）。
    ///   CL 路径的**拒绝决策** before-auth；无 CL 路径的 cap 由 Limited read-time 实施，非 before-auth 413。
    /// 结构性 Hard：唯一 transport core 出口经本 funnel 封层，不可遗漏。security-headers outer 于 body-limit（所有响应
    /// 含 413 均追加安全头）。
    ///
    /// INVARIANT: SERVER-REQUEST-BUDGET-01 { level = "Hard", exec = "native-compile", source = "code", native = "private capability field + required argument" }——唯一 transport core 出口必须消费非零 [`crate::ServerRequestBudget`]，且 `httpd` plaintext/mTLS 只接受 [`ServerService`]；不存在无预算 transport core。
    ///
    /// INVARIANT: HTTP-SERVER-OBSERVATION-POLICY-01 { level = "Hard", exec = "native-compile", source = "code", native = "private capability field + unique transport-core funnel" }——finalizer 构造的非可选 observation policy 随封印类型传播，并且只能由 transport owner 消费；Health Disabled，其余 listener Enabled。
    ///
    /// INVARIANT: HTTP-SERVER-OBSERVATION-ORDER-01 { level = "Medium", exec = "test", source = "code" }——T2 finalized-router 测试锁住 SERVER span 与 RED owner 包含 budget/body-limit/验签桥/panic/handler/body poll 的真实请求顺序。
    ///
    /// 层序（外→内）：`httpd` SERVER observation → security-headers → `request_id` → `correlation`
    /// → observation metadata → server-request-budget → body-limit → 验签桥 → `panic_recovery`
    /// → `Extension(plan)` → enforce → handler。
    ///
    /// 生产出口 [`into_server_service`](Self::into_server_service) 与 typed test 出口共用本 fn ⇒ 层序一致
    /// （test 不漂移）。
    fn sealed_router(self, budget: crate::ServerRequestBudget) -> axum::Router {
        seal_server_router(self.router, self.hardening, budget, self.observation_policy)
    }

    /// **唯一** transport core 出口：封防护层后产出不可独立 bind 的 per-request service。
    /// `httpd` 在真实 plaintext/mTLS serve 分支中构造私有 make-service，并同时持有可信 scheme 与
    /// `ConnectInfo<SocketAddr>`；本 crate 不发射 transport evidence。
    pub fn into_server_service(self, budget: crate::ServerRequestBudget) -> ServerService {
        let observation_policy = self.observation_policy;
        ServerService {
            router: self.sealed_router(budget),
            observation_policy,
        }
    }

    /// 测试专用：取回裸 Router 做 `oneshot` e2e 断言（经 [`sealed_router`](Self::sealed_router) ⇒ 与生产
    /// `into_server_service` 同层序，含 request_id 最外层）。**`cfg(any(test, feature = "test-util"))` 门控（Medium）**——
    /// 生产构建里编译期不存在，不削弱 ROUTE-AUTH-FUNNEL-02（生产唯一 transport core 出口仍是 `into_server_service`）。
    #[cfg(any(test, feature = "test-util"))]
    pub fn into_plaintext_router_for_test(self) -> axum::Router {
        self.sealed_router(crate::ServerRequestBudget::for_test())
    }

    /// Test-only exit with an explicit short budget for deterministic timeout/cancellation tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn into_plaintext_router_for_test_with_budget(
        self,
        budget: crate::ServerRequestBudget,
    ) -> axum::Router {
        self.sealed_router(budget)
    }
}

fn seal_server_router(
    router: axum::Router,
    hardening: crate::protect::EdgeHardening,
    budget: crate::ServerRequestBudget,
    observation_policy: crate::ServerObservationPolicy,
) -> axum::Router {
    // `.layer` calls are inner→outer. The timeout covers every fallible/async request component;
    // request/correlation context wraps it so a timeout response remains correlated. Mechanical
    // security response headers stay outermost so the synthetic 503 receives the same headers.
    let router = router
        .layer(axum::middleware::from_fn_with_state(
            hardening.body_limit,
            crate::middleware::body_limit,
        ))
        .layer(axum::middleware::from_fn_with_state(
            budget,
            crate::middleware::server_request_budget,
        ));
    let router = match observation_policy {
        crate::ServerObservationPolicy::Enabled(_) => router.layer(axum::middleware::from_fn(
            crate::middleware::http_server_observation_metadata,
        )),
        crate::ServerObservationPolicy::Disabled => router,
    };
    let mut router = router
        .layer(axum::middleware::from_fn(crate::middleware::correlation))
        .layer(axum::middleware::from_fn(crate::middleware::request_id));

    for header_layer in hardening.headers.response_layers() {
        router = router.layer(header_layer);
    }
    router
}

/// 从 listener auth plan 派生统一 observation 策略。Health listener 是高频 probe/scrape 面，
/// 同时禁用 SERVER span 与 HTTP RED；未知未来 listener fail-closed 为 Enabled。
fn observation_policy_from_plan(plan: AuthPlan) -> crate::ServerObservationPolicy {
    match plan.listener() {
        ListenerKind::Health => crate::ServerObservationPolicy::Disabled,
        ListenerKind::Primary => {
            crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Primary)
        }
        ListenerKind::Internal => {
            crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Internal)
        }
        ListenerKind::Admin => {
            crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Admin)
        }
        _ => crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Other),
    }
}

/// 所有非 Primary route 注册完成后装配 auth enforcement（plan 由组合根注入，本函数不构造 `AuthPlan`）。
/// Primary listener 必须使用 [`finalize_primary_auth`] / [`finalize_primary_auth_with_audit`] 注入
/// [`RouteAuthorizer`]，避免 permission route 误装配成缺 authorizer 的请求期 403。
///
/// #1113 funnel transform：消费 [`UnfinalizedRoutes`] 产 [`AuthenticatedRoutes`]——本 fn 是后者**唯一**
/// 生产者（ROUTE-AUTH-FUNNEL-02）。业务不得绕过最终 matcher（runtime-api.md）。
///
/// 层序（`.layer` 调用顺序 = 内→外）：`Extension(plan)`（最内，EnforceService 读 plan）→ `panic_recovery`
/// （request-aware panic → 500 envelope）。listener 派生 observation policy 作为非可选 capability 随封印类型传递，
/// 到 transport owner 才消费。`request_id` / `correlation` / observation metadata / server budget **不**在此挂——均由唯一 bindable 出口
/// [`AuthenticatedRoutes::sealed_router`] 封装（ROUTE-REQUESTID-OUTERMOST-01 /
/// ROUTE-CORRELATION-INNER-REQUESTID-01 / SERVER-REQUEST-BUDGET-01 / #1320）。完整请求流（外→内）：
/// `httpd` SERVER observation（Health 无）→ security headers → `request_id` → `correlation`
/// → observation metadata → server budget → 验签桥 → `panic_recovery` → `Extension(plan)`
/// → 路由匹配 → `EnforceService` → handler。
///
/// 验签桥（#1109）经 [`AuthenticatedRoutes::layer`] 叠在 `finalize_auth` 产物的**外层**（请求方向先于
/// `EnforceService`），其注入的 [`Authenticated`](crate::Authenticated) 证据在 enforce 读取前就位；request_id
/// 再外封一层（见上）。Health 固定 framework route 当前只支持 `NoAuth`；其它 scheme 在共享 finalizer
/// 入口 fail-fast，避免返回一个声明已认证、实际未挂 auth enforcement 的 router。
pub fn finalize_auth(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    if plan.listener() == primitives::ListenerKind::Primary {
        return Err(listener_mismatch(&routes, plan.listener()));
    }
    finalize_auth_inner(routes, plan, None, None)
}

/// #1113 funnel transform with auth decision audit sink.
///
/// The sink records final enforce decisions. Missing authenticated evidence is not audited because no trusted tenant can
/// be derived without the verify bridge.
pub fn finalize_auth_with_audit(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: AuditSinkHandle,
    clock: Arc<dyn diport::Clock>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    if plan.listener() == primitives::ListenerKind::Primary {
        return Err(listener_mismatch(&routes, plan.listener()));
    }
    finalize_auth_inner(routes, plan, Some(AuthAudit::new(audit_sink, clock)), None)
}

pub fn finalize_auth_with_audit_and_authorizer(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: AuditSinkHandle,
    clock: Arc<dyn diport::Clock>,
    authorizer: Arc<dyn RouteAuthorizer>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    if plan.listener() == primitives::ListenerKind::Primary {
        return Err(listener_mismatch(&routes, plan.listener()));
    }
    finalize_auth_inner(
        routes,
        plan,
        Some(AuthAudit::new(audit_sink, clock)),
        Some(authorizer),
    )
}

pub fn finalize_primary_auth(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    authorizer: Arc<dyn RouteAuthorizer>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    if plan.listener() != primitives::ListenerKind::Primary {
        return Err(listener_mismatch(&routes, plan.listener()));
    }
    finalize_auth_inner(routes, plan, None, Some(authorizer))
}

pub fn finalize_primary_auth_with_audit(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: AuditSinkHandle,
    clock: Arc<dyn diport::Clock>,
    authorizer: Arc<dyn RouteAuthorizer>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    if plan.listener() != primitives::ListenerKind::Primary {
        return Err(listener_mismatch(&routes, plan.listener()));
    }
    finalize_auth_inner(
        routes,
        plan,
        Some(AuthAudit::new(audit_sink, clock)),
        Some(authorizer),
    )
}

fn finalize_auth_inner(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    audit: Option<AuthAudit>,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    if plan.listener() == ListenerKind::Health && plan.scheme() != primitives::AuthScheme::NoAuth {
        return Err(RouteGroupError::UnsupportedAuthPlan {
            listener: plan.listener(),
            scheme: plan.scheme(),
        });
    }
    if routes.conflicting_listener.is_some()
        || routes
            .listener
            .is_some_and(|listener| listener != plan.listener())
    {
        return Err(listener_mismatch(&routes, plan.listener()));
    }
    let observation_policy = observation_policy_from_plan(plan);
    let mut router = routes.router.layer(axum::Extension(plan));
    if let Some(audit) = audit {
        router = router.layer(axum::Extension(audit));
    }
    if let Some(authorizer) = authorizer {
        router = router.layer(axum::Extension(authorizer));
    }
    let router = router.layer(axum::middleware::from_fn(crate::middleware::panic_recovery));
    Ok(AuthenticatedRoutes::new(router, observation_policy))
}

fn listener_mismatch(routes: &UnfinalizedRoutes, finalized: ListenerKind) -> RouteGroupError {
    RouteGroupError::ListenerMismatch {
        registered: routes.listener,
        conflicting: routes.conflicting_listener,
        finalized,
    }
}

/// 测试专用：跑一个 listener-typed register 闭包，产出单组 [`UnfinalizedRoutes`]（直接挂载，**不** nest
/// prefix——测试路径即完整路径）。供 httpserve **外**的 funnel e2e 测试（bins `auth_e2e`）构造 funnel 输入——
/// 它们无法直接构造 `pub(crate)` 的 [`ListenerRouter`]。生产路径经 `bootstrap::Registry::route_group` +
/// `finalize_routes` 构造。
///
/// **`cfg(any(test, feature = "test-util"))` 门控（Medium）**：生产构建里编译期不存在，不削弱封印——产物是
/// [`UnfinalizedRoutes`]（无 bindable 出口，ROUTE-AUTH-FUNNEL-01），且 routes 仍经 typed `ListenerRouter<L>`
/// 挂载（ROUTE-LISTENER-TYPED-01）。
#[cfg(any(test, feature = "test-util"))]
pub fn unfinalized_for_test<L: Listener>(
    build: impl FnOnce(ListenerRouter<L>) -> Result<ListenerRouter<L>, RouteGroupError>,
) -> Result<UnfinalizedRoutes, RouteGroupError> {
    let (router, mounted) = build(ListenerRouter::<L>::new(axum::Router::new(), ""))?.into_parts();
    Ok(UnfinalizedRoutes {
        router,
        mounted,
        listener: Some(L::KIND),
        conflicting_listener: None,
    })
}

#[cfg(test)]
mod tests {
    //! routes funnel 行为单测：typed listener marker（KIND 落值）+ funnel 三态（empty/nest_group →
    //! UnfinalizedRoutes → finalize_auth → AuthenticatedRoutes）round-trip serve + `layer` 保封印 +
    //! `into_server_service` transport core 出口存在。compile-fail 负向证据（不可绕过）见 `tests/ui/`。
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    // 测试断言用 expect/unwrap：item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn oneshot_status(router: axum::Router, uri: &str) -> StatusCode {
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        router.oneshot(req).await.expect("oneshot").status()
    }

    const TEST_EFFECTS: &[vocab::HttpEffectKind] =
        &[vocab::HttpEffectKind::Auth, vocab::HttpEffectKind::Read];
    const PRODUCER_EFFECTS: &[vocab::HttpEffectKind] = &[
        vocab::HttpEffectKind::BusinessWrite,
        vocab::HttpEffectKind::BusinessTransaction,
        vocab::HttpEffectKind::Outbox,
        vocab::HttpEffectKind::Publish,
    ];
    const PRODUCER_FACT: ContractBinding = ContractBinding::from_static(
        "test",
        "test.fact",
        "v1",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    );
    const OTHER_FACT: ContractBinding = ContractBinding::from_static(
        "test",
        "test.other-fact",
        "v1",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    );

    const PRODUCER_EVENT_FACT: vocab::EventFactBinding =
        vocab::EventFactBinding::from_static(PRODUCER_FACT, "test.produced");
    const OTHER_EVENT_FACT: vocab::EventFactBinding =
        vocab::EventFactBinding::from_static(OTHER_FACT, "test.other");

    enum TestRouteMarker {}

    impl vocab::http::OpenHttpResponseMarker for TestRouteMarker {}
    enum OtherTestRouteMarker {}
    impl vocab::http::OpenHttpResponseMarker for OtherTestRouteMarker {}

    #[derive(Clone)]
    struct TestReadState;

    impl ClassifiedRouteState for TestReadState {
        type Effect = ReadEffect;
        type Privilege = LocalPrivilege;
    }

    #[derive(Clone)]
    struct OtherTestReadState;

    impl ClassifiedRouteState for OtherTestReadState {
        type Effect = ReadEffect;
        type Privilege = LocalPrivilege;
    }

    fn test_binding(
        path: &'static str,
        contract_id: &'static str,
        auth: vocab::HttpRouteAuth,
    ) -> vocab::HttpRouteBinding<TestRouteMarker, vocab::http::LocalOnly> {
        test_binding_with_method(path, contract_id, "GET", auth)
    }

    fn test_binding_with_method(
        path: &'static str,
        contract_id: &'static str,
        method: &'static str,
        auth: vocab::HttpRouteAuth,
    ) -> vocab::HttpRouteBinding<TestRouteMarker, vocab::http::LocalOnly> {
        test_binding_for_with_method(path, contract_id, method, auth, TEST_EFFECTS)
    }

    fn test_binding_for<M>(
        path: &'static str,
        contract_id: &'static str,
        auth: vocab::HttpRouteAuth,
    ) -> vocab::HttpRouteBinding<M, vocab::http::LocalOnly> {
        test_binding_for_with_method(path, contract_id, "GET", auth, TEST_EFFECTS)
    }

    fn test_binding_for_with_method<M>(
        path: &'static str,
        contract_id: &'static str,
        method: &'static str,
        auth: vocab::HttpRouteAuth,
        effects: &'static [vocab::HttpEffectKind],
    ) -> vocab::HttpRouteBinding<M, vocab::http::LocalOnly> {
        vocab::HttpRouteBinding::from_static(
            vocab::HttpContractOwner::domain("test"),
            vocab::ContractBinding::from_static(
                "test",
                contract_id,
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            path,
            method,
            &[],
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            auth,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(effects),
        )
    }

    fn admin_route(path: &'static str) -> TestRoute {
        TestRoute {
            method: Method::GET,
            path,
            contract_id: "test.admin.list",
        }
    }

    fn producer_binding<M>() -> HttpProducerBinding<M> {
        let route = HttpRouteBinding::from_static(
            vocab::HttpContractOwner::domain("test"),
            ContractBinding::from_static(
                "test",
                "test.produce",
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "/test/produce",
            "POST",
            &[],
            vocab::HttpSuccessStatus::new(201),
            vocab::HttpIdempotency::NonIdempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(PRODUCER_EFFECTS),
        );
        HttpProducerBinding::from_static(route, &[PRODUCER_FACT])
    }

    #[test]
    fn producer_receipt_authorizes_only_its_reviewed_event_fact() {
        let producer = producer_binding::<TestRouteMarker>();
        let rejected = ProducerMarker::for_test(producer)
            .into_receipt()
            .authorize(OTHER_EVENT_FACT, OTHER_FACT);
        assert!(rejected.is_none());

        let authorization = ProducerMarker::for_test(producer)
            .into_receipt()
            .authorize(PRODUCER_EVENT_FACT, PRODUCER_FACT);
        assert!(authorization.is_some(), "generated fact must be authorized");
        if let Some(authorization) = authorization {
            let retry_copy = authorization;
            assert_eq!(authorization.fact_contract(), PRODUCER_FACT);
            assert_eq!(retry_copy.producer_contract().contract_id(), "test.produce");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn producer_marker_without_private_route_witness_fails_closed() {
        let request = Request::builder()
            .uri("/test/produce")
            .body(Body::empty())
            .expect("request");
        let (mut parts, _) = request.into_parts();

        let response = ProducerMarker::<TestRouteMarker>::from_request_parts(&mut parts, &())
            .await
            .err()
            .expect("missing producer witness must reject extraction");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn producer_endpoint_installs_its_private_route_witness() {
        let producer = producer_binding::<TestRouteMarker>();
        let endpoint = GeneratedPrimaryEndpoint::<(), OutboxFact>::new_producer(
            producer,
            |marker: ProducerMarker<TestRouteMarker>| async move {
                marker
                    .into_receipt()
                    .authorize(PRODUCER_EVENT_FACT, PRODUCER_FACT)
                    .map_or(StatusCode::INTERNAL_SERVER_ERROR, |_| StatusCode::CREATED)
            },
        )
        .expect("producer endpoint");
        let router = axum::Router::new().route("/test/produce", endpoint.0.handler);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/test/produce")
            .body(Body::empty())
            .expect("request");

        let status = router.oneshot(request).await.expect("oneshot").status();

        assert_eq!(status, StatusCode::CREATED);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn producer_route_witness_can_only_be_extracted_once() {
        let request = Request::builder()
            .uri("/test/produce")
            .extension(ProducerRouteWitness(producer_binding::<TestRouteMarker>()))
            .body(Body::empty())
            .expect("request");
        let (mut parts, _) = request.into_parts();

        let first = ProducerMarker::<TestRouteMarker>::from_request_parts(&mut parts, &()).await;
        let second = ProducerMarker::<TestRouteMarker>::from_request_parts(&mut parts, &()).await;

        assert!(
            first.is_ok(),
            "mounted witness must authorize one extraction"
        );
        assert!(second.is_err(), "mounted witness must be consumed");
    }

    #[test]
    fn local_only_mounted_route_proof_is_zero_cost() {
        assert_eq!(
            core::mem::size_of::<LocalOnlyMountedRouteProof<TestRouteMarker, TestReadState>>(),
            0
        );
    }

    #[allow(clippy::expect_used)]
    fn test_routes<L: Listener>(
        build: impl FnOnce(ListenerRouter<L>) -> Result<ListenerRouter<L>, RouteGroupError>,
    ) -> UnfinalizedRoutes {
        unfinalized_for_test(build).expect("test route mount")
    }

    #[test]
    fn generated_mount_preserves_exact_route_evidence() -> Result<(), RouteGroupError> {
        let binding = test_binding(
            "/api/v1/evidence",
            "test.evidence",
            vocab::HttpRouteAuth::Public,
        );
        let expected = binding.evidence();
        let routes =
            UnfinalizedRoutes::empty().nest_group::<Primary, RouteGroupError>("/api/v1", |rb| {
                let endpoint = GeneratedPrimaryEndpoint::new(
                    binding,
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                rb.mount(endpoint)
            })?;
        assert_eq!(routes.route_evidence(), &[expected]);
        assert!(
            prove_local_only_mounted_route_state::<TestReadState, _>(&routes, &binding).is_err()
        );
        assert!(prove_stateless_local_only_mounted_route(&routes, &binding).is_ok());
        Ok(())
    }

    #[test]
    fn stateful_mount_only_mints_matching_stateful_proof() -> Result<(), RouteGroupError> {
        let binding = test_binding(
            "/api/v1/stateful",
            "test.stateful",
            vocab::HttpRouteAuth::Public,
        );
        let routes =
            UnfinalizedRoutes::empty().nest_group::<Primary, RouteGroupError>("/api/v1", |rb| {
                let endpoint = GeneratedPrimaryEndpoint::new(
                    binding,
                    |_: ContractMarker<TestRouteMarker>,
                     axum::extract::State(_): axum::extract::State<TestReadState>| async {
                        "ok"
                    },
                )?
                .with_classified_state(TestReadState);
                rb.mount(endpoint)
            })?;

        assert!(
            prove_local_only_mounted_route_state::<TestReadState, _>(&routes, &binding).is_ok()
        );
        assert!(
            prove_local_only_mounted_route_state::<OtherTestReadState, _>(&routes, &binding)
                .is_err()
        );
        assert!(prove_stateless_local_only_mounted_route(&routes, &binding).is_err());
        Ok(())
    }

    #[test]
    fn mounted_route_proof_rejects_same_evidence_with_different_marker()
    -> Result<(), RouteGroupError> {
        let binding = test_binding("/api/v1/typed", "test.typed", vocab::HttpRouteAuth::Public);
        let forged = test_binding_for::<OtherTestRouteMarker>(
            "/api/v1/typed",
            "test.typed",
            vocab::HttpRouteAuth::Public,
        );
        let routes =
            UnfinalizedRoutes::empty().nest_group::<Primary, RouteGroupError>("/api/v1", |rb| {
                let endpoint = GeneratedPrimaryEndpoint::new(
                    binding,
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                rb.mount(endpoint)
            })?;

        assert_eq!(binding.evidence(), forged.evidence());
        assert!(prove_stateless_local_only_mounted_route(&routes, &forged).is_err());
        Ok(())
    }

    #[test]
    fn raw_test_mount_cannot_mint_generated_route_proof() -> Result<(), RouteGroupError> {
        const RAW_EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
        let binding = test_binding_for_with_method::<TestRouteMarker>(
            "/raw",
            "test.raw",
            "GET",
            vocab::HttpRouteAuth::ServiceOwned,
            RAW_EFFECTS,
        );
        let routes = unfinalized_for_test::<Admin>(|rb| {
            rb.mount_raw_for_test(
                TestRoute {
                    method: Method::GET,
                    path: "/raw",
                    contract_id: "test.raw",
                },
                get(|| async { "raw" }),
            )
        })?;

        assert_eq!(routes.route_evidence(), &[binding.evidence()]);
        assert!(prove_stateless_local_only_mounted_route(&routes, &binding).is_err());
        assert!(
            prove_local_only_mounted_route_state::<TestReadState, _>(&routes, &binding).is_err()
        );
        Ok(())
    }

    #[test]
    fn mounted_route_proof_rejects_empty_and_different_routes() -> Result<(), RouteGroupError> {
        let expected: HttpRouteBinding<TestRouteMarker, LocalOnly> = test_binding(
            "/api/v1/expected",
            "test.expected",
            vocab::HttpRouteAuth::Public,
        );
        let different: HttpRouteBinding<TestRouteMarker, LocalOnly> = test_binding(
            "/api/v1/different",
            "test.different",
            vocab::HttpRouteAuth::Public,
        );
        let routes =
            UnfinalizedRoutes::empty().nest_group::<Primary, RouteGroupError>("/api/v1", |rb| {
                let endpoint = GeneratedPrimaryEndpoint::new(
                    different,
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                rb.mount(endpoint)
            })?;
        assert!(
            prove_local_only_mounted_route_state::<TestReadState, _>(
                &UnfinalizedRoutes::empty(),
                &expected,
            )
            .is_err()
        );
        assert!(
            prove_local_only_mounted_route_state::<TestReadState, _>(&routes, &expected).is_err()
        );
        assert!(prove_stateless_local_only_mounted_route(&routes, &expected).is_err());
        Ok(())
    }

    #[test]
    fn listener_kind_maps_marker_to_value() {
        assert_eq!(Primary::KIND, ListenerKind::Primary);
        assert_eq!(Internal::KIND, ListenerKind::Internal);
        assert_eq!(Admin::KIND, ListenerKind::Admin);
        assert_eq!(Health::KIND, ListenerKind::Health);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_finalization_selects_closed_server_observation_policy() {
        for (listener, scheme, expected) in [
            (
                ListenerKind::Health,
                primitives::AuthScheme::NoAuth,
                crate::ServerObservationPolicy::Disabled,
            ),
            (
                ListenerKind::Primary,
                primitives::AuthScheme::RssAccessToken,
                crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Primary),
            ),
            (
                ListenerKind::Internal,
                primitives::AuthScheme::ServiceToken,
                crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Internal),
            ),
            (
                ListenerKind::Admin,
                primitives::AuthScheme::RssAccessToken,
                crate::ServerObservationPolicy::Enabled(crate::ServerObservationListener::Admin),
            ),
        ] {
            let plan = AuthPlan::new(listener, scheme).expect("test observation plan");
            assert_eq!(observation_policy_from_plan(plan), expected);
        }
    }

    #[test]
    fn generated_endpoint_rejects_unsupported_method_with_route_context() {
        let result = GeneratedEndpoint::<(), vocab::http::LocalOnly>::new(
            test_binding_with_method(
                "/api/v1/x",
                "test.invalid-method",
                "BREW",
                vocab::HttpRouteAuth::ServiceOwned,
            ),
            |_: ContractMarker<TestRouteMarker>| async { "ok" },
        );

        assert!(matches!(
            result,
            Err(RouteGroupError::InvalidMethod {
                contract_id: "test.invalid-method",
                path: "/api/v1/x",
                ref method,
            }) if method == "BREW"
        ));
    }

    #[test]
    fn mount_rejects_path_outside_group_with_route_context() {
        let result =
            UnfinalizedRoutes::empty().nest_group::<Admin, RouteGroupError>("/admin/v1", |rb| {
                let endpoint = GeneratedEndpoint::new(
                    test_binding(
                        "/internal/v1/x",
                        "test.outside-group",
                        vocab::HttpRouteAuth::ServiceOwned,
                    ),
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                rb.mount(endpoint)
            });

        assert!(matches!(
            result,
            Err(RouteGroupError::PathOutsideGroup {
                contract_id: "test.outside-group",
                method: "GET",
                path: "/internal/v1/x",
                prefix: "/admin/v1",
                listener: ListenerKind::Admin,
            })
        ));
    }

    #[test]
    fn primary_mount_rejects_incompatible_auth_with_route_context() {
        let result =
            UnfinalizedRoutes::empty().nest_group::<Primary, RouteGroupError>("/api/v1", |rb| {
                let endpoint = GeneratedPrimaryEndpoint::new(
                    test_binding(
                        "/api/v1/x",
                        "test.invalid-primary-auth",
                        vocab::HttpRouteAuth::Bootstrap,
                    ),
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                rb.mount(endpoint)
            });

        assert!(matches!(
            result,
            Err(RouteGroupError::InvalidAuth {
                contract_id: "test.invalid-primary-auth",
                method: "GET",
                path: "/api/v1/x",
                listener: ListenerKind::Primary,
                auth: vocab::HttpRouteAuth::Bootstrap,
            })
        ));
    }

    #[test]
    fn nonprimary_mount_rejects_public_auth_with_route_context() {
        fn assert_rejected(
            result: Result<UnfinalizedRoutes, RouteGroupError>,
            path: &'static str,
            expected_listener: ListenerKind,
        ) {
            assert!(matches!(
                result,
                Err(RouteGroupError::InvalidAuth {
                    contract_id: "test.public-nonprimary",
                    method: "GET",
                    path: actual_path,
                    listener,
                    auth: vocab::HttpRouteAuth::Public,
                }) if actual_path == path && listener == expected_listener
            ));
        }

        let admin = UnfinalizedRoutes::empty().nest_group::<Admin, RouteGroupError>(
            "/admin/v1",
            |router| {
                let endpoint = GeneratedEndpoint::new(
                    test_binding(
                        "/admin/v1/x",
                        "test.public-nonprimary",
                        vocab::HttpRouteAuth::Public,
                    ),
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                router.mount(endpoint)
            },
        );
        assert_rejected(admin, "/admin/v1/x", ListenerKind::Admin);

        let internal = UnfinalizedRoutes::empty().nest_group::<Internal, RouteGroupError>(
            "/internal/v1",
            |router| {
                let endpoint = GeneratedEndpoint::new(
                    test_binding(
                        "/internal/v1/x",
                        "test.public-nonprimary",
                        vocab::HttpRouteAuth::Public,
                    ),
                    |_: ContractMarker<TestRouteMarker>| async { "ok" },
                )?;
                router.mount(
                    endpoint,
                    ServiceCallerPolicy::exact(
                        "test.public-nonprimary",
                        vocab::ServiceCallerDomain::MaintenanceOperator,
                    ),
                )
            },
        );
        assert_rejected(internal, "/internal/v1/x", ListenerKind::Internal);
    }

    #[test]
    fn internal_mount_rejects_service_policy_for_another_contract() {
        let result = UnfinalizedRoutes::empty().nest_group::<Internal, RouteGroupError>(
            "/internal/v1",
            |router| {
                router.mount_internal_raw_for_test(
                    TestRoute {
                        method: axum::http::Method::GET,
                        path: "/internal/v1/x",
                        contract_id: "test.service-contract",
                    },
                    ServiceCallerPolicy::exact(
                        "test.other-contract",
                        vocab::ServiceCallerDomain::MaintenanceOperator,
                    ),
                    axum::routing::get(|| async { "ok" }),
                )
            },
        );
        assert!(matches!(
            result,
            Err(RouteGroupError::InvalidServiceCallerPolicy)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn ambient_permission_binding_is_admin_local_only_specific() {
        let binding = test_binding(
            "/admin/v1/x",
            "test.admin-local-permission",
            vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::AuditRead),
        );
        let admin =
            nonprimary_authz::<vocab::http::LocalOnly>(binding.evidence(), ListenerKind::Admin)
                .expect("Admin LocalOnly permission metadata");
        assert!(matches!(
            admin,
            Some(PrimaryRouteAuthz::Permission(RoutePermission {
                tenant_binding: RouteTenantBinding::Ambient,
                ..
            }))
        ));

        let global =
            vocab::HttpRouteBinding::<TestRouteMarker, vocab::http::LocalOnly>::from_static(
                vocab::HttpContractOwner::framework(),
                vocab::ContractBinding::from_static(
                    "runtime",
                    "runtime.inventory",
                    "v1",
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                "/api/v1/runtime/inventory",
                "GET",
                &[],
                vocab::HttpSuccessStatus::new(200),
                vocab::HttpIdempotency::Idempotent,
                vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::RuntimeInventoryRead),
                Some("runtimeInventory"),
                false,
                vocab::http::HttpResourceSharing::Global,
                vocab::HttpEffectProfile::new(TEST_EFFECTS),
            );
        let admin =
            nonprimary_authz::<vocab::http::LocalOnly>(global.evidence(), ListenerKind::Admin)
                .expect("Admin global LocalOnly permission metadata");
        assert!(matches!(
            admin,
            Some(PrimaryRouteAuthz::Permission(RoutePermission {
                tenant_binding: RouteTenantBinding::Unrestricted,
                scope: RouteResourceScope::None,
                ..
            }))
        ));

        let internal =
            nonprimary_authz::<vocab::http::LocalOnly>(binding.evidence(), ListenerKind::Internal)
                .expect("Internal LocalOnly keeps mTLS authorization path");
        assert!(internal.is_none());
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn mixed_listener_groups_fail_before_finalize_bind() {
        let routes = UnfinalizedRoutes::empty()
            .nest_group::<Admin, RouteGroupError>("/admin/v1", Ok)
            .expect("first group")
            .nest_group::<Internal, RouteGroupError>("/internal/v1", Ok)
            .expect("mixed group is recorded for finalization");
        let plan = AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::RssAccessToken)
            .expect("plan");

        let result = finalize_auth(routes, plan);

        assert!(matches!(
            result,
            Err(RouteGroupError::ListenerMismatch {
                registered: Some(ListenerKind::Admin),
                conflicting: Some(ListenerKind::Internal),
                finalized: ListenerKind::Admin,
            })
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn health_routes_reject_appended_business_group_before_bind() {
        let routes = crate::health::routes(
            || primitives::HealthReport::aggregate(Vec::new()),
            String::new,
        )
        .nest_group::<Admin, RouteGroupError>("/admin/v1", |rb| {
            let endpoint = GeneratedEndpoint::new(
                test_binding(
                    "/admin/v1/x",
                    "test.health-admin-leak",
                    vocab::HttpRouteAuth::ServiceOwned,
                ),
                |_: ContractMarker<TestRouteMarker>| async { "must not bind" },
            )?;
            rb.mount(endpoint)
        })
        .expect("mixed group is recorded for finalization");
        let plan = AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("Health plan");

        assert!(matches!(
            finalize_auth(routes, plan),
            Err(RouteGroupError::ListenerMismatch {
                registered: Some(ListenerKind::Health),
                conflicting: Some(ListenerKind::Admin),
                finalized: ListenerKind::Health,
            })
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn http_server_observation_headers_never_grant_protected_route_authority() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let routes = test_routes::<Admin>(|rb| {
                rb.mount_raw_for_test(admin_route("/protected"), get(|| async { "secret" }))
            });
            let plan = AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::RssAccessToken)
                .expect("plan");
            let router = finalize_auth(routes, plan)
                .expect("finalize")
                .into_plaintext_router_for_test();
            for traceparent in [
                None,
                Some("not-w3c"),
                Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            ] {
                let mut request = Request::builder().uri("/protected");
                if let Some(value) = traceparent {
                    request = request.header("traceparent", value);
                }
                let status = router
                    .clone()
                    .oneshot(request.body(Body::empty()).expect("request"))
                    .await
                    .expect("oneshot")
                    .status();
                assert_eq!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "traceparent={traceparent:?}"
                );
            }
        });
    }

    /// funnel round-trip：`unfinalized_for_test` → `finalize_auth` → `AuthenticatedRoutes` → 取回裸 Router
    /// oneshot。挂载路径 matched（enforce 无证据 fail-closed 403，非 404）；未挂载路径 404。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_auth_round_trip_serves_mounted_route() {
        let routes = test_routes::<Admin>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan =
            primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::RssAccessToken)
                .expect("plan");
        let authed = finalize_auth(routes, plan).expect("finalize_auth");
        let router = authed.into_plaintext_router_for_test();

        // 强断言精确 fail-closed 码（非弱 `assert_ne!(404)`）：matched + finalize_auth 注入 Jwt plan →
        // Require(Jwt) + 无 Authenticated 证据 → 401（AUTH-EVIDENCE-REQUIRE-01）。若 enforce 失效（误放行 200）
        // 或路由未挂（404）测试即红——锁住 funnel 产出的 router 确实经 enforce。
        assert_eq!(
            oneshot_status(router.clone(), "/list").await,
            StatusCode::UNAUTHORIZED,
            "挂载路径 matched + Require(Jwt) 无证据 → fail-closed 401"
        );
        assert_eq!(
            oneshot_status(router, "/absent").await,
            StatusCode::NOT_FOUND,
            "未挂载路径 404"
        );
    }

    /// `nest_group` 把组路由挂到声明 prefix 下（empty 累加器 → 完整路径命中、裸相对路径 404）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn nest_group_mounts_under_prefix() {
        let routes = UnfinalizedRoutes::empty()
            .nest_group::<Admin, RouteGroupError>("/api/v1/audit", |rb| {
                rb.mount_raw_for_test(admin_route("/api/v1/audit/list"), get(|| async { "ok" }))
            })
            .expect("nest ok");
        let plan =
            primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::RssAccessToken)
                .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_plaintext_router_for_test();

        assert_eq!(
            oneshot_status(router.clone(), "/api/v1/audit/list").await,
            StatusCode::UNAUTHORIZED,
            "完整 prefix 路径 matched + Require(Jwt) 无证据 → 401"
        );
        assert_eq!(
            oneshot_status(router, "/list").await,
            StatusCode::NOT_FOUND,
            "裸相对路径 404（prefix 参与挂载）"
        );
    }

    /// `AuthenticatedRoutes::layer` 保封印：叠一层透传中间件后产物仍是 `AuthenticatedRoutes` 且仍可 serve。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn layer_preserves_authenticated_and_serves() {
        let routes = test_routes::<Admin>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan =
            primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::RssAccessToken)
                .expect("plan");
        let authed: AuthenticatedRoutes = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .layer(axum::middleware::from_fn(
                |req: axum::extract::Request, next: axum::middleware::Next| async move {
                    next.run(req).await
                },
            ));
        // 仍是 AuthenticatedRoutes（类型已断言），且 transport core 出口可构造。
        {
            let r = authed.into_plaintext_router_for_test();
            assert_eq!(
                oneshot_status(r, "/list").await,
                StatusCode::UNAUTHORIZED,
                "叠透传层后仍 matched + Require(Jwt) 无证据 → 401（层不注证据）"
            );
        }
    }

    /// `into_server_service` 是 transport core 出口（仅 `AuthenticatedRoutes` 有，assemblies/runtime
    /// launch 交给 httpd bind 点消费）——可构造即证存在。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn authenticated_routes_into_server_service_available() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async {}))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let authed = finalize_auth(routes, plan).expect("finalize_auth");
        let _server_service = authed.into_server_service(crate::ServerRequestBudget::for_test());
    }

    /// 取回完整 Response（不仅 status）做 header 断言（request_id 封口验证）。
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn oneshot_response(router: axum::Router, uri: &str) -> axum::response::Response {
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        router.oneshot(req).await.expect("oneshot")
    }

    /// ROUTE-REQUESTID-OUTERMOST-01：`request_id` 不在 `finalize_auth` 内挂，但 bindable 出口
    /// （`sealed_router`，test 经 typed plaintext/TLS 出口同路径）仍封它 ⇒ 响应带 `x-request-id`。
    /// NoAuth listener 取 200 路径（避免 enforce 401 干扰，纯验出口封口）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn request_id_sealed_at_bindable_exit() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_plaintext_router_for_test();
        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK, "NoAuth matched → 200");
        let rid = resp
            .headers()
            .get("x-request-id")
            .expect("出口 sealed_router 须封 request_id（即便 finalize_auth 未挂）");
        assert!(!rid.is_empty(), "x-request-id 非空");
    }

    /// ROUTE-REQUESTID-OUTERMOST-01：request_id 在组合根后叠的**外层**（验签桥位）**之前**运行 ⇒ 该外层
    /// 中间件运行时已能读到 `RequestId` extension（落实「桥可读 requestId」）。用一个验签桥位的探针层断言
    /// extension 在场，命中即回写 `x-saw-rid: 1`。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn request_id_visible_to_outer_bridge_layer() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        // 探针层模拟验签桥（经 AuthenticatedRoutes::layer 叠在 finalize_auth 外、request_id 内）：
        // 读 RequestId extension，在场则回写 marker header。
        let probed =
            finalize_auth(routes, plan)
                .expect("finalize_auth")
                .layer(axum::middleware::from_fn(
                    |req: axum::extract::Request, next: axum::middleware::Next| async move {
                        let saw = req
                            .extensions()
                            .get::<crate::middleware::VerifiedRequestId>()
                            .is_some();
                        let mut resp = next.run(req).await;
                        if saw {
                            resp.headers_mut()
                                .insert("x-saw-rid", axum::http::HeaderValue::from_static("1"));
                        }
                        resp
                    },
                ));
        let resp = oneshot_response(probed.into_plaintext_router_for_test(), "/list").await;
        assert_eq!(
            resp.headers().get("x-saw-rid").map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "外层（验签桥位）中间件运行时 RequestId 须在场（request_id 已外封先行运行）"
        );
    }

    /// `request_id_str` accessor：从 extension 读 request id（在场 → `Some`，不在场 → `None`），
    /// 不暴露 `RequestId` newtype（供验签桥等组合根外层中间件读关联 id）。
    #[test]
    fn request_id_str_reads_from_extensions() {
        let mut ext = axum::http::Extensions::new();
        assert_eq!(crate::request_id_str(&ext), None, "无 RequestId → None");
        ext.insert(crate::middleware::VerifiedRequestId::from_middleware(
            "test-rid".to_owned(),
        ));
        assert_eq!(
            crate::request_id_str(&ext),
            Some("test-rid"),
            "在场 → Some(借出字符串)"
        );
    }

    // ── edge hardening 集成测试（经 sealed_router / typed test funnel）─────────────────

    /// security-headers 通过 sealed_router funnel 叠在所有响应上（200 路径）。
    /// 验证 `x-content-type-options: nosniff` 等默认安全头存在且值正确。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn security_headers_present_in_successful_response() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_plaintext_router_for_test();

        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK, "NoAuth → 200");

        // 各安全头存在且值正确。
        let headers = resp.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .expect("x-content-type-options")
                .as_bytes(),
            b"nosniff"
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .expect("x-frame-options")
                .as_bytes(),
            b"DENY"
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .expect("referrer-policy")
                .as_bytes(),
            b"no-referrer"
        );
        assert_eq!(
            headers
                .get("cross-origin-resource-policy")
                .expect("corp")
                .as_bytes(),
            b"same-origin"
        );
        assert!(
            headers.get("strict-transport-security").is_some(),
            "HSTS 默认开启"
        );
        assert!(
            headers.get("cache-control").is_some(),
            "cache-control 默认注入"
        );
    }

    /// CORP 默认由框架 overriding；显式 opt-out 后 handler 的跨域资源策略原样保留。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn security_headers_corp_opt_out_preserves_handler_value() {
        let routes = || {
            test_routes::<Health>(|rb| {
                rb.mount_raw_for_test(
                    admin_route("/list"),
                    get(|| async { ([("cross-origin-resource-policy", "cross-origin")], "ok") }),
                )
            })
        };
        let plan = || {
            primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
                .expect("plan")
        };

        let default_router = finalize_auth(routes(), plan())
            .expect("finalize default")
            .into_plaintext_router_for_test();
        let default_response = oneshot_response(default_router, "/list").await;
        assert_eq!(
            default_response
                .headers()
                .get("cross-origin-resource-policy")
                .expect("default CORP"),
            "same-origin",
            "默认策略必须覆盖 handler"
        );

        let opted_out_router = finalize_auth(routes(), plan())
            .expect("finalize opt-out")
            .with_edge_hardening(crate::protect::EdgeHardening {
                body_limit: crate::protect::BodyLimit::default(),
                headers: crate::protect::SecurityHeaders::default().without_corp(),
            })
            .into_plaintext_router_for_test();
        let opted_out_response = oneshot_response(opted_out_router, "/list").await;
        assert_eq!(
            opted_out_response
                .headers()
                .get("cross-origin-resource-policy")
                .expect("handler CORP"),
            "cross-origin",
            "opt-out 后不得删除或覆盖 handler 值"
        );
    }

    /// body-limit 超出 Content-Length 门限时返回 413，经 sealed_router funnel 有效（#1106）。
    /// 使用 with_edge_hardening 设小上限（10 bytes）验证 funnel 叠层生效。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    // reason: test helper — NonZeroUsize::new(10) is known non-zero, unwrap is infallible.
    async fn body_limit_via_sealed_router_returns_413_on_oversized_cl() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .with_edge_hardening(crate::protect::EdgeHardening {
                body_limit: crate::protect::BodyLimit::new(
                    std::num::NonZeroUsize::new(10).unwrap(),
                ),
                headers: crate::protect::SecurityHeaders::default(),
            })
            .into_plaintext_router_for_test();

        // Content-Length: 11 > 10 → 413
        let req = Request::builder()
            .uri("/list")
            .header("content-length", "11")
            .body(Body::empty())
            .expect("request");
        let resp = router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE, "CL>cap → 413");

        // Content-Length: 10 ≤ 10 → 200（NoAuth）
        let req_ok = Request::builder()
            .uri("/list")
            .header("content-length", "10")
            .body(Body::empty())
            .expect("request");
        let resp_ok = router.oneshot(req_ok).await.expect("oneshot");
        assert_eq!(resp_ok.status(), StatusCode::OK, "CL==cap → 200");
    }

    /// FIX-5：security-headers 叠在 body-limit 外侧 → 413 错误响应也包含安全头。
    ///
    /// 证 security-headers outer 于 body-limit（layer 叠加顺序：security-headers 在 body-limit 外层），
    /// 所有响应（含 413 拒绝路径）均追加安全头。复用 body-limit 413 setup + 追加安全头断言。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    // reason: test helper — NonZeroUsize::new(10) is known non-zero, unwrap is infallible.
    async fn security_headers_present_in_413_error_response() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .with_edge_hardening(crate::protect::EdgeHardening {
                body_limit: crate::protect::BodyLimit::new(
                    std::num::NonZeroUsize::new(10).unwrap(),
                ),
                headers: crate::protect::SecurityHeaders::default(),
            })
            .into_plaintext_router_for_test();

        // Content-Length: 11 > 10 → 413（CL fast-reject）。
        let req = Request::builder()
            .uri("/list")
            .header("content-length", "11")
            .body(Body::empty())
            .expect("request");
        let resp = router.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE, "CL>cap → 413");

        // 413 响应也必须有安全头（security-headers outer 于 body-limit）。
        let headers = resp.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .expect("413 须有 x-content-type-options")
                .as_bytes(),
            b"nosniff",
            "security-headers 应在 413 错误响应上存在（outer 于 body-limit）"
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .expect("413 须有 x-frame-options")
                .as_bytes(),
            b"DENY"
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .expect("413 须有 referrer-policy")
                .as_bytes(),
            b"no-referrer"
        );
    }

    /// request_id 头仍在（回归：加入 edge hardening 层后 request_id 封口不受影响）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn request_id_still_present_after_edge_hardening_layers() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_plaintext_router_for_test();

        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("x-request-id").is_some(),
            "x-request-id 在 edge hardening 层后仍存在"
        );
    }

    // ── correlation sealed_router 不变式测试 ──────────────────────────────────────────────────

    /// ROUTE-CORRELATION-INNER-REQUESTID-01：`sealed_router` 封了 `correlation` ⇒ 响应带
    /// `x-correlation-id`。NoAuth listener 取 200 路径（避免 enforce 401 干扰，纯验封口）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn correlation_sealed_at_bindable_exit() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_plaintext_router_for_test();

        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK, "NoAuth matched → 200");
        let cid = resp
            .headers()
            .get("x-correlation-id")
            .expect("sealed_router 须封 correlation middleware ⇒ 响应须有 x-correlation-id");
        assert!(!cid.is_empty(), "x-correlation-id 非空");
    }

    /// ROUTE-CORRELATION-INNER-REQUESTID-01：验签桥位（`AuthenticatedRoutes::layer`）运行时
    /// `diagctx::correlation()` 须在场——`correlation` 在 `request_id` 内侧、验签桥外侧，
    /// `diagctx::scope` 包住桥 + handler 全链。
    ///
    /// 用探针层模拟验签桥（经 `AuthenticatedRoutes::layer` 叠在 `finalize_auth` 外）：
    /// 读 `diagctx::correlation()`，在场则回写 `x-saw-correlation: 1`。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn correlation_visible_to_outer_bridge_layer() {
        let routes = test_routes::<Health>(|rb| {
            rb.mount_raw_for_test(admin_route("/list"), get(|| async { "ok" }))
        });
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        // 探针层叠在验签桥位（correlation 内侧，sealed_router 封 correlation + request_id 后成为外侧）。
        let probed =
            finalize_auth(routes, plan)
                .expect("finalize_auth")
                .layer(axum::middleware::from_fn(
                    |req: axum::extract::Request, next: axum::middleware::Next| async move {
                        let saw = diagctx::correlation().is_some();
                        let mut resp = next.run(req).await;
                        if saw {
                            resp.headers_mut().insert(
                                "x-saw-correlation",
                                axum::http::HeaderValue::from_static("1"),
                            );
                        }
                        resp
                    },
                ));
        let resp = oneshot_response(probed.into_plaintext_router_for_test(), "/list").await;
        assert_eq!(
            resp.headers()
                .get("x-saw-correlation")
                .map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "外层（验签桥位）中间件运行时 diagctx::correlation() 须在场（correlation sealed_router 先行运行）"
        );
    }
}
