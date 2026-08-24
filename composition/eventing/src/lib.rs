//! Shared event-consumer composition for executable assembly roots.
//!
//! The public surface is intentionally narrow: generated topology is resolved into an opaque
//! dispatch token, worker inputs can only be built through their constructor, and feature-gated
//! factories select the closed Postgres handlers. The handler trait, outcomes, commit evidence,
//! and Ack-authorizing driver remain private to this crate.
//!
//! ref: serverlesstechnology/cqrs persistence/postgres-es/src/event_repository.rs@main

mod consumer_tx;

use std::sync::Arc;

use bootstrap::{SubscriberBinding, SubscriberCapability, WorkerSpec};
use consistency::ConsumerGroup;
use eventexec::{ConsumerMeta, LeaseConfig, WorkerHealth};
use generated::event::{
    EventSpec, SubscriberReadiness, SubscriptionDispatchKey, SubscriptionEffect,
    SubscriptionExecution, SubscriptionSpec,
};
use vocab::ExternalEffectPolicy;

use consumer_tx::{ConsumerTxHandler, policy, spawn_consumer_ackable_tx_subscriber};

#[derive(Clone)]
enum DispatchPlan {
    #[cfg(feature = "audit-consumers")]
    SessionCreated,
    #[cfg(feature = "audit-consumers")]
    RoleAssigned,
    #[cfg(feature = "audit-consumers")]
    RoleRevoked,
    #[cfg(feature = "audit-consumers")]
    PolicyUpdated,
    #[cfg(feature = "audit-consumers")]
    SecurityEvent,
    #[cfg(feature = "settings-consumers")]
    ConfigVersionChanged(Arc<settings::ConfigVersionReconciler>),
}

/// Opaque proof that a generated subscription and its assembly capability select one closed
/// ConsumerTx handler.
///
/// Fields and constructors are private: assembly roots can carry this token but cannot forge a
/// dispatch identity or inject a handler implementation.
#[derive(Clone)]
pub struct GeneratedDispatchToken {
    dispatch: SubscriptionDispatchKey,
    policy: ExternalEffectPolicy,
    plan: DispatchPlan,
}

impl GeneratedDispatchToken {
    /// Resolve one generated subscription into the factory token selected by compiled features.
    pub fn resolve(
        spec: SubscriptionSpec,
        capability: SubscriberCapability,
    ) -> anyhow::Result<Self> {
        resolve_parts(
            spec.dispatch(),
            spec.execution(),
            spec.effect(),
            spec.external_effect_policy(),
            capability,
        )
    }

    /// Generated dispatch identity retained by this token.
    #[must_use]
    pub const fn dispatch(&self) -> SubscriptionDispatchKey {
        self.dispatch
    }

    /// Closed external-effect policy retained from generated topology.
    #[must_use]
    pub const fn policy(&self) -> ExternalEffectPolicy {
        self.policy
    }
}

/// Sealed bridge from one generated subscription and its registered runtime capability.
pub struct BridgedSubscription {
    event: EventSpec,
    subscription: SubscriptionSpec,
    group: ConsumerGroup,
    consumer_tx: GeneratedDispatchToken,
}

/// Opaque, exact generated subscription bridge consumed by runtime event transport wiring.
///
/// Consumer workers and inbox backlog selection are derived in the same bridge pass and cannot be
/// assembled independently by a caller.
pub struct BridgedSubscriptions {
    subscriptions: Vec<BridgedSubscription>,
    inbox_backlog: eventexec::InboxBacklogSelection,
}

impl BridgedSubscriptions {
    /// Whether the selected runtime owns no generated event subscriptions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subscriptions.is_empty()
    }

    /// Borrow the exact bridged subscriptions for inspection.
    #[must_use]
    pub fn subscriptions(&self) -> &[BridgedSubscription] {
        &self.subscriptions
    }

    /// Consume the single-origin bundle inside the runtime composition root.
    #[must_use]
    pub fn into_runtime_parts(
        self,
    ) -> (Vec<BridgedSubscription>, eventexec::InboxBacklogSelection) {
        (self.subscriptions, self.inbox_backlog)
    }
}

macro_rules! run_coordinated_sampler {
    ($coordinator:expr, $token:expr, $health:expr, $interval:expr, $operation:expr, $retire:expr) => {{
        loop {
            if $token.is_cancelled() {
                break;
            }
            match $coordinator.run_active($operation).await {
                Ok(distributed::MaintenanceObservation::Active(())) => break,
                Ok(distributed::MaintenanceObservation::Standby) => $health.mark_started(),
                Err(_) => $health.mark_degraded(),
            }
            $retire;
            tokio::select! {
                () = $token.cancelled() => break,
                () = tokio::time::sleep($interval) => {}
            }
        }
    }};
}

/// Run an ownership-stable inbox sampler. The distributed lease covers provider reads,
/// validation, zero/NaN transitions, and metric emission, and is retained between ticks.
pub async fn coordinated_inbox_backlog_sampler_loop<S>(
    source: Arc<S>,
    coordinator: distributed::MaintenanceCoordinator<distributed::InboxBacklogMaintenance>,
    config: eventexec::InboxSamplerConfig,
    token: tokio_util::sync::CancellationToken,
    health: Arc<eventexec::WorkerHealth>,
    metrics: Arc<dyn eventexec::InboxMetrics>,
) where
    S: eventexec::InboxBacklogSource,
{
    let mut state = eventexec::InboxSamplerState::default();
    run_coordinated_sampler!(
        coordinator,
        token,
        health,
        config.sample_interval(),
        async {
            let operation = async {
                eventexec::inbox_backlog_sampler_session(
                    Arc::clone(&source),
                    &config,
                    &mut state,
                    token.clone(),
                    Arc::clone(&health),
                    Arc::clone(&metrics),
                )
                .await;
                Ok(())
            };
            operation.await
        },
        eventexec::retire_inbox_backlog_metrics(&mut state, metrics.as_ref())
    );
    eventexec::retire_inbox_backlog_metrics(&mut state, metrics.as_ref());
    health.mark_stopped();
}

/// Run an ownership-stable outbox sampler on a lane isolated from retention maintenance.
pub async fn coordinated_outbox_backlog_sampler_loop<B>(
    source: Arc<B>,
    coordinator: distributed::MaintenanceCoordinator<distributed::OutboxBacklogMaintenance>,
    config: eventexec::SamplerConfig,
    token: tokio_util::sync::CancellationToken,
    health: Arc<eventexec::WorkerHealth>,
    metrics: Arc<dyn eventexec::OutboxMetrics>,
) where
    B: consistency::OutboxBacklog,
{
    let mut state = eventexec::OutboxSamplerState::default();
    run_coordinated_sampler!(
        coordinator,
        token,
        health,
        config.sample_interval(),
        async {
            let operation = async {
                eventexec::backlog_sampler_session(
                    Arc::clone(&source),
                    &config,
                    &mut state,
                    token.clone(),
                    Arc::clone(&health),
                    Arc::clone(&metrics),
                )
                .await;
                Ok(())
            };
            operation.await
        },
        eventexec::retire_outbox_backlog_metrics(&mut state, config.domains(), metrics.as_ref())
    );
    eventexec::retire_outbox_backlog_metrics(&mut state, config.domains(), metrics.as_ref());
    health.mark_stopped();
}

impl BridgedSubscription {
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.event.contract_id()
    }

    #[must_use]
    pub const fn topic(&self) -> &'static str {
        self.event.topic()
    }

    #[must_use]
    pub const fn schema_version(&self) -> &'static str {
        self.event.schema_version()
    }

    #[must_use]
    pub const fn schema_hash(&self) -> &'static str {
        self.event.schema_hash()
    }

    #[must_use]
    pub const fn consumer(&self) -> &'static str {
        self.subscription.consumer()
    }

    #[must_use]
    pub const fn group(&self) -> &ConsumerGroup {
        &self.group
    }

    #[must_use]
    pub const fn readiness(&self) -> SubscriberReadiness {
        self.subscription.readiness()
    }

    #[must_use]
    pub fn topic_owner(&self) -> String {
        topic_owner(self.topic())
    }

    #[must_use]
    pub fn identity_slug(&self) -> String {
        format!(
            "{}__{}__{}",
            self.topic().replace('.', "_"),
            self.consumer().replace('.', "_"),
            self.group().as_str().replace('.', "_")
        )
    }

    #[must_use]
    pub const fn dispatch_token(&self) -> &GeneratedDispatchToken {
        &self.consumer_tx
    }

    #[must_use]
    pub fn consumer_meta(&self, tenant_authority: Arc<eventexec::TenantAuthority>) -> ConsumerMeta {
        ConsumerMeta::new(
            self.consumer(),
            self.topic_owner(),
            self.contract_id(),
            self.topic(),
            self.group().as_str(),
            tenant_authority,
        )
        .with_expected_schema(self.schema_version(), self.schema_hash())
    }
}

/// Bridge all registered subscriber bindings against the complete generated event registry.
pub fn bridge_generated_subscriptions(
    bindings: Vec<SubscriberBinding>,
) -> anyhow::Result<BridgedSubscriptions> {
    bridge_subscriptions_with_events_selected(bindings, generated::event::EVENTS, admitted_dispatch)
}

/// Bridge exactly the placement-selected generated subscription dispatches.
///
/// The selection is a closed generated enum, never a consumer string or caller-defined spec. Each
/// requested dispatch must name exactly one compiled generated subscription before live bindings
/// can enter the normal exact-set bridge.
pub fn bridge_generated_subscriptions_selected(
    bindings: Vec<SubscriberBinding>,
    selected: &[SubscriptionDispatchKey],
) -> anyhow::Result<BridgedSubscriptions> {
    for (index, dispatch) in selected.iter().copied().enumerate() {
        anyhow::ensure!(
            !selected[..index].contains(&dispatch),
            "placement-selected subscription dispatch is duplicated"
        );
        let matches = generated::event::EVENTS
            .iter()
            .flat_map(|event| event.subscriptions())
            .filter(|subscription| {
                subscription.dispatch() == dispatch && admitted_dispatch(dispatch)
            })
            .count();
        anyhow::ensure!(
            matches == 1,
            "placement-selected subscription dispatch has {matches} compiled generated specs"
        );
    }
    bridge_subscriptions_with_events_selected(bindings, generated::event::EVENTS, |dispatch| {
        selected.contains(&dispatch)
    })
}

/// Bridge the exact generated Identity-to-Audit subscription family.
///
/// This entrypoint deliberately ignores unrelated compiled consumer features. Cargo feature
/// unification can enable settings consumers in the same workspace build, but a smaller assembly
/// must still prove and activate only its declared five-subscription topology.
#[cfg(feature = "audit-consumers")]
pub fn bridge_generated_audit_subscriptions(
    bindings: Vec<SubscriberBinding>,
) -> anyhow::Result<BridgedSubscriptions> {
    bridge_subscriptions_with_events_selected(
        bindings,
        generated::event::EVENTS,
        admitted_audit_dispatch,
    )
}

/// Bridge the exact generated Settings config-version reconciliation subscription.
///
/// This entrypoint remains exact when Cargo feature unification also compiles audit consumers:
/// settings assemblies can activate only the required v1 settings binding and its reconcile
/// ConsumerTx factory.
#[cfg(feature = "settings-consumers")]
pub fn bridge_generated_settings_subscriptions(
    bindings: Vec<SubscriberBinding>,
) -> anyhow::Result<BridgedSubscriptions> {
    let bridged = bridge_subscriptions_with_events_selected(
        bindings,
        generated::event::EVENTS,
        admitted_settings_dispatch,
    )?;
    let [subscription] = bridged.subscriptions() else {
        anyhow::bail!(
            "settings topology must contain exactly one config-version reconciliation subscription"
        );
    };
    anyhow::ensure!(
        subscription.contract_id() == generated::event::settings_v1::CONTRACT_ID
            && subscription.topic() == generated::event::settings_v1::TOPIC
            && subscription.schema_version() == "v1"
            && subscription.consumer() == "settings"
            && subscription.group().as_str() == generated::event::settings_v1::TOPIC
            && subscription.readiness() == SubscriberReadiness::Required
            && subscription.dispatch_token().dispatch()
                == SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            && subscription.dispatch_token().policy() == ExternalEffectPolicy::Reconcile,
        "generated settings subscription does not match the required config-version reconciliation topology"
    );
    Ok(bridged)
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn bridge_subscriptions_with_events_for_test(
    bindings: Vec<SubscriberBinding>,
    events: &[EventSpec],
) -> anyhow::Result<BridgedSubscriptions> {
    bridge_subscriptions_with_events_selected(bindings, events, admitted_dispatch)
}

fn bridge_subscriptions_with_events_selected(
    bindings: Vec<SubscriberBinding>,
    events: &[EventSpec],
    select: impl Fn(SubscriptionDispatchKey) -> bool + Copy,
) -> anyhow::Result<BridgedSubscriptions> {
    let specs: Vec<(EventSpec, SubscriptionSpec)> = events
        .iter()
        .flat_map(|event| {
            event
                .subscriptions()
                .iter()
                .filter(|subscription| select(subscription.dispatch()))
                .map(move |subscription| (*event, *subscription))
        })
        .collect();
    let mut bridged = Vec::with_capacity(bindings.len());
    let mut matched_specs = vec![false; specs.len()];
    for binding in bindings {
        let (contract_id, topic, consumer, binding_group, capability) = binding.into_parts();
        let mut matches = specs.iter().enumerate().filter(|(_, (event, spec))| {
            event.contract_id() == contract_id
                && event.topic() == topic
                && spec.consumer() == consumer
        });
        let Some((matched_index, (event, spec))) = matches.next() else {
            anyhow::bail!(
                "subscriber binding has no generated topology spec: contract={} topic={} consumer={} group={}",
                contract_id,
                topic,
                consumer,
                binding_group.as_str()
            );
        };
        if matches.next().is_some() {
            anyhow::bail!(
                "subscriber binding matches duplicate generated topology specs: contract={} topic={} consumer={} group={}",
                contract_id,
                topic,
                consumer,
                binding_group.as_str()
            );
        }
        let event = *event;
        let spec = *spec;
        let group = ConsumerGroup::parse(spec.group()).map_err(|_| {
            anyhow::anyhow!(
                "generated subscription group is invalid: contract={} consumer={} group={}",
                event.contract_id(),
                spec.consumer(),
                spec.group()
            )
        })?;
        anyhow::ensure!(
            group == binding_group,
            "subscriber group drift after generated topology parse: contract={} consumer={} group={}",
            event.contract_id(),
            spec.consumer(),
            spec.group()
        );
        anyhow::ensure!(
            !matched_specs[matched_index],
            "subscriber binding duplicates generated topology spec: contract={} topic={} consumer={} group={}",
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group()
        );
        let consumer_tx = GeneratedDispatchToken::resolve(spec, capability)?;
        matched_specs[matched_index] = true;
        bridged.push(BridgedSubscription {
            event,
            subscription: spec,
            group,
            consumer_tx,
        });
    }
    for ((event, spec), matched) in specs.iter().zip(matched_specs) {
        anyhow::ensure!(
            matched,
            "generated topology spec has no subscriber binding: contract={} topic={} consumer={} group={}",
            event.contract_id(),
            event.topic(),
            spec.consumer(),
            spec.group()
        );
    }
    let specs = bridged
        .iter()
        .map(|subscription| subscription.subscription)
        .collect::<Vec<_>>();
    let inbox_backlog = eventexec::InboxBacklogSelection::from_generated(&specs)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(BridgedSubscriptions {
        subscriptions: bridged,
        inbox_backlog,
    })
}

#[cfg(feature = "audit-consumers")]
const fn admitted_audit_dispatch(dispatch: SubscriptionDispatchKey) -> bool {
    match dispatch {
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
        | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
        | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
        | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
        | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => true,
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => false,
    }
}

#[cfg(feature = "settings-consumers")]
const fn admitted_settings_dispatch(dispatch: SubscriptionDispatchKey) -> bool {
    match dispatch {
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => true,
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
        | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
        | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
        | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
        | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => false,
    }
}

const fn admitted_dispatch(dispatch: SubscriptionDispatchKey) -> bool {
    match dispatch {
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
        | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
        | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
        | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
        | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => {
            cfg!(feature = "audit-consumers")
        }
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
            cfg!(feature = "settings-consumers")
        }
    }
}

fn topic_owner(topic: &str) -> String {
    topic
        .split('.')
        .next()
        .unwrap_or(topic)
        .to_ascii_lowercase()
}

fn resolve_parts(
    dispatch: SubscriptionDispatchKey,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    policy: ExternalEffectPolicy,
    capability: SubscriberCapability,
) -> anyhow::Result<GeneratedDispatchToken> {
    match policy {
        ExternalEffectPolicy::TransactionalOnly | ExternalEffectPolicy::Reconcile => {}
        ExternalEffectPolicy::IdempotencyKey | ExternalEffectPolicy::Compensated => {
            anyhow::bail!(
                "unsupported active ConsumerTx external-effect policy: dispatch={dispatch:?} policy={policy:?}"
            );
        }
    }

    // Exhaustive generated match is deliberate. A future generated subscription cannot silently
    // skip its concrete factory mapping: the new enum variant fails this crate at compile time.
    let plan = match dispatch {
        SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => {
            #[cfg(feature = "audit-consumers")]
            {
                require_adapter_native(dispatch, execution, effect, policy, capability)?;
                DispatchPlan::SessionCreated
            }
            #[cfg(not(feature = "audit-consumers"))]
            return Err(feature_disabled(dispatch, "audit-consumers"));
        }
        SubscriptionDispatchKey::IdentityRoleAssignedV1Audit => {
            #[cfg(feature = "audit-consumers")]
            {
                require_adapter_native(dispatch, execution, effect, policy, capability)?;
                DispatchPlan::RoleAssigned
            }
            #[cfg(not(feature = "audit-consumers"))]
            return Err(feature_disabled(dispatch, "audit-consumers"));
        }
        SubscriptionDispatchKey::IdentityRoleRevokedV1Audit => {
            #[cfg(feature = "audit-consumers")]
            {
                require_adapter_native(dispatch, execution, effect, policy, capability)?;
                DispatchPlan::RoleRevoked
            }
            #[cfg(not(feature = "audit-consumers"))]
            return Err(feature_disabled(dispatch, "audit-consumers"));
        }
        SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit => {
            #[cfg(feature = "audit-consumers")]
            {
                require_adapter_native(dispatch, execution, effect, policy, capability)?;
                DispatchPlan::PolicyUpdated
            }
            #[cfg(not(feature = "audit-consumers"))]
            return Err(feature_disabled(dispatch, "audit-consumers"));
        }
        SubscriptionDispatchKey::IdentitySecurityEventV1Audit => {
            #[cfg(feature = "audit-consumers")]
            {
                require_adapter_native(dispatch, execution, effect, policy, capability)?;
                DispatchPlan::SecurityEvent
            }
            #[cfg(not(feature = "audit-consumers"))]
            return Err(feature_disabled(dispatch, "audit-consumers"));
        }
        SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
            #[cfg(feature = "settings-consumers")]
            {
                DispatchPlan::ConfigVersionChanged(require_settings_reconcile(
                    dispatch, execution, effect, policy, capability,
                )?)
            }
            #[cfg(not(feature = "settings-consumers"))]
            return Err(feature_disabled(dispatch, "settings-consumers"));
        }
    };
    Ok(GeneratedDispatchToken {
        dispatch,
        policy,
        plan,
    })
}

#[cfg(not(all(feature = "audit-consumers", feature = "settings-consumers")))]
fn feature_disabled(dispatch: SubscriptionDispatchKey, feature: &'static str) -> anyhow::Error {
    anyhow::anyhow!("generated ConsumerTx dispatch {dispatch:?} requires feature `{feature}`")
}

#[cfg(feature = "audit-consumers")]
fn require_adapter_native(
    dispatch: SubscriptionDispatchKey,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    policy: ExternalEffectPolicy,
    capability: SubscriberCapability,
) -> anyhow::Result<()> {
    let generated_matches = matches!(
        (execution, effect, policy),
        (
            SubscriptionExecution::AdapterNative,
            None,
            ExternalEffectPolicy::TransactionalOnly
        )
    );
    match capability {
        SubscriberCapability::AdapterNativeTransactional if generated_matches => Ok(()),
        SubscriberCapability::AdapterNativeTransactional
        | SubscriberCapability::DomainReconcile(_) => anyhow::bail!(
            "adapter-native subscription dispatch or runtime capability mismatch: dispatch={dispatch:?} execution={execution:?} effect={effect:?} policy={policy:?}"
        ),
    }
}

#[cfg(feature = "settings-consumers")]
fn require_settings_reconcile(
    dispatch: SubscriptionDispatchKey,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    policy: ExternalEffectPolicy,
    capability: SubscriberCapability,
) -> anyhow::Result<Arc<settings::ConfigVersionReconciler>> {
    let generated_matches = matches!(
        (execution, effect, policy),
        (
            SubscriptionExecution::DomainEffect,
            Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            ExternalEffectPolicy::Reconcile
        )
    );
    match capability {
        SubscriberCapability::DomainReconcile(effect) if generated_matches => effect
            .into_owner::<settings::ConfigVersionReconciler>()
            .map_err(|_| {
                anyhow::anyhow!(
                    "settings config-version refresh owner capability mismatch: dispatch={dispatch:?}"
                )
            }),
        SubscriberCapability::AdapterNativeTransactional
        | SubscriberCapability::DomainReconcile(_) => anyhow::bail!(
            "settings config-version refresh subscription dispatch or runtime capability mismatch: dispatch={dispatch:?} execution={execution:?} effect={effect:?} policy={policy:?}"
        ),
    }
}

/// Closed inputs required to construct one supervised ConsumerTx worker.
pub struct WorkerInputs {
    worker_name: String,
    subscriber: Box<diport::DynAckableSubscriber<'static>>,
    topic: diport::Topic,
    idempotency: Arc<postgres::PgInboxStore>,
    dlx: Box<diport::DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    lease_cfg: LeaseConfig,
    health: Arc<WorkerHealth>,
    admission: primitives::ConsumerAdmission,
}

impl WorkerInputs {
    /// Construct the full worker dependency bundle. No field is externally replaceable after
    /// construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_name: String,
        subscriber: Box<diport::DynAckableSubscriber<'static>>,
        topic: diport::Topic,
        idempotency: Arc<postgres::PgInboxStore>,
        dlx: Box<diport::DynDeadLetterStore<'static>>,
        meta: ConsumerMeta,
        lease_cfg: LeaseConfig,
        health: Arc<WorkerHealth>,
        admission: primitives::ConsumerAdmission,
    ) -> Self {
        Self {
            worker_name,
            subscriber,
            topic,
            idempotency,
            dlx,
            meta,
            lease_cfg,
            health,
            admission,
        }
    }
}

#[cfg(feature = "audit-consumers")]
/// Factory for the five generated audit ConsumerTx handlers.
pub struct AuditConsumerFactory<'a> {
    pg: &'a postgres::PgRuntimeHandle,
    audit_key: &'a primitives::MacKey,
}

#[cfg(feature = "audit-consumers")]
impl<'a> AuditConsumerFactory<'a> {
    /// Bind the verified Postgres runtime and audit chain key.
    #[must_use]
    pub const fn new(pg: &'a postgres::PgRuntimeHandle, audit_key: &'a primitives::MacKey) -> Self {
        Self { pg, audit_key }
    }

    /// Build the worker selected by an opaque generated audit dispatch token.
    pub fn worker(
        self,
        token: GeneratedDispatchToken,
        inputs: WorkerInputs,
    ) -> anyhow::Result<WorkerSpec> {
        use audit::ports::AuditChainHasher;
        use crypto::RustCryptoMacVerifier;

        let hasher = || {
            AuditChainHasher::new(RustCryptoMacVerifier, self.audit_key.clone()).ok_or_else(|| {
                anyhow::anyhow!(
                    "audit chain key must be at least 32 bytes (weak key; INVARIANT: AUDIT-LEDGER-BYTES-01)"
                )
            })
        };
        match token.plan {
            DispatchPlan::SessionCreated => {
                let handler = self
                    .pg
                    .for_domain::<postgres::caps::Audit>()
                    .session_created_consumer_tx(hasher().map_err(|error| {
                        error.context("audit session-created consumer tx chain key")
                    })?);
                Ok(worker_spec::<policy::TransactionalOnly, _>(inputs, handler))
            }
            DispatchPlan::RoleAssigned => {
                let handler = self
                    .pg
                    .for_domain::<postgres::caps::Audit>()
                    .role_assigned_consumer_tx(hasher().map_err(|error| {
                        error.context("audit role-assigned consumer tx chain key")
                    })?);
                Ok(worker_spec::<policy::TransactionalOnly, _>(inputs, handler))
            }
            DispatchPlan::RoleRevoked => {
                let handler = self
                    .pg
                    .for_domain::<postgres::caps::Audit>()
                    .role_revoked_consumer_tx(hasher().map_err(|error| {
                        error.context("audit role-revoked consumer tx chain key")
                    })?);
                Ok(worker_spec::<policy::TransactionalOnly, _>(inputs, handler))
            }
            DispatchPlan::PolicyUpdated => {
                let handler = self
                    .pg
                    .for_domain::<postgres::caps::Audit>()
                    .policy_updated_consumer_tx(hasher().map_err(|error| {
                        error.context("audit policy-updated consumer tx chain key")
                    })?);
                Ok(worker_spec::<policy::TransactionalOnly, _>(inputs, handler))
            }
            DispatchPlan::SecurityEvent => {
                let handler = self
                    .pg
                    .for_domain::<postgres::caps::Audit>()
                    .security_event_consumer_tx(hasher().map_err(|error| {
                        error.context("audit security-event consumer tx chain key")
                    })?);
                Ok(worker_spec::<policy::TransactionalOnly, _>(inputs, handler))
            }
            #[cfg(feature = "settings-consumers")]
            DispatchPlan::ConfigVersionChanged(_) => {
                anyhow::bail!("settings dispatch token passed to AuditConsumerFactory")
            }
        }
    }
}

#[cfg(feature = "settings-consumers")]
/// Factory for the generated settings reconcile ConsumerTx handler.
pub struct SettingsConsumerFactory<'a> {
    pg: &'a postgres::PgRuntimeHandle,
}

#[cfg(feature = "settings-consumers")]
impl<'a> SettingsConsumerFactory<'a> {
    /// Bind the verified Postgres runtime.
    #[must_use]
    pub const fn new(pg: &'a postgres::PgRuntimeHandle) -> Self {
        Self { pg }
    }

    /// Build the worker selected by an opaque generated settings dispatch token.
    pub fn worker(
        self,
        token: GeneratedDispatchToken,
        inputs: WorkerInputs,
    ) -> anyhow::Result<WorkerSpec> {
        match token.plan {
            DispatchPlan::ConfigVersionChanged(effect) => {
                let handler = self
                    .pg
                    .for_domain::<postgres::caps::Settings>()
                    .config_version_changed_consumer_tx(effect);
                Ok(worker_spec::<policy::Reconcile, _>(inputs, handler))
            }
            #[cfg(feature = "audit-consumers")]
            DispatchPlan::SessionCreated
            | DispatchPlan::RoleAssigned
            | DispatchPlan::RoleRevoked
            | DispatchPlan::PolicyUpdated
            | DispatchPlan::SecurityEvent => {
                anyhow::bail!("audit dispatch token passed to SettingsConsumerFactory")
            }
        }
    }
}

fn worker_spec<P, H>(inputs: WorkerInputs, handler: H) -> WorkerSpec
where
    P: policy::Policy,
    H: ConsumerTxHandler<P>,
{
    let WorkerInputs {
        worker_name,
        subscriber,
        topic,
        idempotency,
        dlx,
        meta,
        lease_cfg,
        health,
        admission,
    } = inputs;
    let worker_identity = format!("event-consumer:{worker_name}");
    WorkerSpec::consumer_deferred(
        worker_identity,
        &admission,
        move |token, _consumer_admission| {
            diport::DynManagedResource::new_box(spawn_consumer_ackable_tx_subscriber(
                worker_name,
                subscriber,
                topic,
                idempotency,
                dlx,
                meta,
                handler,
                lease_cfg,
                token,
                health,
                eventing::lifecycle::RetryPolicy::STANDARD,
                _consumer_admission,
                eventing::lifecycle::ShutdownBudget::STANDARD,
            ))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bootstrap::ReconcileSubscriberOwner;

    fn capability(spec: SubscriptionSpec) -> SubscriberCapability {
        match spec.dispatch() {
            SubscriptionDispatchKey::IdentityPolicyUpdatedV1Audit
            | SubscriptionDispatchKey::IdentityRoleAssignedV1Audit
            | SubscriptionDispatchKey::IdentityRoleRevokedV1Audit
            | SubscriptionDispatchKey::IdentitySecurityEventV1Audit
            | SubscriptionDispatchKey::IdentitySessionCreatedV1Audit => {
                SubscriberCapability::AdapterNativeTransactional
            }
            SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings => {
                SubscriberCapability::DomainReconcile(ReconcileSubscriberOwner::from_owner(
                    settings::ConfigVersionReconciler::test_ack(),
                ))
            }
        }
    }

    fn bindings_selected_by(
        select: fn(SubscriptionDispatchKey) -> bool,
    ) -> anyhow::Result<Vec<SubscriberBinding>> {
        let mut registry = bootstrap::Registry::new();
        macro_rules! subscribe_if_selected {
            ($spec:path, $wrapper:path) => {{
                let spec = $spec;
                if select(spec.dispatch()) {
                    $wrapper(&mut registry, capability(spec))?;
                }
            }};
        }
        subscribe_if_selected!(
            generated::event::identity_v1::policy_updated::AUDIT_SUBSCRIPTION,
            generated::event::identity_v1::policy_updated::subscribe_audit
        );
        subscribe_if_selected!(
            generated::event::identity_v1::role_assigned::AUDIT_SUBSCRIPTION,
            generated::event::identity_v1::role_assigned::subscribe_audit
        );
        subscribe_if_selected!(
            generated::event::identity_v1::role_revoked::AUDIT_SUBSCRIPTION,
            generated::event::identity_v1::role_revoked::subscribe_audit
        );
        subscribe_if_selected!(
            generated::event::identity_v1::security_event::AUDIT_SUBSCRIPTION,
            generated::event::identity_v1::security_event::subscribe_audit
        );
        subscribe_if_selected!(
            generated::event::identity_v1::session_created::AUDIT_SUBSCRIPTION,
            generated::event::identity_v1::session_created::subscribe_audit
        );
        subscribe_if_selected!(
            generated::event::settings_v1::SETTINGS_SUBSCRIPTION,
            generated::event::settings_v1::subscribe_settings
        );
        Ok(registry.drain_subscribers())
    }

    #[test]
    fn admitted_generated_specs_follow_compiled_consumer_features() {
        let admitted = generated::event::EVENTS
            .iter()
            .flat_map(|event| event.subscriptions())
            .filter(|spec| admitted_dispatch(spec.dispatch()))
            .count();
        let expected = usize::from(cfg!(feature = "audit-consumers")) * 5
            + usize::from(cfg!(feature = "settings-consumers"));
        assert_eq!(admitted, expected);
    }

    #[cfg(any(
        all(feature = "audit-consumers", not(feature = "settings-consumers")),
        all(feature = "settings-consumers", not(feature = "audit-consumers"))
    ))]
    fn admitted_bindings() -> anyhow::Result<Vec<SubscriberBinding>> {
        bindings_selected_by(admitted_dispatch)
    }

    #[cfg(all(feature = "audit-consumers", not(feature = "settings-consumers")))]
    #[test]
    fn audit_only_bridge_requires_exactly_five_audit_bindings() -> anyhow::Result<()> {
        let bridged = bridge_generated_subscriptions(admitted_bindings()?)?;
        anyhow::ensure!(
            bridged.subscriptions().len() == 5,
            "audit-only bridge must admit five specs"
        );
        anyhow::ensure!(bridged.subscriptions().iter().all(|subscription| {
            subscription.dispatch_token().policy() == ExternalEffectPolicy::TransactionalOnly
        }));
        Ok(())
    }

    #[cfg(all(feature = "settings-consumers", not(feature = "audit-consumers")))]
    #[test]
    fn settings_only_bridge_requires_exactly_one_settings_binding() -> anyhow::Result<()> {
        let bridged = bridge_generated_settings_subscriptions(admitted_bindings()?)?;
        let subscription = bridged
            .subscriptions()
            .first()
            .ok_or_else(|| anyhow::anyhow!("settings-only bridge must admit one spec"))?;
        anyhow::ensure!(bridged.subscriptions().len() == 1);
        anyhow::ensure!(subscription.dispatch_token().policy() == ExternalEffectPolicy::Reconcile);
        Ok(())
    }

    #[cfg(all(feature = "audit-consumers", feature = "settings-consumers"))]
    #[test]
    fn placement_selected_bridge_accepts_each_local_consumer_exact_set() -> anyhow::Result<()> {
        let settings = [SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings];
        let settings_bridged = bridge_generated_subscriptions_selected(
            bindings_selected_by(admitted_settings_dispatch)?,
            &settings,
        )?;
        anyhow::ensure!(settings_bridged.subscriptions().len() == 1);

        let audit = generated::event::EVENTS
            .iter()
            .flat_map(|event| event.subscriptions())
            .filter(|spec| admitted_audit_dispatch(spec.dispatch()))
            .map(|spec| spec.dispatch())
            .collect::<Vec<_>>();
        let audit_bridged = bridge_generated_subscriptions_selected(
            bindings_selected_by(admitted_audit_dispatch)?,
            &audit,
        )?;
        anyhow::ensure!(audit_bridged.subscriptions().len() == 5);
        Ok(())
    }

    #[cfg(all(feature = "audit-consumers", feature = "settings-consumers"))]
    #[test]
    fn all_generated_dispatches_map_to_closed_factories() -> anyhow::Result<()> {
        let tokens = generated::event::EVENTS
            .iter()
            .flat_map(|event| event.subscriptions())
            .map(|spec| GeneratedDispatchToken::resolve(*spec, capability(*spec)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let audit = tokens
            .iter()
            .filter(|token| token.policy() == ExternalEffectPolicy::TransactionalOnly)
            .count();
        let settings = tokens
            .iter()
            .filter(|token| token.policy() == ExternalEffectPolicy::Reconcile)
            .count();
        assert_eq!(audit, 5);
        assert_eq!(settings, 1);
        Ok(())
    }

    #[cfg(all(feature = "audit-consumers", feature = "settings-consumers"))]
    #[test]
    fn audit_bridge_is_exact_under_workspace_feature_unification() -> anyhow::Result<()> {
        let audit_bindings = bindings_selected_by(admitted_audit_dispatch)?;
        assert_eq!(
            bridge_generated_audit_subscriptions(audit_bindings)?
                .subscriptions()
                .len(),
            5
        );

        let mut missing_audit = bindings_selected_by(admitted_audit_dispatch)?;
        missing_audit.pop();
        assert!(bridge_generated_audit_subscriptions(missing_audit).is_err());

        let settings_only = bindings_selected_by(|dispatch| {
            matches!(
                dispatch,
                SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            )
        })?;
        assert!(bridge_generated_audit_subscriptions(settings_only).is_err());
        Ok(())
    }

    #[cfg(all(feature = "audit-consumers", feature = "settings-consumers"))]
    #[test]
    fn settings_bridge_is_exact_under_workspace_feature_unification() -> anyhow::Result<()> {
        let settings_bindings = bindings_selected_by(|dispatch| {
            matches!(
                dispatch,
                SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            )
        })?;
        let bridged = bridge_generated_settings_subscriptions(settings_bindings)?;
        let (bridged, selection) = bridged.into_runtime_parts();
        let subscription = bridged
            .first()
            .ok_or_else(|| anyhow::anyhow!("settings bridge must admit one spec"))?;
        assert_eq!(bridged.len(), 1);
        assert_eq!(selection.groups().len(), 1);
        assert_eq!(
            selection.groups()[0].as_str(),
            subscription.group().as_str()
        );
        assert_eq!(
            subscription.contract_id(),
            "settings.config-version-changed"
        );
        assert_eq!(subscription.schema_version(), "v1");
        assert_eq!(subscription.consumer(), "settings");
        assert_eq!(
            subscription.group().as_str(),
            "settings.config-version-changed"
        );
        assert_eq!(subscription.readiness(), SubscriberReadiness::Required);
        assert_eq!(
            subscription.dispatch_token().policy(),
            ExternalEffectPolicy::Reconcile
        );

        assert!(bridge_generated_settings_subscriptions(Vec::new()).is_err());

        let audit_only = bindings_selected_by(admitted_audit_dispatch)?;
        assert!(bridge_generated_settings_subscriptions(audit_only).is_err());

        let mut duplicate = bindings_selected_by(|dispatch| {
            matches!(
                dispatch,
                SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            )
        })?;
        duplicate.extend(bindings_selected_by(|dispatch| {
            matches!(
                dispatch,
                SubscriptionDispatchKey::SettingsConfigVersionChangedV1Settings
            )
        })?);
        assert!(bridge_generated_settings_subscriptions(duplicate).is_err());

        // The typed wrapper has no contract/topic/consumer/group parameters, so a wrong group is
        // not representable at this registration seam.
        let mut typed_group_registry = bootstrap::Registry::new();
        let spec = generated::event::settings_v1::SPEC.subscriptions()[0];
        generated::event::settings_v1::subscribe_settings(
            &mut typed_group_registry,
            capability(spec),
        )?;
        let typed_group =
            bridge_generated_settings_subscriptions(typed_group_registry.drain_subscribers())?;
        assert_eq!(
            typed_group.subscriptions()[0].group().as_str(),
            generated::event::settings_v1::SETTINGS_SUBSCRIPTION.group()
        );
        Ok(())
    }

    #[cfg(feature = "settings-consumers")]
    #[test]
    fn settings_bridge_rejects_non_reconcile_policy() {
        let spec = generated::event::settings_v1::SPEC.subscriptions()[0];
        for policy in [
            ExternalEffectPolicy::TransactionalOnly,
            ExternalEffectPolicy::IdempotencyKey,
            ExternalEffectPolicy::Compensated,
        ] {
            assert!(
                resolve_parts(
                    spec.dispatch(),
                    spec.execution(),
                    spec.effect(),
                    policy,
                    capability(spec),
                )
                .is_err()
            );
        }
    }

    #[cfg(feature = "audit-consumers")]
    #[test]
    fn inactive_policies_fail_closed_before_worker_activation() {
        let spec = generated::event::identity_v1::session_created::SPEC.subscriptions()[0];
        for policy in [
            ExternalEffectPolicy::IdempotencyKey,
            ExternalEffectPolicy::Compensated,
        ] {
            assert!(
                resolve_parts(
                    spec.dispatch(),
                    spec.execution(),
                    spec.effect(),
                    policy,
                    SubscriberCapability::AdapterNativeTransactional,
                )
                .is_err()
            );
        }
    }
}
