//! Closed provider vocabulary and the canonical provider-role registry.
//!
//! A manifest may select only a registered role. Every other provider fact is
//! checked against that role before code generation, planning, or locking.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiportProvider {
    pub id: ProviderRole,
    pub port: DiportPort,
    pub provider: ProviderConstructor,
    #[serde(rename = "providerCrate")]
    pub provider_crate: String,
    #[serde(default, rename = "requiredFeatures")]
    pub required_features: Vec<String>,
    pub consumer: ProviderConsumer,
    pub lifecycle: ProviderLifecycle,
    pub durability: ProviderDurability,
    #[serde(default)]
    pub scope: Option<ProviderScope>,
    #[serde(default, rename = "failurePosture")]
    pub failure_posture: Option<ProviderFailurePosture>,
    pub purpose: String,
    pub outputs: Vec<LifecycleChannel>,
}

impl DiportProvider {
    pub(crate) fn registry_mismatch_fields(&self) -> Vec<ProviderRegistryMismatch> {
        let expected = provider_role_spec(self.id);
        let mut mismatches = Vec::new();
        if self.port != expected.port {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.port",
                expected.port.as_str(),
                self.port.as_str(),
            ));
        }
        if self.provider != expected.constructor {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.provider",
                expected.constructor.as_str(),
                self.provider.as_str(),
            ));
        }
        if self.provider_crate != expected.provider_crate {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.providerCrate",
                format!("{:?}", expected.provider_crate),
                format!("{:?}", self.provider_crate),
            ));
        }
        if !same_string_set(&self.required_features, expected.required_features) {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.requiredFeatures",
                render_string_set(expected.required_features.iter().copied()),
                render_string_set(self.required_features.iter().map(String::as_str)),
            ));
        }
        if self.consumer != expected.consumer {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.consumer",
                expected.consumer.as_str(),
                self.consumer.as_str(),
            ));
        }
        if self.lifecycle != expected.lifecycle {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.lifecycle",
                expected.lifecycle.as_str(),
                self.lifecycle.as_str(),
            ));
        }
        if self.durability != expected.durability {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.durability",
                expected.durability.as_str(),
                self.durability.as_str(),
            ));
        }
        if self.scope != expected.scope {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.scope",
                render_optional(expected.scope.map(ProviderScope::as_str)),
                render_optional(self.scope.map(ProviderScope::as_str)),
            ));
        }
        if self.failure_posture != expected.failure_posture {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.failurePosture",
                render_optional(expected.failure_posture.map(ProviderFailurePosture::as_str)),
                render_optional(self.failure_posture.map(ProviderFailurePosture::as_str)),
            ));
        }
        if !same_channel_set(&self.outputs, expected.outputs) {
            mismatches.push(ProviderRegistryMismatch::new(
                "diportProviders.outputs",
                render_channel_set(expected.outputs),
                render_channel_set(&self.outputs),
            ));
        }
        mismatches
    }
}

fn render_optional(value: Option<&str>) -> String {
    value.map_or_else(|| "unset".to_owned(), ToOwned::to_owned)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderRegistryMismatch {
    pub(crate) field: &'static str,
    pub(crate) expected: String,
    pub(crate) actual: String,
}

impl ProviderRegistryMismatch {
    fn new(field: &'static str, expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            field,
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

fn render_string_set<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    format!("{values:?}")
}

fn render_channel_set(values: &[LifecycleChannel]) -> String {
    let mut values = values
        .iter()
        .map(|value| value.as_str())
        .collect::<Vec<_>>();
    values.sort_unstable();
    format!("{values:?}")
}

fn same_string_set(actual: &[String], expected: &[&str]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut actual: Vec<_> = actual.iter().map(String::as_str).collect();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    actual == expected
}

fn same_channel_set(actual: &[LifecycleChannel], expected: &[LifecycleChannel]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let mut actual = actual.to_vec();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    actual == expected
}

/// Closed runtime activation owner for a provider role.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "domain",
    deny_unknown_fields
)]
pub enum ProviderActivation {
    Process,
    DomainLocal(crate::AssemblyDomain),
    LocalEventExecution,
}

macro_rules! provider_roles {
    ($( $variant:ident => $wire:literal ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
        #[repr(u8)]
        pub enum ProviderRole {
            $( #[serde(rename = $wire)] $variant, )+
        }

        impl ProviderRole {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            const COUNT: usize = Self::ALL.len();

            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }

            pub const fn activation(self) -> ProviderActivation {
                provider_role_spec(self).activation
            }
        }

        const _: () = {
            let mut index = 0;
            while index < ProviderRole::COUNT {
                assert!(
                    ProviderRole::ALL[index] as usize == index,
                    "provider role discriminants must remain contiguous"
                );
                index += 1;
            }
        };
    };
}

provider_roles! {
    EventPublisher => "event-publisher",
    EventSubscriber => "event-subscriber",
    ListenerRateLimiter => "listener-rate-limiter",
    DistributedLockStore => "distributed-lock-store",
    DistributedCasStoreAlternative => "distributed-cas-store-alternative",
    RuntimeObjectStore => "runtime-object-store",
    DlxArchiveStore => "dlx-archive-store",
    DlxArchiveKeyProvider => "dlx-archive-key-provider",
    DlxHotKeyProvider => "dlx-hot-key-provider",
}

impl ProviderRole {
    pub const fn factory_symbol(self) -> Option<ProviderFactorySymbol> {
        provider_role_spec(self).factory
    }
}

impl Ord for ProviderRole {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for ProviderRole {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderConsumer {
    Eventexec,
    Httpserve,
    Distributed,
    Runtime,
}

impl ProviderConsumer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eventexec => "eventexec",
            Self::Httpserve => "httpserve",
            Self::Distributed => "distributed",
            Self::Runtime => "runtime",
        }
    }
}

macro_rules! provider_factory_symbols {
    ($( $variant:ident => $wire:literal ),+ $(,)?) => {
        /// Closed identity of a provider factory. These are evidence symbols,
        /// not dynamically callable paths.
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
        )]
        #[repr(u8)]
        pub enum ProviderFactorySymbol {
            $( #[serde(rename = $wire)] $variant, )+
        }

        impl ProviderFactorySymbol {
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }
        }
    };
}

provider_factory_symbols! {
    EventexecAmqpPublisher => "eventexec::amqp-publisher",
    EventexecAmqpSubscriber => "eventexec::amqp-subscriber",
    HttpserveRedisRateLimiter => "httpserve::redis-rate-limiter",
    DistributedRedisLockStore => "distributed::redis-lock-store",
    RuntimeS3ObjectStore => "runtime::s3-object-store",
    EventexecS3DlxArchiveStore => "eventexec::s3-dlx-archive-store",
    EventexecVaultArchiveKeyProvider => "eventexec::vault-archive-key-provider",
    EventexecVaultHotKeyProvider => "eventexec::vault-hot-key-provider",
}

/// Closed registry of provider constructors accepted by an AssemblyManifest and RuntimePlan v3.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
pub enum ProviderConstructor {
    #[serde(rename = "redis::RedisRateLimiter")]
    RedisRateLimiter,
    #[serde(rename = "amqp::AmqpPublisher")]
    AmqpPublisher,
    #[serde(rename = "amqp::AmqpSubscriber")]
    AmqpSubscriber,
    #[serde(rename = "redis::RedisLockStore")]
    RedisLockStore,
    #[serde(rename = "redis::RedisCasStore")]
    RedisCasStore,
    #[serde(rename = "vault::VaultKeyProvider")]
    VaultKeyProvider,
    #[serde(rename = "s3::S3Store")]
    S3Store,
    #[serde(rename = "s3::VerifiedS3DlxArchiveStore")]
    S3VerifiedDlxArchiveStore,
}

impl ProviderConstructor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RedisRateLimiter => "redis::RedisRateLimiter",
            Self::AmqpPublisher => "amqp::AmqpPublisher",
            Self::AmqpSubscriber => "amqp::AmqpSubscriber",
            Self::RedisLockStore => "redis::RedisLockStore",
            Self::RedisCasStore => "redis::RedisCasStore",
            Self::VaultKeyProvider => "vault::VaultKeyProvider",
            Self::S3Store => "s3::S3Store",
            Self::S3VerifiedDlxArchiveStore => "s3::VerifiedS3DlxArchiveStore",
        }
    }

    /// Constructor-level DI port used by dependency checks. Manifest catalog
    /// identity is validated by the role registry, not by this helper.
    pub const fn port(self) -> DiportPort {
        match self {
            Self::RedisRateLimiter => DiportPort::RateLimiter,
            Self::AmqpPublisher => DiportPort::Publisher,
            Self::AmqpSubscriber => DiportPort::AckableSubscriber,
            Self::RedisLockStore => DiportPort::Lock,
            Self::RedisCasStore => DiportPort::Cas,
            Self::VaultKeyProvider => DiportPort::KeyProvider,
            Self::S3Store => DiportPort::ObjectStore,
            Self::S3VerifiedDlxArchiveStore => DiportPort::DlxArchiveStore,
        }
    }

    /// Provider-crate feature requirements used by Cargo graph validation.
    pub const fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::AmqpPublisher
            | Self::AmqpSubscriber
            | Self::RedisRateLimiter
            | Self::RedisLockStore
            | Self::RedisCasStore
            | Self::VaultKeyProvider
            | Self::S3Store
            | Self::S3VerifiedDlxArchiveStore => &["backend"],
        }
    }

    pub const fn durability(self) -> ProviderDurability {
        ProviderDurability::Persistent
    }

    pub const fn provider_crate(self) -> &'static str {
        match self {
            Self::RedisRateLimiter => "redis",
            Self::AmqpPublisher | Self::AmqpSubscriber => "amqp",
            Self::RedisLockStore | Self::RedisCasStore => "redis",
            Self::VaultKeyProvider => "vault",
            Self::S3Store | Self::S3VerifiedDlxArchiveStore => "s3",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleChannel {
    Probes,
    Resources,
    Workers,
}

impl LifecycleChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Probes => "probes",
            Self::Resources => "resources",
            Self::Workers => "workers",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
pub enum DiportPort {
    #[serde(rename = "diport::Publisher")]
    Publisher,
    #[serde(rename = "diport::AckableSubscriber")]
    AckableSubscriber,
    #[serde(rename = "diport::KeyProvider")]
    KeyProvider,
    #[serde(rename = "diport::RateLimiter")]
    RateLimiter,
    #[serde(rename = "diport::LockStore")]
    Lock,
    #[serde(rename = "diport::CasStore")]
    Cas,
    #[serde(rename = "diport::ObjectStore")]
    ObjectStore,
    #[serde(rename = "diport::DlxArchiveStore")]
    DlxArchiveStore,
}

impl DiportPort {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publisher => "diport::Publisher",
            Self::AckableSubscriber => "diport::AckableSubscriber",
            Self::KeyProvider => "diport::KeyProvider",
            Self::RateLimiter => "diport::RateLimiter",
            Self::Lock => "diport::LockStore",
            Self::Cas => "diport::CasStore",
            Self::ObjectStore => "diport::ObjectStore",
            Self::DlxArchiveStore => "diport::DlxArchiveStore",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "lowercase")]
pub enum ProviderLifecycle {
    Draft,
    Active,
    Deprecated,
}

impl ProviderLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderDurability {
    EphemeralMemory,
    Persistent,
}

impl ProviderDurability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EphemeralMemory => "ephemeral-memory",
            Self::Persistent => "persistent",
        }
    }
}

/// Provider state visibility across runtime replicas.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderScope {
    ProcessLocal,
    ClusterGlobal,
}

impl ProviderScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLocal => "process-local",
            Self::ClusterGlobal => "cluster-global",
        }
    }
}

/// Authentication behavior when a required provider cannot complete.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderFailurePosture {
    FailOpen,
    FailClosed,
}

impl ProviderFailurePosture {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailOpen => "fail-open",
            Self::FailClosed => "fail-closed",
        }
    }
}

macro_rules! display_as_str {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    )+};
}

display_as_str!(
    ProviderRole,
    ProviderConsumer,
    ProviderFactorySymbol,
    ProviderConstructor,
    LifecycleChannel,
    DiportPort,
    ProviderLifecycle,
    ProviderDurability,
    ProviderScope,
    ProviderFailurePosture,
);

#[derive(Debug, Clone, Copy)]
struct ProviderRoleSpec {
    role: ProviderRole,
    activation: ProviderActivation,
    lifecycle: ProviderLifecycle,
    port: DiportPort,
    constructor: ProviderConstructor,
    provider_crate: &'static str,
    required_features: &'static [&'static str],
    consumer: ProviderConsumer,
    durability: ProviderDurability,
    scope: Option<ProviderScope>,
    failure_posture: Option<ProviderFailurePosture>,
    outputs: &'static [LifecycleChannel],
    factory: Option<ProviderFactorySymbol>,
}

const P: LifecycleChannel = LifecycleChannel::Probes;
const R: LifecycleChannel = LifecycleChannel::Resources;
const W: LifecycleChannel = LifecycleChannel::Workers;

const PROVIDER_ROLE_SPECS: [ProviderRoleSpec; ProviderRole::COUNT] = [
    ProviderRoleSpec {
        role: ProviderRole::EventPublisher,
        activation: ProviderActivation::LocalEventExecution,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::Publisher,
        constructor: ProviderConstructor::AmqpPublisher,
        provider_crate: "amqp",
        required_features: &["backend"],
        consumer: ProviderConsumer::Eventexec,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[P, R, W],
        factory: Some(ProviderFactorySymbol::EventexecAmqpPublisher),
    },
    ProviderRoleSpec {
        role: ProviderRole::EventSubscriber,
        activation: ProviderActivation::LocalEventExecution,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::AckableSubscriber,
        constructor: ProviderConstructor::AmqpSubscriber,
        provider_crate: "amqp",
        required_features: &["backend"],
        consumer: ProviderConsumer::Eventexec,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[P, R, W],
        factory: Some(ProviderFactorySymbol::EventexecAmqpSubscriber),
    },
    ProviderRoleSpec {
        role: ProviderRole::ListenerRateLimiter,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::RateLimiter,
        constructor: ProviderConstructor::RedisRateLimiter,
        provider_crate: "redis",
        required_features: &["backend"],
        consumer: ProviderConsumer::Httpserve,
        durability: ProviderDurability::Persistent,
        scope: Some(ProviderScope::ClusterGlobal),
        failure_posture: Some(ProviderFailurePosture::FailOpen),
        outputs: &[],
        factory: Some(ProviderFactorySymbol::HttpserveRedisRateLimiter),
    },
    ProviderRoleSpec {
        role: ProviderRole::DistributedLockStore,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::Lock,
        constructor: ProviderConstructor::RedisLockStore,
        provider_crate: "redis",
        required_features: &["backend"],
        consumer: ProviderConsumer::Distributed,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[P, R, W],
        factory: Some(ProviderFactorySymbol::DistributedRedisLockStore),
    },
    ProviderRoleSpec {
        role: ProviderRole::DistributedCasStoreAlternative,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Draft,
        port: DiportPort::Cas,
        constructor: ProviderConstructor::RedisCasStore,
        provider_crate: "redis",
        required_features: &["backend"],
        consumer: ProviderConsumer::Distributed,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[R],
        factory: None,
    },
    ProviderRoleSpec {
        role: ProviderRole::RuntimeObjectStore,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::ObjectStore,
        constructor: ProviderConstructor::S3Store,
        provider_crate: "s3",
        required_features: &["backend"],
        consumer: ProviderConsumer::Runtime,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[R],
        factory: Some(ProviderFactorySymbol::RuntimeS3ObjectStore),
    },
    ProviderRoleSpec {
        role: ProviderRole::DlxArchiveStore,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::DlxArchiveStore,
        constructor: ProviderConstructor::S3VerifiedDlxArchiveStore,
        provider_crate: "s3",
        required_features: &["backend"],
        consumer: ProviderConsumer::Eventexec,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[P, W],
        factory: Some(ProviderFactorySymbol::EventexecS3DlxArchiveStore),
    },
    ProviderRoleSpec {
        role: ProviderRole::DlxArchiveKeyProvider,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::KeyProvider,
        constructor: ProviderConstructor::VaultKeyProvider,
        provider_crate: "vault",
        required_features: &["backend"],
        consumer: ProviderConsumer::Eventexec,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[P, R, W],
        factory: Some(ProviderFactorySymbol::EventexecVaultArchiveKeyProvider),
    },
    ProviderRoleSpec {
        role: ProviderRole::DlxHotKeyProvider,
        activation: ProviderActivation::Process,
        lifecycle: ProviderLifecycle::Active,
        port: DiportPort::KeyProvider,
        constructor: ProviderConstructor::VaultKeyProvider,
        provider_crate: "vault",
        required_features: &["backend"],
        consumer: ProviderConsumer::Eventexec,
        durability: ProviderDurability::Persistent,
        scope: None,
        failure_posture: None,
        outputs: &[P, R, W],
        factory: Some(ProviderFactorySymbol::EventexecVaultHotKeyProvider),
    },
];

const fn provider_role_spec(role: ProviderRole) -> &'static ProviderRoleSpec {
    &PROVIDER_ROLE_SPECS[role as usize]
}

/// Whether the closed provider registry assigns at least one local provider to `domain`.
#[must_use]
pub fn has_domain_local_provider_activation(domain: crate::AssemblyDomain) -> bool {
    PROVIDER_ROLE_SPECS.iter().any(|spec| {
        spec.activation == ProviderActivation::DomainLocal(domain)
            && spec.lifecycle == ProviderLifecycle::Active
    })
}

const fn str_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn str_slice_eq(left: &[&str], right: &[&str]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if !str_eq(left[index], right[index]) {
            return false;
        }
        index += 1;
    }
    true
}

const fn channel_slice_eq(left: &[LifecycleChannel], right: &[LifecycleChannel]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] as u8 != right[index] as u8 {
            return false;
        }
        index += 1;
    }
    true
}

const fn assert_registry_invariants(specs: &[ProviderRoleSpec]) {
    assert!(
        specs.len() == ProviderRole::COUNT,
        "every provider role requires exactly one registry spec"
    );
    let mut index = 0;
    while index < specs.len() {
        let spec = &specs[index];
        assert!(
            spec.role as usize == index,
            "provider role registry order drift"
        );
        assert!(
            spec.port as u8 == spec.constructor.port() as u8,
            "provider role port must match its constructor"
        );
        assert!(
            str_eq(spec.provider_crate, spec.constructor.provider_crate()),
            "provider role crate must match its constructor"
        );
        assert!(
            str_slice_eq(spec.required_features, spec.constructor.required_features()),
            "provider role features must match its constructor"
        );
        assert!(
            spec.durability as u8 == spec.constructor.durability() as u8,
            "provider role durability must match its constructor"
        );
        let active = spec.lifecycle as u8 == ProviderLifecycle::Active as u8;
        assert!(
            active == spec.factory.is_some(),
            "active roles require one factory; non-active roles require none"
        );
        if let Some(factory) = spec.factory {
            let mut other = index + 1;
            while other < specs.len() {
                if let Some(other_factory) = specs[other].factory {
                    assert!(
                        factory as u8 != other_factory as u8,
                        "provider factory symbols must be unique"
                    );
                }
                other += 1;
            }
        }
        index += 1;
    }
}

const _: () = assert_registry_invariants(&PROVIDER_ROLE_SPECS);

/// Canonical capability evidence. Fields and construction are intentionally
/// private; only a checked catalog entry can expose this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapabilityEvidence {
    port: DiportPort,
    constructor: ProviderConstructor,
    provider_crate: &'static str,
    required_features: &'static [&'static str],
    consumer: ProviderConsumer,
    durability: ProviderDurability,
    scope: Option<ProviderScope>,
    failure_posture: Option<ProviderFailurePosture>,
    outputs: &'static [LifecycleChannel],
}

impl ProviderCapabilityEvidence {
    pub const fn port(&self) -> DiportPort {
        self.port
    }

    pub const fn constructor(&self) -> ProviderConstructor {
        self.constructor
    }

    pub const fn provider_crate(&self) -> &'static str {
        self.provider_crate
    }

    pub const fn required_features(&self) -> &'static [&'static str] {
        self.required_features
    }

    pub const fn consumer(&self) -> ProviderConsumer {
        self.consumer
    }

    pub const fn durability(&self) -> ProviderDurability {
        self.durability
    }

    pub const fn scope(&self) -> Option<ProviderScope> {
        self.scope
    }

    pub const fn failure_posture(&self) -> Option<ProviderFailurePosture> {
        self.failure_posture
    }

    pub const fn outputs(&self) -> &'static [LifecycleChannel] {
        self.outputs
    }
}

/// A compile-time checked active provider catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCatalogEntry {
    role: ProviderRole,
    activation: ProviderActivation,
    factory: ProviderFactorySymbol,
    evidence: ProviderCapabilityEvidence,
}

impl ProviderCatalogEntry {
    #[allow(clippy::too_many_arguments)]
    pub const fn checked(
        role: ProviderRole,
        activation: ProviderActivation,
        port: DiportPort,
        constructor: ProviderConstructor,
        factory: ProviderFactorySymbol,
        provider_crate: &'static str,
        required_features: &'static [&'static str],
        consumer: ProviderConsumer,
        durability: ProviderDurability,
        scope: Option<ProviderScope>,
        failure_posture: Option<ProviderFailurePosture>,
        outputs: &'static [LifecycleChannel],
    ) -> Self {
        let spec = provider_role_spec(role);
        assert!(
            provider_activation_eq(role.activation(), activation),
            "provider activation drift"
        );
        assert!(
            spec.lifecycle as u8 == ProviderLifecycle::Active as u8,
            "draft provider roles cannot enter an active catalog"
        );
        assert!(spec.port as u8 == port as u8, "provider port drift");
        assert!(
            spec.constructor as u8 == constructor as u8,
            "provider constructor drift"
        );
        assert!(
            spec.factory.is_some(),
            "active provider role has no factory"
        );
        let expected_factory = match spec.factory {
            Some(value) => value,
            // Unreachable after the const assertion; a concrete value keeps
            // this function const without exposing an unchecked constructor.
            None => ProviderFactorySymbol::EventexecAmqpPublisher,
        };
        assert!(
            expected_factory as u8 == factory as u8,
            "provider factory drift"
        );
        assert!(
            str_eq(spec.provider_crate, provider_crate),
            "provider crate drift"
        );
        assert!(
            str_slice_eq(spec.required_features, required_features),
            "provider feature drift"
        );
        assert!(
            spec.consumer as u8 == consumer as u8,
            "provider consumer drift"
        );
        assert!(
            spec.durability as u8 == durability as u8,
            "provider durability drift"
        );
        assert!(optional_scope_eq(spec.scope, scope), "provider scope drift");
        assert!(
            optional_failure_posture_eq(spec.failure_posture, failure_posture),
            "provider failure posture drift"
        );
        assert!(
            channel_slice_eq(spec.outputs, outputs),
            "provider output drift"
        );
        Self {
            role: spec.role,
            activation,
            factory: expected_factory,
            evidence: ProviderCapabilityEvidence {
                port: spec.port,
                constructor: spec.constructor,
                provider_crate: spec.provider_crate,
                required_features: spec.required_features,
                consumer: spec.consumer,
                durability: spec.durability,
                scope: spec.scope,
                failure_posture: spec.failure_posture,
                outputs: spec.outputs,
            },
        }
    }

    pub const fn role(&self) -> ProviderRole {
        self.role
    }

    pub const fn activation(&self) -> ProviderActivation {
        self.activation
    }

    pub const fn factory(&self) -> ProviderFactorySymbol {
        self.factory
    }

    pub const fn evidence(&self) -> &ProviderCapabilityEvidence {
        &self.evidence
    }
}

const fn provider_activation_eq(left: ProviderActivation, right: ProviderActivation) -> bool {
    match (left, right) {
        (ProviderActivation::Process, ProviderActivation::Process)
        | (ProviderActivation::LocalEventExecution, ProviderActivation::LocalEventExecution) => {
            true
        }
        (ProviderActivation::DomainLocal(left), ProviderActivation::DomainLocal(right)) => {
            left as u8 == right as u8
        }
        _ => false,
    }
}

const fn optional_scope_eq(left: Option<ProviderScope>, right: Option<ProviderScope>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left as u8 == right as u8,
        (None, None) => true,
        _ => false,
    }
}

const fn optional_failure_posture_eq(
    left: Option<ProviderFailurePosture>,
    right: Option<ProviderFailurePosture>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left as u8 == right as u8,
        (None, None) => true,
        _ => false,
    }
}
