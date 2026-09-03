use assembly_schema::{
    DiportPort, LifecycleChannel, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer,
    ProviderDurability, ProviderFactorySymbol, ProviderFailurePosture, ProviderRole, ProviderScope,
};

const DRAFT: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::DistributedCasStoreAlternative,
    ProviderRole::DistributedCasStoreAlternative.activation(),
    DiportPort::Cas,
    ProviderConstructor::RedisCasStore,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "redis",
    &["backend"],
    ProviderConsumer::Distributed,
    ProviderDurability::Persistent,
    None,
    None,
    &[LifecycleChannel::Resources],
);

const CONSTRUCTOR: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpSubscriber,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    None,
    None,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const FACTORY: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpSubscriber,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    None,
    None,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const PROVIDER_CRATE: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "postgres",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    None,
    None,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const FEATURES: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &[],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    None,
    None,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const CONSUMER: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Runtime,
    ProviderDurability::Persistent,
    None,
    None,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const DURABILITY: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::EphemeralMemory,
    None,
    None,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const OUTPUTS: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    ProviderRole::EventPublisher.activation(),
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    None,
    None,
    &[LifecycleChannel::Resources],
);

const SCOPE: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    ProviderRole::ListenerRateLimiter.activation(),
    DiportPort::RateLimiter,
    ProviderConstructor::RedisRateLimiter,
    ProviderFactorySymbol::HttpserveRedisRateLimiter,
    "redis",
    &["backend"],
    ProviderConsumer::Httpserve,
    ProviderDurability::Persistent,
    Some(ProviderScope::ProcessLocal),
    Some(ProviderFailurePosture::FailOpen),
    &[],
);

const FAILURE_POSTURE: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    ProviderRole::ListenerRateLimiter.activation(),
    DiportPort::RateLimiter,
    ProviderConstructor::RedisRateLimiter,
    ProviderFactorySymbol::HttpserveRedisRateLimiter,
    "redis",
    &["backend"],
    ProviderConsumer::Httpserve,
    ProviderDurability::Persistent,
    Some(ProviderScope::ClusterGlobal),
    Some(ProviderFailurePosture::FailClosed),
    &[],
);

fn main() {
    let _ = (
        DRAFT,
        CONSTRUCTOR,
        FACTORY,
        PROVIDER_CRATE,
        FEATURES,
        CONSUMER,
        DURABILITY,
        OUTPUTS,
        SCOPE,
        FAILURE_POSTURE,
    );
}
