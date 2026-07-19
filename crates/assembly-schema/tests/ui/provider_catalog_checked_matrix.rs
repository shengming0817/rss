use assembly_schema::{
    DiportPort, LifecycleChannel, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer,
    ProviderDurability, ProviderFactorySymbol, ProviderRole,
};

const DRAFT: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::DeviceRevocationStore,
    DiportPort::RevocationStore,
    ProviderConstructor::SoftcaInMemRevocationLedger,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "softca",
    &["backend"],
    ProviderConsumer::Deviceloop,
    ProviderDurability::EphemeralMemory,
    &[],
);

const CONSTRUCTOR: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpSubscriber,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const FACTORY: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpSubscriber,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const PROVIDER_CRATE: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "postgres",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const FEATURES: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &[],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const CONSUMER: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Runtime,
    ProviderDurability::Persistent,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const DURABILITY: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::EphemeralMemory,
    &[
        LifecycleChannel::Probes,
        LifecycleChannel::Resources,
        LifecycleChannel::Workers,
    ],
);

const OUTPUTS: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::EventPublisher,
    DiportPort::Publisher,
    ProviderConstructor::AmqpPublisher,
    ProviderFactorySymbol::EventexecAmqpPublisher,
    "amqp",
    &["backend"],
    ProviderConsumer::Eventexec,
    ProviderDurability::Persistent,
    &[LifecycleChannel::Resources],
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
    );
}
