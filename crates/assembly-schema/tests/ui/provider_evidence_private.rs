use assembly_schema::{
    DiportPort, ProviderCapabilityEvidence, ProviderConstructor, ProviderConsumer,
    ProviderDurability,
};

fn main() {
    let _ = ProviderCapabilityEvidence {
        port: DiportPort::Publisher,
        constructor: ProviderConstructor::AmqpPublisher,
        provider_crate: "amqp",
        required_features: &["backend"],
        consumer: ProviderConsumer::Eventexec,
        durability: ProviderDurability::Persistent,
        outputs: &[],
    };
}
