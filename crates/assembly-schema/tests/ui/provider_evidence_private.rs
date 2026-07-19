use assembly_schema::{
    DiportPort, ProviderCapabilityEvidence, ProviderConstructor, ProviderConsumer,
    ProviderDurability,
};

fn main() {
    let _ = ProviderCapabilityEvidence {
        port: DiportPort::Pdp,
        constructor: ProviderConstructor::OidcProvider,
        provider_crate: "oidc",
        required_features: &["backend"],
        consumer: ProviderConsumer::Httpserve,
        durability: ProviderDurability::Persistent,
        outputs: &[],
    };
}
