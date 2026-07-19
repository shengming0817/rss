use assembly_schema::{
    DiportPort, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderRole,
};

const FORGED: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    DiportPort::Signer,
    ProviderConstructor::RatelimitGovernorLimiter,
    ProviderFactorySymbol::HttpserveGovernorRateLimiter,
    "ratelimit",
    &[],
    ProviderConsumer::Httpserve,
    ProviderDurability::EphemeralMemory,
    None,
    None,
    &[],
);

fn main() {
    let _ = FORGED;
}
