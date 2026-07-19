use assembly_schema::{
    DiportPort, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderRole,
};

const VALID: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    DiportPort::RateLimiter,
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
    let _ = ProviderCatalogEntry {
        role: ProviderRole::ListenerRateLimiter,
        factory: ProviderFactorySymbol::HttpserveGovernorRateLimiter,
        evidence: *VALID.evidence(),
    };
}
