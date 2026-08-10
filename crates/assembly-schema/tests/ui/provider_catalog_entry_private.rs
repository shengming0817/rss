use assembly_schema::{
    DiportPort, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderRole,
};

const VALID: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    DiportPort::RateLimiter,
    ProviderConstructor::RedisRateLimiter,
    ProviderFactorySymbol::HttpserveRedisRateLimiter,
    "redis",
    &["backend"],
    ProviderConsumer::Httpserve,
    ProviderDurability::Persistent,
    Some(assembly_schema::ProviderScope::ClusterGlobal),
    Some(assembly_schema::ProviderFailurePosture::FailOpen),
    &[],
);

fn main() {
    let _ = ProviderCatalogEntry {
        role: ProviderRole::ListenerRateLimiter,
        factory: ProviderFactorySymbol::HttpserveRedisRateLimiter,
        evidence: *VALID.evidence(),
    };
}
