use assembly_schema::{
    DiportPort, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderRole,
};

const FORGED: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    DiportPort::Signer,
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
    let _ = FORGED;
}
