use assembly_schema::{
    DiportPort, ProviderCatalogEntry, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFactorySymbol, ProviderRole,
};

const FORGED: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    ProviderRole::ListenerRateLimiter.activation(),
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

const WRONG_ACTIVATION: ProviderCatalogEntry = ProviderCatalogEntry::checked(
    ProviderRole::ListenerRateLimiter,
    assembly_schema::ProviderActivation::LocalEventExecution,
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
    let _ = FORGED;
}
