//! Real Docker acceptance for two same-generation production runtime replicas.

#[path = "support/runtime_compose_fixture.rs"]
mod runtime_compose_fixture;

#[test]
fn two_replicas_survive_provider_outage_and_graceful_replacement() -> anyhow::Result<()> {
    runtime_compose_fixture::run_two_replica_acceptance()
}
