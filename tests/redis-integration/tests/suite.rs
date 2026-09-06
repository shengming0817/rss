//! Two owned Redis lifecycles: ordinary command semantics and private-CA transport.
use redis::RedisPrivateCa;
use testkit::FixtureError;

#[path = "scenarios/claimer.rs"]
mod claimer;
#[path = "scenarios/rate_limit.rs"]
mod rate_limit;

#[tokio::test]
async fn redis_command_suite() -> Result<(), FixtureError> {
    let fixture = testkit::managed_redis().await?;
    let url = fixture.url();
    claimer::distlock_mutex_ttl_and_fencing(url)
        .await
        .map_err(|error| error.context("distlock_mutex_ttl_and_fencing"))?;
    claimer::distlock_cross_key_isolation(url)
        .await
        .map_err(|error| error.context("distlock_cross_key_isolation"))?;
    claimer::distlock_concurrent_same_key_single_winner(url)
        .await
        .map_err(|error| error.context("distlock_concurrent_same_key_single_winner"))?;
    claimer::redis_cas_three_states_and_fencing(url)
        .await
        .map_err(|error| error.context("redis_cas_three_states_and_fencing"))?;
    claimer::redis_cas_concurrent_create_has_single_winner(url)
        .await
        .map_err(|error| error.context("redis_cas_concurrent_create_has_single_winner"))?;
    claimer::redis_cas_token_overflow_fails_fast(url)
        .await
        .map_err(|error| error.context("redis_cas_token_overflow_fails_fast"))?;
    rate_limit::two_handles_share_atomic_buckets_and_expire(url)
        .await
        .map_err(|error| error.context("two_handles_share_atomic_buckets_and_expire"))?;
    rate_limit::policy_changes_have_independent_bucket_identity(url)
        .await
        .map_err(|error| error.context("policy_changes_have_independent_bucket_identity"))?;
    rate_limit::concurrent_burst_is_exactly_atomic(url)
        .await
        .map_err(|error| error.context("concurrent_burst_is_exactly_atomic"))?;
    rate_limit::saturated_pool_fails_within_limiter_budget(url)
        .await
        .map_err(|error| error.context("saturated_pool_fails_within_limiter_budget"))?;
    rate_limit::acl_without_time_rejects_startup_capability(url)
        .await
        .map_err(|error| error.context("acl_without_time_rejects_startup_capability"))?;
    Ok(())
}

#[tokio::test]
async fn private_ca_accepts_matching_redis_and_rejects_wrong_ca() -> Result<(), FixtureError> {
    let network = testkit::bridge_network("rss-redis-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::redis_tls(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: &dns_name,
    })
    .await?;
    let endpoint =
        secure::RedisEndpoint::parse(fixture.url(), secure::PlaintextEndpointPolicy::Deny)?;
    let good_ca = RedisPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?;
    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, good_ca)?;
    deps.ping().await?;

    let wrong_ca = RedisPrivateCa::from_pem(fixture.wrong_ca_pem().as_bytes().to_vec())?;
    let wrong = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, wrong_ca)?;
    assert!(wrong.ping().await.is_err());
    Ok(())
}
