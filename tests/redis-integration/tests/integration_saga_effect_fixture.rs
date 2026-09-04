//! Real Redis coverage for the Saga effect fixture.
//!
//! The independent integration package directly enables the Redis adapter backend.

use consistency::{SagaEffectPhase, SagaIdempotencyKey};
use deadpool_redis::{Config, Runtime};
use redis::{RedisRuntimeDeps, RedisSagaEffectApplyOutcome, RedisSagaEffectProbeOutcome};
use rss_runtime::ManagedResource;
use testkit::FixtureError;

fn unique_key() -> SagaIdempotencyKey {
    let id = uuid::Uuid::new_v4();
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(id.as_bytes());
    bytes[16..].copy_from_slice(id.as_bytes());
    SagaIdempotencyKey::from_storage(bytes, SagaEffectPhase::Forward)
}

fn make_deps(url: &str) -> Result<RedisRuntimeDeps, FixtureError> {
    let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    Ok(RedisRuntimeDeps::setup_for_test(pool))
}

#[tokio::test]
async fn integration_saga_effect_apply_duplicate_conflict_and_probe() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = make_deps(redis.url())?;
    let fixture = deps.infra().saga_effect_fixture();
    let effect_key = unique_key();
    let effect = b"provider receipt alpha";

    assert_eq!(
        fixture.probe(&effect_key).await?,
        RedisSagaEffectProbeOutcome::Missing
    );
    assert_eq!(
        fixture.apply(&effect_key, effect).await?,
        RedisSagaEffectApplyOutcome::Applied
    );
    assert_eq!(
        fixture.probe(&effect_key).await?,
        RedisSagaEffectProbeOutcome::Applied
    );
    assert_eq!(
        fixture.apply(&effect_key, effect).await?,
        RedisSagaEffectApplyOutcome::ExactDuplicate
    );
    assert_eq!(
        fixture
            .apply(&effect_key, b"provider receipt conflict")
            .await?,
        RedisSagaEffectApplyOutcome::Conflict
    );

    let observation = fixture.observation();
    assert_eq!(observation.apply_count(), 3);
    assert_eq!(observation.write_count(), 1);
    assert_eq!(observation.duplicate_count(), 1);
    assert_eq!(observation.conflict_count(), 1);
    assert_eq!(observation.probe_count(), 2);

    let fixture_debug = format!("{fixture:?}");
    let observation_debug = format!("{observation:?}");
    assert!(!fixture_debug.contains(&effect_key.to_hex()));
    assert!(!fixture_debug.contains("provider receipt"));
    assert!(!observation_debug.contains(&effect_key.to_hex()));
    assert!(!observation_debug.contains("provider receipt"));
    for resource in deps.runtime_resources().into_iter().rev() {
        resource.shutdown().await?;
    }
    Ok(())
}
