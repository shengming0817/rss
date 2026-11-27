use super::*;
use crate::{ProviderClock, ReusePolicy, test_support::reuse_policy};
use rss_request_context::SharedExecutionTimer;
use std::{sync::atomic::Ordering, time::SystemTime};
#[path = "../../../../tests/fixtures/pg_clock.rs"]
mod fixture_clock;

fn resources(cap: usize) -> anyhow::Result<Arc<Resources>> {
    Ok(Resources::new(
        ReusePolicy {
            max_resident_bytes: cap,
            ..reuse_policy()
        },
        ProviderClock::new(SharedExecutionTimer::new(fixture_clock::TestClock), || {
            SystemTime::UNIX_EPOCH
        }),
    )?)
}
fn install(state: &mut State, r: &Resources, path: &str) -> anyhow::Result<Arc<Representation>> {
    let metadata = serde_json::from_value(
        serde_json::json!({"issuer":"https://idp.test","authorization_endpoint":"https://idp.test/login","jwks_uri":format!("https://idp.test/{path}"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}),
    )?;
    let parent = Representation::admit(
        state,
        r,
        PublicDocument::Metadata(Box::new(metadata)),
        &HeaderMap::new(),
        ProviderStage::Discovery,
    )?;
    state.cached = Some(Cached {
        value: parent.clone(),
        until: r.now(),
        freshness: Default::default(),
    });
    Ok(parent)
}
#[test]
fn old_readers_share_one_child_charge_at_exact_capacity() -> anyhow::Result<()> {
    let probe = resources(1 << 20)?;
    let mut probe_state = State::default();
    install(&mut probe_state, &probe, "a")?;
    let single = probe.bytes.load(Ordering::Acquire);
    let cap = 2 * single - size_of::<Document>();
    let r = resources(cap)?;
    let mut state = State::default();
    let old = install(&mut state, &r, "a")?;
    let shared = install(&mut state, &r, "a")?;
    let child = old.keys()?.1.clone();
    assert!(Arc::ptr_eq(&child, shared.keys()?.1));
    assert_eq!(r.bytes.load(Ordering::Acquire), cap);
    assert!(install(&mut state, &r, "b").is_err());
    assert_eq!(r.bytes.load(Ordering::Acquire), cap);
    assert!(child.check().is_err());
    drop(old);
    drop(shared);
    assert_eq!(r.bytes.load(Ordering::Acquire), size_of::<Document>());
    let new = install(&mut state, &r, "b")?;
    assert!(!Arc::ptr_eq(&child, new.keys()?.1));
    drop(child);
    assert_eq!(r.bytes.load(Ordering::Acquire), single);
    drop(new);
    drop(state);
    assert_eq!(r.bytes.load(Ordering::Acquire), 0);
    Ok(())
}
