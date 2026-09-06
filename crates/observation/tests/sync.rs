use rss_contract::Timepoint;
use rss_observation::{
    Batch, Body, Change, Coverage, Id, NeedSnapshot, Policy, State, SyncOutcome,
};
#[allow(clippy::expect_used)]
// reason: static valid fixture IDs.
fn id(s: &str) -> Id {
    Id::new(s).expect("fixture id")
}
fn coverage() -> Coverage {
    Coverage::new(id("all"), id("v1"), id("catalog-v1"), id("bytes-v1"))
}
#[allow(clippy::expect_used)]
// reason: bounded fixture construction.
fn batch(name: &str, seq: u64, body: Body) -> Batch {
    Batch::new(
        id(name),
        seq,
        Timepoint::try_from(10).expect("time"),
        coverage(),
        body,
    )
    .expect("fixture batch")
}
#[allow(clippy::expect_used)]
// reason: static valid fixture policy.
fn policy() -> Policy {
    Policy::new(100, 10, 20).expect("policy")
}
#[test]
#[allow(clippy::expect_used)]
// reason: fixture expectations fail the test.
fn gap_is_sticky_and_empty_snapshot_recovers() {
    let initial = State::initial();
    let snapshot = batch("base", 1, Body::Snapshot(vec![]));
    let first = initial
        .advance(&snapshot, 100, &policy())
        .expect("snapshot");
    assert_eq!(first.outcome(), &SyncOutcome::Snapshot);
    let gap = batch(
        "gap",
        3,
        Body::Delta {
            baseline: id("base"),
            previous: 2,
            changes: vec![],
        },
    );
    let second = first.state().advance(&gap, 101, &policy()).expect("gap");
    assert_eq!(
        second.outcome(),
        &SyncOutcome::NeedSnapshot(NeedSnapshot::Gap)
    );
    assert_eq!(second.state().cursor(), Some(1));
    let late = batch(
        "late",
        2,
        Body::Delta {
            baseline: id("base"),
            previous: 1,
            changes: vec![],
        },
    );
    assert!(
        !second
            .state()
            .advance(&late, 102, &policy())
            .expect("late")
            .outcome()
            .is_applicable()
    );
    let recovery = batch("recovery", 4, Body::Snapshot(vec![]));
    assert_eq!(
        second
            .state()
            .advance(&recovery, 103, &policy())
            .expect("recovery")
            .state()
            .cursor(),
        Some(4)
    );
}
#[test]
#[allow(clippy::expect_used)]
// reason: fixture expectations fail the test.
fn expiry_and_partial_do_not_clear_facts() {
    let first = State::initial()
        .advance(
            &batch(
                "s",
                0,
                Body::Snapshot(vec![Change::upsert(id("key"), vec![1])]),
            ),
            100,
            &policy(),
        )
        .expect("first");
    let delta = batch(
        "d",
        1,
        Body::Delta {
            baseline: id("s"),
            previous: 0,
            changes: vec![Change::delete(id("key"))],
        },
    );
    assert_eq!(
        first
            .state()
            .advance(&delta, 120, &policy())
            .expect("expired")
            .outcome(),
        &SyncOutcome::NeedSnapshot(NeedSnapshot::BaselineExpired)
    );
    let partial = batch("p", 1, Body::Partial(vec![]));
    let result = first
        .state()
        .advance(&partial, 101, &policy())
        .expect("partial");
    assert_eq!(result.state().cursor(), Some(0));
    assert!(!result.outcome().is_applicable());
    assert!(
        !result
            .state()
            .advance(&delta, 102, &policy())
            .expect("retry")
            .outcome()
            .is_applicable()
    );
}
#[test]
fn coverage_failure_and_ordering_matrix() -> anyhow::Result<()> {
    let p = policy();
    let initial = State::initial();
    let missing = batch(
        "missing",
        1,
        Body::Delta {
            baseline: id("unknown"),
            previous: 0,
            changes: vec![],
        },
    );
    assert_eq!(
        initial.advance(&missing, 0, &p)?.outcome(),
        &SyncOutcome::NeedSnapshot(NeedSnapshot::MissingBaseline)
    );
    let first = initial.advance(&batch("base", 1, Body::Snapshot(vec![])), 100, &p)?;
    let different = Coverage::new(id("subset"), id("v2"), id("catalog-v2"), id("bytes-v1"));
    let mismatch = Batch::new(
        id("wrong"),
        2,
        Timepoint::try_from(0)?,
        different.clone(),
        Body::Delta {
            baseline: id("base"),
            previous: 1,
            changes: vec![],
        },
    )?;
    assert_eq!(
        first.state().advance(&mismatch, 101, &p)?.outcome(),
        &SyncOutcome::NeedSnapshot(NeedSnapshot::BaselineMismatch)
    );
    let wrong_base = batch(
        "wrong-base",
        2,
        Body::Delta {
            baseline: id("other"),
            previous: 1,
            changes: vec![],
        },
    );
    assert_eq!(
        first.state().advance(&wrong_base, 101, &p)?.outcome(),
        &SyncOutcome::NeedSnapshot(NeedSnapshot::BaselineMismatch)
    );
    let failed = batch(
        "failed",
        2,
        Body::Failed {
            code: id("timeout"),
        },
    );
    let failed_state = first.state().advance(&failed, 101, &p)?;
    assert_eq!(
        failed_state.outcome(),
        &SyncOutcome::NeedSnapshot(NeedSnapshot::CollectionFailed)
    );
    let late = batch("old-full", 0, Body::Snapshot(vec![]));
    assert_eq!(
        failed_state.state().advance(&late, 102, &p)?.outcome(),
        &SyncOutcome::Stale
    );
    let changed = Batch::new(
        id("changed"),
        3,
        Timepoint::try_from(0)?,
        different,
        Body::Snapshot(vec![]),
    )?;
    assert_eq!(
        failed_state.state().advance(&changed, 102, &p)?.outcome(),
        &SyncOutcome::Snapshot
    );
    let last = initial.advance(&batch("max", u64::MAX, Body::Snapshot(vec![])), 100, &p)?;
    assert_eq!(
        last.state()
            .advance(&batch("wrap", 0, Body::Snapshot(vec![])), 101, &p)?
            .outcome(),
        &SyncOutcome::Stale
    );
    // Device time drift never affects an otherwise valid predecessor chain.
    let backwards = Batch::new(
        id("time-backwards"),
        2,
        Timepoint::try_from(0)?,
        coverage(),
        Body::Delta {
            baseline: id("base"),
            previous: 1,
            changes: vec![],
        },
    )?;
    assert_eq!(
        first.state().advance(&backwards, 101, &p)?.outcome(),
        &SyncOutcome::Delta
    );
    assert_eq!(
        rss_observation::State::decode(&first.state().encode()?)?,
        *first.state()
    );
    Ok(())
}
#[test]
fn malformed_state_and_policy_fail_closed() -> anyhow::Result<()> {
    assert!(Policy::new(0, 1, 1).is_err());
    assert!(Policy::new(1, 0, 1).is_err());
    assert!(Policy::new(1, 1, 0).is_err());
    assert!(Policy::new(u64::MAX, 1, 1).is_err());
    assert!(Policy::new(1, 1, u64::MAX).is_err());
    let first = State::initial().advance(&batch("s", 1, Body::Snapshot(vec![])), 100, &policy())?;
    let mut value: serde_json::Value = serde_json::from_str(&first.state().encode()?)?;
    value["cursor"] = 99.into();
    assert!(State::decode(&value.to_string()).is_err());
    value["cursor"] = 1.into();
    value["baseline"] = serde_json::Value::Null;
    assert!(State::decode(&value.to_string()).is_err());
    let decision = rss_observation::Decision::restore(
        &first.encode()?,
        &batch("s", 1, Body::Snapshot(vec![])),
        100,
        &policy(),
    )?;
    assert_eq!(decision, first);
    assert!(
        rss_observation::Decision::restore(
            &first.encode()?,
            &batch("s", 2, Body::Snapshot(vec![])),
            100,
            &policy()
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn degraded_state_and_versioned_restore_are_closed() -> anyhow::Result<()> {
    let first = State::initial().advance(&batch("s", 1, Body::Snapshot(vec![])), 100, &policy())?;
    for (body, expected) in [
        (
            Body::Delta {
                baseline: id("s"),
                previous: 2,
                changes: vec![],
            },
            NeedSnapshot::Gap,
        ),
        (Body::Partial(vec![]), NeedSnapshot::Partial),
    ] {
        let degraded = first
            .state()
            .advance(&batch("bad", 3, body), 101, &policy())?;
        assert_eq!(degraded.state().needs_snapshot(), Some(&expected));
        let restored = State::decode(&degraded.state().encode()?)?;
        assert_eq!(restored.needs_snapshot(), Some(&expected));
    }
    let initial = serde_json::from_str::<serde_json::Value>(&State::initial().encode()?)?;
    assert_eq!(initial["version"], serde_json::json!(1));
    let mut invalid = initial.clone();
    invalid["highWater"] = 1.into();
    assert!(serde_json::from_value::<State>(invalid).is_err());
    let mut unknown = initial;
    unknown["version"] = 2.into();
    assert!(State::decode(&unknown.to_string()).is_err());
    let mut p: serde_json::Value = serde_json::from_str(&policy().encode()?)?;
    p["version"] = 2.into();
    assert!(Policy::decode(&p.to_string()).is_err());
    p["version"] = 1.into();
    p["retrySeconds"] = 0.into();
    assert!(serde_json::from_value::<Policy>(p).is_err());
    let mut d: serde_json::Value = serde_json::from_str(&first.encode()?)?;
    d["version"] = 2.into();
    assert!(
        rss_observation::Decision::restore(
            &d.to_string(),
            &batch("s", 1, Body::Snapshot(vec![])),
            100,
            &policy()
        )
        .is_err()
    );
    Ok(())
}
