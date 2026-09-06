use rss_reconcile::{ActualState, DesiredState, DriftKind, Policy, ReconcileDiff};
use std::time::Duration;
#[test]
fn diff_truth_table_and_redaction() {
    for (desired, actual, expected) in [
        (None, None, DriftKind::Converged),
        (Some("secret"), None, DriftKind::MissingActual),
        (None, Some("secret"), DriftKind::UnexpectedActual),
        (Some("a"), Some("b"), DriftKind::Changed),
        (Some("a"), Some("a"), DriftKind::Converged),
    ] {
        let d = desired.map_or_else(DesiredState::missing, DesiredState::present);
        let a = actual.map_or_else(ActualState::missing, ActualState::present);
        let diff = ReconcileDiff::between(d, a);
        assert_eq!(diff.drift(), expected);
        assert!(!format!("{diff:?}").contains("secret"));
    }
}
#[test]
fn bounded_policy_and_saturating_backoff() -> Result<(), rss_reconcile::Error> {
    let make = |n| {
        Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: n,
            lease_ttl: Duration::from_millis(30),
            attempt_timeout: Duration::from_millis(10),
            scan_interval: Duration::from_millis(1),
            initial_backoff: Duration::from_millis(2),
            max_backoff: Duration::from_millis(8),
            max_attempts: 3,
        })
    };
    assert!(make(0).is_err());
    assert!(make(65).is_err());
    let p = make(2)?;
    assert_eq!(p.backoff(1), Duration::from_millis(2));
    assert_eq!(p.backoff(u32::MAX), Duration::from_millis(8));
    Ok(())
}
