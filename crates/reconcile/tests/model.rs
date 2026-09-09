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

#[test]
fn identities_remain_hidden_in_recursive_observations() -> anyhow::Result<()> {
    use rss_reconcile::{Error, ErrorKind, Observation, Scope, Stage, Target};
    let tenant_text = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    let tenant = rss_request_context::TenantId::parse(tenant_text)?;
    let scope = Scope::new(tenant, "private-reconciler")?;
    let target = Target::new(scope.clone(), "private-entity")?;
    let error = Error::new(ErrorKind::InvalidInput);
    let attempt = Observation::AttemptFailed {
        target: target.clone(),
        stage: Stage::Observe,
        error: error.clone(),
    };
    let scan = Observation::ScanFailed {
        scope: scope.clone(),
        error,
    };
    assert_eq!(scope.tenant(), tenant);
    assert_eq!(target.entity(), "private-entity");
    for value in [&scope as &dyn std::fmt::Debug, &target, &attempt, &scan] {
        for rendered in [format!("{value:?}"), format!("{value:#?}")] {
            assert!(rendered.contains("<redacted>"));
            for identity in [tenant_text, "private-reconciler", "private-entity"] {
                assert!(!rendered.contains(identity), "{rendered}");
            }
        }
    }
    Ok(())
}
