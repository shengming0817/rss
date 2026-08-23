//! RSS access-token signing-key rotation readiness probe.
//!
//! Complements JWKS refresh readiness: active kid must be present in JWKS, and retiring
//! keys past `verify_until` signal operator cleanup debt (degraded). In-window retiring
//! kids missing from JWKS fail closed (planned: unhealthy; emergency: degraded).

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use oidc::JwksReadinessHandle;
use primitives::{HealthCheck, HealthStatus, ProbeName};

use crate::config::RssAccessTokenConfig;

/// Readyz probe name for RSS access signing-key rotation health.
pub(crate) const RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME: &str =
    "rss_access_token_signing_rotation";

/// Absolute unix `verify_until` of the nearest retiring key (not a remaining-seconds gauge).
const GAUGE_ROTATION_VERIFY_UNTIL_TIMESTAMP: &str = "authn_rotation_verify_until_timestamp";

/// Build the rotation readiness probe from RSS access config + JWKS readiness.
pub(crate) fn signing_rotation_probe(
    config: &RssAccessTokenConfig,
    jwks: JwksReadinessHandle,
    clock: Box<dyn diport::Clock>,
) -> SigningKeyRotationProbe {
    let ring = config.signing_key_ring();
    SigningKeyRotationProbe::new(
        ring.active().as_str().to_owned(),
        ring.next().map(|kid| kid.as_str().to_owned()),
        ring.retiring()
            .iter()
            .map(|(kid, until)| (kid.as_str().to_owned(), *until))
            .collect(),
        config.rotation_mode(),
        jwks,
        clock,
    )
}

/// Readyz probe: active JWKS presence + retiring deadline hygiene.
pub(crate) struct SigningKeyRotationProbe {
    name: ProbeName,
    active_kid: String,
    next_kid: Option<String>,
    retiring: Vec<(String, i64)>,
    rotation_mode: authn::RotationMode,
    jwks: Box<dyn KidPresence>,
    clock: Box<dyn diport::Clock>,
}

impl SigningKeyRotationProbe {
    #[allow(clippy::expect_used)]
    pub(crate) fn new(
        active_kid: String,
        next_kid: Option<String>,
        retiring: Vec<(String, i64)>,
        rotation_mode: authn::RotationMode,
        jwks: impl KidPresence + 'static,
        clock: Box<dyn diport::Clock>,
    ) -> Self {
        Self {
            name: ProbeName::parse(RSS_ACCESS_TOKEN_SIGNING_ROTATION_PROBE_NAME)
                .expect("valid RSS access signing rotation probe name"),
            active_kid,
            next_kid,
            retiring,
            rotation_mode,
            jwks: Box::new(jwks),
            clock,
        }
    }

    fn now_unix(&self) -> i64 {
        rss_contract::Timepoint::saturating_from_system_time(self.clock.now()).unix_seconds()
    }

    fn nearest_deadline(&self) -> Option<i64> {
        self.retiring.iter().map(|(_, until)| *until).min()
    }

    fn record_deadline_gauge(&self) {
        let Some(deadline) = self.nearest_deadline() else {
            return;
        };
        metrics::gauge!(GAUGE_ROTATION_VERIFY_UNTIL_TIMESTAMP).set(deadline as f64);
    }

    fn healthy_detail(&self) -> &'static str {
        if self.rotation_mode == authn::RotationMode::Emergency {
            return "ok emergency rotation mode";
        }
        match self.next_kid.as_deref() {
            Some(next) if !self.jwks.has_kid(next) => "next signing key not yet in jwks",
            _ => "ok",
        }
    }

    fn missing_in_window_retiring(&self, now: i64) -> Option<&str> {
        self.retiring
            .iter()
            .find(|(kid, verify_until)| now <= *verify_until && !self.jwks.has_kid(kid))
            .map(|(kid, _)| kid.as_str())
    }
}

impl bootstrap::HealthProbe for SigningKeyRotationProbe {
    fn check(&self) -> HealthCheck {
        self.record_deadline_gauge();
        let now = self.now_unix();

        if !self.jwks.has_kid(&self.active_kid) {
            return HealthCheck::new(
                self.name.clone(),
                HealthStatus::Unhealthy,
                "active signing key missing from jwks",
            );
        }

        if self.missing_in_window_retiring(now).is_some() {
            let status = match self.rotation_mode {
                authn::RotationMode::Planned => HealthStatus::Unhealthy,
                authn::RotationMode::Emergency => HealthStatus::Degraded,
            };
            return HealthCheck::new(
                self.name.clone(),
                status,
                "retiring signing key missing from jwks",
            );
        }

        if self
            .retiring
            .iter()
            .any(|(_, verify_until)| now > *verify_until)
        {
            return HealthCheck::new(
                self.name.clone(),
                HealthStatus::Degraded,
                "retiring key past verify-until deadline",
            );
        }

        HealthCheck::new(
            self.name.clone(),
            HealthStatus::Healthy,
            self.healthy_detail(),
        )
    }
}

/// Minimal JWKS kid lookup surface for the rotation probe (production + tests).
pub(crate) trait KidPresence: Send + Sync {
    fn has_kid(&self, kid: &str) -> bool;
}

impl KidPresence for JwksReadinessHandle {
    fn has_kid(&self, kid: &str) -> bool {
        JwksReadinessHandle::has_kid(self, kid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::time::Duration;

    use bootstrap::HealthProbe;

    struct FixedClock(SystemTime);

    impl diport::Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    struct FakeJwks(Mutex<HashSet<String>>);

    impl FakeJwks {
        fn with(kids: &[&str]) -> Self {
            Self(Mutex::new(kids.iter().map(|k| (*k).to_owned()).collect()))
        }
    }

    impl KidPresence for FakeJwks {
        fn has_kid(&self, kid: &str) -> bool {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(kid)
        }
    }

    fn probe(
        active: &str,
        next: Option<&str>,
        retiring: Vec<(&str, i64)>,
        mode: authn::RotationMode,
        jwks: FakeJwks,
        now_unix: u64,
    ) -> SigningKeyRotationProbe {
        SigningKeyRotationProbe::new(
            active.to_owned(),
            next.map(str::to_owned),
            retiring
                .into_iter()
                .map(|(kid, until)| (kid.to_owned(), until))
                .collect(),
            mode,
            jwks,
            Box::new(FixedClock(UNIX_EPOCH + Duration::from_secs(now_unix))),
        )
    }

    #[test]
    fn active_kid_missing_from_jwks_is_unhealthy() {
        let probe = probe(
            "active",
            None,
            vec![],
            authn::RotationMode::Planned,
            FakeJwks::with(&[]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Unhealthy);
        assert_eq!(check.detail(), "active signing key missing from jwks");
    }

    #[test]
    fn retiring_past_deadline_is_degraded() {
        let probe = probe(
            "active",
            None,
            vec![("old", 1_699_999_999)],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active", "old"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Degraded);
        assert_eq!(check.detail(), "retiring key past verify-until deadline");
    }

    #[test]
    fn in_window_retiring_missing_from_jwks_is_unhealthy_when_planned() {
        let probe = probe(
            "active",
            None,
            vec![("old", 1_800_000_000)],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Unhealthy);
        assert_eq!(check.detail(), "retiring signing key missing from jwks");
    }

    #[test]
    fn in_window_retiring_missing_from_jwks_is_degraded_when_emergency() {
        let probe = probe(
            "active",
            None,
            vec![("old", 1_800_000_000)],
            authn::RotationMode::Emergency,
            FakeJwks::with(&["active"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Degraded);
        assert_eq!(check.detail(), "retiring signing key missing from jwks");
    }

    #[test]
    fn mixed_retiring_past_and_in_window_prefers_missing_over_past_deadline() {
        // One past deadline (still in JWKS) + one in-window missing → missing wins (Unhealthy).
        let probe = probe(
            "active",
            None,
            vec![("expired", 1_699_999_999), ("window", 1_800_000_000)],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active", "expired"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Unhealthy);
        assert_eq!(check.detail(), "retiring signing key missing from jwks");
    }

    #[test]
    fn mixed_retiring_both_present_past_deadline_is_degraded() {
        let probe = probe(
            "active",
            None,
            vec![("expired", 1_699_999_999), ("window", 1_800_000_000)],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active", "expired", "window"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Degraded);
        assert_eq!(check.detail(), "retiring key past verify-until deadline");
    }

    #[test]
    fn healthy_when_active_present_and_deadlines_open() {
        let probe = probe(
            "active",
            Some("next"),
            vec![("old", 1_800_000_000)],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active", "old", "next"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Healthy);
        assert_eq!(check.detail(), "ok");
    }

    #[test]
    fn next_missing_stays_healthy_with_detail() {
        let probe = probe(
            "active",
            Some("next"),
            vec![],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Healthy);
        assert_eq!(check.detail(), "next signing key not yet in jwks");
    }

    #[test]
    fn emergency_mode_healthy_detail() {
        let probe = probe(
            "active",
            Some("next"),
            vec![],
            authn::RotationMode::Emergency,
            FakeJwks::with(&["active"]),
            1_700_000_000,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Healthy);
        assert_eq!(check.detail(), "ok emergency rotation mode");
    }

    #[test]
    fn retiring_at_exact_deadline_remains_healthy() {
        let now = 1_700_000_000_u64;
        let probe = probe(
            "active",
            None,
            vec![("old", now as i64)],
            authn::RotationMode::Planned,
            FakeJwks::with(&["active", "old"]),
            now,
        );
        assert_eq!(probe.check().status(), HealthStatus::Healthy);
    }

    #[test]
    fn deadline_gauge_emits_nearest_verify_until_timestamp() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let probe = probe(
                "active",
                None,
                vec![("far", 1_900_000_000), ("near", 1_800_000_000)],
                authn::RotationMode::Planned,
                FakeJwks::with(&["active", "far", "near"]),
                1_700_000_000,
            );
            let _ = probe.check();
        });
        let rendered = handle.render();
        assert!(
            rendered.contains(GAUGE_ROTATION_VERIFY_UNTIL_TIMESTAMP),
            "missing gauge: {rendered}"
        );
        assert!(
            rendered.contains("1800000000"),
            "nearest verify_until not emitted: {rendered}"
        );
    }

    #[test]
    fn deadline_gauge_skipped_without_retiring() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let probe = probe(
                "active",
                None,
                vec![],
                authn::RotationMode::Planned,
                FakeJwks::with(&["active"]),
                1_700_000_000,
            );
            let _ = probe.check();
        });
        let rendered = handle.render();
        assert!(
            !rendered.contains(GAUGE_ROTATION_VERIFY_UNTIL_TIMESTAMP),
            "gauge must stay quiet without retiring: {rendered}"
        );
    }
}
