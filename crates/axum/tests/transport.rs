#![cfg(feature = "http1")]

use rss_axum::{Http1ServePolicy, ServePolicy};
use std::time::Duration;

#[test]
#[allow(clippy::unwrap_used)] // reason: positive policy is the test fixture.
fn policies_reject_unbounded_or_unsupported_inputs() {
    let second = Duration::from_secs(1);
    assert!(ServePolicy::new(0, second, Duration::from_secs(30), second).is_err());
    for invalid in [Duration::ZERO, Duration::MAX] {
        assert!(ServePolicy::new(1, invalid, Duration::from_secs(30), second).is_err());
        assert!(ServePolicy::new(1, second, Duration::from_secs(30), invalid).is_err());
    }
    let serve = ServePolicy::new(1, second, Duration::from_secs(30), second).unwrap();
    assert!(Http1ServePolicy::new(serve, Duration::ZERO, 64, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, Duration::MAX, 64, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, second, 0, 32768).is_err());
    assert!(Http1ServePolicy::new(serve, second, 64, 8191).is_err());
    assert!(Http1ServePolicy::new(serve, second, 64, 8192).is_ok());
}

#[test]
#[allow(clippy::expect_used)] // reason: known supported fixture budget.
fn phase_timeout_support_is_stable_and_includes_establishment() {
    let day = Duration::from_secs(24 * 60 * 60);
    let too_large = day + Duration::from_nanos(1);
    assert!(ServePolicy::new(1, day, day, day).is_ok());
    assert!(ServePolicy::new(1, too_large, day, day).is_err());
    assert!(ServePolicy::new(1, day, too_large, day).is_err());
    assert!(ServePolicy::new(1, day, day, too_large).is_err());
    assert!(ServePolicy::new(1, day, Duration::ZERO, day).is_err());
    assert!(ServePolicy::new(1, day, Duration::MAX, day).is_err());
    let serve = ServePolicy::new(1, day, day, day).expect("supported policy");
    assert!(Http1ServePolicy::new(serve, day, 64, 32768).is_ok());
    assert!(Http1ServePolicy::new(serve, too_large, 64, 32768).is_err());
}

#[test]
#[allow(clippy::unwrap_used)] // reason: exact invalid field is the public diagnostic under test.
fn policy_errors_identify_the_rejected_field() {
    let second = Duration::from_secs(1);
    for (index, field) in [
        (0, "preparation_timeout"),
        (1, "establishment_timeout"),
        (2, "shutdown_timeout"),
    ] {
        for invalid in [Duration::ZERO, Duration::MAX] {
            let mut budgets = [second; 3];
            budgets[index] = invalid;
            let error = ServePolicy::new(1, budgets[0], budgets[1], budgets[2]).unwrap_err();
            assert!(
                error.to_string().contains(field),
                "missing field {field}: {error}"
            );
        }
    }
    let error = ServePolicy::new(0, second, second, second).unwrap_err();
    assert!(error.to_string().contains("connection_limit"));
    let serve = ServePolicy::new(1, second, second, second).unwrap();
    for invalid in [Duration::ZERO, Duration::MAX] {
        let error = Http1ServePolicy::new(serve, invalid, 64, 32768).unwrap_err();
        assert!(error.to_string().contains("header_read_timeout"));
    }
    assert!(
        Http1ServePolicy::new(serve, second, 0, 32768)
            .unwrap_err()
            .to_string()
            .contains("max_headers")
    );
    assert!(
        Http1ServePolicy::new(serve, second, 64, 8191)
            .unwrap_err()
            .to_string()
            .contains("max_buffer_size")
    );
}

#[test]
#[allow(clippy::unwrap_used)] // reason: each validation branch must preserve its exact typed field identity.
fn policy_error_variants_preserve_field_identity() {
    use rss_axum::{ServePolicyError as E, ServePolicyField as F};
    let second = Duration::from_secs(1);
    for (index, field) in [
        (0, F::PreparationTimeout),
        (1, F::EstablishmentTimeout),
        (2, F::ShutdownTimeout),
    ] {
        for (invalid, expected) in [
            (Duration::ZERO, E::ZeroTimeout(field)),
            (Duration::MAX, E::TimeoutTooLarge(field)),
        ] {
            let mut budgets = [second; 3];
            budgets[index] = invalid;
            let actual = ServePolicy::new(1, budgets[0], budgets[1], budgets[2]).unwrap_err();
            assert_eq!(actual, expected);
            assert_eq!(actual.field(), field);
        }
    }
    assert_eq!(
        ServePolicy::new(0, second, second, second).unwrap_err(),
        E::ZeroCapacity(F::ConnectionLimit)
    );
    let serve = ServePolicy::new(1, second, second, second).unwrap();
    for (invalid, expected) in [
        (Duration::ZERO, E::ZeroTimeout(F::HeaderReadTimeout)),
        (Duration::MAX, E::TimeoutTooLarge(F::HeaderReadTimeout)),
    ] {
        assert_eq!(
            Http1ServePolicy::new(serve, invalid, 64, 32768).unwrap_err(),
            expected
        );
    }
    assert_eq!(
        Http1ServePolicy::new(serve, second, 0, 32768).unwrap_err(),
        E::ZeroCapacity(F::MaxHeaders)
    );
    let error = Http1ServePolicy::new(serve, second, 64, 8191).unwrap_err();
    assert_eq!(error, E::BufferTooSmall);
    assert_eq!(error.field(), F::MaxBufferSize);
}
