//! INVARIANT: LOCAL-ONLY-RUNTIME-EFFECTS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "every_forbidden_effect_has_a_synthetic_red", anti_vacuity = "clean_operation_preserves_output_with_non_zero_baseline" }.
//! Integration carrier for the LocalOnly runtime side-effect conformance gate.

mod local_only {
    use testkit::local_only::{
        BusinessWrite, LocalOnlyConformanceError, LocalOnlyObservers, Outbox, ProviderCounter,
        Publish, assert_local_only_with_receipt,
    };

    struct TestRouteMarker;

    const CONTRACT_ID: &str = "testkit.local-only-fixture";

    fn observers(
        business_writes: &ProviderCounter<BusinessWrite>,
        outbox: &ProviderCounter<Outbox>,
        publishes: &ProviderCounter<Publish>,
    ) -> LocalOnlyObservers {
        LocalOnlyObservers::new(
            business_writes.handle(),
            outbox.handle(),
            publishes.handle(),
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn clean_operation_preserves_output_with_non_zero_baseline() {
        let business_writes = ProviderCounter::business_write();
        let outbox = ProviderCounter::outbox();
        let publishes = ProviderCounter::publish();
        business_writes.add(7);
        outbox.add(11);
        publishes.add(13);
        let (output, receipt) = assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
            CONTRACT_ID,
            observers(&business_writes, &outbox, &publishes),
            || async { "operation-output" },
        )
        .await
        .expect("clean operation produces a receipt");

        assert_eq!(output, "operation-output");
        assert_eq!(receipt.contract_id(), CONTRACT_ID);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn domain_error_output_still_produces_a_receipt() {
        let result = assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
            CONTRACT_ID,
            observers(
                &ProviderCounter::business_write(),
                &ProviderCounter::outbox(),
                &ProviderCounter::publish(),
            ),
            || async { Result::<(), &str>::Err("domain failure") },
        )
        .await
        .expect("domain error is an operation output, not a conformance error");

        assert_eq!(result.0, Err("domain failure"));
        assert_eq!(result.1.contract_id(), CONTRACT_ID);
    }

    #[tokio::test]
    async fn every_forbidden_effect_has_a_synthetic_red() {
        for (effect, expected) in [
            ("business-write", (2, 0, 0)),
            ("outbox", (0, 3, 0)),
            ("publish", (0, 0, 4)),
        ] {
            let business_writes = ProviderCounter::business_write();
            let outbox = ProviderCounter::outbox();
            let publishes = ProviderCounter::publish();
            business_writes.add(10);
            outbox.add(20);
            publishes.add(30);
            let operation_business_writes = business_writes.clone();
            let operation_outbox = outbox.clone();
            let operation_publishes = publishes.clone();

            let result = assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
                CONTRACT_ID,
                observers(&business_writes, &outbox, &publishes),
                move || async move {
                    match effect {
                        "business-write" => operation_business_writes.add(2),
                        "outbox" => operation_outbox.add(3),
                        "publish" => operation_publishes.add(4),
                        _ => unreachable!("table contains only known effects"),
                    }
                },
            )
            .await;

            assert!(
                matches!(
                    result,
                    Err(LocalOnlyConformanceError::ForbiddenEffects {
                        business_writes,
                        outbox,
                        publishes,
                    }) if (business_writes, outbox, publishes) == expected
                ),
                "synthetic red for {effect}: forbidden effects cannot produce a receipt"
            );
        }
    }

    #[tokio::test]
    async fn business_write_dimension_is_explicit_and_closed() {
        use testkit::local_only::BusinessWrite;

        let business_writes = ProviderCounter::<BusinessWrite>::business_write();
        let operation_business_writes = business_writes.clone();
        let result = assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
            CONTRACT_ID,
            LocalOnlyObservers::new(
                business_writes.handle(),
                ProviderCounter::outbox().handle(),
                ProviderCounter::publish().handle(),
            ),
            move || async move { operation_business_writes.record() },
        )
        .await;

        assert!(matches!(
            result,
            Err(LocalOnlyConformanceError::ForbiddenEffects {
                business_writes: 1,
                outbox: 0,
                publishes: 0,
            })
        ));
    }

    #[tokio::test]
    async fn observer_regression_cannot_produce_a_receipt() {
        let business_writes = ProviderCounter::business_write();
        business_writes.add(u64::MAX);
        let operation_business_writes = business_writes.clone();
        let result = assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
            CONTRACT_ID,
            observers(
                &business_writes,
                &ProviderCounter::outbox(),
                &ProviderCounter::publish(),
            ),
            move || async move { operation_business_writes.record() },
        )
        .await;

        assert!(matches!(
            result,
            Err(LocalOnlyConformanceError::ObservationRegressed {
                effect: "business-write",
                before: u64::MAX,
                after: 0,
            })
        ));
    }

    #[tokio::test]
    async fn operation_construction_effect_cannot_produce_a_receipt() {
        let business_writes = ProviderCounter::business_write();
        let outbox = ProviderCounter::outbox();
        let publishes = ProviderCounter::publish();
        let operation_business_writes = business_writes.clone();

        let result = assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
            CONTRACT_ID,
            observers(&business_writes, &outbox, &publishes),
            move || {
                operation_business_writes.record();
                async {}
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(LocalOnlyConformanceError::ForbiddenEffects {
                business_writes: 1,
                outbox: 0,
                publishes: 0,
            })
        ));
    }
}
