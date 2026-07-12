//! INVARIANT: LOCAL-ONLY-RUNTIME-EFFECTS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "every_forbidden_effect_has_a_synthetic_red", anti_vacuity = "clean_operation_preserves_output_with_non_zero_baseline" }.
//! Integration carrier for the LocalOnly runtime side-effect conformance gate.

mod local_only {
    use testkit::local_only::{
        LocalOnlyConformanceError, LocalOnlyObservers, Outbox, ProviderCounter, Publish, Write,
        assert_local_only,
    };

    fn observers(
        writes: &ProviderCounter<Write>,
        outbox: &ProviderCounter<Outbox>,
        publishes: &ProviderCounter<Publish>,
    ) -> LocalOnlyObservers {
        LocalOnlyObservers::new(writes.handle(), outbox.handle(), publishes.handle())
    }

    #[tokio::test]
    async fn clean_operation_preserves_output_with_non_zero_baseline() {
        let writes = ProviderCounter::write();
        let outbox = ProviderCounter::outbox();
        let publishes = ProviderCounter::publish();
        writes.add(7);
        outbox.add(11);
        publishes.add(13);
        let result = assert_local_only(observers(&writes, &outbox, &publishes), || async {
            "operation-output"
        })
        .await;

        assert_eq!(result, Ok("operation-output"));
    }

    #[tokio::test]
    async fn every_forbidden_effect_has_a_synthetic_red() {
        for (effect, expected) in [
            ("write", (2, 0, 0)),
            ("outbox", (0, 3, 0)),
            ("publish", (0, 0, 4)),
        ] {
            let writes = ProviderCounter::write();
            let outbox = ProviderCounter::outbox();
            let publishes = ProviderCounter::publish();
            writes.add(10);
            outbox.add(20);
            publishes.add(30);
            let operation_writes = writes.clone();
            let operation_outbox = outbox.clone();
            let operation_publishes = publishes.clone();

            let result = assert_local_only(
                observers(&writes, &outbox, &publishes),
                move || async move {
                    match effect {
                        "write" => operation_writes.add(2),
                        "outbox" => operation_outbox.add(3),
                        "publish" => operation_publishes.add(4),
                        _ => unreachable!("table contains only known effects"),
                    }
                },
            )
            .await;

            assert_eq!(
                result,
                Err(LocalOnlyConformanceError::ForbiddenEffects {
                    writes: expected.0,
                    outbox: expected.1,
                    publishes: expected.2,
                }),
                "synthetic red for {effect}"
            );
        }
    }
}
