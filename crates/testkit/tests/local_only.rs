//! INVARIANT: LOCAL-ONLY-RUNTIME-EFFECTS-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "every_forbidden_effect_has_a_synthetic_red", anti_vacuity = "clean_operation_preserves_output_with_non_zero_baseline" }.
//! INVARIANT: LOCAL-ONLY-EXECUTION-MARKER-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "forbidden_effect_does_not_write_execution_marker", anti_vacuity = "clean_receipt_writes_strict_execution_marker" }.
//! Integration carrier for the LocalOnly runtime side-effect conformance gate.

mod local_only {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use testkit::local_only::{
        BusinessWrite, LocalOnlyConformanceError, LocalOnlyObservers, Outbox, ProviderCounter,
        Publish, assert_local_only_with_receipt,
    };

    struct TestRouteMarker;

    const CONTRACT_ID: &str = "testkit.local-only-fixture";
    const EXECUTION_DIR_ENV: &str = "RSS_LOCAL_ONLY_EXECUTION_DIR";
    const SUBPROCESS_CASE_ENV: &str = "RSS_TESTKIT_LOCAL_ONLY_MARKER_CASE";

    static EXECUTION_ENV_LOCK: Mutex<()> = Mutex::new(());
    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    struct ScopedTempDir(PathBuf);

    impl ScopedTempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScopedTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[allow(clippy::panic)]
    // reason: test fixture setup cannot continue without an isolated marker directory.
    fn create_temp_dir() -> ScopedTempDir {
        loop {
            let suffix = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "rss-testkit-local-only-marker-{}-{suffix}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return ScopedTempDir(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated marker directory: {error}"),
            }
        }
    }

    fn marker_path(directory: &Path, contract_id: &str) -> PathBuf {
        directory.join(format!("{contract_id}.json"))
    }

    #[allow(clippy::expect_used)]
    // reason: test fixture assertion requires the isolated directory to remain readable.
    fn assert_directory_empty(directory: &Path) {
        let mut entries = fs::read_dir(directory).expect("read isolated marker directory");
        assert!(
            entries.next().is_none(),
            "marker directory must remain empty"
        );
    }

    fn execution_env_lock() -> std::sync::MutexGuard<'static, ()> {
        match EXECUTION_ENV_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[allow(clippy::expect_used)]
    fn run_marker_subprocess(case: &str, execution_dir: Option<&Path>) -> Output {
        let mut command = Command::new(env::current_exe().expect("locate integration test binary"));
        command
            .arg("--exact")
            .arg("local_only::execution_marker_subprocess")
            .arg("--nocapture")
            .env(SUBPROCESS_CASE_ENV, case);
        match execution_dir {
            Some(directory) => {
                command.env(EXECUTION_DIR_ENV, directory);
            }
            None => {
                command.env_remove(EXECUTION_DIR_ENV);
            }
        }
        command.output().expect("run isolated marker subprocess")
    }

    fn assert_subprocess_succeeded(output: &Output) {
        assert!(output.status.success(), "marker subprocess must succeed");
    }

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

    async fn clean_conformance(contract_id: &'static str) -> Result<(), LocalOnlyConformanceError> {
        assert_local_only_with_receipt::<TestRouteMarker, _, _, _>(
            contract_id,
            observers(
                &ProviderCounter::business_write(),
                &ProviderCounter::outbox(),
                &ProviderCounter::publish(),
            ),
            || async {},
        )
        .await
        .map(|_| ())
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

    #[test]
    #[allow(clippy::expect_used)]
    fn clean_receipt_writes_strict_execution_marker() {
        let _lock = execution_env_lock();
        let directory = create_temp_dir();

        let output = run_marker_subprocess("green", Some(directory.path()));

        assert_subprocess_succeeded(&output);
        let marker = fs::read_to_string(marker_path(directory.path(), CONTRACT_ID))
            .expect("read execution marker");
        assert_eq!(
            marker,
            r#"{"schemaVersion":1,"contractId":"testkit.local-only-fixture"}"#
        );
    }

    #[test]
    fn forbidden_effect_does_not_write_execution_marker() {
        let _lock = execution_env_lock();
        let directory = create_temp_dir();

        let output = run_marker_subprocess("forbidden", Some(directory.path()));

        assert_subprocess_succeeded(&output);
        assert_directory_empty(directory.path());
    }

    #[test]
    fn duplicate_execution_marker_fails_closed() {
        let _lock = execution_env_lock();
        let directory = create_temp_dir();

        let output = run_marker_subprocess("duplicate", Some(directory.path()));

        assert_subprocess_succeeded(&output);
    }

    #[test]
    fn invalid_contract_id_cannot_address_execution_marker() {
        let _lock = execution_env_lock();
        let directory = create_temp_dir();

        let output = run_marker_subprocess("invalid", Some(directory.path()));

        assert_subprocess_succeeded(&output);
        assert_directory_empty(directory.path());
    }

    #[test]
    fn marker_io_error_does_not_disclose_execution_path() {
        let _lock = execution_env_lock();
        let directory = create_temp_dir();
        let missing_directory = directory.path().join("missing");

        let output = run_marker_subprocess("io", Some(&missing_directory));

        assert_subprocess_succeeded(&output);
        assert_directory_empty(directory.path());
    }

    #[test]
    fn unset_execution_directory_is_a_no_op() {
        let _lock = execution_env_lock();
        let directory = create_temp_dir();

        let output = run_marker_subprocess("unset", None);

        assert_subprocess_succeeded(&output);
        assert_directory_empty(directory.path());
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: unknown cases indicate an invalid test-only subprocess invocation.
    async fn execution_marker_subprocess() {
        let Ok(case) = env::var(SUBPROCESS_CASE_ENV) else {
            return;
        };

        match case.as_str() {
            "green" | "unset" => {
                assert!(clean_conformance(CONTRACT_ID).await.is_ok());
            }
            "forbidden" => {
                let business_writes = ProviderCounter::business_write();
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
                    Err(LocalOnlyConformanceError::ForbiddenEffects { .. })
                ));
            }
            "duplicate" => {
                assert!(clean_conformance(CONTRACT_ID).await.is_ok());
                let duplicate = clean_conformance(CONTRACT_ID).await;
                assert!(matches!(
                    duplicate,
                    Err(LocalOnlyConformanceError::DuplicateExecutionMarker)
                ));
            }
            "invalid" => {
                for invalid in [
                    "",
                    "single-segment",
                    "../escape",
                    "Testkit.fixture",
                    "testkit.-fixture",
                    "testkit.fixture--escape",
                    "testkit.fixture/escape",
                ] {
                    let result = clean_conformance(invalid).await;
                    match result {
                        Err(error @ LocalOnlyConformanceError::InvalidExecutionContractId) => {
                            let rendered = error.to_string();
                            if !invalid.is_empty() {
                                assert!(!rendered.contains(invalid));
                            }
                            if let Ok(directory) = env::var(EXECUTION_DIR_ENV) {
                                assert!(!rendered.contains(&directory));
                            }
                        }
                        _ => panic!("invalid contract id must fail closed"),
                    }
                }
            }
            "io" => {
                let result = clean_conformance(CONTRACT_ID).await;
                match result {
                    Err(
                        error @ LocalOnlyConformanceError::ExecutionMarkerIo {
                            operation: "create",
                            kind: std::io::ErrorKind::NotFound,
                        },
                    ) => {
                        let rendered = error.to_string();
                        assert!(!rendered.contains(CONTRACT_ID));
                        if let Ok(directory) = env::var(EXECUTION_DIR_ENV) {
                            assert!(!rendered.contains(&directory));
                        }
                    }
                    _ => panic!("missing marker directory must fail closed"),
                }
            }
            other => panic!("unknown marker subprocess case: {other}"),
        }
    }
}
