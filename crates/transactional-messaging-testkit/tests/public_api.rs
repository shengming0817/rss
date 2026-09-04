use std::sync::atomic::{AtomicUsize, Ordering};

use rss_transactional_messaging::policy::ExecutionBudget;
use rss_transactional_messaging::transaction::{FailureClass, LocalTxAttempt};
use rss_transactional_messaging_testkit::localtx::{LocalTxDriver, run_localtx_conformance};
use rss_transactional_messaging_testkit::memory::FakeClock;

#[derive(Default)]
struct Driver {
    writes: AtomicUsize,
    attempts: AtomicUsize,
    state: AtomicUsize,
    defective_classification: bool,
    defective_commit_state: bool,
    residual_rollback_state: bool,
    residual_validation_state: bool,
    residual_authorization_state: bool,
    exhaust_budget_on_commit: bool,
    clock: FakeClock,
}

impl LocalTxDriver for Driver {
    type Error = SecretProviderError;
    type Snapshot = usize;

    fn reset(&self) {
        self.writes.store(0, Ordering::SeqCst);
        self.attempts.store(0, Ordering::SeqCst);
        self.state.store(0, Ordering::SeqCst);
    }

    async fn committed(&self) -> LocalTxAttempt<(), Self::Error> {
        if self.exhaust_budget_on_commit {
            self.clock.advance(ExecutionBudget::STANDARD.total());
        }
        self.writes.store(1, Ordering::SeqCst);
        self.attempts.store(1, Ordering::SeqCst);
        self.state.store(
            if self.defective_commit_state { 2 } else { 1 },
            Ordering::SeqCst,
        );
        LocalTxAttempt::committed(())
    }

    async fn rolled_back(&self) -> LocalTxAttempt<(), Self::Error> {
        self.attempts.store(1, Ordering::SeqCst);
        if self.residual_rollback_state {
            self.state.store(1, Ordering::SeqCst);
        }
        LocalTxAttempt::rolled_back(SecretProviderError(
            FailureClass::Transient,
            "postgres://operator:super-secret@provider.invalid/db",
        ))
    }

    async fn validation_rejected(&self) -> LocalTxAttempt<(), Self::Error> {
        self.attempts.store(1, Ordering::SeqCst);
        if self.residual_validation_state {
            self.state.store(1, Ordering::SeqCst);
        }
        LocalTxAttempt::not_started(SecretProviderError(
            FailureClass::Permanent,
            "postgres://operator:super-secret@provider.invalid/db",
        ))
    }

    async fn authorization_rejected(&self) -> LocalTxAttempt<(), Self::Error> {
        self.attempts.store(1, Ordering::SeqCst);
        if self.residual_authorization_state {
            self.state.store(1, Ordering::SeqCst);
        }
        LocalTxAttempt::not_started(SecretProviderError(
            FailureClass::Permanent,
            "postgres://operator:super-secret@provider.invalid/db",
        ))
    }

    async fn commit_unknown(&self) -> LocalTxAttempt<(), Self::Error> {
        self.attempts.store(1, Ordering::SeqCst);
        LocalTxAttempt::commit_unknown(SecretProviderError(
            FailureClass::Infrastructure,
            "postgres://operator:super-secret@provider.invalid/db",
        ))
    }

    async fn rollback_failed(&self) -> LocalTxAttempt<(), Self::Error> {
        self.attempts.store(1, Ordering::SeqCst);
        LocalTxAttempt::rollback_failed(SecretProviderError(
            FailureClass::Infrastructure,
            "postgres://operator:super-secret@provider.invalid/db",
        ))
    }

    fn classify(&self, error: &Self::Error) -> FailureClass {
        let _consumed_without_formatting = error.1.len();
        if self.defective_classification && error.0 == FailureClass::Transient {
            FailureClass::Permanent
        } else {
            error.0
        }
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    async fn snapshot(&self) -> Self::Snapshot {
        self.state.load(Ordering::SeqCst)
    }

    fn committed_snapshot(&self) -> Self::Snapshot {
        1
    }
}

#[tokio::test]
async fn runner_uses_one_total_budget_across_all_stages() {
    let driver = Driver {
        exhaust_budget_on_commit: true,
        ..Driver::default()
    };
    let result = run_localtx_conformance(&driver, &driver.clock, ExecutionBudget::STANDARD).await;
    assert!(
        result.is_err(),
        "the consumed suite budget must stop the next stage"
    );
    let Some(error) = result.err() else {
        return;
    };
    assert_eq!(error.stage(), "localtx.commit.snapshot.budget");
    assert_eq!(
        error.to_string(),
        "localtx.commit.snapshot.budget: expected completed-within-budget, got deadline_elapsed"
    );
}

#[tokio::test]
async fn durable_snapshot_oracles_reject_wrong_commit_and_residual_writes() {
    for driver in [
        Driver {
            defective_commit_state: true,
            ..Driver::default()
        },
        Driver {
            residual_rollback_state: true,
            ..Driver::default()
        },
        Driver {
            residual_validation_state: true,
            ..Driver::default()
        },
        Driver {
            residual_authorization_state: true,
            ..Driver::default()
        },
    ] {
        assert!(
            run_localtx_conformance(&driver, &FakeClock::new(), ExecutionBudget::STANDARD)
                .await
                .is_err()
        );
    }
}

struct SecretProviderError(FailureClass, &'static str);

#[tokio::test]
async fn opaque_provider_error_needs_no_formatting_trait() {
    assert_eq!(
        run_localtx_conformance(
            &Driver::default(),
            &FakeClock::new(),
            ExecutionBudget::STANDARD
        )
        .await,
        Ok(())
    );
}

#[tokio::test]
async fn conformance_diagnostics_never_render_provider_secrets() {
    let result = run_localtx_conformance(
        &Driver {
            defective_classification: true,
            ..Driver::default()
        },
        &FakeClock::new(),
        ExecutionBudget::STANDARD,
    )
    .await;
    assert!(
        result.is_err(),
        "defective classification escaped conformance"
    );
    if let Err(error) = result {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("provider.invalid"));
    }
}
