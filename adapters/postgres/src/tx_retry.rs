//! Postgres transaction retry classification and boundary metrics.
//!
//! INVARIANT: TX-RETRY-BOUNDARY-01 { level = "Medium", exec = "manual/opt-in", source = "code" } -
//! Postgres owns the SQLSTATE/repo-error mapping before delegating full UoW retries to consistency.

use std::error::Error;
use std::future::Future;
use std::time::Duration;

use consistency::{TxRetryClass, TxRetryFinalStatus, TxRetryPolicy, TxRetryReport, run_tx_retry};
use identity::ports::IdentityError;
use settings::ports::ConfigRepoError;

/// Retry boundary label for settings config UoW writes.
pub(crate) const SETTINGS_CONFIG_BOUNDARY: &str = "settings.config";
/// Retry boundary label for identity credential UoW writes.
pub(crate) const IDENTITY_CREDENTIAL_BOUNDARY: &str = "identity.credential";

/// Classify a SQLSTATE code.
pub(crate) fn classify_sqlstate(code: Option<&str>) -> TxRetryClass {
    match code {
        // Serialization failure / deadlock / lock timeout: the whole transaction may be retried.
        Some("40001" | "40P01" | "55P03") => TxRetryClass::Transient,
        // Connection exception family and server shutdown/recovery states.
        Some(
            "08000" | "08001" | "08003" | "08004" | "08006" | "08007" | "57P01" | "57P02" | "57P03",
        ) => TxRetryClass::Transient,
        // Integrity / authorization / syntax / data exceptions are not made correct by retrying.
        Some(_) | None => TxRetryClass::Permanent,
    }
}

/// Classify sqlx errors at the Postgres boundary.
pub(crate) fn classify_sqlx_error(error: &sqlx::Error) -> TxRetryClass {
    match error {
        sqlx::Error::Database(db) => classify_sqlstate(db.code().as_deref()),
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => {
            TxRetryClass::Transient
        }
        sqlx::Error::PoolClosed
        | sqlx::Error::Configuration(_)
        | sqlx::Error::Protocol(_)
        | sqlx::Error::RowNotFound
        | sqlx::Error::TypeNotFound { .. }
        | sqlx::Error::ColumnIndexOutOfBounds { .. }
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::Decode(_)
        | sqlx::Error::AnyDriverError(_)
        | sqlx::Error::Migrate(_) => TxRetryClass::Permanent,
        _ => TxRetryClass::Permanent,
    }
}

fn classify_source(source: &(dyn Error + Send + Sync + 'static)) -> TxRetryClass {
    source
        .downcast_ref::<sqlx::Error>()
        .map(classify_sqlx_error)
        .unwrap_or(TxRetryClass::Permanent)
}

/// Classify settings repository/UoW errors.
pub(crate) fn classify_config_repo_error(error: &ConfigRepoError) -> TxRetryClass {
    match error {
        ConfigRepoError::VersionConflict => TxRetryClass::Conflict,
        ConfigRepoError::Storage(source) => classify_source(source.as_ref()),
        _ => TxRetryClass::Permanent,
    }
}

/// Classify identity repository/UoW errors.
pub(crate) fn classify_identity_error(error: &IdentityError) -> TxRetryClass {
    match error {
        IdentityError::VersionConflict => TxRetryClass::Conflict,
        IdentityError::Storage(source) => classify_source(source.as_ref()),
        _ => TxRetryClass::Permanent,
    }
}

/// Run a Postgres UoW under the default retry policy and emit closed-label metrics.
pub(crate) async fn run_pg_tx_retry<T, E, Op, OpFut, Classify>(
    boundary: &'static str,
    op: Op,
    classify: Classify,
) -> Result<T, E>
where
    Op: FnMut(u32) -> OpFut,
    OpFut: Future<Output = Result<T, E>>,
    Classify: Fn(&E) -> TxRetryClass,
{
    let (result, report) = run_tx_retry(
        TxRetryPolicy::default(),
        op,
        |error| {
            let class = classify(error);
            record_attempt(boundary, class);
            class
        },
        sleep_delay,
    )
    .await;
    record_final(boundary, report);
    result
}

async fn sleep_delay(delay: Duration) {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

fn record_attempt(boundary: &'static str, class: TxRetryClass) {
    metrics::counter!(
        "tx_retry_attempts_total",
        "boundary" => boundary,
        "class" => class.as_label(),
    )
    .increment(1);
}

fn record_final(boundary: &'static str, report: TxRetryReport) {
    if report.final_status() == TxRetryFinalStatus::Exhausted {
        tracing::warn!(
            target: "postgres",
            boundary,
            attempts = report.attempts(),
            status = report.final_status().as_label(),
            "transaction retry budget exhausted"
        );
    }
    metrics::counter!(
        "tx_retry_final_total",
        "boundary" => boundary,
        "status" => report.final_status().as_label(),
    )
    .increment(1);
    metrics::histogram!(
        "tx_retry_attempts",
        "boundary" => boundary,
        "status" => report.final_status().as_label(),
    )
    .record(f64::from(report.attempts()));
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{
        SETTINGS_CONFIG_BOUNDARY, classify_config_repo_error, classify_sqlstate,
        classify_sqlx_error, run_pg_tx_retry,
    };
    use crate::cotx::commit_unknown;
    use consistency::TxRetryClass;
    use settings::ports::ConfigRepoError;

    #[derive(Debug)]
    enum FakeError {
        Transient,
        Conflict,
    }

    fn classify_fake(error: &FakeError) -> TxRetryClass {
        match error {
            FakeError::Transient => TxRetryClass::Transient,
            FakeError::Conflict => TxRetryClass::Conflict,
        }
    }

    #[test]
    fn sqlstate_classification_is_closed_and_fail_closed() {
        let cases = [
            (Some("40001"), TxRetryClass::Transient),
            (Some("40P01"), TxRetryClass::Transient),
            (Some("55P03"), TxRetryClass::Transient),
            (Some("08006"), TxRetryClass::Transient),
            (Some("57P03"), TxRetryClass::Transient),
            (Some("23505"), TxRetryClass::Permanent),
            (Some("23503"), TxRetryClass::Permanent),
            (Some("42601"), TxRetryClass::Permanent),
            (Some("99999"), TxRetryClass::Permanent),
            (None, TxRetryClass::Permanent),
        ];
        for (code, expected) in cases {
            assert_eq!(classify_sqlstate(code), expected, "code={code:?}");
        }
    }

    #[test]
    fn sqlx_non_database_errors_are_classified() {
        assert_eq!(
            classify_sqlx_error(&sqlx::Error::PoolTimedOut),
            TxRetryClass::Transient
        );
        assert_eq!(
            classify_sqlx_error(&sqlx::Error::PoolClosed),
            TxRetryClass::Permanent
        );
        assert_eq!(
            classify_sqlx_error(&sqlx::Error::RowNotFound),
            TxRetryClass::Permanent
        );
    }

    #[test]
    fn commit_unknown_is_not_retryable() {
        let err = commit_unknown(sqlx::Error::PoolTimedOut);
        assert_eq!(classify_sqlx_error(&err), TxRetryClass::Permanent);
        assert_eq!(
            classify_config_repo_error(&ConfigRepoError::Storage(Box::new(err))),
            TxRetryClass::Permanent
        );
    }

    #[test]
    fn retry_metrics_emit_closed_labels() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                let attempts = AtomicU32::new(0);
                let ok = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |attempt| {
                        attempts.store(attempt, Ordering::Release);
                        async move {
                            if attempt == 1 {
                                Err::<(), _>(FakeError::Transient)
                            } else {
                                Ok(())
                            }
                        }
                    },
                    classify_fake,
                )
                .await;
                assert!(ok.is_ok());
                assert_eq!(attempts.load(Ordering::Acquire), 2);

                let conflict = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |_attempt| async { Err::<(), _>(FakeError::Conflict) },
                    classify_fake,
                )
                .await;
                assert!(matches!(conflict, Err(FakeError::Conflict)));

                let exhausted = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |_attempt| async { Err::<(), _>(FakeError::Transient) },
                    classify_fake,
                )
                .await;
                assert!(matches!(exhausted, Err(FakeError::Transient)));
            });
        });
        let rendered = handle.render();
        assert!(rendered.contains("tx_retry_attempts_total"), "{rendered}");
        assert!(rendered.contains("tx_retry_final_total"), "{rendered}");
        assert!(rendered.contains("tx_retry_attempts"), "{rendered}");
        assert!(
            rendered.contains("boundary=\"settings.config\""),
            "{rendered}"
        );
        assert!(rendered.contains("class=\"transient\""), "{rendered}");
        assert!(rendered.contains("status=\"success\""), "{rendered}");
        assert!(rendered.contains("status=\"conflict\""), "{rendered}");
        assert!(rendered.contains("status=\"exhausted\""), "{rendered}");
        Ok(())
    }
}
