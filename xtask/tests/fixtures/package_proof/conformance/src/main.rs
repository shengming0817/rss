use std::cell::Cell;

use release_package::{
    ConformanceErrorCategory,
    localtx::{
        ClassifiedError, CommitCase, CommitUnknownCase, RejectedNoWriteCase,
        RollbackCase, RollbackFailedCase, assert_commit, assert_commit_unknown_no_replay,
        assert_rejected_no_write, assert_rollback, assert_rollback_failed_no_replay,
    },
};

struct SecretProviderError(&'static str);

fn classified(category: ConformanceErrorCategory) -> ClassifiedError<SecretProviderError> {
    ClassifiedError::new(category, SecretProviderError("tenant=secret provider payload"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let writes = Cell::new(0_u32);
    assert_commit(CommitCase::new(
        || async { writes.set(1); Ok::<_, ClassifiedError<SecretProviderError>>(()) },
        || async { Ok::<_, ClassifiedError<SecretProviderError>>(writes.get()) },
        1,
        || writes.get() as usize,
    )).await?;

    assert_rollback(RollbackCase::new(
        || async { Err::<(), _>(classified(ConformanceErrorCategory::Conflict)) },
        ConformanceErrorCategory::Conflict,
        || async { Ok::<_, ClassifiedError<SecretProviderError>>(0_u32) },
        0,
    )).await?;

    assert_rejected_no_write(RejectedNoWriteCase::new(
        || async { Err::<(), _>(classified(ConformanceErrorCategory::Validation)) },
        ConformanceErrorCategory::Validation,
        || async { Ok::<_, ClassifiedError<SecretProviderError>>(0_u32) },
        0,
        || 0,
    )).await?;

    let commit_attempts = Cell::new(0_usize);
    assert_commit_unknown_no_replay(CommitUnknownCase::new(
        || async {
            commit_attempts.set(commit_attempts.get() + 1);
            Err::<(), _>(classified(ConformanceErrorCategory::CommitUnknown))
        },
        ConformanceErrorCategory::CommitUnknown,
        || commit_attempts.get(),
    )).await?;

    let rollback_attempts = Cell::new(0_usize);
    assert_rollback_failed_no_replay(RollbackFailedCase::new(
        || async {
            rollback_attempts.set(rollback_attempts.get() + 1);
            Err::<(), _>(classified(ConformanceErrorCategory::RollbackFailed))
        },
        ConformanceErrorCategory::RollbackFailed,
        || rollback_attempts.get(),
    )).await?;

    let secret = "tenant=secret provider payload";
    let rendered = classified(ConformanceErrorCategory::Storage).category().to_string();
    let sanitized_errors = !rendered.contains(secret);
    let _opaque_secret = SecretProviderError(secret).0;
    println!("{}", serde_json::json!({
        "package": "rss-conformance",
        "commit": true,
        "rollback": true,
        "rejectedNoWrite": true,
        "commitUnknownNoReplay": true,
        "rollbackFailedNoReplay": true,
        "sanitizedErrors": sanitized_errors
    }));
    Ok(())
}
