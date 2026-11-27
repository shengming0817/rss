//! Typed host failures remain recoverable without a formatting side channel.
use rss_audit_postgres::{Error, TransactionError};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::error::Error as _;

// The host error deliberately implements neither Debug, Display nor std::error::Error.
struct BusinessFailure(&'static str);

#[test]
fn transaction_errors_preserve_opaque_business_causes_without_formatting_them() {
    let failure = TransactionError::Operation(BusinessFailure("private-business-reason"));
    assert!(!format!("{failure:?} {failure}").contains("private-business-reason"));
    assert!(failure.source().is_none());
    let failure = TransactionError::Rollback {
        operation: Box::new(failure),
        settlement: Error::Cancelled(LocalTxDeadlineStage::Rollback),
    };
    assert!(!format!("{failure:?} {failure}").contains("private-business-reason"));
    assert!(failure.source().is_some());
    assert!(matches!(
        failure,
        TransactionError::Rollback { operation, settlement: Error::Cancelled(_) }
            if matches!(*operation, TransactionError::Operation(BusinessFailure("private-business-reason")))
    ));
}
