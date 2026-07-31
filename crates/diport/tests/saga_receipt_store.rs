use diport::{
    SagaReceiptCommitOutcome, SagaReceiptStore, SagaReceiptStoreError, SagaStepCompletion,
    StoredSagaReceipt,
};

struct NoopReceiptStore;

impl SagaReceiptStore for NoopReceiptStore {
    async fn commit_completed(
        &self,
        _lease: &consistency::SagaLease,
        _completion: SagaStepCompletion,
    ) -> Result<SagaReceiptCommitOutcome, SagaReceiptStoreError> {
        Ok(SagaReceiptCommitOutcome::Committed)
    }

    async fn load_exact(
        &self,
        _scope: &consistency::SagaReceiptScope,
    ) -> Result<Option<StoredSagaReceipt>, SagaReceiptStoreError> {
        Ok(None)
    }

    async fn shutdown(&self) -> Result<(), SagaReceiptStoreError> {
        Ok(())
    }
}

fn assert_port<T: SagaReceiptStore>() {}

#[test]
fn receipt_store_is_a_native_async_port() {
    assert_port::<NoopReceiptStore>();
}
