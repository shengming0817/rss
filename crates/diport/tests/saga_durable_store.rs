use std::num::NonZeroUsize;

use diport::{
    SagaClaimOutcome, SagaClaimRequest, SagaDurableMutation, SagaDurableMutationOutcome,
    SagaDurableStore, SagaDurableStoreError, SagaInstanceRegistration, SagaLeaseTtl,
    SagaRecoveryOutcome, SagaRecoveryRequest, SagaRunnableInstance, SagaTerminalReceiptOutcome,
    SagaTerminalReceiptRequest, SagaWorkerIdentity,
};

struct NoopDurableStore;

impl SagaDurableStore for NoopDurableStore {
    async fn register(
        &self,
        _authorization: diport::SagaStartAuthorization,
        _registration: SagaInstanceRegistration,
    ) -> Result<consistency::SagaInstanceRecord, SagaDurableStoreError> {
        unimplemented!()
    }

    async fn get(
        &self,
        _instance: &consistency::SagaInstanceRef,
    ) -> Result<Option<consistency::SagaInstanceRecord>, SagaDurableStoreError> {
        Ok(None)
    }

    async fn list_runnable(
        &self,
        _identity: &SagaWorkerIdentity,
        _tenant: rss_request_context::TenantId,
        _limit: NonZeroUsize,
    ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError> {
        Ok(Vec::new())
    }

    async fn claim(
        &self,
        _request: SagaClaimRequest,
    ) -> Result<SagaClaimOutcome, SagaDurableStoreError> {
        Ok(SagaClaimOutcome::Missing)
    }

    async fn renew(
        &self,
        _lease: &consistency::SagaLease,
        _ttl: SagaLeaseTtl,
    ) -> Result<consistency::SagaLeaseOutcome, SagaDurableStoreError> {
        Ok(consistency::SagaLeaseOutcome::Lost)
    }

    async fn release(
        &self,
        _lease: &consistency::SagaLease,
    ) -> Result<consistency::SagaLeaseOutcome, SagaDurableStoreError> {
        Ok(consistency::SagaLeaseOutcome::Lost)
    }

    async fn recovery_snapshot(
        &self,
        _request: SagaRecoveryRequest,
    ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
        Ok(SagaRecoveryOutcome::LeaseLost)
    }

    async fn terminal_receipt(
        &self,
        _request: SagaTerminalReceiptRequest,
    ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError> {
        Ok(SagaTerminalReceiptOutcome::Missing)
    }

    async fn mutate(
        &self,
        _lease: &consistency::SagaLease,
        _mutation: SagaDurableMutation,
    ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
        Ok(SagaDurableMutationOutcome::LeaseLost)
    }

    async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
        Ok(())
    }
}

fn assert_port<T: SagaDurableStore>() {}

#[test]
fn durable_store_is_a_native_async_port() {
    assert_port::<NoopDurableStore>();
}
