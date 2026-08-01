fn raw_target_recovery<R, D>(
    executor: &eventexec::SagaExecutorImpl<R, D>,
    instance: consistency::SagaInstanceRef,
    reason: consistency::SagaOperatorReason,
    authorization: diport::SagaOperatorRepairAuthorization,
    ticket: diport::SagaOperatorChangeTicket,
) where
    R: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
    D: diport::DeadLetterStore + Send + Sync + 'static,
{
    let _ = executor.recover_operator(instance, reason, authorization, ticket);
}

fn main() {}
