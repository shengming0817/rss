fn caller_submits_repair_decision<R>(
    service: &eventexec::SagaOperatorService<R>,
    authorization: diport::SagaOperatorAuthorization<diport::saga_operator_action::Repair>,
    decision: diport::SagaOperatorRepair,
) where
    R: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
{
    let _ = service.repair(authorization, decision);
}

fn main() {}
