use diport::SagaOperatorStore;

fn cross_provider<A: SagaOperatorStore, B: SagaOperatorStore>(
    target: &B,
    claim: A::RepairClaim,
    decision: diport::SagaOperatorRepair,
) {
    let _ = target.commit_repair(claim, decision);
}

fn main() {}
