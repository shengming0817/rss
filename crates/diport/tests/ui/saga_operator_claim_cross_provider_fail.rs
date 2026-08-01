use diport::SagaOperatorStore;

fn cross_provider<A: SagaOperatorStore, B: SagaOperatorStore>(
    target: &B,
    claim: A::Claim,
    decision: diport::SagaOperatorRepair,
) {
    let _ = target.repair(claim, decision);
}

fn main() {}
