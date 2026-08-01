use diport::SagaOperatorStore;

fn consume_twice<S: SagaOperatorStore>(
    store: &S,
    claim: S::RepairClaim,
    first: diport::SagaOperatorRepair,
    second: diport::SagaOperatorRepair,
) {
    let _first = store.commit_repair(claim, first);
    let _second = store.commit_repair(claim, second);
}

fn main() {}
