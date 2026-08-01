use diport::SagaOperatorStore;

fn consume_twice<S: SagaOperatorStore>(
    store: &S,
    claim: S::Claim,
    first: diport::SagaOperatorRepair,
    second: diport::SagaOperatorRepair,
) {
    let _first = store.repair(claim, first);
    let _second = store.repair(claim, second);
}

fn main() {}
