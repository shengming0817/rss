use eventing::delivery::ConsumerTxOutcome;

fn main() {
    let outcome = ConsumerTxOutcome::Committed(());
    let _duplicate = outcome.clone();
}
