use eventexec::consumer_tx::ConsumerTxOutcome;

fn main() {
    let outcome = ConsumerTxOutcome::Committed(());
    let _duplicate = outcome.clone();
}
