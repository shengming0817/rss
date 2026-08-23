use eventexec::consumer_tx::ConsumerTxOutcome;

fn main() {
    println!("{:?}", ConsumerTxOutcome::<()>::CommitUnknown);
}
