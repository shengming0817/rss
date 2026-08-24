use eventing::delivery::ConsumerTxOutcome;

fn main() {
    println!("{:?}", ConsumerTxOutcome::<()>::CommitUnknown);
}
