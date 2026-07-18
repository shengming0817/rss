use postgres::{PgConsumerTxCommitProof, PgConsumerTxOutcome};

fn main() {
    let _: PgConsumerTxOutcome = PgConsumerTxOutcome::Committed(());
    let _: Option<PgConsumerTxCommitProof> = None;
}
