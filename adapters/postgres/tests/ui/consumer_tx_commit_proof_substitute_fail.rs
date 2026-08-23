use eventexec::consumer_tx::ConsumerTxOutcome;
use postgres::PgConsumerTxCommitProof;

fn main() {
    let _: ConsumerTxOutcome<PgConsumerTxCommitProof> = ConsumerTxOutcome::Committed(());
    let _: Option<PgConsumerTxCommitProof> = None;
}
