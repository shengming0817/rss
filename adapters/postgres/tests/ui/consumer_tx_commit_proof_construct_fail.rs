use postgres::PgConsumerTxCommitProof;

fn main() {
    let _ = PgConsumerTxCommitProof {};
    let _ = PgConsumerTxCommitProof::committed();
}
