use rss_transactional_messaging::{
    message::MessageEnvelope,
    policy::OperationDeadline,
    transaction::{ConsumerTx, TerminalDisposition},
};
use rss_transactional_messaging_postgres::{PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, PgTransaction};
struct Effect;
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(&self, _: &mut PgTransaction<'_>, _: &MessageEnvelope<Vec<u8>>, _: OperationDeadline)
        -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        Ok(TerminalDisposition::Succeeded)
    }
}
type Proof = <PgConsumerTx<Effect> as ConsumerTx<Vec<u8>>>::CommitProof;
fn main() {
    let _forged = Proof { _private: () };
}
