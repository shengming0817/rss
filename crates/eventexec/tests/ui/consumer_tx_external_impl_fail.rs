use std::sync::Arc;

use consistency::{IdemKey, InboxReceiptContext, LeaseToken};
use diport::Message;
use eventexec::consumer_tx::policy::TransactionalOnly;
use eventexec::{ConsumerTxHandler, ConsumerTxOutcome};
use futures::future::BoxFuture;

struct ForgedHandler;

impl ConsumerTxHandler<TransactionalOnly> for ForgedHandler {
    type CommitProof = ();

    fn handle(
        self: Arc<Self>,
        _message: Message,
        _context: InboxReceiptContext,
        _key: IdemKey,
        _lease: LeaseToken,
    ) -> BoxFuture<'static, ConsumerTxOutcome<Self::CommitProof>> {
        Box::pin(async { ConsumerTxOutcome::Committed(()) })
    }
}

fn main() {}
