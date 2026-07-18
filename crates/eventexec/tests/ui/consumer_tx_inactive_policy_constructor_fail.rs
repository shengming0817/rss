use consistency::{IdemKey, InboxReceiptContext, LeaseToken};
use diport::Message;
use eventexec::ConsumerTxHandler;
use eventexec::consumer_tx::policy::IdempotencyKey;
use futures::FutureExt as _;

fn main() {
    let _: ConsumerTxHandler<IdempotencyKey> = ConsumerTxHandler::idempotency_key(
        |_message: Message, _context: InboxReceiptContext, _key: IdemKey, _lease: LeaseToken| {
            async { eventexec::ConsumerTxOutcome::Committed }.boxed()
        },
    );
}
