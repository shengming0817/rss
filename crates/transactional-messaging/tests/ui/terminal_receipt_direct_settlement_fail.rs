use rss_transactional_messaging::inbox::ConsumerIdentity;
use rss_transactional_messaging::message::MessageFingerprint;
use rss_transactional_messaging::transaction::{TerminalDisposition, TerminalReceipt};

fn main() {
    let consumer = provider_consumer();
    let fingerprint = provider_fingerprint();
    let provider_receipt = TerminalReceipt::from_durable(
        consumer,
        fingerprint,
        TerminalDisposition::Succeeded,
    );
    let _settlement = provider_receipt.into_settlement();
}

fn provider_consumer() -> ConsumerIdentity {
    unimplemented!()
}

fn provider_fingerprint() -> MessageFingerprint {
    unimplemented!()
}
