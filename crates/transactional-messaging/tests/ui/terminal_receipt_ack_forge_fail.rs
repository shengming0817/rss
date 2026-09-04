use rss_transactional_messaging::inbox::ConsumerIdentity;
use rss_transactional_messaging::message::MessageFingerprint;
use rss_transactional_messaging::transaction::{TerminalDisposition, TerminalReceipt};

fn main() {
    let consumer = forged_consumer();
    let fingerprint = forged_fingerprint();
    let forged = TerminalReceipt::from_durable(
        consumer,
        fingerprint,
        TerminalDisposition::Succeeded,
    );
    let _ack = forged.into_settlement();
}

fn forged_consumer() -> ConsumerIdentity {
    unimplemented!()
}

fn forged_fingerprint() -> MessageFingerprint {
    unimplemented!()
}
