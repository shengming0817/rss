use rss_transactional_messaging::transaction::{TerminalDisposition, TerminalReceipt};

fn main() {
    let _forged = TerminalReceipt {
        consumer: panic!(),
        fingerprint: panic!(),
        disposition: TerminalDisposition::Succeeded,
    };
}
