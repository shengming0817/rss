use diport::{DeadLetterProvenance, DeadLetterRecord, DeadLetterSummary};
use rss_transactional_messaging::message::TransportContext;

fn main() {
    let _ = DeadLetterRecord::new(
        "identity",
        "message-1",
        DeadLetterProvenance::consumer("identity", "audit"),
        "contract-session",
        "session.created",
        Some("audit.session.consumer".to_string()),
        b"payload".to_vec(),
        DeadLetterSummary::new("max retries exhausted"),
        10,
        TransportContext::new(None, None),
    );
}
