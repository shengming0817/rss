use diport::{DeadLetterRecord, DeadLetterSummary};

fn main() {
    let _ = DeadLetterRecord::new(
        "identity",
        "contract-session",
        "session.created",
        b"payload".to_vec(),
        DeadLetterSummary::new("max retries exhausted"),
        10,
    );
}
