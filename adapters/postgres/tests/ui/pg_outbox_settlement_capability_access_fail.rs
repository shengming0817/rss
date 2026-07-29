//! INVARIANT: PG-OUTBOX-SETTLEMENT-CAPABILITY-01 { level = "Hard", exec = "test", source = "trybuild" }

fn main() {
    let _outcome = postgres::outbox::settlement::Settlement::<()>::expired();
    let _raw_executor = postgres::outbox::settlement::published;
}
