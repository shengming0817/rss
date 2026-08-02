//! INVARIANT: PG-DEVICE-PUBACK-CAPABILITY-01 { level = "Hard", exec = "test", source = "trybuild" }

async fn bypass(
    outbox: &postgres::PgDeviceOutbox,
    raw_claim: postgres::PgClaimedDeviceOutbox,
) {
    let _ = outbox.settle_puback(raw_claim).await;
}

fn main() {}
