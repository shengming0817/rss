//! INVARIANT: PG-DEVICE-PUBACK-CAPABILITY-01 { level = "Medium", exec = "integration-critical", source = "trybuild" }

fn forge(
    raw_claim: postgres::PgClaimedDeviceOutbox,
    accepted: diport::BrokerAccepted,
) -> postgres::PgBrokerAcceptedDeviceOutbox {
    postgres::PgBrokerAcceptedDeviceOutbox {
        claimed: raw_claim,
        _accepted: accepted,
    }
}

fn main() {}
