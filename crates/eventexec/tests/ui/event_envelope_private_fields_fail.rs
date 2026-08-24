use eventing::envelope::{EventEnvelope, EventId};
use eventing::metadata::EventMetadata;

fn contract() -> rss_contract::ContractDescriptor {
    unreachable!()
}

fn metadata() -> EventMetadata {
    unreachable!()
}

fn main() {
    let _ = EventEnvelope {
        contract: contract(),
        event_id: EventId::parse("event-1").expect("event id"),
        metadata: metadata(),
        payload: (),
    };
}
