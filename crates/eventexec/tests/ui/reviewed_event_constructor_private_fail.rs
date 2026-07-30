use consistency::EventEntry;
use diport::OutboxEnvelopeParts;
use eventexec::event::ReviewedEvent;

fn forge(
    entry: EventEntry,
    envelope: OutboxEnvelopeParts,
    fact: vocab::EventFactBinding,
) -> ReviewedEvent {
    ReviewedEvent {
        entry,
        envelope,
        fact,
    }
}

fn main() {}
