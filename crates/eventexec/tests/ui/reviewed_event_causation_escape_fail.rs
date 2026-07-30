use diport::EnvelopeCausationId;
use eventexec::event::ReviewedEvent;

fn reopen_provenance(event: ReviewedEvent, causation_id: EnvelopeCausationId) -> ReviewedEvent {
    event.with_causation_id(causation_id)
}

fn main() {}
