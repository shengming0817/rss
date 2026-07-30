use consistency::{EventTopic, Lsn, ProjectionEventMetadata};
use eventexec::{ProjectionDedupeKey, ValidatedProjectionApply};

fn forge(
    key: ProjectionDedupeKey,
    topic: EventTopic,
    metadata: ProjectionEventMetadata,
) -> ValidatedProjectionApply {
    ValidatedProjectionApply {
        key,
        lsn: Lsn::new(1),
        topic,
        payload: Vec::new(),
        metadata,
        fact_digest: [0; 32],
    }
}

fn main() {}
