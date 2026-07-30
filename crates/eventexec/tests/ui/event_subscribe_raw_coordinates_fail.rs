use generated::event::identity_v1::policy_updated;

#[allow(clippy::too_many_arguments)]
fn append_raw_coordinates<Reg: generated::event::EventSubscribe>(
    registry: &mut Reg,
    capability: Reg::Capability,
    raw_contract: &str,
    raw_schema: &str,
    raw_topic: &str,
    raw_consumer: &str,
    raw_group: &str,
    raw_canonical_envelope_id: &str,
) {
    let _ = policy_updated::subscribe_audit(
        registry,
        capability,
        raw_contract,
        raw_schema,
        raw_topic,
        raw_consumer,
        raw_group,
        raw_canonical_envelope_id,
    );
}

fn main() {}
