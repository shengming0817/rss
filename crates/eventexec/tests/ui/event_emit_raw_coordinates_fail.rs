use consistency::IdemKey;
use diport::{EnvelopeSubjectId, OutboxActor};
use eventexec::event::GeneratedEventEncoder;
use generated::event::identity_v1::device_command_acked;

#[allow(clippy::too_many_arguments)]
fn append_raw_coordinates(
    emitter: &GeneratedEventEncoder,
    payload: device_command_acked::IdentityDeviceCommandAckedPayload,
    tenant: rss_request_context::TenantId,
    subject_id: EnvelopeSubjectId,
    actor: OutboxActor,
    idempotency_key: IdemKey,
    raw_contract: &str,
    raw_schema: &str,
    raw_topic: &str,
    raw_consumer: &str,
    raw_group: &str,
    raw_canonical_envelope_id: &str,
) {
    let _ = device_command_acked::emit(
        emitter,
        payload,
        tenant,
        subject_id,
        actor,
        idempotency_key,
        raw_contract,
        raw_schema,
        raw_topic,
        raw_consumer,
        raw_group,
        raw_canonical_envelope_id,
    );
}

fn main() {}
