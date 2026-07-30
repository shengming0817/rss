use consistency::IdemKey;
use diport::{EnvelopeSubjectId, OutboxActor};
use eventexec::event::GeneratedEventEncoder;
use generated::event::identity_v1::{device_certificate_reported, device_command_acked};

fn emit_wrong_payload(
    emitter: &GeneratedEventEncoder,
    payload: device_command_acked::IdentityDeviceCommandAckedPayload,
    tenant: vocab::TenantId,
    subject_id: EnvelopeSubjectId,
    actor: OutboxActor,
    idempotency_key: IdemKey,
) {
    let _ = device_certificate_reported::emit(
        emitter,
        payload,
        tenant,
        subject_id,
        actor,
        idempotency_key,
    );
}

fn main() {}
