use diport::{EnvelopeSubjectId, OutboxActor};
use generated::{
    command::identity_v1 as certificate_command, event::identity_v1::device_command_acked,
};

fn author_wrong_command(
    payload: device_command_acked::IdentityDeviceCommandAckedPayload,
    tenant: vocab::TenantId,
    subject_id: EnvelopeSubjectId,
    actor: OutboxActor,
) {
    let _ = certificate_command::reconcile_command(
        payload,
        tenant,
        subject_id,
        actor,
        "certificate-command-1".to_string(),
    );
}

fn main() {}
