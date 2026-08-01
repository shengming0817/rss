use generated::{
    command::identity_v1 as certificate_command, event::identity_v1::device_command_acked,
};

fn author_wrong_command(
    payload: device_command_acked::IdentityDeviceCommandAckedPayload,
) {
    let _ = certificate_command::fenced_reconcile_command(payload);
}

fn main() {}
