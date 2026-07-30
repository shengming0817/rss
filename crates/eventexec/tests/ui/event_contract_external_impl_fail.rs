use generated::event::identity_v1::device_command_acked;

struct ForgedContract;

impl generated::event::EventContract for ForgedContract {
    type Payload = device_command_acked::IdentityDeviceCommandAckedPayload;
    const SPEC: generated::event::EventSpec = device_command_acked::SPEC;
    const FACT: vocab::EventFactBinding = device_command_acked::FACT;
}

fn main() {}
