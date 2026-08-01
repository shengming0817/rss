struct ForgedCommand;

impl generated::command::FencedCommandSpec for ForgedCommand {
    type Contract = generated::command::identity_v1::Contract;

    fn request(
        &self,
    ) -> &<Self::Contract as generated::command::CommandContract>::Request {
        unreachable!()
    }

    fn device_id(&self) -> uuid::Uuid {
        unreachable!()
    }

    fn desired_generation(&self) -> std::num::NonZeroU64 {
        unreachable!()
    }

    fn fence_epoch(&self) -> std::num::NonZeroU64 {
        unreachable!()
    }

    fn intent_digest(&self) -> &str { "sha256:0000000000000000000000000000000000000000000000000000000000000000" }

    fn deadline_epoch_seconds(&self) -> std::num::NonZeroU64 { unreachable!() }
}

fn main() {}
