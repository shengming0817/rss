struct ForgedCommand;

impl generated::command::TypedCommandSpec for ForgedCommand {
    type Contract = generated::command::_seed_v1::Contract;
    type SubjectId = diport::EnvelopeSubjectId;
    type Actor = diport::OutboxActor;

    fn request(
        &self,
    ) -> &<Self::Contract as generated::command::CommandContract>::Request {
        unreachable!()
    }

    fn tenant(&self) -> vocab::TenantId {
        unreachable!()
    }

    fn idempotency_key(&self) -> &str {
        "forged"
    }

    fn into_identity(self) -> (Self::SubjectId, Self::Actor) {
        unreachable!()
    }
}

fn main() {}
