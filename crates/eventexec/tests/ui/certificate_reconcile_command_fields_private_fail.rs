use diport::{EnvelopeSubjectId, OutboxActor};
use generated::command::identity_v1::ReconcileCommand;

fn inspect(command: ReconcileCommand<EnvelopeSubjectId, OutboxActor>) {
    let _ = &command.request;
}

fn main() {}
