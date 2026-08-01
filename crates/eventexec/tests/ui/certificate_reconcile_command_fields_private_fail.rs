use generated::command::identity_v1::FencedReconcileCommand;

fn inspect(command: FencedReconcileCommand) {
    let _ = &command.request;
}

fn main() {}
