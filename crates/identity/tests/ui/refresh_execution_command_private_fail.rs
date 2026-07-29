//! INVARIANT: REFRESH-COMMAND-SEALED-01 { level = "Hard", exec = "test", source = "trybuild" }

use identity::ports::RefreshExecutionCommand;

fn main() {
    let _rotate = RefreshExecutionCommand::rotate;
    let _reuse = RefreshExecutionCommand::contain_reuse;
}
