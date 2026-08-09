mod common;

use eventexec::TypedSagaActionFactory;
use generated::saga::test_support::test_v1::primary::Definition;

fn main() {
    let _ = TypedSagaActionFactory::<Definition>::builder()
        .register::<common::Commit, _>(|| common::Commit);
}
