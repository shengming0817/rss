mod common;

use eventexec::TypedSagaActionFactory;
use generated::saga::billing_v1::Definition;

fn main() {
    let _ = TypedSagaActionFactory::<Definition>::builder()
        .register::<common::Capture, _>(|| common::Capture);
}
