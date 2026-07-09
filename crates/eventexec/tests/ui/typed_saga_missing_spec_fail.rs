//! compile-fail：TypedSagaActionFactory builder 必须接收 generated SagaContractBinding。

use eventexec::TypedSagaActionFactory;

fn main() {
    let _builder = TypedSagaActionFactory::builder();
}
