//! compile-fail：SagaStep 是 native AFIT typed authoring port，只能泛型静态分发。

use consistency::SagaStep;

fn main() {
    let _step: Box<dyn SagaStep<Output = ()>>;
}
