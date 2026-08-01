fn raw_resume<E: eventexec::SagaExecutor>(executor: &E) {
    executor.resume();
}

fn main() {}
