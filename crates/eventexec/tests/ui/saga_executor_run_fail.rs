fn raw_run<E: eventexec::SagaExecutor>(executor: &E) {
    executor.run();
}

fn main() {}
