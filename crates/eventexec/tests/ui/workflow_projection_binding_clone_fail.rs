use eventexec::ProjectionRuntimeBinding;

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<ProjectionRuntimeBinding>();
}
