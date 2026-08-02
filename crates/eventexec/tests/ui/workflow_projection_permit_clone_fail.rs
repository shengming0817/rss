use eventexec::ProjectionActivationPermit;

fn require_clone<T: Clone>() {}

fn main() {
    require_clone::<ProjectionActivationPermit>();
}
