use eventing::envelope::EventEnvelope;

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<EventEnvelope<()>>();
}
