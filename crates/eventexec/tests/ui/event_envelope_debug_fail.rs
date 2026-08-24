use eventing::envelope::EventEnvelope;

fn requires_debug<T: std::fmt::Debug>() {}

fn main() {
    requires_debug::<EventEnvelope<()>>();
}
