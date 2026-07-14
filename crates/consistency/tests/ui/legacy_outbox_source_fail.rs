use consistency::OutboxSource;

fn accepts_legacy_source<T: OutboxSource + ?Sized>(_source: &T) {}

fn main() {}
