use diport::ExternalPkiProviderClosure;

fn requires_clone<T: Clone>() {}

fn main() {
    requires_clone::<ExternalPkiProviderClosure>();
}
