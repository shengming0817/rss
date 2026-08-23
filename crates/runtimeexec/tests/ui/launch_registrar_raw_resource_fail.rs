fn raw() -> Box<diport::DynManagedResource<'static>> {
    panic!("compile-only fixture")
}

fn bypass(registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_listener_with_token(|_| raw());
}

fn main() {}
