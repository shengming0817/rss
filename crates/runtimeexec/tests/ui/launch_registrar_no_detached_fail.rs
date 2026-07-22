fn resource() -> Box<diport::DynManagedResource<'static>> {
    panic!("compile-only fixture")
}

fn bypass_token_funnel(registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_detached(resource());
}

fn main() {}
