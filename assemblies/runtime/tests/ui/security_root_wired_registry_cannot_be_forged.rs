fn main() {
    let registry = bootstrap::Registry::new();
    let (_, _, _, writes) = primitives::prepare_dr_admission_controls().into_parts();
    let registry = registry.admit_writes(writes);

    let _ = runtime::test_support::SecurityRootWiredRegistry { registry };
}
