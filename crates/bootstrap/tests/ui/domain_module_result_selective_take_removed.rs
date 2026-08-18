fn main() {
    let mut output = bootstrap::DomainModuleResult::default();
    let _ = output.take_probes();
    let _ = output.take_resources();
    let _ = output.take_workers();
}
