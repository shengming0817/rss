fn main() {
    let provider = runtimeexec::ProviderLifecycleBatch::from_provider_output(
        bootstrap::DomainModuleResult::default(),
    );
    let domain = runtimeexec::DomainLifecycleBatch::from_domain_output(
        bootstrap::DomainModuleResult::default(),
    );

    let _swapped = runtimeexec::LaunchLifecycleBatches::new(domain, provider);
}
