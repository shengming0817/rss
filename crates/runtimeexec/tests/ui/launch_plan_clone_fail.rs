fn ready(_: ()) -> std::future::Ready<anyhow::Result<()>> {
    std::future::ready(Ok(()))
}

fn main() {
    let plan = runtimeexec::LaunchPlan::new(
        (),
        (),
        ready as fn(()) -> std::future::Ready<anyhow::Result<()>>,
        None,
        runtimeexec::LaunchLifecycleBatches::new(
            runtimeexec::ProviderLifecycleBatch::from_provider_output(
                bootstrap::DomainModuleResult::default(),
            ),
            runtimeexec::DomainLifecycleBatch::from_domain_output(
                bootstrap::DomainModuleResult::default(),
            ),
        ),
        runtimeexec::TotalDrainBudget::new(std::time::Duration::from_secs(20))
        .expect("valid test drain budget"),
    );
    let _second_owner = plan.clone();
}
