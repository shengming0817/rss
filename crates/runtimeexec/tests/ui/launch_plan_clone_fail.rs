fn ready(_: ()) -> anyhow::Result<()> {
    Ok(())
}

fn main() {
    let plan = runtimeexec::LaunchPlan::new(
        (),
        (),
        ready as fn(()) -> anyhow::Result<()>,
        None,
        runtimeexec::LaunchLifecycleBatches::new(
            runtimeexec::ProviderLifecycleBatch::from_provider_output(
                bootstrap::DomainModuleResult::default(),
            ),
            runtimeexec::DomainLifecycleBatch::from_domain_output(
                bootstrap::DomainModuleResult::default(),
            ),
        ),
    );
    let _second_owner = plan.clone();
}
