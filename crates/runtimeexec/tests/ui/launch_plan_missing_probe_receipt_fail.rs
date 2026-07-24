fn main() {
    type Hook = fn(()) -> std::future::Ready<anyhow::Result<()>>;
    type Plan = runtimeexec::LaunchPlan<(), (), Hook>;
    type ConstructorWithoutReceipt = fn(
        (),
        Hook,
        Option<Box<diport::DynManagedResource<'static>>>,
        runtimeexec::LaunchLifecycleBatches,
        runtimeexec::TotalDrainBudget,
    ) -> Plan;

    let _missing_receipt: ConstructorWithoutReceipt = runtimeexec::LaunchPlan::new;
}
