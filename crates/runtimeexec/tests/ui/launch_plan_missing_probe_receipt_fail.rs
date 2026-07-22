fn main() {
    type Hook = fn(()) -> anyhow::Result<()>;
    type Plan = runtimeexec::LaunchPlan<(), (), Hook>;
    type ConstructorWithoutReceipt = fn(
        (),
        Hook,
        Option<Box<diport::DynManagedResource<'static>>>,
        runtimeexec::LaunchLifecycleBatches,
    ) -> Plan;

    let _missing_receipt: ConstructorWithoutReceipt = runtimeexec::LaunchPlan::new;
}
