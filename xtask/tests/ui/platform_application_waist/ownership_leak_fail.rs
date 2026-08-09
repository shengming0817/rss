use platform_application_waist_contract::AssemblyLock;
use platform_application_waist_contract::RuntimePlan;
use platform_application_waist_contract::bootstrap;
use platform_application_waist_contract::diport;
use platform_application_waist_contract::eventexec;
use platform_application_waist_contract::generated;
use platform_application_waist_contract::provider;
use platform_application_waist_contract::runtimeexec;

fn main() {
    let _ = std::any::type_name::<AssemblyLock>();
    let _ = std::any::type_name::<RuntimePlan>();
    let _ = std::any::type_name::<diport::Registry>();
    let _ = std::any::type_name::<generated::Registry>();
    let _ = std::any::type_name::<bootstrap::DomainModuleResult>();
    let _ = std::any::type_name::<eventexec::EventRuntime>();
    let _ = std::any::type_name::<runtimeexec::LaunchPlan>();
    let _ = std::any::type_name::<provider::Client>();
}
