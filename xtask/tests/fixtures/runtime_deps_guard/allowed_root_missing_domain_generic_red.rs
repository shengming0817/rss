pub struct SharedRuntimeDeps {
    pub hidden_contract_service: diport::Boxed<contractreg::ContractRegistryService>,
    pub hidden_health_repo: diport::Boxed<syshealth::HealthRepo>,
}
