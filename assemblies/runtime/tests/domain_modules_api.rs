//! Runtime domain module public API contract (#1670).

use bootstrap::DomainBinding;
use runtime::{
    SharedRuntimeDeps, domains, wire_audit, wire_identity, wire_identity_with, wire_settings,
};

#[test]
fn domain_module_entrypoints_return_domain_bindings() {
    async fn assert_settings_module(deps: &SharedRuntimeDeps) -> anyhow::Result<()> {
        let _: DomainBinding = domains::settings::module(deps).await?;
        Ok(())
    }

    async fn assert_identity_module(deps: &SharedRuntimeDeps) -> anyhow::Result<()> {
        let _: DomainBinding = domains::identity::module(deps).await?;
        Ok(())
    }

    async fn assert_audit_module(deps: &SharedRuntimeDeps) -> anyhow::Result<()> {
        let _: DomainBinding = domains::audit::module(deps).await?;
        Ok(())
    }

    let _ = assert_settings_module;
    let _ = assert_identity_module;
    let _ = assert_audit_module;
}

#[test]
fn typed_wire_entrypoints_remain_reexported_from_runtime_root() {
    fn assert_wire_identity_with_is_callable(deps: &SharedRuntimeDeps) {
        let _ = wire_identity_with(deps, |_| None, false);
    }

    let _ = wire_settings;
    let _ = wire_identity;
    let _ = assert_wire_identity_with_is_callable;
    let _ = wire_audit;
}
