pub trait PortEffectClass {}
pub trait PortPrivilegeClass {}
pub trait SubscribeInitializer: Send + Sync {}
mod dyn_ports {
    pub struct DynKeyProvider<'a>(core::marker::PhantomData<&'a ()>);
    pub struct DynSubscriber<'a>(core::marker::PhantomData<&'a ()>);
}
pub use dyn_ports::{DynKeyProvider, DynSubscriber};
pub struct AuthEffect;
pub struct ReadEffect;
pub struct BusinessWriteEffect;
pub struct OutboxEffect;
pub struct WorkflowEffect;
pub struct LocalPrivilege;
pub struct CrossTenantPrivilege;
impl PortEffectClass for AuthEffect {}
impl PortEffectClass for ReadEffect {}
impl PortEffectClass for BusinessWriteEffect {}
impl PortEffectClass for OutboxEffect {}
impl PortEffectClass for WorkflowEffect {}
impl PortPrivilegeClass for LocalPrivilege {}
impl PortPrivilegeClass for CrossTenantPrivilege {}

mod sealed { pub trait DiPortEffect {} }
pub trait DiPortEffect: sealed::DiPortEffect { type Effect: PortEffectClass; type Privilege: PortPrivilegeClass; }
// Matcher mirrors production `effect.rs`: `async_sync` uses `+` (non-empty) so an empty
// Sync-exception bucket cannot vacuous-pass; fixture includes one synthetic async_sync entry.
macro_rules! classify_ports {
    ($(async_sync $async_sync_port:ident => $async_sync_effect:ident;)+ $(async_send $dyn_port:ident => $dyn_effect:ident;)* $(sync_obj $port:ident => $effect:ident;)*) => {
    $(
        impl sealed::DiPortEffect for $async_sync_port<'_> {}
        impl DiPortEffect for $async_sync_port<'_> { type Effect = $async_sync_effect; type Privilege = LocalPrivilege; }
    )+
    $(
        impl sealed::DiPortEffect for $dyn_port<'_> {}
        impl DiPortEffect for $dyn_port<'_> { type Effect = $dyn_effect; type Privilege = LocalPrivilege; }
    )*
    $(
        impl sealed::DiPortEffect for dyn $port + '_ {}
        impl DiPortEffect for dyn $port + '_ { type Effect = $effect; type Privilege = LocalPrivilege; }
    )*};
}
classify_ports! {
    async_sync DynKeyProvider => AuthEffect;
    async_send DynSubscriber => WorkflowEffect;
    sync_obj SubscribeInitializer => WorkflowEffect;
}
