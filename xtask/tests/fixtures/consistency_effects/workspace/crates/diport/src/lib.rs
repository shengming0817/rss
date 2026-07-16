pub trait PortEffectClass {}
pub trait PortPrivilegeClass {}
pub trait SubscribeInitializer: Send + Sync {}
pub struct DynSubscriber<'a>(core::marker::PhantomData<&'a ()>);
pub struct ReadEffect;
pub struct BusinessWriteEffect;
pub struct OutboxEffect;
pub struct WorkflowEffect;
pub struct LocalPrivilege;
pub struct CrossTenantPrivilege;
impl PortEffectClass for ReadEffect {}
impl PortEffectClass for BusinessWriteEffect {}
impl PortEffectClass for OutboxEffect {}
impl PortEffectClass for WorkflowEffect {}
impl PortPrivilegeClass for LocalPrivilege {}
impl PortPrivilegeClass for CrossTenantPrivilege {}

mod sealed { pub trait DiPortEffect {} }
pub trait DiPortEffect: sealed::DiPortEffect { type Effect: PortEffectClass; type Privilege: PortPrivilegeClass; }
macro_rules! classify_ports {
    ($(dyn $dyn_port:ident => $dyn_effect:ident;)* $(sync $port:ident => $effect:ident;)*) => {
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
    dyn DynSubscriber => WorkflowEffect;
    sync SubscribeInitializer => WorkflowEffect;
}
