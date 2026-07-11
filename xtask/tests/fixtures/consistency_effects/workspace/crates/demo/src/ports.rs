use std::sync::Arc;
pub trait ReadRepo: Send + Sync {}
pub type DynReadRepo = dyn ReadRepo;
mod demo_port_effect_sealed { pub trait Sealed {} }
pub trait DemoPortEffect: demo_port_effect_sealed::Sealed {
    type Effect: diport::PortEffectClass;
    type Privilege: diport::PortPrivilegeClass;
}
macro_rules! classify_demo_ports {
    ($port:ident => $effect:ty) => {
        impl demo_port_effect_sealed::Sealed for $port {}
        impl DemoPortEffect for $port { type Effect = $effect; type Privilege = diport::LocalPrivilege; }
        const _: fn() = || { fn assert_effect<T: DemoPortEffect<Effect = E>, E: diport::PortEffectClass>() {} };
    };
}
classify_demo_ports!(DynReadRepo => diport::ReadEffect);
impl<T: DemoPortEffect + ?Sized> demo_port_effect_sealed::Sealed for Arc<T> {}
impl<T: DemoPortEffect + ?Sized> DemoPortEffect for Arc<T> { type Effect = T::Effect; type Privilege = T::Privilege; }
