use std::sync::Arc;

use diport::{
    AuthEffect, LocalPrivilege, OutboxEffect, PortEffectClass, PortPrivilegeClass, WriteEffect,
};
use identity::ports::{
    DynCredentialRepo, DynPolicyLifecycle, DynPolicyRepo, DynRefreshTokenStore,
    DynResourceAttributeRepo, DynRoleBindingLifecycle, DynRoleRepo, DynSessionLifecycle,
    IdentityPortEffect,
};

fn assert_effect<T, E, P>()
where
    T: IdentityPortEffect<Effect = E, Privilege = P> + ?Sized,
    E: PortEffectClass,
    P: PortPrivilegeClass,
{
}

fn main() {
    assert_effect::<DynPolicyRepo<'static>, AuthEffect, LocalPrivilege>();

    assert_effect::<DynResourceAttributeRepo<'static>, WriteEffect, LocalPrivilege>();
    assert_effect::<DynRoleRepo<'static>, WriteEffect, LocalPrivilege>();
    assert_effect::<DynCredentialRepo<'static>, WriteEffect, LocalPrivilege>();
    assert_effect::<DynRefreshTokenStore<'static>, WriteEffect, LocalPrivilege>();

    assert_effect::<DynPolicyLifecycle<'static>, OutboxEffect, LocalPrivilege>();
    assert_effect::<DynRoleBindingLifecycle<'static>, OutboxEffect, LocalPrivilege>();
    assert_effect::<DynSessionLifecycle<'static>, OutboxEffect, LocalPrivilege>();

    assert_effect::<Arc<DynPolicyRepo<'static>>, AuthEffect, LocalPrivilege>();
    assert_effect::<Box<DynRoleRepo<'static>>, WriteEffect, LocalPrivilege>();
}
