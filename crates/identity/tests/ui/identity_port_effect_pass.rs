use std::sync::Arc;

use diport::{
    AuthEffect, BusinessWriteEffect, LocalPrivilege, OutboxEffect, PortEffectClass,
    PortPrivilegeClass, ReadEffect,
};
use identity::ports::{
    DynAccountReactivationLifecycle, DynAccountSecurityReadRepo, DynAuthGrantLifecycle,
    DynCredentialRepo, DynIdentitySecurityLifecycle, DynPolicyLifecycle, DynPolicyRepo,
    DynRefreshTokenStore,
    DynRoleBindingLifecycle, DynRoleBindingReadRepo, DynRoleDefinitionLifecycle, DynRoleReadRepo,
    IdentityPortEffect,
};
use identity::DeviceResourceFactPip;

fn assert_effect<T, E, P>()
where
    T: IdentityPortEffect<Effect = E, Privilege = P> + ?Sized,
    E: PortEffectClass,
    P: PortPrivilegeClass,
{
}

fn main() {
    assert_effect::<DynPolicyRepo<'static>, AuthEffect, LocalPrivilege>();

    assert_effect::<DeviceResourceFactPip, AuthEffect, LocalPrivilege>();
    assert_effect::<DynRoleReadRepo<'static>, ReadEffect, LocalPrivilege>();
    assert_effect::<DynRoleBindingReadRepo<'static>, AuthEffect, LocalPrivilege>();
    assert_effect::<DynRoleDefinitionLifecycle<'static>, BusinessWriteEffect, LocalPrivilege>();
    assert_effect::<DynAccountSecurityReadRepo<'static>, AuthEffect, LocalPrivilege>();
    assert_effect::<DynCredentialRepo<'static>, BusinessWriteEffect, LocalPrivilege>();
    assert_effect::<DynRefreshTokenStore<'static>, AuthEffect, LocalPrivilege>();

    assert_effect::<DynPolicyLifecycle<'static>, OutboxEffect, LocalPrivilege>();
    assert_effect::<DynRoleBindingLifecycle<'static>, OutboxEffect, LocalPrivilege>();
    assert_effect::<DynAuthGrantLifecycle<'static>, OutboxEffect, LocalPrivilege>();
    assert_effect::<DynIdentitySecurityLifecycle<'static>, OutboxEffect, LocalPrivilege>();
    assert_effect::<DynAccountReactivationLifecycle<'static>, BusinessWriteEffect, LocalPrivilege>(
    );
    assert_effect::<Arc<DynPolicyRepo<'static>>, AuthEffect, LocalPrivilege>();
    assert_effect::<Box<DynRoleReadRepo<'static>>, ReadEffect, LocalPrivilege>();
}
