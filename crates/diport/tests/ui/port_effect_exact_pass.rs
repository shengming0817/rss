use diport::{
    AuthEffect, BusinessWriteEffect, DiPortEffect, DynCasStore, DynDeadLetterStore,
    DynKeyProvider, DynLockStore, DynObjectStore,
    DynOwnerCheckpointStore, DynRateLimiter, DynSecretResolver, DynSigner, LocalPrivilege,
    MetricsExporter, PortEffectClass, PortPrivilegeClass, ReadEffect, WorkflowEffect,
};

fn assert_classification<T, E, P>()
where
    T: ?Sized + DiPortEffect<Effect = E, Privilege = P>,
    E: PortEffectClass,
    P: PortPrivilegeClass,
{
}

macro_rules! assert_local_effect {
    ($port:ty, $effect:ty) => {
        assert_classification::<$port, $effect, LocalPrivilege>()
    };
}

fn main() {
    assert_local_effect!(dyn MetricsExporter, ReadEffect);

    assert_local_effect!(DynKeyProvider<'static>, AuthEffect);
    assert_local_effect!(DynRateLimiter<'static>, AuthEffect);
    assert_local_effect!(DynSecretResolver<'static>, AuthEffect);
    assert_local_effect!(DynSigner<'static>, AuthEffect);

    assert_local_effect!(DynCasStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynOwnerCheckpointStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynDeadLetterStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynObjectStore<'static>, BusinessWriteEffect);

    assert_local_effect!(DynLockStore<'static>, WorkflowEffect);
}
