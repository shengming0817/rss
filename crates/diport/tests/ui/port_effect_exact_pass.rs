use diport::{
    AuthEffect, BusinessWriteEffect, Clock, DiPortEffect, DynAckableSubscriber, DynAcker,
    DynAuditSink, DynCasStore, DynDeadLetterStore, DynFencedWriter, DynKeyProvider,
    DynLeaderElector, DynLockStore, DynManagedResource, DynObjectStore, DynOutboxEmitter,
    DynOwnerCheckpointStore, DynPdp, DynPublisher, DynRateLimiter, DynRevocationStore,
    DynSagaDurableStore, DynSagaTenantSource, DynSecretResolver, DynServiceTokenReplayStore,
    DynSigner, DynSubscriber, LocalPrivilege, MetricsExporter, OutboxEffect, PortEffectClass,
    PortPrivilegeClass, ReadEffect, SubscribeInitializer, WorkflowEffect,
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
    assert_local_effect!(dyn Clock, ReadEffect);
    assert_local_effect!(dyn MetricsExporter, ReadEffect);

    assert_local_effect!(DynKeyProvider<'static>, AuthEffect);
    assert_local_effect!(DynPdp<'static>, AuthEffect);
    assert_local_effect!(DynRateLimiter<'static>, AuthEffect);
    assert_local_effect!(DynSecretResolver<'static>, AuthEffect);
    assert_local_effect!(DynServiceTokenReplayStore<'static>, AuthEffect);
    assert_local_effect!(DynSigner<'static>, AuthEffect);

    assert_local_effect!(DynAcker<'static>, BusinessWriteEffect);
    assert_local_effect!(DynAuditSink<'static>, BusinessWriteEffect);
    assert_local_effect!(DynCasStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynOwnerCheckpointStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynDeadLetterStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynFencedWriter<'static>, BusinessWriteEffect);
    assert_local_effect!(DynObjectStore<'static>, BusinessWriteEffect);
    assert_local_effect!(DynRevocationStore<'static>, BusinessWriteEffect);

    assert_local_effect!(DynOutboxEmitter<'static>, OutboxEffect);
    assert_local_effect!(DynPublisher<'static>, OutboxEffect);

    assert_local_effect!(DynAckableSubscriber<'static>, WorkflowEffect);
    assert_local_effect!(DynSubscriber<'static>, WorkflowEffect);
    assert_local_effect!(dyn SubscribeInitializer, WorkflowEffect);
    assert_local_effect!(DynLeaderElector<'static>, WorkflowEffect);
    assert_local_effect!(DynLockStore<'static>, WorkflowEffect);
    assert_local_effect!(DynManagedResource<'static>, WorkflowEffect);
    assert_local_effect!(DynSagaDurableStore<'static>, WorkflowEffect);
    assert_local_effect!(DynSagaTenantSource<'static>, WorkflowEffect);
}
