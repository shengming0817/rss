//! Compile-time effect classification for canonical DI port injection types.
//!
//! A port receives exactly one strongest effect and one privilege class. Both vocabularies and the
//! mapping are closed in this crate: adapters may implement port traits, but downstream crates
//! cannot forge or override the classification used by consistency guards. Effect answers what a
//! capability can do; privilege answers whether it may cross a tenant boundary.
//!
//! `ref: oxidecomputer/omicron nexus/auth/src/storage.rs@fb4c7461e208efce72eee9532da45f8d802b6230`

use std::sync::Arc;

mod sealed {
    pub trait PortEffectClass {}
    pub trait PortPrivilegeClass {}
    pub trait DiPortEffect {}
}

/// Closed vocabulary implemented only by the five canonical effect classes.
pub trait PortEffectClass: sealed::PortEffectClass {}

macro_rules! define_effect_classes {
    ($($effect:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Canonical `", stringify!($effect), "` port classification.")]
            pub struct $effect;

            impl sealed::PortEffectClass for $effect {}
            impl PortEffectClass for $effect {}
        )+
    };
}

define_effect_classes!(
    ReadEffect,
    AuthEffect,
    BusinessWriteEffect,
    OutboxEffect,
    WorkflowEffect,
);

/// Closed privilege vocabulary for canonical port injection types.
pub trait PortPrivilegeClass: sealed::PortPrivilegeClass {}

macro_rules! define_privilege_classes {
    ($($privilege:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Canonical `", stringify!($privilege), "` port privilege classification.")]
            pub struct $privilege;

            impl sealed::PortPrivilegeClass for $privilege {}
            impl PortPrivilegeClass for $privilege {}
        )+
    };
}

define_privilege_classes!(LocalPrivilege, CrossTenantPrivilege);

/// Compile-time classification of a canonical DI port injection type.
///
/// This trait is owner-sealed. Downstream crates can inspect `Effect`, but cannot implement the
/// trait for their own types or change the classification of a canonical port.
pub trait DiPortEffect: sealed::DiPortEffect {
    type Effect: PortEffectClass;
    type Privilege: PortPrivilegeClass;
}

struct EffectAssertion<T: ?Sized, E, P>(std::marker::PhantomData<(*const T, E, P)>)
where
    T: DiPortEffect<Effect = E, Privilege = P>,
    E: PortEffectClass,
    P: PortPrivilegeClass;

impl<T: ?Sized + sealed::DiPortEffect> sealed::DiPortEffect for Arc<T> {}
impl<T: ?Sized + DiPortEffect> DiPortEffect for Arc<T> {
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

impl<T: ?Sized + sealed::DiPortEffect> sealed::DiPortEffect for Box<T> {}
impl<T: ?Sized + DiPortEffect> DiPortEffect for Box<T> {
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

// The owner-local table is the single source for sealing, classification, and a compile-time
// associated-type assertion. `dyn` means a dynosaur wrapper; `sync` means a sync trait object.
macro_rules! classify_ports {
    ($(dyn $port:ident => $effect:ident;)* $(sync $sync_port:ident => $sync_effect:ident;)*) => {
        $(
            impl sealed::DiPortEffect for crate::$port<'_> {}
            impl DiPortEffect for crate::$port<'_> {
                type Effect = $effect;
                type Privilege = LocalPrivilege;
            }
            const _: Option<EffectAssertion<crate::$port<'static>, $effect, LocalPrivilege>> = None;
        )*
        $(
            impl<'a> sealed::DiPortEffect for dyn crate::$sync_port + 'a {}
            impl<'a> DiPortEffect for dyn crate::$sync_port + 'a {
                type Effect = $sync_effect;
                type Privilege = LocalPrivilege;
            }
            const _: Option<EffectAssertion<dyn crate::$sync_port, $sync_effect, LocalPrivilege>> = None;
        )*
    };
}

classify_ports! {
    dyn DynKeyProvider => AuthEffect;
    dyn DynPdp => AuthEffect;
    dyn DynRateLimiter => AuthEffect;
    dyn DynSecretResolver => AuthEffect;
    dyn DynSigner => AuthEffect;

    dyn DynAcker => BusinessWriteEffect;
    dyn DynAuditSink => BusinessWriteEffect;
    dyn DynCasStore => BusinessWriteEffect;
    dyn DynOwnerCheckpointStore => BusinessWriteEffect;
    dyn DynDeadLetterStore => BusinessWriteEffect;
    dyn DynFencedWriter => BusinessWriteEffect;
    dyn DynObjectStore => BusinessWriteEffect;
    dyn DynRevocationStore => BusinessWriteEffect;

    dyn DynOutboxEmitter => OutboxEffect;
    dyn DynPublisher => OutboxEffect;

    dyn DynAckableSubscriber => WorkflowEffect;
    dyn DynSubscriber => WorkflowEffect;
    dyn DynLeaderElector => WorkflowEffect;
    dyn DynLockStore => WorkflowEffect;
    dyn DynManagedResource => WorkflowEffect;
    dyn DynSagaInstanceStore => WorkflowEffect;
    dyn DynSagaTenantSource => WorkflowEffect;
    dyn DynSagaJournal => WorkflowEffect;

    sync Clock => ReadEffect;
    sync MetricsExporter => ReadEffect;
    sync ServiceTokenReplayGuard => AuthEffect;
    sync SubscribeInitializer => WorkflowEffect;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_effect<
        T: ?Sized + DiPortEffect<Effect = E, Privilege = LocalPrivilege>,
        E: PortEffectClass,
    >() {
    }

    #[test]
    fn arc_and_box_preserve_the_inner_effect() {
        assert_effect::<Arc<crate::DynSigner<'static>>, AuthEffect>();
        assert_effect::<Box<Arc<crate::DynSigner<'static>>>, AuthEffect>();
        assert_effect::<Arc<dyn crate::Clock>, ReadEffect>();
    }
}
