//! Compile-time effect classification for canonical DI port injection types.
//!
//! A port receives exactly one strongest effect and one privilege class. Both vocabularies and the
//! mapping are closed in this crate: adapters may implement port traits, but downstream crates
//! cannot forge or override the classification used by consistency guards. Effect answers what a
//! capability can do; privilege answers whether it may cross a tenant boundary.
//!
//! Concurrency buckets (`async_sync` / `async_send` / `sync_obj`) live in the same
//! [`classify_ports!`] table — the sole identity source for Dyn* Arc Send/Sync shape.
//!
//! INVARIANT: DIPORT-DYN-CONCURRENCY-01 { level = "Hard", exec = "native-compile", source = "code", native = "classify_ports concurrency buckets + Arc Send/Sync asserts" }
//!
//! `ref: oxidecomputer/omicron nexus/auth/src/storage.rs@fb4c7461e208efce72eee9532da45f8d802b6230`

use std::sync::Arc;

mod sealed {
    pub trait PortEffectClass {}
    pub trait PortPrivilegeClass {}
    pub trait DiPortEffect {}
    pub trait DiPortConcurrency {}
    pub trait ConcurrencyBucket {}
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

/// Closed concurrency-bucket vocabulary for canonical DI port injection types.
pub trait ConcurrencyBucket: sealed::ConcurrencyBucket {}

macro_rules! define_concurrency_buckets {
    ($($bucket:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Canonical `", stringify!($bucket), "` concurrency bucket.")]
            pub struct $bucket;

            impl sealed::ConcurrencyBucket for $bucket {}
            impl ConcurrencyBucket for $bucket {}
        )+
    };
}

define_concurrency_buckets!(AsyncSync, AsyncSend, SyncObj);

/// Compile-time classification of a canonical DI port injection type.
///
/// This trait is owner-sealed. Downstream crates can inspect `Effect`, but cannot implement the
/// trait for their own types or change the classification of a canonical port.
pub trait DiPortEffect: sealed::DiPortEffect {
    type Effect: PortEffectClass;
    type Privilege: PortPrivilegeClass;
}

/// Compile-time concurrency bucket of a canonical DI port injection type.
///
/// Owner-sealed alongside [`DiPortEffect`]. `Bucket` is the Hard identity for Arc Send/Sync shape:
/// `AsyncSync` ⇒ `Arc<DynX>: Send + Sync`; `AsyncSend` ⇒ `Arc<DynX>: !Send`; `SyncObj` ⇒ sync
/// trait object (no Dyn* Arc gate).
pub trait DiPortConcurrency: sealed::DiPortConcurrency {
    type Bucket: ConcurrencyBucket;
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

impl<T: ?Sized + sealed::DiPortConcurrency> sealed::DiPortConcurrency for Arc<T> {}
impl<T: ?Sized + DiPortConcurrency> DiPortConcurrency for Arc<T> {
    type Bucket = T::Bucket;
}

impl<T: ?Sized + sealed::DiPortConcurrency> sealed::DiPortConcurrency for Box<T> {}
impl<T: ?Sized + DiPortConcurrency> DiPortConcurrency for Box<T> {
    type Bucket = T::Bucket;
}

fn assert_send_sync_bound<T: Send + Sync>() {}

/// Shared expansion for `async_sync` / `async_send` arms of [`classify_ports!`].
macro_rules! classify_async_port {
    ($port:ident => $effect:ident; bucket = $bucket:ty) => {
        impl sealed::DiPortEffect for crate::$port<'_> {}
        impl DiPortEffect for crate::$port<'_> {
            type Effect = $effect;
            type Privilege = LocalPrivilege;
        }
        impl sealed::DiPortConcurrency for crate::$port<'_> {}
        impl DiPortConcurrency for crate::$port<'_> {
            type Bucket = $bucket;
        }
        const _: Option<EffectAssertion<crate::$port<'static>, $effect, LocalPrivilege>> = None;
    };
    ($port:ident => $effect:ident; bucket = $bucket:ty; assert_arc_send_sync) => {
        classify_async_port!($port => $effect; bucket = $bucket);
        const _: fn() = || {
            assert_send_sync_bound::<Arc<crate::$port<'static>>>();
        };
    };
}

// The owner-local table is the single source for sealing, effect classification, concurrency
// buckets, compile-time Arc Send+Sync assertions, and trybuild UI macros.
// `async_sync` / `async_send` = dynosaur wrappers; `sync_obj` = sync trait objects.
// `async_sync` uses `+` (non-empty) so an empty Sync-exception bucket cannot vacuous-pass.
// Hard proof = this expansion (sealed DiPortConcurrency + assert_send_sync_bound). Medium
// anti-vacuity = exported `ui_assert_*` trybuild macros (see tests/trybuild.rs).
macro_rules! classify_ports {
    (
        $(async_sync $async_sync_port:ident => $async_sync_effect:ident;)+
        $(async_send $async_send_port:ident => $async_send_effect:ident;)*
        $(sync_obj $sync_port:ident => $sync_effect:ident;)*
    ) => {
        $(
            classify_async_port!(
                $async_sync_port => $async_sync_effect;
                bucket = AsyncSync;
                assert_arc_send_sync
            );
        )+
        $(
            classify_async_port!($async_send_port => $async_send_effect; bucket = AsyncSend);
        )*
        $(
            impl<'a> sealed::DiPortEffect for dyn crate::$sync_port + 'a {}
            impl<'a> DiPortEffect for dyn crate::$sync_port + 'a {
                type Effect = $sync_effect;
                type Privilege = LocalPrivilege;
            }
            impl<'a> sealed::DiPortConcurrency for dyn crate::$sync_port + 'a {}
            impl<'a> DiPortConcurrency for dyn crate::$sync_port + 'a {
                type Bucket = SyncObj;
            }
            const _: Option<EffectAssertion<dyn crate::$sync_port, $sync_effect, LocalPrivilege>> = None;
        )*

        /// Trybuild UI: assert every `async_sync` port's `Arc<DynX>: Send + Sync`.
        ///
        /// Call sites must provide `fn assert_send_sync<T: Send + Sync>()`.
        /// Medium anti-vacuity only — Hard Arc Send+Sync proof is macro-internal
        /// `assert_send_sync_bound` in `classify_ports!` (DIPORT-DYN-CONCURRENCY-01).
        #[doc(hidden)]
        #[macro_export]
        macro_rules! ui_assert_async_sync_arc_send_sync {
            () => {{
                $(
                    assert_send_sync::<::std::sync::Arc<$crate::$async_sync_port<'static>>>();
                )+
            }};
        }

        /// Trybuild UI: assert every `async_send` port's `Arc<DynX>: Send` (expected to fail — !Send).
        ///
        /// Call sites must provide `fn assert_send<T: Send>()`.
        /// Medium anti-vacuity for the `async_send` exact set from `classify_ports!`.
        #[doc(hidden)]
        #[macro_export]
        macro_rules! ui_assert_async_send_arc_not_send {
            () => {{
                $(
                    assert_send::<::std::sync::Arc<$crate::$async_send_port<'static>>>();
                )*
            }};
        }
    };
}

classify_ports! {
    async_sync DynKeyProvider => AuthEffect;
    async_sync DynPdp => AuthEffect;
    async_sync DynSecretResolver => AuthEffect;
    async_sync DynServiceTokenReplayStore => AuthEffect;

    async_send DynRateLimiter => AuthEffect;
    async_send DynSigner => AuthEffect;

    async_send DynAcker => BusinessWriteEffect;
    async_send DynAuditSink => BusinessWriteEffect;
    async_send DynCasStore => BusinessWriteEffect;
    async_send DynOwnerCheckpointStore => BusinessWriteEffect;
    async_send DynDeadLetterStore => BusinessWriteEffect;
    async_send DynFencedWriter => BusinessWriteEffect;
    async_send DynObjectStore => BusinessWriteEffect;
    async_send DynRevocationStore => BusinessWriteEffect;

    async_send DynOutboxEmitter => OutboxEffect;
    async_send DynPublisher => OutboxEffect;

    async_send DynAckableSubscriber => WorkflowEffect;
    async_send DynSubscriber => WorkflowEffect;
    async_send DynLeaderElector => WorkflowEffect;
    async_send DynLockStore => WorkflowEffect;
    async_send DynManagedResource => WorkflowEffect;
    async_send DynSagaInstanceStore => WorkflowEffect;
    async_send DynSagaTenantSource => WorkflowEffect;
    async_send DynSagaJournal => WorkflowEffect;

    sync_obj Clock => ReadEffect;
    sync_obj MetricsExporter => ReadEffect;
    sync_obj SubscribeInitializer => WorkflowEffect;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_effect<
        T: ?Sized + DiPortEffect<Effect = E, Privilege = LocalPrivilege>,
        E: PortEffectClass,
    >() {
    }

    fn assert_bucket<T: ?Sized + DiPortConcurrency<Bucket = B>, B: ConcurrencyBucket>() {}

    #[test]
    fn arc_and_box_preserve_the_inner_effect() {
        assert_effect::<Arc<crate::DynSigner<'static>>, AuthEffect>();
        assert_effect::<Box<Arc<crate::DynSigner<'static>>>, AuthEffect>();
        assert_effect::<Arc<dyn crate::Clock>, ReadEffect>();
    }

    #[test]
    fn concurrency_buckets_match_classify_ports_tags() {
        assert_bucket::<crate::DynKeyProvider<'static>, AsyncSync>();
        assert_bucket::<crate::DynPdp<'static>, AsyncSync>();
        assert_bucket::<crate::DynSecretResolver<'static>, AsyncSync>();
        assert_bucket::<crate::DynServiceTokenReplayStore<'static>, AsyncSync>();
        assert_bucket::<crate::DynSigner<'static>, AsyncSend>();
        assert_bucket::<dyn crate::Clock, SyncObj>();
    }

    #[test]
    fn arc_and_box_preserve_bucket() {
        assert_bucket::<Arc<crate::DynKeyProvider<'static>>, AsyncSync>();
        assert_bucket::<Box<crate::DynSigner<'static>>, AsyncSend>();
        assert_bucket::<Arc<Box<dyn crate::Clock>>, SyncObj>();
    }
}
