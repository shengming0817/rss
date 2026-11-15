//! One resource owner, independently revocable tenant capabilities, borrowed operations.
use crate::{ConnectionConfig, Credentials, CursorKey, Limits, config::Connections, probe};
use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::{Atomicity, Error, Guarantees, Scope};
use sqlx::PgPool;
use std::{
    future::Future,
    num::NonZeroU64,
    sync::{Arc, Weak, atomic::{AtomicBool, Ordering}},
};
use tokio::sync::{RwLock, RwLockReadGuard, Semaphore, SemaphorePermit};

/// Sole owner of one admitted installation's PG pool and HTTPS transport.
/// The supplied pool is adopted, including any host-retained clones. Keep this
/// owner alive while using its tenant stores and explicitly await `close`.
pub struct ChOwner<C> {
    inner: Arc<Shared<C>>,
}

/// An admitted tenant capability; it never keeps the physical resources alive.
/// Products own authorization, provisioning and switching between material versions.
pub struct ChStore<C> {
    pub(crate) owner: Weak<Shared<C>>,
    clock: Arc<C>,
    tenant: TenantId,
    version: NonZeroU64,
    material: RwLock<Option<Material>>,
    retired: AtomicBool,
    pub(crate) guarantees: Guarantees,
    #[cfg(feature = "integration")]
    pub(crate) fault: std::sync::atomic::AtomicU8,
}

pub(crate) struct Shared<C> {
    clock: Arc<C>,
    limits: Limits,
    instance: String,
    closed: AtomicBool,
    capacity: Semaphore,
    resources: RwLock<Option<Resources>>,
}
pub(crate) struct Resources {
    pub(crate) pool: PgPool,
    pub(crate) ch: Connections,
}
pub(crate) struct Material {
    reader: Credentials,
    pub(crate) key: CursorKey,
}

/// Private construction fixes authority and retains resources through settlement.
pub(crate) struct Operation<'a, C> {
    // Fields drop in declaration order: no reader outlives the resource permit.
    pub(crate) reader: clickhouse::Client,
    pub(crate) material: RwLockReadGuard<'a, Material>,
    pub(crate) resources: RwLockReadGuard<'a, Resources>,
    _capacity: SemaphorePermit<'a>,
    pub(crate) clock: &'a C,
    pub(crate) limits: &'a Limits,
    pub(crate) instance: &'a str,
    pub(crate) tenant: TenantId,
    #[cfg(feature = "integration")]
    pub(crate) fault: &'a std::sync::atomic::AtomicU8,
}

pub(crate) async fn bounded<C: Clock, T>(
    clock: &C,
    deadline: Deadline,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let remaining = deadline.remaining(clock.now()).ok_or(Error::Deadline)?;
    tokio::time::timeout(remaining, future).await.map_err(|_| Error::Deadline)?
}

impl<C: Clock> ChOwner<C> {
    /// Validate an installation without installing or repairing its schema.
    pub async fn new(
        pool: PgPool,
        config: ConnectionConfig,
        clock: C,
        limits: Limits,
        deadline: Deadline,
    ) -> Result<Self, Error> {
        if limits.replay_micros.get() > i64::MAX as u64
            || limits.cursor_micros.get() > i64::MAX as u64
            || limits.max_concurrent_operations.get() as usize > Semaphore::MAX_PERMITS
        {
            return Err(Error::InvalidInput);
        }
        let ch = config.connect();
        let instance = bounded(&clock, deadline, probe::installation(&pool, &ch)).await?;
        Ok(Self { inner: Arc::new(Shared {
            clock: Arc::new(clock),
            capacity: Semaphore::new(limits.max_concurrent_operations.get() as usize),
            limits,
            instance,
            closed: AtomicBool::new(false),
            resources: RwLock::new(Some(Resources { pool, ch })),
        }) })
    }

    /// Validate a new immutable reader capability on this exact installation.
    /// Versions identify host materials; they neither replace nor revoke other stores.
    pub async fn bind_tenant(
        &self,
        tenant: TenantId,
        reader: Credentials,
        key: CursorKey,
        material_version: NonZeroU64,
        deadline: Deadline,
    ) -> Result<ChStore<C>, Error> {
        bounded(self.inner.clock.as_ref(), deadline, async {
            let (_capacity, resources) = self.inner.enter().await?;
            if resources.ch.users.contains(&reader.user) {
                return Err(Error::Unauthorized);
            }
            let client = resources.ch.reader(&reader);
            probe::tenant(&resources.ch, &client, &reader.user, tenant, &self.inner.instance).await?;
            self.inner.open()?;
            Ok(ChStore {
                owner: Arc::downgrade(&self.inner),
                clock: self.inner.clock.clone(),
                tenant,
                version: material_version,
                material: RwLock::new(Some(Material { reader, key })),
                retired: AtomicBool::new(false),
                guarantees: Guarantees {
                    atomicity: Atomicity::RecoverableBatch,
                    replay_micros: self.inner.limits.replay_micros,
                },
                #[cfg(feature = "integration")]
                fault: std::sync::atomic::AtomicU8::new(0),
            })
        }).await
    }

    /// Stop admission, drain calls, close PG and release the shared HTTP clients.
    /// Timeout/cancellation leaves admission closed; another call resumes waiting.
    /// This does not prove remote query termination or undo uncertain effects.
    pub async fn close(&self, deadline: Deadline) -> Result<(), Error> {
        self.inner.stop();
        bounded(self.inner.clock.as_ref(), deadline, async {
            let mut resources = self.inner.resources.write().await;
            if let Some(resources) = resources.as_ref() {
                resources.pool.close().await;
            }
            resources.take();
            Ok(())
        }).await
    }
}
impl<C> Drop for ChOwner<C> {
    fn drop(&mut self) {
        self.inner.stop();
    }
}
impl<C> Shared<C> {
    fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        self.capacity.close();
    }
    fn open(&self) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) { Err(Error::Unavailable) } else { Ok(()) }
    }
    async fn enter(&self) -> Result<(SemaphorePermit<'_>, RwLockReadGuard<'_, Resources>), Error> {
        self.open()?;
        let capacity = self.capacity.acquire().await.map_err(|_| Error::Unavailable)?;
        let resources = self.resources.read().await;
        self.open()?;
        let resources = RwLockReadGuard::try_map(resources, Option::as_ref)
            .map_err(|_| Error::Unavailable)?;
        Ok((capacity, resources))
    }
}
impl<C: Clock> Shared<C> {
    pub(crate) async fn operation<'a>(
        &'a self,
        store: &'a ChStore<C>,
        scope: &Scope,
        deadline: Deadline,
    ) -> Result<Operation<'a, C>, Error> {
        store.admit(scope)?;
        bounded(self.clock.as_ref(), deadline, async {
            let (capacity, resources) = self.enter().await?;
            let material = store.material.read().await;
            self.open()?;
            store.admit(scope)?;
            let material = RwLockReadGuard::try_map(material, Option::as_ref)
                .map_err(|_| Error::Unavailable)?;
            Ok(Operation {
                reader: resources.ch.reader(&material.reader),
                material,
                resources,
                _capacity: capacity,
                clock: self.clock.as_ref(),
                limits: &self.limits,
                instance: &self.instance,
                tenant: store.tenant,
                #[cfg(feature = "integration")]
                fault: &store.fault,
            })
        }).await
    }
}
impl<C: Clock> ChStore<C> {
    /// The fixed tenant whose reader was admitted for this capability.
    pub fn tenant(&self) -> TenantId { self.tenant }
    /// Host-provided identity of this immutable material set, not a fencing epoch.
    pub fn material_version(&self) -> NonZeroU64 { self.version }
    fn admit(&self, scope: &Scope) -> Result<(), Error> {
        if scope.tenant() != self.tenant { return Err(Error::Unauthorized); }
        if self.retired.load(Ordering::Acquire) { return Err(Error::Unavailable); }
        Ok(())
    }
    /// Permanently stop this capability and drain its calls, leaving other stores open.
    /// Cancellation/timeout can be resumed. Does not require a live resource owner.
    pub async fn retire(&self, deadline: Deadline) -> Result<(), Error> {
        self.retired.store(true, Ordering::Release);
        bounded(self.clock.as_ref(), deadline, async {
            self.material.write().await.take();
            Ok(())
        }).await
    }
}
