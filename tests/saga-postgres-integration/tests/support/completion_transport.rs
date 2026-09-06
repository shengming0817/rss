use rss_saga::*;
use rss_saga_postgres::*;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
pub struct CompletionFault {
    pub store: PgStore,
    pub armed: AtomicBool,
    pub arm: std::sync::Arc<std::sync::atomic::AtomicU8>,
    pub when: EventKind,
}
impl Store for CompletionFault {
    async fn register<T: Timer>(
        &self,
        s: Scope,
        d: &Definition,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.register(s, d, c).await
    }
    async fn claim<T: Timer>(
        &self,
        s: Scope,
        t: Duration,
        c: &Control<'_, T>,
    ) -> Result<Lease, Error> {
        self.store.claim(s, t, c).await
    }
    async fn renew<T: Timer>(
        &self,
        l: &Lease,
        t: Duration,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store.renew(l, t, c).await
    }
    async fn release<T: Timer>(&self, l: &Lease, c: &Control<'_, T>) -> Result<(), Error> {
        self.store.release(l, c).await
    }
    async fn snapshot<T: Timer>(&self, l: &Lease, c: &Control<'_, T>) -> Result<Snapshot, Error> {
        self.store.snapshot(l, c).await
    }
    async fn candidates<T: Timer>(
        &self,
        t: rss_request_context::TenantId,
        after: Option<uuid::Uuid>,
        n: u32,
        c: &Control<'_, T>,
    ) -> Result<Vec<Scope>, Error> {
        self.store.candidates(t, after, n, c).await
    }
    async fn commit<T: Timer>(
        &self,
        l: &Lease,
        m: Mutation,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        if m.event().kind == self.when && self.armed.swap(false, Ordering::SeqCst) {
            self.arm.store(1, Ordering::SeqCst);
        }
        self.store.commit(l, m, c).await
    }
}
