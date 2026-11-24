use crate::{AuthorizedTarget, IdlePoolLimits, Limits, Target, connection::Connection};
use rss_request_context::{Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::policy::within;
use sha2::{Digest as _, Sha256};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError},
};
use tokio::{sync::{Mutex as AsyncMutex, Notify}, task::JoinHandle};

/// Closed failures when waiting for publisher shutdown. Admission stays closed after either error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CloseError {
    /// In-flight publication or the idle cleaner did not finish within the deadline.
    #[error("webhook shutdown deadline elapsed")]
    Deadline,
    /// The idle cleanup task did not exit normally.
    #[error("webhook idle cleanup interrupted")]
    Cleanup,
}

#[derive(PartialEq, Eq)]
pub(crate) struct Identity {
    tenant: TenantId,
    target: Target,
    endpoint: [u8; 32],
    trust: [u8; 32],
    signing: [u8; 32],
}

impl Identity {
    pub(crate) fn of(target: &AuthorizedTarget) -> Self {
        Self {
            tenant: target.tenant,
            target: target.target.clone(),
            endpoint: Sha256::digest(target.url.as_str().as_bytes()).into(),
            trust: target.trust.identity,
            signing: target.keys.identity(),
        }
    }
}

struct Idle {
    connection: Connection,
    identity: Identity,
    expires: Deadline,
}

#[derive(Default)]
struct State {
    active: usize,
    closed: bool,
    idle: VecDeque<Idle>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    wake_cleaner: Notify,
    drained: Notify,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stop(&self) {
        let mut state = self.state();
        state.closed = true;
        state.idle.clear();
        self.wake_cleaner.notify_one();
    }

    async fn clean<T: ExecutionTimer>(&self, timer: &T) {
        loop {
            let next = {
                let mut state = self.state();
                if state.closed {
                    return;
                }
                let now = timer.now();
                while state.idle.front().is_some_and(|entry| entry.expires.is_expired(now)) {
                    state.idle.pop_front();
                }
                state.idle.front().map(|entry| entry.expires)
            };
            if let Some(deadline) = next {
                tokio::select! {
                    () = timer.sleep_until(deadline) => (),
                    () = self.wake_cleaner.notified() => (),
                }
            } else {
                self.wake_cleaner.notified().await;
            }
        }
    }

    async fn wait_drained(&self) {
        loop {
            let changed = self.drained.notified();
            if self.state().active == 0 {
                return;
            }
            changed.await;
        }
    }
}

pub(crate) struct Admission<'a>(&'a Shared);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.active -= 1;
        if state.closed && state.active == 0 {
            self.0.drained.notify_waiters();
        }
    }
}

type Cleaner = AsyncMutex<Result<Option<JoinHandle<()>>, CloseError>>;

pub(crate) struct Connections {
    shared: Arc<Shared>,
    cleaner: OnceLock<Cleaner>,
    limits: Limits,
}

impl Connections {
    pub(crate) fn new(limits: Limits) -> Self {
        Self { shared: Arc::default(), cleaner: OnceLock::new(), limits }
    }

    pub(crate) fn admit(&self) -> Option<Admission<'_>> {
        let mut state = self.shared.state();
        if state.closed || state.active >= self.limits.concurrent {
            return None;
        }
        state.active += 1;
        Some(Admission(&self.shared))
    }

    pub(crate) fn checkout(
        &self,
        identity: &Identity,
        target: &AuthorizedTarget,
        timer: &impl ExecutionTimer,
    ) -> Option<Connection> {
        let mut state = self.shared.state();
        let now = timer.now();
        let index = state.idle.iter().rposition(|entry| {
            let peer = entry.connection.peer;
            !entry.expires.is_expired(now) && &entry.identity == identity
                && target.network.addresses.contains(&peer) && target.network.permits(peer.ip())
        })?;
        let mut entry = state.idle.remove(index)?;
        drop(state);
        entry.connection.ready_now().then_some(entry.connection)
    }

    pub(crate) fn put<T: ExecutionTimer + 'static>(
        &self,
        connection: Connection,
        identity: Identity,
        limits: IdlePoolLimits,
        timer: &Arc<T>,
    ) {
        let mut state = self.shared.state();
        if state.closed {
            return;
        }
        let Ok(expires) = Deadline::from_timeout(timer.as_ref(), limits.timeout) else {
            return;
        };
        let cleaner = self.cleaner.get_or_init(|| {
            let shared = self.shared.clone();
            let timer = timer.clone();
            AsyncMutex::new(Ok(Some(tokio::spawn(async move { shared.clean(timer.as_ref()).await }))))
        });
        // A stopped runtime cannot service future idle deadlines on this publisher.
        if let Ok(task) = cleaner.try_lock()
            && !matches!(&*task, Ok(Some(handle)) if !handle.is_finished()) {
            state.idle.clear();
            return;
        }
        if state.idle.len() == limits.max_idle {
            state.idle.pop_front();
        }
        let wake = state.idle.is_empty();
        state.idle.push_back(Idle { connection, identity, expires });
        if wake {
            self.shared.wake_cleaner.notify_one();
        }
    }

    pub(crate) async fn close(&self, timer: &impl ExecutionTimer, deadline: Deadline) -> Result<(), CloseError> {
        self.shared.stop();
        within(timer, deadline, |_| async {
            self.shared.wait_drained().await;
            if let Some(cleaner) = self.cleaner.get() {
                let mut slot = cleaner.lock().await;
                if let Some(task) = slot.as_mut().map_err(|error| *error)? {
                    *slot = task.await.map(|()| None).map_err(|_| CloseError::Cleanup);
                }
                slot.as_ref().map_err(|error| *error)?;
            }
            Ok(())
        }).await.map_err(|_| CloseError::Deadline)?
    }
}

impl Drop for Connections {
    fn drop(&mut self) {
        self.shared.stop();
        if let Some(cleaner) = self.cleaner.get_mut()
            && let Ok(Some(handle)) = cleaner.get_mut() {
            handle.abort();
        }
    }
}

