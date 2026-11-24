use crate::{AuthorizedTarget, Limits, Target, connection::Connection};
use rss_request_context::{Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::policy::within;
use sha2::{Digest as _, Sha256};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};

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
    cleaner_stopped: bool,
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
                while state
                    .idle
                    .front()
                    .is_some_and(|entry| entry.expires.is_expired(now))
                {
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

// The guard travels with the task, even when the runtime cancels it before its first poll.
struct IdleOwner(Arc<Shared>);

impl IdleOwner {
    async fn run<T: ExecutionTimer>(self, timer: Arc<T>) {
        self.0.clean(timer.as_ref()).await;
    }
}

impl Drop for IdleOwner {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.cleaner_stopped = true;
        state.idle.clear();
    }
}

pub(crate) struct Admission<'a>(&'a Connections);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        let mut state = self.0.shared.state();
        state.active -= 1;
        if state.closed && state.active == 0 {
            self.0.shared.drained.notify_waiters();
        }
    }
}

type Cleaner = AsyncMutex<Result<Option<JoinHandle<()>>, CloseError>>;

pub(crate) struct Connections {
    shared: Arc<Shared>,
    cleaner: Mutex<Option<Arc<Cleaner>>>,
    limits: Limits,
}

impl Connections {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            shared: Arc::default(),
            cleaner: Mutex::default(),
            limits,
        }
    }

    pub(crate) fn admit(&self) -> Option<Admission<'_>> {
        let mut state = self.shared.state();
        if state.closed || state.active >= self.limits.concurrent {
            return None;
        }
        state.active += 1;
        Some(Admission(self))
    }

    pub(crate) fn checkout(
        &self,
        identity: &Identity,
        target: &AuthorizedTarget,
        timer: &impl ExecutionTimer,
    ) -> Option<Connection> {
        // Bound the search even if concurrent borrowers keep returning other entries.
        let candidates = self.shared.state().idle.len();
        for _ in 0..candidates {
            let mut entry = {
                let mut state = self.shared.state();
                let now = timer.now();
                let index = state.idle.iter().rposition(|entry| {
                    let peer = entry.connection.peer;
                    !entry.expires.is_expired(now)
                        && &entry.identity == identity
                        && target.network.addresses.contains(&peer)
                        && target.network.permits(peer.ip())
                })?;
                state.idle.remove(index)?
            };
            if entry.connection.ready_now() {
                return Some(entry.connection);
            }
        }
        None
    }

    fn cleaner(&self) -> MutexGuard<'_, Option<Arc<Cleaner>>> {
        self.cleaner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) async fn close(
        &self,
        timer: &impl ExecutionTimer,
        deadline: Deadline,
    ) -> Result<(), CloseError> {
        let cleaner = {
            let cleaner = self.cleaner();
            self.shared.stop();
            cleaner.clone()
        };
        within(timer, deadline, |_| async {
            self.shared.wait_drained().await;
            if let Some(cleaner) = cleaner {
                let mut slot = cleaner.lock().await;
                if let Some(task) = slot.as_mut().map_err(|error| *error)? {
                    *slot = task.await.map(|()| None).map_err(|_| CloseError::Cleanup);
                }
                slot.as_ref().map_err(|error| *error)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| CloseError::Deadline)?
    }
}

impl Drop for Connections {
    fn drop(&mut self) {
        self.shared.stop();
        if let Some(cleaner) = self.cleaner().as_ref()
            && let Ok(slot) = cleaner.try_lock()
            && let Ok(Some(handle)) = &*slot
        {
            handle.abort();
        }
    }
}

impl Admission<'_> {
    pub(crate) fn put<T: ExecutionTimer + 'static>(
        &self,
        connection: Connection,
        identity: Identity,
        timer: &Arc<T>,
    ) {
        let pool = self.0;
        let Some(limits) = pool.limits.pool else {
            return;
        };
        // Serialize first task startup with close. The task's Drop guard only uses the
        // state mutex, which is released before spawning (including on a stopped runtime).
        let mut cleaner = pool.cleaner();
        let mut state = pool.shared.state();
        if state.closed || state.cleaner_stopped {
            return;
        }
        let Ok(expires) = Deadline::from_timeout(timer.as_ref(), limits.timeout) else {
            return;
        };
        if state.idle.len() == limits.max_idle {
            state.idle.pop_front();
        }
        let wake = state.idle.is_empty();
        state.idle.push_back(Idle {
            connection,
            identity,
            expires,
        });
        drop(state);
        cleaner.get_or_insert_with(|| {
            let owner = IdleOwner(pool.shared.clone());
            Arc::new(AsyncMutex::new(Ok(Some(tokio::spawn(
                owner.run(timer.clone()),
            )))))
        });
        if wake {
            pool.shared.wake_cleaner.notify_one();
        }
    }
}
