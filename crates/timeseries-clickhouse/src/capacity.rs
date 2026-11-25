//! Owner-local admission with indexed cancellation and one bypass per blocked head.
// ref: tokio tokio/src/sync/batch_semaphore.rs@tokio-1.53.3
use rss_timeseries::Error;
use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionClass {
    Unit,
    Read,
}
impl AdmissionClass {
    fn index(self) -> usize {
        match self {
            Self::Unit => 0,
            Self::Read => 1,
        }
    }
    pub(crate) fn units(self, query_threads: NonZeroU32) -> NonZeroU32 {
        match self {
            Self::Unit => NonZeroU32::MIN,
            Self::Read => query_threads,
        }
    }
}

pub(crate) struct Capacity(Mutex<State>);
struct State {
    slots: u32,
    units: u32,
    query_threads: NonZeroU32,
    max_waiters: u32,
    next_id: u64,
    closed: bool,
    queues: [BTreeMap<u64, Waiter>; 2],
    #[cfg(test)]
    probes: usize,
}
struct Waiter {
    ticket: Arc<Ticket>,
    ready: oneshot::Sender<()>,
    bypassed: bool,
}
struct Ticket {
    id: u64,
    class: AdmissionClass,
    units: u32,
    // All accesses are under the capacity mutex, including cancellation after grant.
    granted: AtomicBool,
}
#[derive(Clone, Copy)]
struct Head {
    id: u64,
    class: AdmissionClass,
    units: u32,
    bypassed: bool,
}
impl State {
    fn len(&self) -> usize {
        self.queues.iter().map(BTreeMap::len).sum()
    }
    fn head(&mut self, class: AdmissionClass, incoming: Option<&Ticket>) -> Option<Head> {
        #[cfg(test)]
        { self.probes += 1; }
        self.queues[class.index()].first_key_value().map(|(&id, w)| Head {
            id, class, units: w.ticket.units, bypassed: w.bypassed,
        }).or_else(|| incoming.filter(|t| t.class == class).map(|t| Head {
            id: t.id, class, units: t.units, bypassed: false,
        }))
    }
    // The virtual incoming tail participates in the same choice, without exceeding the cap.
    fn next(&mut self, incoming: Option<&Ticket>) -> Option<Head> {
        if self.closed || self.slots == 0 { return None; }
        let heads = [self.head(AdmissionClass::Unit, incoming), self.head(AdmissionClass::Read, incoming)];
        let head = heads.into_iter().flatten().min_by_key(|h| h.id)?;
        let chosen = if head.units <= self.units {
            head
        } else {
            if head.bypassed { return None; }
            heads.into_iter().flatten().find(|h| h.units <= self.units)?
        };
        if chosen.id != head.id {
            // A virtual tail cannot precede an existing successor.
            self.queues[head.class.index()].get_mut(&head.id)?.bypassed = true;
        }
        Some(chosen)
    }
    fn grant(&mut self, ticket: &Ticket) {
        self.slots -= 1;
        self.units -= ticket.units;
        ticket.granted.store(true, Ordering::Relaxed);
    }
    fn dispatch(&mut self) -> Vec<oneshot::Sender<()>> {
        let mut wake = Vec::new();
        while let Some(head) = self.next(None) {
            let Some(waiter) = self.queues[head.class.index()].remove(&head.id) else { break; };
            self.grant(&waiter.ticket);
            wake.push(waiter.ready);
        }
        wake
    }
}
fn notify(wake: Vec<oneshot::Sender<()>>) {
    for ready in wake {
        // The permit guard owns all returns, including cancellation before this send.
        let _ = ready.send(());
    }
}
impl Capacity {
    pub(crate) fn new(slots: u32, units: u32, query_threads: NonZeroU32, max_waiters: u32) -> Self {
        Self(Mutex::new(State {
            slots, units, query_threads, max_waiters, next_id: 0, closed: false,
            queues: Default::default(),
            #[cfg(test)]
            probes: 0,
        }))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn close(&self) {
        let queues = {
            let mut state = self.state();
            state.closed = true;
            std::mem::take(&mut state.queues)
        };
        drop(queues); // Wake and destroy all waiters outside the capacity mutex.
    }
    pub(crate) async fn acquire(&self, class: AdmissionClass) -> Result<Permit<'_>, Error> {
        let (ready, received) = oneshot::channel();
        let (permit, immediate) = {
            let mut state = self.state();
            if state.closed { return Err(Error::Unavailable); }
            let id = state.next_id;
            state.next_id = id.checked_add(1).ok_or(Error::Invariant)?;
            let ticket = Arc::new(Ticket {
                id, class, units: class.units(state.query_threads).get(),
                granted: AtomicBool::new(false),
            });
            // Every release/cancel dispatches to quiescence before unlocking. Only the
            // incoming request can become newly eligible without a capacity change.
            let immediate = state.next(Some(&ticket)).is_some_and(|h| h.id == id);
            if immediate {
                state.grant(&ticket);
            } else {
                if state.len() >= state.max_waiters as usize { return Err(Error::Unavailable); }
                state.queues[class.index()].insert(id, Waiter {
                    ticket: ticket.clone(), ready, bypassed: false,
                });
            }
            (Permit { capacity: self, ticket }, immediate)
        };
        if !immediate { received.await.map_err(|_| Error::Unavailable)?; }
        Ok(permit)
    }
}
pub(crate) struct Permit<'a> {
    capacity: &'a Capacity,
    ticket: Arc<Ticket>,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.capacity.state();
            if self.ticket.granted.load(Ordering::Relaxed) {
                state.units += self.ticket.units;
                state.slots += 1;
            } else {
                #[cfg(test)]
                { state.probes += 1; }
                state.queues[self.ticket.class.index()].remove(&self.ticket.id);
            }
            state.dispatch()
        };
        notify(wake);
    }
}

#[cfg(test)]
mod tests;
