//! Owner-local admission. At most one fitting successor can bypass each blocked head.
// ref: tokio/src/sync/batch_semaphore.rs@tokio-1.53.3
use rss_timeseries::Error;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::oneshot;

pub(crate) struct Capacity(Mutex<State>);
struct State {
    slots: u32,
    units: u32,
    closed: bool,
    queue: VecDeque<Waiter>,
}
struct Waiter {
    ticket: Arc<Ticket>,
    ready: oneshot::Sender<()>,
    bypassed: bool,
}
struct Ticket {
    units: u32,
    // Accessed only under the capacity mutex, including cancellation after notification.
    granted: AtomicBool,
}
impl State {
    fn next(&self) -> Option<usize> {
        let head = self.queue.front()?;
        if self.slots == 0 {
            return None;
        }
        if head.ticket.units <= self.units {
            return Some(0);
        }
        if head.bypassed {
            return None;
        }
        self.queue.iter().position(|w| w.ticket.units <= self.units)
    }
    fn dispatch(&mut self) {
        while let Some(index) = self.next() {
            let Some(waiter) = self.queue.remove(index) else {
                break;
            };
            if waiter.ready.send(()).is_err() {
                continue;
            }
            if index != 0 {
                self.queue[0].bypassed = true;
            }
            self.slots -= 1;
            self.units -= waiter.ticket.units;
            waiter.ticket.granted.store(true, Ordering::Relaxed);
        }
    }
}
impl Capacity {
    pub(crate) fn new(slots: u32, units: u32) -> Self {
        Self(Mutex::new(State {
            slots,
            units,
            closed: false,
            queue: VecDeque::new(),
        }))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn close(&self) {
        let mut state = self.state();
        state.closed = true;
        state.queue.clear();
    }
    pub(crate) async fn acquire(&self, units: u32) -> Result<Permit<'_>, Error> {
        let (ready, received) = oneshot::channel();
        let permit = {
            let mut state = self.state();
            if state.closed {
                return Err(Error::Unavailable);
            }
            let ticket = Arc::new(Ticket {
                units,
                granted: AtomicBool::new(false),
            });
            state.queue.push_back(Waiter {
                ticket: ticket.clone(),
                ready,
                bypassed: false,
            });
            if units <= state.units && state.slots > 0 {
                state.dispatch();
            }
            Permit {
                capacity: self,
                ticket,
            }
        };
        received.await.map_err(|_| Error::Unavailable)?;
        Ok(permit)
    }
}
pub(crate) struct Permit<'a> {
    capacity: &'a Capacity,
    ticket: Arc<Ticket>,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self.capacity.state();
        if self.ticket.granted.load(Ordering::Relaxed) {
            state.units += self.ticket.units;
            state.slots += 1;
        } else {
            state
                .queue
                .retain(|w| !Arc::ptr_eq(&w.ticket, &self.ticket));
        }
        state.dispatch();
    }
}
