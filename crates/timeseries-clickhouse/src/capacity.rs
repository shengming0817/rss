//! Owner-local admission. At most one fitting successor can bypass each blocked head.
use rss_timeseries::Error;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::Notify;

pub(crate) struct Capacity {
    state: Mutex<State>,
    changed: Notify,
}
struct State {
    slots: u32,
    units: u32,
    closed: bool,
    queue: VecDeque<Waiter>,
}
struct Waiter {
    ticket: Arc<()>,
    units: u32,
    bypassed: bool,
}
impl State {
    fn next(&self) -> Option<usize> {
        let head = self.queue.front()?;
        if self.slots == 0 {
            return None;
        }
        if head.units <= self.units {
            return Some(0);
        }
        if head.bypassed {
            return None;
        }
        self.queue.iter().position(|w| w.units <= self.units)
    }
}
impl Capacity {
    pub(crate) fn new(slots: u32, units: u32) -> Self {
        Self {
            state: Mutex::new(State { slots, units, closed: false, queue: VecDeque::new() }),
            changed: Notify::new(),
        }
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn close(&self) {
        self.state().closed = true;
        self.changed.notify_waiters();
    }
    pub(crate) async fn acquire(&self, units: u32) -> Result<Permit<'_>, Error> {
        let ticket = Arc::new(());
        self.state().queue.push_back(Waiter {ticket: ticket.clone(), units, bypassed:false});
        let mut registration = Registration {capacity:self, ticket:Some(ticket.clone())};
        loop {
            // Construct before inspecting the queue so notify_waiters cannot be lost.
            let changed = self.changed.notified();
            {
                let mut state = self.state();
                if state.closed {
                    return Err(Error::Unavailable);
                }
                if let Some(index) = state.next()
                    && Arc::ptr_eq(&state.queue[index].ticket, &ticket)
                {
                    state.queue.remove(index);
                    if index != 0 {
                        state.queue[0].bypassed = true;
                    }
                    state.slots -= 1;
                    state.units -= units;
                    registration.ticket.take();
                    self.changed.notify_waiters();
                    return Ok(Permit {capacity:self, units});
                }
            }
            changed.await;
        }
    }
}
struct Registration<'a> {
    capacity: &'a Capacity,
    ticket: Option<Arc<()>>,
}
impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(ticket) = &self.ticket {
            self.capacity.state().queue.retain(|w| !Arc::ptr_eq(&w.ticket, ticket));
            self.capacity.changed.notify_waiters();
        }
    }
}
pub(crate) struct Permit<'a> {
    capacity: &'a Capacity,
    units: u32,
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self.capacity.state();
        state.slots += 1;
        state.units += self.units;
        drop(state);
        self.capacity.changed.notify_waiters();
    }
}
