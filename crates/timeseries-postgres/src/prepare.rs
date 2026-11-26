//! One admission decision covers a prepared batch slot and its full byte charge.
//! ref: tokio tokio/src/sync/batch_semaphore.rs@tokio-1.53.3
use crate::Limits;
use rss_timeseries::{Batch, Error};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::oneshot;

/// Two bounded JSON arenas and their SQLx copy. All selected definitions occur inside
/// distinct samples, so their combined JSON fits one input length. Per item cover
/// three digest arrays, two offset arrays, one definition binding (three words),
/// and binary bytea[] elements (76/sample and 40/definition). Fixed space covers
/// scalar identity strings, argument/array headers and fixed preparation state.
pub(crate) const fn charge(json: usize, count: usize) -> u32 {
    (4 * json + count * (116 + 96 + 5 * size_of::<usize>()) + 4096) as u32
}
#[derive(Clone)]
pub(crate) struct Capacity(Arc<Mutex<State>>);

struct State {
    slots: u32,
    bytes: u32,
    next: u64,
    closed: bool,
    waiting: BTreeMap<u64, Waiter>,
}

struct Waiter {
    weight: u32,
    bypassed: bool,
    ready: Option<oneshot::Sender<()>>,
    #[cfg(feature = "integration")]
    session: rss_timeseries::measurement::Session,
}

// A queued ticket absent from the map has already received both resources,
// even if the woken receiver has not yet been polled.
pub(crate) struct Permit {
    queued: Option<u64>,
    capacity: Capacity,
    weight: u32,
    #[cfg(feature = "integration")]
    session: rss_timeseries::measurement::Session,
}

type Wake = Vec<oneshot::Sender<()>>;

impl Capacity {
    pub(crate) fn new(limits: &Limits) -> Result<Self, Error> {
        let bytes = limits.max_prepare_bytes.get();
        if bytes < Limits::MIN_PREPARE_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(Self(Arc::new(Mutex::new(State {
            slots: limits.max_prepare_batches.get(),
            bytes,
            next: 0,
            closed: false,
            waiting: BTreeMap::new(),
        }))))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn grant(
        state: &mut State,
        weight: u32,
        #[cfg(feature = "integration")] session: rss_timeseries::measurement::Session,
    ) {
        state.slots -= 1;
        state.bytes -= weight;
        #[cfg(feature = "integration")]
        session.update(|r| {
            r.reserved_bytes += weight as usize;
            r.peak_reserved_bytes = r.peak_reserved_bytes.max(r.reserved_bytes);
        });
    }
    // At most one fitting successor may pass a byte-blocked head. A cancellation
    // or release can make older waiters eligible; service those before new arrivals.
    fn dispatch(state: &mut State) -> Wake {
        let mut grants = Vec::new();
        while state.slots > 0 && !state.closed {
            let Some((&first, head)) = state.waiting.first_key_value() else {
                break;
            };
            let id = if head.weight <= state.bytes {
                first
            } else {
                if head.bypassed {
                    break;
                }
                let Some((&id, _)) = state.waiting.iter().find(|(_, w)| w.weight <= state.bytes)
                else {
                    break;
                };
                if let Some(mut head) = state.waiting.first_entry() {
                    head.get_mut().bypassed = true;
                }
                id
            };
            if let Some(waiter) = state.waiting.remove(&id) {
                Self::grant(
                    state,
                    waiter.weight,
                    #[cfg(feature = "integration")]
                    waiter.session,
                );
                if let Some(ready) = waiter.ready {
                    grants.push(ready);
                }
            }
        }
        grants
    }

    pub(crate) async fn acquire(&self, batch: &Batch) -> Result<Permit, Error> {
        #[cfg(feature = "integration")]
        let start = rss_timeseries::measurement::timer();
        let weight = charge(batch.encoded_len(), batch.samples().len());
        #[cfg(feature = "integration")]
        let blocked_on;
        #[cfg(feature = "integration")]
        let session = rss_timeseries::measurement::Session::detailed();
        let (mut permit, received) = {
            let mut state = self.lock();
            if state.closed {
                return Err(Error::Unavailable);
            }
            // dispatch leaves the queue quiescent. Only this new tail can use
            // capacity now, so arrival never rescans older non-fitting requests.
            let fits = state.slots > 0 && weight <= state.bytes;
            let immediate = fits
                && match state.waiting.first_entry() {
                    None => true,
                    Some(mut head) if !head.get().bypassed => {
                        head.get_mut().bypassed = true;
                        true
                    }
                    _ => false,
                };
            if immediate {
                #[cfg(feature = "integration")]
                rss_timeseries::measurement::record("permit_wait", start, weight as usize, 0);
                Self::grant(
                    &mut state,
                    weight,
                    #[cfg(feature = "integration")]
                    session,
                );
                return Ok(Permit {
                    capacity: self.clone(),
                    weight,
                    queued: None,
                    #[cfg(feature = "integration")]
                    session,
                });
            }
            #[cfg(feature = "integration")]
            {
                blocked_on = if state.slots == 0 {
                    "queued_without_slot"
                } else if weight > state.bytes {
                    "queued_without_bytes"
                } else {
                    "queued_by_order"
                };
            }
            let id = state.next;
            state.next = id.checked_add(1).ok_or(Error::Invariant)?;
            let (ready, rx) = oneshot::channel();
            state.waiting.insert(
                id,
                Waiter {
                    weight,
                    bypassed: false,
                    ready: Some(ready),
                    #[cfg(feature = "integration")]
                    session,
                },
            );
            (
                Permit {
                    capacity: self.clone(),
                    weight,
                    queued: Some(id),
                    #[cfg(feature = "integration")]
                    session,
                },
                rx,
            )
        };
        received.await.map_err(|_| Error::Unavailable)?;
        permit.queued = None;
        #[cfg(feature = "integration")]
        {
            rss_timeseries::measurement::record(blocked_on, start, 0, 0);
            rss_timeseries::measurement::record("permit_wait", start, weight as usize, 0);
        }
        Ok(permit)
    }

    pub(crate) fn close(&self) {
        let waiting = {
            let mut state = self.lock();
            state.closed = true;
            state
                .waiting
                .values_mut()
                .filter_map(|w| w.ready.take())
                .collect::<Vec<_>>()
        };
        drop(waiting);
    }

    #[cfg(feature = "integration")]
    pub(crate) fn available(&self) -> (usize, usize) {
        let state = self.lock();
        (state.slots as usize, state.bytes as usize)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let wake = {
            let mut state = self.capacity.lock();
            let was_head = self.queued.is_some_and(|id| {
                state
                    .waiting
                    .first_key_value()
                    .is_some_and(|(&first, _)| first == id)
            });
            if self
                .queued
                .is_some_and(|id| state.waiting.remove(&id).is_some())
            {
                if !was_head {
                    return;
                }
            } else {
                state.slots += 1;
                state.bytes += self.weight;
                #[cfg(feature = "integration")]
                self.session
                    .update(|r| r.reserved_bytes -= self.weight as usize);
            }
            Capacity::dispatch(&mut state)
        };
        for ready in wake {
            let _ = ready.send(());
        }
    }
}
