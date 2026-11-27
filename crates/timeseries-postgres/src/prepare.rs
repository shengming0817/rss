//! One admission decision covers a prepared batch slot and its full byte charge.
//! ref: tokio tokio/src/sync/batch_semaphore.rs@tokio-1.53.3
mod weights;
use crate::Limits;
use rss_timeseries::{Batch, Error};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::oneshot;
use weights::Weights;

/// Charge the largest live phase, including simultaneous old/new hash tables on growth.
/// With at most count entries, each hashbrown table has fewer than 4*count buckets
/// (small tables and SIMD control padding fit in the fixed allowance). A bucket
/// holds its key/value and one control byte. Both indexes are gone before SQLx binding.
pub(crate) const fn charge(json: usize, count: usize) -> u32 {
    let word = size_of::<usize>();
    let series_bucket = 2 * word + 1;
    let binding_bucket = size_of::<((&rss_timeseries::Id, u64), usize)>() + 1;
    let indexing = json + count * (64 + word + 4 * (series_bucket + 2 * binding_bucket));
    // When definitions are encoded, only their index remains. Its 4*binding_bucket
    // bytes per sample fit in the 116 bytes/item wire allowance below.
    let binding = 4 * json + count * (116 + 96 + 2 * word);
    let peak = if indexing > binding {
        indexing
    } else {
        binding
    };
    (peak + 4096) as u32
}
#[derive(Clone)]
pub(crate) struct Capacity(Arc<Mutex<State>>);

struct State {
    slots: u32,
    bytes: u32,
    max_waiters: u32,
    next: u64,
    closed: bool,
    waiting: BTreeMap<u64, Waiter>,
    weights: Weights,
}

struct Waiter {
    weight: u32,
    bypassed: bool,
    granted: Arc<AtomicBool>,
    ready: oneshot::Sender<Granted>,
    #[cfg(feature = "integration")]
    session: rss_timeseries::measurement::Session,
}

struct Granted {
    #[cfg(feature = "integration")]
    at: Option<rss_timeseries::measurement::Started>,
}

pub(crate) struct Permit {
    // The flag is shared only with the queued entry. All transitions are under
    // the capacity lock, including close racing a grant before its first poll.
    queued: Option<(u64, Arc<AtomicBool>)>,
    capacity: Capacity,
    weight: u32,
    #[cfg(feature = "integration")]
    session: rss_timeseries::measurement::Session,
}

type Wake = Vec<(oneshot::Sender<Granted>, Granted)>;

impl Capacity {
    pub(crate) fn new(limits: &Limits) -> Result<Self, Error> {
        let bytes = limits.max_prepare_bytes.get();
        if bytes < Limits::MIN_PREPARE_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(Self(Arc::new(Mutex::new(State {
            slots: limits.max_prepare_batches.get(),
            bytes,
            max_waiters: limits.max_prepare_waiters,
            next: 0,
            closed: false,
            waiting: BTreeMap::new(),
            weights: Weights::default(),
        }))))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn grant(
        state: &mut State,
        weight: u32,
        #[cfg(feature = "integration")] session: rss_timeseries::measurement::Session,
    ) -> Granted {
        state.slots -= 1;
        state.bytes -= weight;
        #[cfg(feature = "integration")]
        session.update(|r| {
            r.granted_batches += 1;
            r.reserved_bytes += weight as usize;
            r.peak_reserved_bytes = r.peak_reserved_bytes.max(r.reserved_bytes);
        });
        Granted {
            #[cfg(feature = "integration")]
            at: session.capacity(state.slots, state.bytes, state.waiting.len()),
        }
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
                let Some(id) = state.weights.first(state.bytes) else {
                    break;
                };
                if let Some(mut head) = state.waiting.first_entry() {
                    head.get_mut().bypassed = true;
                }
                id
            };
            if let Some(waiter) = state.waiting.remove(&id) {
                state.weights.set(id, None);
                let grant = Self::grant(
                    state,
                    waiter.weight,
                    #[cfg(feature = "integration")]
                    waiter.session,
                );
                waiter.granted.store(true, Ordering::Relaxed);
                grants.push((waiter.ready, grant));
            }
        }
        grants
    }

    pub(crate) async fn acquire(&self, batch: &Batch) -> Result<Permit, Error> {
        self.acquire_weight(charge(batch.encoded_len(), batch.samples().len()))
            .await
    }
    async fn acquire_weight(&self, weight: u32) -> Result<Permit, Error> {
        #[cfg(feature = "integration")]
        let start = rss_timeseries::measurement::timer();
        #[cfg(feature = "integration")]
        let queued_at;
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
            if state.waiting.len() >= state.max_waiters as usize {
                return Err(Error::Overloaded);
            }
            let id = state.next;
            state.next = id.checked_add(1).ok_or(Error::Invariant)?;
            let (ready, rx) = oneshot::channel();
            let granted = Arc::new(AtomicBool::new(false));
            state.weights.set(id, Some(weight));
            state.waiting.insert(
                id,
                Waiter {
                    weight,
                    bypassed: false,
                    ready,
                    granted: granted.clone(),
                    #[cfg(feature = "integration")]
                    session,
                },
            );
            #[cfg(feature = "integration")]
            {
                queued_at = session.capacity(state.slots, state.bytes, state.waiting.len());
            }
            (
                Permit {
                    capacity: self.clone(),
                    weight,
                    queued: Some((id, granted)),
                    #[cfg(feature = "integration")]
                    session,
                },
                rx,
            )
        };
        let _grant = received.await.map_err(|_| Error::Unavailable)?;
        permit.queued = None;
        #[cfg(feature = "integration")]
        {
            session.preparation_wait(weight, queued_at, _grant.at);
            rss_timeseries::measurement::record("permit_wait", start, weight as usize, 0);
        }
        Ok(permit)
    }

    pub(crate) fn close(&self) {
        let waiting = {
            let mut state = self.lock();
            state.closed = true;
            #[cfg(feature = "integration")]
            if !state.waiting.is_empty() {
                rss_timeseries::measurement::Session::detailed().capacity(
                    state.slots,
                    state.bytes,
                    0,
                );
            }
            (
                std::mem::take(&mut state.waiting),
                std::mem::take(&mut state.weights),
            )
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
        let removed;
        let wake = {
            let mut state = self.capacity.lock();
            if let Some((id, granted)) = &self.queued
                && !granted.load(Ordering::Relaxed)
            {
                if state.closed {
                    return;
                }
                let was_head = state
                    .waiting
                    .first_key_value()
                    .is_some_and(|(first, _)| first == id);
                removed = state.waiting.remove(id);
                state.weights.set(*id, None);
                #[cfg(feature = "integration")]
                self.session
                    .capacity(state.slots, state.bytes, state.waiting.len());
                if !was_head {
                    drop(state);
                    drop(removed);
                    return;
                }
            } else {
                removed = None;
                state.slots += 1;
                state.bytes += self.weight;
                #[cfg(feature = "integration")]
                {
                    self.session.update(|r| {
                        r.reserved_bytes -= self.weight as usize;
                        r.granted_batches -= 1;
                    });
                    self.session
                        .capacity(state.slots, state.bytes, state.waiting.len());
                }
            }
            Capacity::dispatch(&mut state)
        };
        drop(removed);
        for (ready, grant) in wake {
            let _ = ready.send(grant);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll, Waker};

    use futures::FutureExt;

    fn capacity(max_waiters: u32) -> Capacity {
        Capacity(Arc::new(Mutex::new(State {
            slots: 2,
            bytes: 10,
            max_waiters,
            next: 0,
            closed: false,
            waiting: BTreeMap::new(),
            weights: Weights::default(),
        })))
    }

    fn pending(f: std::pin::Pin<&mut dyn Future<Output = Result<Permit, Error>>>) -> bool {
        matches!(
            f.poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        )
    }

    #[test]
    fn zero_waiters_allows_only_complete_immediate_grants() -> anyhow::Result<()> {
        let capacity = capacity(0);
        let active = capacity
            .acquire_weight(8)
            .now_or_never()
            .ok_or(Error::Invariant)??;
        assert_eq!(
            capacity
                .acquire_weight(3)
                .now_or_never()
                .ok_or(Error::Invariant)?
                .err(),
            Some(Error::Overloaded)
        );
        let fitting = capacity
            .acquire_weight(2)
            .now_or_never()
            .ok_or(Error::Invariant)??;
        drop((active, fitting));
        assert_eq!(capacity.lock().slots, 2);
        Ok(())
    }

    #[test]
    fn full_queue_allows_one_bypass_and_grants_its_head_before_new_writers() -> anyhow::Result<()> {
        let capacity = capacity(1);
        let active = capacity
            .acquire_weight(8)
            .now_or_never()
            .ok_or(Error::Invariant)??;
        let mut head = Box::pin(capacity.acquire_weight(9));
        assert!(pending(head.as_mut()));
        let bypass = capacity
            .acquire_weight(2)
            .now_or_never()
            .ok_or(Error::Invariant)??;
        drop(bypass);
        assert_eq!(
            capacity
                .acquire_weight(2)
                .now_or_never()
                .ok_or(Error::Invariant)?
                .err(),
            Some(Error::Overloaded)
        );
        drop(active);
        // The unread grant already owns nine bytes and has vacated its waiting place.
        let mut next = Box::pin(capacity.acquire_weight(2));
        assert!(pending(next.as_mut()));
        drop(head);
        let next = next.now_or_never().ok_or(Error::Invariant)??;
        drop(next);
        let state = capacity.lock();
        assert_eq!((state.slots, state.bytes, state.waiting.len()), (2, 10, 0));
        Ok(())
    }

    #[test]
    fn close_drains_unpolled_waiters_and_preserves_only_granted_capacity() -> anyhow::Result<()> {
        let capacity = capacity(2);
        let active = capacity
            .acquire_weight(8)
            .now_or_never()
            .ok_or(Error::Invariant)??;
        let mut head = Box::pin(capacity.acquire_weight(7));
        let mut cancelled = Box::pin(capacity.acquire_weight(9));
        assert!(pending(head.as_mut()) && pending(cancelled.as_mut()));
        drop(active);
        // The head now owns 7 bytes in its unread notification; the other waiter owns none.
        capacity.close();
        capacity.close();
        {
            let state = capacity.lock();
            assert!(state.waiting.is_empty() && state.weights.first(u32::MAX).is_none());
            assert_eq!((state.slots, state.bytes), (1, 3));
        }
        assert_eq!(
            cancelled.now_or_never().ok_or(Error::Invariant)?.err(),
            Some(Error::Unavailable)
        );
        drop(head);
        let state = capacity.lock();
        assert_eq!((state.slots, state.bytes), (2, 10));
        Ok(())
    }
}
