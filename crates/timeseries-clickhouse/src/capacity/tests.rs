use super::*;
use std::{future::Future, pin::Pin, task::{Context, Poll, Wake, Waker}};

fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<'a, F: Future<Output = Result<Permit<'a>, Error>>>(f: Pin<&mut F>) -> anyhow::Result<Permit<'a>> {
    match poll(f) {
        Poll::Ready(result) => Ok(result?),
        Poll::Pending => anyhow::bail!("permit remained pending"),
    }
}
fn capacity(slots: u32, units: u32, read: u32, waiters: u32) -> anyhow::Result<Capacity> {
    Ok(Capacity::new(slots, units, NonZeroU32::new(read).ok_or(Error::InvalidInput)?, waiters))
}
fn balances(c: &Capacity, slots: u32, units: u32, waiters: usize) {
    let s = c.state();
    assert_eq!((s.slots, s.units, s.len()), (slots, units, waiters));
}

#[test]
fn full_queue_allows_one_bypass_then_accumulates_for_the_head() -> anyhow::Result<()> {
    let c = capacity(3, 4, 4, 1)?;
    let held = ready(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut())?;
    let mut wide = Box::pin(c.acquire(AdmissionClass::Read));
    assert!(poll(wide.as_mut()).is_pending());
    let bypass = ready(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut())?;
    balances(&c, 1, 2, 1);
    drop(bypass);
    assert!(matches!(poll(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut()), Poll::Ready(Err(Error::Unavailable))));
    drop(held);
    let wide = ready(wide.as_mut())?;
    balances(&c, 2, 0, 0);
    drop(wide);
    balances(&c, 3, 4, 0);
    Ok(())
}

#[test]
fn zero_waiters_and_equal_weights_follow_the_same_admission_rules() -> anyhow::Result<()> {
    let c = capacity(1, 1, 1, 0)?;
    let permit = ready(Box::pin(c.acquire(AdmissionClass::Read)).as_mut())?;
    assert!(matches!(poll(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut()), Poll::Ready(Err(Error::Unavailable))));
    drop(permit);
    drop(ready(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut())?);
    let c = capacity(1, 1, 1, 3)?;
    let held = ready(Box::pin(c.acquire(AdmissionClass::Read)).as_mut())?;
    let mut first = Box::pin(c.acquire(AdmissionClass::Unit));
    let mut second = Box::pin(c.acquire(AdmissionClass::Read));
    assert!(poll(first.as_mut()).is_pending());
    assert!(poll(second.as_mut()).is_pending());
    drop(held);
    assert!(poll(second.as_mut()).is_pending());
    drop(ready(first.as_mut())?);
    drop(ready(second.as_mut())?);
    balances(&c, 1, 1, 0);
    Ok(())
}

#[test]
fn head_middle_and_not_yet_observed_grants_cancel_without_losing_capacity() -> anyhow::Result<()> {
    let c = capacity(1, 3, 3, 3)?;
    let held = ready(Box::pin(c.acquire(AdmissionClass::Read)).as_mut())?;
    let mut first = Box::pin(c.acquire(AdmissionClass::Read));
    let mut middle = Box::pin(c.acquire(AdmissionClass::Unit));
    let mut last = Box::pin(c.acquire(AdmissionClass::Read));
    for f in [&mut first, &mut middle, &mut last] { assert!(poll(f.as_mut()).is_pending()); }
    drop(middle);
    drop(first);
    balances(&c, 0, 0, 1);
    drop(held);
    balances(&c, 0, 0, 0);
    drop(last); // already granted, but never observed by the receiving future
    balances(&c, 1, 3, 0);
    Ok(())
}

#[test]
fn cancellation_between_grant_and_notification_returns_once() -> anyhow::Result<()> {
    let c = capacity(1, 2, 2, 1)?;
    // Model the mutex-linearized release with its notification batch paused outside the lock.
    c.state().slots = 0;
    c.state().units = 0;
    let mut waiting = Box::pin(c.acquire(AdmissionClass::Read));
    assert!(poll(waiting.as_mut()).is_pending());
    let notifications = {
        let mut s = c.state();
        s.slots = 1;
        s.units = 2;
        s.dispatch()
    };
    drop(waiting);
    balances(&c, 1, 2, 0);
    notify(notifications);
    balances(&c, 1, 2, 0);
    Ok(())
}

struct CheckWake {
    capacity: Arc<Capacity>,
    calls: std::sync::atomic::AtomicUsize,
}
impl Wake for CheckWake {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        assert!(self.capacity.0.try_lock().is_ok(), "notification held the capacity mutex");
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn grant_and_close_wake_outside_the_mutex_and_close_preserves_active_permits() -> anyhow::Result<()> {
    let c = Arc::new(capacity(1, 1, 1, 3)?);
    let held = ready(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut())?;
    let wake = Arc::new(CheckWake { capacity: c.clone(), calls: 0.into() });
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut first = Box::pin(c.acquire(AdmissionClass::Read));
    let mut second = Box::pin(c.acquire(AdmissionClass::Unit));
    let mut third = Box::pin(c.acquire(AdmissionClass::Read));
    for f in [&mut first, &mut second, &mut third] { assert!(f.as_mut().poll(&mut context).is_pending()); }
    drop(held);
    assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
    let active = ready(first.as_mut())?;
    c.close();
    c.close();
    assert_eq!(wake.calls.load(Ordering::Relaxed), 3);
    for f in [&mut second, &mut third] { assert!(matches!(poll(f.as_mut()), Poll::Ready(Err(Error::Unavailable)))); }
    balances(&c, 0, 0, 0);
    drop(active);
    balances(&c, 1, 1, 0);
    assert!(matches!(poll(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut()), Poll::Ready(Err(Error::Unavailable))));
    Ok(())
}

fn cancellation_work(count: u32, blocked_wide: bool) -> anyhow::Result<usize> {
    let c = capacity(if blocked_wide { 2 } else { 1 }, 4, 4, count)?;
    let held = ready(Box::pin(c.acquire(AdmissionClass::Unit)).as_mut())?;
    let mut waiters = Vec::new();
    for _ in 0..count {
        let mut f = Box::pin(c.acquire(AdmissionClass::Read));
        assert!(poll(f.as_mut()).is_pending());
        waiters.push(f);
    }
    c.state().probes = 0;
    // Alternate head and middle removal; each removal must locate its own ticket.
    while !waiters.is_empty() {
        let at = waiters.len() / 2;
        drop(waiters.swap_remove(at));
    }
    let work = c.state().probes;
    drop(held);
    balances(&c, if blocked_wide { 2 } else { 1 }, 4, 0);
    Ok(work)
}
#[test]
fn doubled_cancel_population_has_linear_index_operation_count() -> anyhow::Result<()> {
    for blocked in [false, true] {
        let w = cancellation_work(128, blocked)?;
        let twice = cancellation_work(256, blocked)?;
        assert!(w >= 128);
        assert!(twice <= 2 * w + 4, "{w} -> {twice}");
    }
    // Each measured operation is a BTreeMap lookup/remove: total O(W log(W + 1)).
    Ok(())
}
