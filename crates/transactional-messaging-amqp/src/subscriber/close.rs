//! One continuously driven channel-close receipt per subscription.
use std::sync::{Arc, Mutex};

use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

use crate::{AmqpShutdownError, conn};

/// Preserve a started close's result; only an already terminal generation needs no RPC.
pub(super) async fn close_channel(channel: &lapin::Channel) -> lapin::Result<()> {
    let started_connected = channel.status().connected();
    let result = channel
        .close(conn::REPLY_SUCCESS, "subscription ownership ended".into())
        .await;
    match result {
        Err(error) if !started_connected && terminal_channel_error(&error) => Ok(()),
        result => result,
    }
}

fn terminal_channel_error(error: &lapin::Error) -> bool {
    matches!(
        error.kind(),
        lapin::ErrorKind::InvalidChannelState(
            lapin::ChannelState::Closed | lapin::ChannelState::Error,
            _
        )
    )
}

#[derive(Default)]
struct AdmissionState {
    sealed: bool,
    active: usize,
}

#[derive(Default)]
struct Admission {
    state: Mutex<AdmissionState>,
    drained: CancellationToken,
}

pub(super) struct SettlementPermit(Arc<Admission>);
impl Drop for SettlementPermit {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active -= 1;
        if state.sealed && state.active == 0 {
            self.0.drained.cancel();
        }
    }
}

#[derive(Clone)]
pub(super) struct SubscriptionClose {
    future: Shared<BoxFuture<'static, lapin::Result<()>>>,
    pub(super) requested: CancellationToken,
    admission: Arc<Admission>,
    finished: CancellationToken,
    #[cfg(feature = "test-support")]
    pause: Arc<Mutex<Option<conn::TestPause>>>,
}

impl SubscriptionClose {
    pub(super) fn new(
        close: impl std::future::Future<Output = lapin::Result<()>> + Send + 'static,
    ) -> Self {
        #[cfg(feature = "test-support")]
        let pause: Arc<Mutex<Option<conn::TestPause>>> = Arc::default();
        #[cfg(feature = "test-support")]
        let close_pause = Arc::clone(&pause);
        let future = async move {
            #[cfg(feature = "test-support")]
            {
                let pause = close_pause
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(pause) = pause {
                    pause.wait().await;
                }
            }
            close.await
        }
        .boxed()
        .shared();
        Self {
            future,
            requested: CancellationToken::new(),
            admission: Arc::default(),
            finished: CancellationToken::new(),
            #[cfg(feature = "test-support")]
            pause,
        }
    }

    pub(super) fn acquire(&self, cancelled: &CancellationToken) -> Option<SettlementPermit> {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.sealed || cancelled.is_cancelled() || self.requested.is_cancelled() {
            return None;
        }
        state.active += 1;
        Some(SettlementPermit(Arc::clone(&self.admission)))
    }

    pub(super) fn seal(&self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sealed = true;
        if state.active == 0 {
            self.admission.drained.cancel();
        }
    }

    pub(super) async fn drained(&self) {
        self.admission.drained.cancelled().await;
    }

    pub(super) async fn drive(&self) -> lapin::Result<()> {
        let result = self.future.clone().await;
        self.finished.cancel();
        result
    }

    pub(super) async fn wait(&self) -> lapin::Result<()> {
        self.finished.cancelled().await;
        self.future.clone().await
    }

    #[cfg(feature = "test-support")]
    pub(super) fn pause(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (pause, entered, resume) = conn::TestPause::new();
        *self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pause);
        (entered, resume)
    }
}

pub(super) struct OwnedSubscription {
    pub(super) task: AbortOnDropHandle<()>,
    pub(super) closing: SubscriptionClose,
}

impl OwnedSubscription {
    pub(super) async fn wait(self) -> Result<(), AmqpShutdownError> {
        self.task.await.map_err(AmqpShutdownError::task)?;
        self.closing
            .wait()
            .await
            .map_err(AmqpShutdownError::operation)
    }

    pub(super) fn observed_finished(&mut self) -> bool {
        crate::shutdown::observe_finished_task(&mut self.task, "subscription_close")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn transition_states_are_not_successful_close_receipts() {
        use lapin::ChannelState::{Closed, Closing, Connected, Error, Initial, Reconnecting};
        for state in [Initial, Reconnecting, Connected, Closing, Closed, Error] {
            let error = lapin::ErrorKind::InvalidChannelState(state, "fixture").into();
            assert_eq!(
                terminal_channel_error(&error),
                matches!(state, Closed | Error)
            );
        }
        assert!(!terminal_channel_error(&lapin::Error::from(
            std::io::Error::other("fixture")
        )));
    }

    #[tokio::test]
    async fn sealed_admission_waits_for_existing_settlement() {
        let close = SubscriptionClose::new(async { Ok(()) });
        let token = CancellationToken::new();
        let permit = close.acquire(&token);
        assert!(permit.is_some());
        close.seal();
        assert!(close.acquire(&token).is_none());
        assert!(close.drained().now_or_never().is_none());
        drop(permit);
        assert!(close.drained().now_or_never().is_some());
    }

    #[tokio::test]
    async fn concurrent_close_waiters_share_one_operation_and_result() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let close = SubscriptionClose::new(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Err(lapin::Error::from(std::io::Error::other(
                "fixture close failure",
            )))
        });
        close.requested.cancel();
        let (driven, first, second) = tokio::join!(close.drive(), close.wait(), close.wait());
        assert!(driven.is_err());
        assert!(first.is_err() && second.is_err());
        assert!(close.wait().await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(close.acquire(&CancellationToken::new()).is_none());
    }
}
