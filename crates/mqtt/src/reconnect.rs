use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
use std::time::Duration;

/// Bounded exponential retry policy. Actual waits begin in `[initial, 2 * initial)`
/// and grow to `[maximum / 2, maximum)`, with independent jitter on every attempt.
#[derive(Clone, Copy, Debug)]
pub struct ReconnectPolicy {
    initial: Duration,
    maximum: Duration,
}
impl ReconnectPolicy {
    /// Require at least one millisecond initially and room for jitter below the maximum.
    /// Maximum waits may not exceed one day, keeping timer arithmetic bounded.
    pub fn new(initial: Duration, maximum: Duration) -> Result<Self, crate::MqttError> {
        if initial < Duration::from_millis(1)
            || initial > maximum / 2
            || maximum > Duration::from_secs(86_400)
        {
            return Err(crate::MqttError::InvalidConfig);
        }
        Ok(Self { initial, maximum })
    }
    fn builder(self) -> ExponentialBuilder {
        // backon adds jitter *after* applying max_delay. Halve its cap so the
        // jittered result remains bounded without synchronizing clients at a clamp.
        ExponentialBuilder::default()
            .with_min_delay(self.initial)
            .with_max_delay(self.maximum / 2)
            .with_factor(2.0)
            .with_jitter()
            .without_max_times()
    }
    pub(crate) fn build(self) -> Reconnect {
        Reconnect {
            policy: self,
            delays: self.builder().build(),
        }
    }
}
impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(100),
            maximum: Duration::from_secs(30),
        }
    }
}
pub(crate) struct Reconnect {
    policy: ReconnectPolicy,
    delays: ExponentialBackoff,
}
impl Reconnect {
    pub(crate) fn reset(&mut self) {
        self.delays = self.policy.builder().build();
    }
    pub(crate) async fn wait(&mut self, cancelled: &tokio_util::sync::CancellationToken) -> bool {
        tokio::select! {
            () = cancelled.cancelled() => false,
            () = tokio::time::sleep(self.next()) => true,
        }
    }
    fn next(&mut self) -> Duration {
        self.delays
            .next()
            .unwrap_or(self.policy.maximum)
            .min(self.policy.maximum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_a_backoff_wait() {
        let mut retry = ReconnectPolicy::default().build();
        let cancelled = tokio_util::sync::CancellationToken::new();
        let cancellation = cancelled.clone();
        let task = tokio::spawn(async move { retry.wait(&cancelled).await });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(matches!(task.await, Ok(false)));
    }

    #[tokio::test(start_paused = true)]
    async fn growing_jitter_stays_bounded_and_reset_restores_initial_range() -> anyhow::Result<()> {
        let policy = ReconnectPolicy::new(Duration::from_millis(100), Duration::from_secs(4))?;
        let mut retry = policy.build();
        retry.delays = policy.builder().with_jitter_seed(42).build();
        let mut plateau = Vec::new();
        for attempt in 0..100 {
            let delay = retry.next();
            let base =
                Duration::from_millis(100 * (1u64 << attempt.min(5))).min(Duration::from_secs(2));
            assert!(delay >= base && delay <= base * 2);
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            tokio::time::advance(delay / 2).await;
            assert!(
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(sleep.as_mut().poll(cx).is_pending())
                })
                .await
            );
            sleep.await;
            if attempt > 5 {
                plateau.push(delay);
            }
        }
        assert!(plateau.windows(2).any(|v| v[0] != v[1]));
        retry.reset();
        let delay = retry.next();
        assert!(delay >= policy.initial && delay <= policy.initial * 2);
        Ok(())
    }
}
