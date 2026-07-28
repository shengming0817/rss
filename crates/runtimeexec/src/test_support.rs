//! Typed control seam for tests that must drive the production launch kernel.

use std::future::Future;

use anyhow::Context as _;
use tokio::sync::oneshot;

use super::{LaunchAdapter, LaunchPlan, launch_until};

/// Ready-hook capability that publishes one typed result and requests a normal shutdown.
pub struct ControlledReady<T> {
    result: oneshot::Sender<anyhow::Result<T>>,
    shutdown: oneshot::Sender<()>,
}

/// Runner that owns the matching result and shutdown receivers.
pub struct ControlledLaunch<T> {
    result: oneshot::Receiver<anyhow::Result<T>>,
    shutdown: oneshot::Receiver<()>,
}

/// Create a single-use typed completion capability and its launch runner.
pub fn controlled<T>() -> (ControlledReady<T>, ControlledLaunch<T>) {
    let (result_sender, result_receiver) = oneshot::channel();
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    (
        ControlledReady {
            result: result_sender,
            shutdown: shutdown_sender,
        },
        ControlledLaunch {
            result: result_receiver,
            shutdown: shutdown_receiver,
        },
    )
}

impl<T> ControlledReady<T> {
    /// Preserve the request outcome by value, then trigger the launch kernel's normal shutdown path.
    pub fn complete(self, result: anyhow::Result<T>) -> anyhow::Result<()> {
        self.result
            .send(result)
            .map_err(|_| anyhow::anyhow!("controlled launch result receiver was dropped"))?;
        self.shutdown
            .send(())
            .map_err(|_| anyhow::anyhow!("controlled launch shutdown receiver was dropped"))
    }
}

impl<T> ControlledLaunch<T> {
    /// Run a production launch plan with a typed, test-owned shutdown signal.
    pub async fn run<Adapter, ProbeReceipt, ReadyHook, Ready>(
        self,
        plan: LaunchPlan<Adapter, ProbeReceipt, ReadyHook>,
    ) -> anyhow::Result<T>
    where
        Adapter: LaunchAdapter<ProbeReceipt>,
        ReadyHook: FnOnce(Adapter::Inventory) -> Ready,
        Ready: Future<Output = anyhow::Result<()>>,
    {
        let Self { result, shutdown } = self;
        let _outputs = launch_until(plan, || {
            Ok(async move {
                shutdown
                    .await
                    .context("controlled launch completion dropped before shutdown")?;
                Ok(())
            })
        })
        .await?;
        result
            .await
            .context("controlled launch completion dropped before publishing a result")?
    }
}
