//! Capability-specific ownership for bound Tokio TCP listeners.
//!
//! A [`ListenerTaskRegistration`] can only be minted by consuming a real bound listener. The
//! future factory receives both that listener and the same cancellation token owned by the
//! canonical managed task, so callers cannot substitute an unrelated background task.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use diport::{ManagedTask, ManagedTaskRegistration, ShutdownError};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// A bound socket that has not yet transferred into its serving task.
#[derive(Debug)]
#[must_use = "a bound listener must be started or dropped before readiness"]
pub struct BoundTcpListener {
    name: &'static str,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl BoundTcpListener {
    /// Adopt one already-bound socket as a move-only listener capability.
    pub fn new(name: &'static str, listener: TcpListener) -> std::io::Result<Self> {
        let local_addr = listener.local_addr()?;
        Ok(Self {
            name,
            listener,
            local_addr,
        })
    }

    /// Return the kernel-confirmed bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Consume the socket and mint the only registration accepted by RuntimeExec's listener funnel.
    pub fn spawn<F, Make>(
        self,
        token: CancellationToken,
        shutdown_timeout: Duration,
        make: Make,
    ) -> ListenerTaskRegistration
    where
        F: Future<Output = Result<(), ShutdownError>> + Send + 'static,
        Make: FnOnce(TcpListener, CancellationToken) -> F,
    {
        let (start, _) = ManagedTask::prepare(self.name, shutdown_timeout);
        let listener = self.listener;
        let task = start.spawn(token, move |managed_token| make(listener, managed_token));
        ListenerTaskRegistration {
            registration: task.into_registration(),
        }
    }
}

/// Opaque proof that a managed task consumed a real bound TCP listener.
#[must_use = "listener registration must enter RuntimeExec's listener funnel"]
pub struct ListenerTaskRegistration {
    registration: ManagedTaskRegistration,
}

impl ListenerTaskRegistration {
    /// Transfer the canonical task registration into the runtime shutdown owner.
    pub fn into_managed(self) -> ManagedTaskRegistration {
        self.registration
    }
}
