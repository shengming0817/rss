use std::sync::atomic::{AtomicU8, Ordering};

use primitives::healthz::HealthStatus;

const HEALTHY: u8 = 0;
const DEGRADED: u8 = 1;
const UNHEALTHY: u8 = 2;
const STARTING: u8 = 3;
const INVARIANT: u8 = 4;

/// Small process-local health latch shared by retained control loops.
pub struct WorkerHealth(AtomicU8);

impl WorkerHealth {
    #[must_use]
    pub fn healthy() -> Self {
        Self(AtomicU8::new(HEALTHY))
    }
    #[must_use]
    pub fn starting() -> Self {
        Self(AtomicU8::new(STARTING))
    }
    #[must_use]
    pub fn status(&self) -> HealthStatus {
        match self.0.load(Ordering::Acquire) {
            HEALTHY => HealthStatus::Healthy,
            DEGRADED => HealthStatus::Degraded,
            _ => HealthStatus::Unhealthy,
        }
    }
    #[must_use]
    pub fn detail(&self) -> &'static str {
        match self.0.load(Ordering::Acquire) {
            HEALTHY => "worker",
            DEGRADED => "degraded",
            STARTING => "starting",
            INVARIANT => "invariant",
            _ => "stopped",
        }
    }
    pub fn mark_healthy(&self) {
        if self.0.load(Ordering::Acquire) != INVARIANT {
            self.0.store(HEALTHY, Ordering::Release);
        }
    }
    pub fn mark_degraded(&self) {
        if self.0.load(Ordering::Acquire) != INVARIANT {
            self.0.store(DEGRADED, Ordering::Release);
        }
    }
    pub fn mark_invariant(&self) {
        self.0.store(INVARIANT, Ordering::Release);
    }
    pub fn mark_stopped(&self) {
        self.0.store(UNHEALTHY, Ordering::Release);
    }
}
