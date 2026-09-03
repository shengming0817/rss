//! Neutral runtime health registry.

use crate::domain::{Domain, KernelError};

struct ProbeDecl {
    name: primitives::ProbeName,
    probe: Box<dyn HealthProbe>,
}

pub trait HealthProbe: Send + Sync {
    fn check(&self) -> primitives::HealthCheck;
}

pub struct HealthReporter {
    probes: Vec<ProbeDecl>,
}

impl HealthReporter {
    #[must_use]
    pub fn report(&self) -> primitives::HealthReport {
        aggregate(&self.probes)
    }

    #[must_use]
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }
}

#[derive(Default)]
pub struct Registry {
    probes: Vec<ProbeDecl>,
}

impl Registry {
    #[must_use]
    pub const fn new() -> Self {
        Self { probes: Vec::new() }
    }

    pub fn probe(
        &mut self,
        name: primitives::ProbeName,
        probe: Box<dyn HealthProbe>,
    ) -> Result<(), KernelError> {
        if self.probes.iter().any(|candidate| candidate.name == name) {
            return Err(KernelError::Probe);
        }
        self.probes.push(ProbeDecl { name, probe });
        Ok(())
    }

    #[must_use]
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    #[must_use]
    pub fn readyz_report(&self) -> primitives::HealthReport {
        aggregate(&self.probes)
    }

    pub fn take_health_reporter(&mut self) -> HealthReporter {
        HealthReporter {
            probes: std::mem::take(&mut self.probes),
        }
    }

    pub(crate) fn init_domain(
        &mut self,
        _name: &'static str,
        domain: &dyn Domain,
    ) -> Result<(), KernelError> {
        domain.init(self)
    }
}

fn aggregate(probes: &[ProbeDecl]) -> primitives::HealthReport {
    primitives::HealthReport::aggregate(
        probes
            .iter()
            .map(|entry| {
                let check = entry.probe.check();
                primitives::HealthCheck::new(entry.name.clone(), check.status(), check.detail())
            })
            .collect(),
    )
}
