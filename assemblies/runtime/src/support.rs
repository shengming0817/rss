//! Small production providers owned by the runtime composition boundary.

use std::time::SystemTime;

/// Production system clock injected into runtime providers.
pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: the composition boundary is the sanctioned production system-clock owner.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

/// Lightweight auth decision audit sink used by tests and non-production assembly checks.
///
/// Production uses `postgres::PgAuthAuditSink` through `postgres::PgRuntimeDeps`.
#[derive(Clone, Default)]
pub struct TracingAuthAuditSink;

impl diport::AuditSink for TracingAuthAuditSink {
    async fn record(&self, event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
        let outcome = match event.outcome {
            diport::AuditOutcome::Success => "success",
            diport::AuditOutcome::Failure { reason } => reason,
            _ => "unknown",
        };
        tracing::info!(
            audit.action = event.action,
            audit.outcome = outcome,
            resource.kind = event.resource_kind,
            principal.kind = ?event.principal_kind,
            "http auth audit event"
        );
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }
}

#[cfg(test)]
impl audit::ports::AuditListTenantAppender for TracingAuthAuditSink {
    async fn append(
        &self,
        command: audit::ports::AuditListTenantAppend,
    ) -> Result<(), diport::AuditSinkError> {
        let (scope, event, _observation) = command.into_parts();
        debug_assert_eq!(event.tenant_id, Some(scope.tenant()));
        diport::AuditSink::record(self, event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::Clock as _;
    use std::time::UNIX_EPOCH;

    #[test]
    fn system_clock_is_after_unix_epoch() {
        assert!(SystemClock.now() > UNIX_EPOCH);
    }
}
