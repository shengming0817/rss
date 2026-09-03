//! Closed authorization proof for DLQ operator actions.

use std::marker::PhantomData;

mod sealed {
    pub trait Sealed {}
}

/// Closed set of DLQ operator actions.
pub trait DlqOperatorAction: sealed::Sealed + std::fmt::Debug {
    /// Canonical value-level identity shared by grants, audit labels and type markers.
    const KIND: DlqOperatorActionKind;
    /// Stable authorization/audit label.
    const LABEL: &'static str = Self::KIND.as_str();
}

/// Canonical closed DLQ action catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlqOperatorActionKind {
    List,
    Inspect,
    ReplayDeadLetter,
    RedriveOutbox,
    ResolveExpiredOutbox,
}

impl DlqOperatorActionKind {
    /// Parses the exact operator grant/CLI label.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "list" => Some(Self::List),
            "inspect" => Some(Self::Inspect),
            "replay-dead-letter" => Some(Self::ReplayDeadLetter),
            "redrive-outbox" => Some(Self::RedriveOutbox),
            "resolve-expired-outbox" => Some(Self::ResolveExpiredOutbox),
            _ => None,
        }
    }

    /// Returns the stable operator grant and audit label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Inspect => "inspect",
            Self::ReplayDeadLetter => "replay-dead-letter",
            Self::RedriveOutbox => "redrive-outbox",
            Self::ResolveExpiredOutbox => "resolve-expired-outbox",
        }
    }
}

/// Sealed DLQ action markers.
pub mod dlq_operator_action {
    macro_rules! action {
        ($name:ident, $kind:ident) => {
            #[derive(Debug)]
            pub struct $name;
            impl super::sealed::Sealed for $name {}
            impl super::DlqOperatorAction for $name {
                const KIND: super::DlqOperatorActionKind = super::DlqOperatorActionKind::$kind;
            }
        };
    }

    action!(List, List);
    action!(Inspect, Inspect);
    action!(ReplayDeadLetter, ReplayDeadLetter);
    action!(RedriveOutbox, RedriveOutbox);
    action!(ResolveExpiredOutbox, ResolveExpiredOutbox);
}

/// Durable identity shared by the start and finish audit for one DLQ command.
#[derive(Clone, PartialEq, Eq)]
pub struct DlqOperatorStartAuditId(String);

impl std::fmt::Debug for DlqOperatorStartAuditId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DlqOperatorStartAuditId(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DlqOperatorStartAuditIdError {
    /// The value was empty, padded, too long, or contained control characters.
    #[error("DLQ operator start audit id is invalid")]
    Invalid,
}

impl DlqOperatorStartAuditId {
    /// Validates an opaque correlation identifier.
    ///
    /// Values must be 1–128 bytes, have no surrounding whitespace, and contain no control
    /// characters. The identifier is redacted from [`Debug`](std::fmt::Debug) output.
    pub fn parse(raw: impl Into<String>) -> Result<Self, DlqOperatorStartAuditIdError> {
        let value = raw.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(DlqOperatorStartAuditIdError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the validated correlation identifier for durable audit persistence and controlled
    /// operator diagnostics.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Move-only proof that exact authentication, authorization and durable start audit completed.
pub struct DlqOperatorAuthorization<A: DlqOperatorAction> {
    caller: vocab::ServiceCallerDomain,
    operator_subject: String,
    tenant: rss_request_context::TenantId,
    start_audit_id: DlqOperatorStartAuditId,
    action: PhantomData<A>,
}

impl<A: DlqOperatorAction> std::fmt::Debug for DlqOperatorAuthorization<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DlqOperatorAuthorization")
            .field("caller", &self.caller)
            .field("operator_subject", &"<redacted>")
            .field("tenant", &self.tenant)
            .field("start_audit_id", &self.start_audit_id)
            .field("action", &std::any::type_name::<A>())
            .finish()
    }
}

impl<A: DlqOperatorAction> DlqOperatorAuthorization<A> {
    /// Issues an action-specific authorization after durable start audit, authentication, role,
    /// tenant, and exact-action grant checks have succeeded.
    ///
    /// Production callers cannot obtain the required mint outside the runtime composition root.
    pub fn issue(
        _mint: dlqauthmint::DlqOperatorMint,
        caller: vocab::ServiceCallerDomain,
        operator_subject: String,
        tenant: rss_request_context::TenantId,
        start_audit_id: DlqOperatorStartAuditId,
    ) -> Self {
        Self {
            caller,
            operator_subject,
            tenant,
            start_audit_id,
            action: PhantomData,
        }
    }

    /// Returns the verified service caller domain.
    pub const fn caller(&self) -> vocab::ServiceCallerDomain {
        self.caller
    }

    /// Returns the verified operator subject.
    ///
    /// This value is sensitive and is deliberately redacted from `Debug`; callers must avoid
    /// emitting it outside controlled audit sinks.
    pub fn operator_subject(&self) -> &str {
        &self.operator_subject
    }

    /// Returns the tenant bound by the exact authorization check.
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    /// Returns the durable start-audit identifier bound to this authorization.
    pub const fn start_audit_id(&self) -> &DlqOperatorStartAuditId {
        &self.start_audit_id
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DlqOperatorAction, DlqOperatorActionKind, DlqOperatorAuthorization,
        DlqOperatorStartAuditId, dlq_operator_action,
    };

    #[test]
    fn action_kinds_are_the_single_stable_marker_and_label_catalog() {
        let cases = [
            (
                DlqOperatorActionKind::List,
                <dlq_operator_action::List as DlqOperatorAction>::KIND,
            ),
            (
                DlqOperatorActionKind::Inspect,
                <dlq_operator_action::Inspect as DlqOperatorAction>::KIND,
            ),
            (
                DlqOperatorActionKind::ReplayDeadLetter,
                <dlq_operator_action::ReplayDeadLetter as DlqOperatorAction>::KIND,
            ),
            (
                DlqOperatorActionKind::RedriveOutbox,
                <dlq_operator_action::RedriveOutbox as DlqOperatorAction>::KIND,
            ),
            (
                DlqOperatorActionKind::ResolveExpiredOutbox,
                <dlq_operator_action::ResolveExpiredOutbox as DlqOperatorAction>::KIND,
            ),
        ];
        for (kind, marker_kind) in cases {
            assert_eq!(kind, marker_kind);
            assert_eq!(DlqOperatorActionKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn audit_id_rejects_unsafe_values_and_redacts_debug() -> Result<(), Box<dyn std::error::Error>>
    {
        for invalid in ["", " padded", "padded ", "line\nbreak"] {
            assert!(DlqOperatorStartAuditId::parse(invalid).is_err());
        }
        let id = DlqOperatorStartAuditId::parse("dlq-operator-123")?;
        assert_eq!(id.as_str(), "dlq-operator-123");
        assert_eq!(format!("{id:?}"), "DlqOperatorStartAuditId(<redacted>)");
        Ok(())
    }

    #[test]
    fn authorization_debug_redacts_operator_subject() -> Result<(), Box<dyn std::error::Error>> {
        let authorization = DlqOperatorAuthorization::<dlq_operator_action::List>::issue(
            dlqauthmint::DlqOperatorMint::capability(),
            vocab::ServiceCallerDomain::MaintenanceOperator,
            "sensitive-operator-subject".to_owned(),
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            DlqOperatorStartAuditId::parse("dlq-operator-123")?,
        );

        let debug = format!("{authorization:?}");
        assert!(!debug.contains("sensitive-operator-subject"));
        assert!(debug.contains("<redacted>"));
        Ok(())
    }
}
