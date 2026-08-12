//! Authority-free request values and read-only views for RSS handlers.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContextValueError {
    Empty,
    TooLong,
    InvalidFormat,
}

impl fmt::Display for ContextValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid request context value")
    }
}
impl Error for ContextValueError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TenantIdError {
    Empty,
    Nil,
    InvalidFormat,
}
impl fmt::Display for TenantIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid tenant identifier")
    }
}
impl Error for TenantIdError {}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TenantId(uuid::Uuid);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, TenantIdError> {
        if value.is_empty() {
            return Err(TenantIdError::Empty);
        }
        let parsed = uuid::Uuid::try_parse(value).map_err(|_| TenantIdError::InvalidFormat)?;
        if parsed.hyphenated().to_string() != value {
            return Err(TenantIdError::InvalidFormat);
        }
        if parsed.is_nil() {
            return Err(TenantIdError::Nil);
        }
        Ok(Self(parsed))
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}
impl fmt::Debug for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TenantId")
            .field(&self.to_string())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RequestId(Box<str>);

impl RequestId {
    pub fn parse(value: &str) -> Result<Self, ContextValueError> {
        if value.is_empty() {
            return Err(ContextValueError::Empty);
        }
        if value.len() > 128 {
            return Err(ContextValueError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ContextValueError::InvalidFormat);
        }
        Ok(Self(value.into()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RequestId")
            .field(&self.as_str())
            .finish()
    }
}
impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalKind {
    User,
    Device,
    Admin,
    SuperAdmin,
    Service,
    Anonymous,
}
impl PrincipalKind {
    #[must_use]
    pub const fn as_actor_metadata_label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::Admin => "admin",
            Self::SuperAdmin => "super_admin",
            Self::Service => "service",
            Self::Anonymous => "anonymous",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalRef {
    kind: PrincipalKind,
    subject: Box<str>,
}

impl PrincipalRef {
    pub fn new(kind: PrincipalKind, subject: &str) -> Result<Self, ContextValueError> {
        if subject.is_empty() {
            return Err(ContextValueError::Empty);
        }
        if subject.len() > 512 {
            return Err(ContextValueError::TooLong);
        }
        Ok(Self {
            kind,
            subject: subject.into(),
        })
    }
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }
    #[must_use]
    pub fn matches_subject(&self, candidate: &str) -> bool {
        self.subject.as_ref() == candidate
    }
}
impl fmt::Debug for PrincipalRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalRef")
            .field("kind", &self.kind)
            .field("subject", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline(Instant);

impl Deadline {
    #[must_use]
    pub const fn at(instant: Instant) -> Self {
        Self(instant)
    }
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.0
    }
    #[must_use]
    pub fn is_expired(self, now: Instant) -> bool {
        now >= self.0
    }
    #[must_use]
    pub fn remaining(self, now: Instant) -> Option<Duration> {
        self.0.checked_duration_since(now)
    }
    #[must_use]
    pub fn shortened_to(self, earlier: Instant) -> Self {
        Self(self.0.min(earlier))
    }
}

/// Closed reason why an admitted request must stop executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationReason {
    Cancelled,
    DeadlineExceeded,
}

/// Stable boxed wait future used by cancellation observers without selecting an async runtime.
pub type CancellationFuture<'a> = Pin<Box<dyn Future<Output = CancellationReason> + Send + 'a>>;

/// Read-only cancellation source. Implementations retain all trigger authority.
pub trait CancellationObserver: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self, deadline: Deadline) -> CancellationFuture<'_>;
}

#[derive(Clone, Copy)]
pub struct Cancellation<'a>(&'a dyn CancellationObserver);

impl<'a> Cancellation<'a> {
    #[must_use]
    pub const fn observe(observer: &'a dyn CancellationObserver) -> Self {
        Self(observer)
    }
    #[must_use]
    pub fn is_cancelled(self) -> bool {
        self.0.is_cancelled()
    }
    #[must_use]
    pub fn cancelled(self, deadline: Deadline) -> CancellationFuture<'a> {
        self.0.cancelled(deadline)
    }
}
impl fmt::Debug for Cancellation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cancellation")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowScope {
    SelfOnly,
    Device,
    Tenant,
}
impl RowScope {
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::SelfOnly => "self-only",
            Self::Device => "device",
            Self::Tenant => "tenant",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FieldMaskView<'a> {
    fields: &'a [&'a str],
}
impl<'a> FieldMaskView<'a> {
    #[must_use]
    pub const fn new(fields: &'a [&'a str]) -> Self {
        Self { fields }
    }
    #[must_use]
    pub fn allows(self, field: &str) -> bool {
        self.fields.contains(&field)
    }
    pub fn iter(self) -> impl ExactSizeIterator<Item = &'a str> {
        self.fields.iter().copied()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ObligationsView<'a> {
    row_scope: Option<RowScope>,
    field_mask: FieldMaskView<'a>,
}
impl<'a> ObligationsView<'a> {
    #[must_use]
    pub const fn new(row_scope: Option<RowScope>, field_mask: FieldMaskView<'a>) -> Self {
        Self {
            row_scope,
            field_mask,
        }
    }
    #[must_use]
    pub const fn row_scope(self) -> Option<RowScope> {
        self.row_scope
    }
    #[must_use]
    pub const fn field_mask(self) -> FieldMaskView<'a> {
        self.field_mask
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RequestContextView<'a> {
    tenant: Option<&'a TenantId>,
    request_id: &'a RequestId,
    principal: &'a PrincipalRef,
    deadline: Deadline,
    cancellation: Cancellation<'a>,
    obligations: ObligationsView<'a>,
}
impl<'a> RequestContextView<'a> {
    #[must_use]
    pub const fn new(
        tenant: Option<&'a TenantId>,
        request_id: &'a RequestId,
        principal: &'a PrincipalRef,
        deadline: Deadline,
        cancellation: Cancellation<'a>,
        obligations: ObligationsView<'a>,
    ) -> Self {
        Self {
            tenant,
            request_id,
            principal,
            deadline,
            cancellation,
            obligations,
        }
    }
    #[must_use]
    pub const fn tenant(self) -> Option<&'a TenantId> {
        self.tenant
    }
    #[must_use]
    pub const fn request_id(self) -> &'a RequestId {
        self.request_id
    }
    #[must_use]
    pub const fn principal(self) -> &'a PrincipalRef {
        self.principal
    }
    #[must_use]
    pub const fn deadline(self) -> Deadline {
        self.deadline
    }
    #[must_use]
    pub const fn cancellation(self) -> Cancellation<'a> {
        self.cancellation
    }
    #[must_use]
    pub const fn obligations(self) -> ObligationsView<'a> {
        self.obligations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Never;
    impl CancellationObserver for Never {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn cancelled(&self, _: Deadline) -> CancellationFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    #[test]
    fn tenant_is_canonical_and_non_nil() {
        let id = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        assert_eq!(id.to_string(), "11111111-1111-4111-8111-111111111111");
        assert!(TenantId::parse("00000000-0000-0000-0000-000000000000").is_err());
        assert!(TenantId::parse("11111111111141118111111111111111").is_err());
    }

    #[test]
    fn request_id_and_principal_are_bounded_and_redacted() {
        assert!(RequestId::parse("request.1_A-b").is_ok());
        assert!(RequestId::parse("request 1").is_err());
        let principal = PrincipalRef::new(PrincipalKind::User, "secret-subject").unwrap();
        assert!(principal.matches_subject("secret-subject"));
        assert!(!format!("{principal:?}").contains("secret-subject"));
    }

    #[test]
    fn exhaustive_public_view_boundaries() {
        assert_eq!(TenantId::parse(""), Err(TenantIdError::Empty));
        assert_eq!(
            TenantId::parse("00000000-0000-0000-0000-000000000000"),
            Err(TenantIdError::Nil)
        );
        assert!(TenantId::parse("11111111111141118111111111111111").is_err());
        let tenant = TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        assert_eq!(tenant.octets().len(), 16);
        assert_eq!(RequestId::parse(""), Err(ContextValueError::Empty));
        assert!(RequestId::parse(&"a".repeat(128)).is_ok());
        assert_eq!(
            RequestId::parse(&"a".repeat(129)),
            Err(ContextValueError::TooLong)
        );
        assert_eq!(
            RequestId::parse("bad/id"),
            Err(ContextValueError::InvalidFormat)
        );
        assert_eq!(
            PrincipalRef::new(PrincipalKind::User, ""),
            Err(ContextValueError::Empty)
        );
        assert!(PrincipalRef::new(PrincipalKind::User, &"x".repeat(512)).is_ok());
        assert_eq!(
            PrincipalRef::new(PrincipalKind::User, &"x".repeat(513)),
            Err(ContextValueError::TooLong)
        );
        for (kind, label) in [
            (PrincipalKind::User, "user"),
            (PrincipalKind::Device, "device"),
            (PrincipalKind::Admin, "admin"),
            (PrincipalKind::SuperAdmin, "super_admin"),
            (PrincipalKind::Service, "service"),
            (PrincipalKind::Anonymous, "anonymous"),
        ] {
            assert_eq!(kind.as_actor_metadata_label(), label);
        }
        for (scope, label) in [
            (RowScope::SelfOnly, "self-only"),
            (RowScope::Device, "device"),
            (RowScope::Tenant, "tenant"),
        ] {
            assert_eq!(scope.as_label(), label);
        }
        let now = Instant::now();
        let deadline = Deadline::at(now + Duration::from_secs(2));
        assert!(!deadline.is_expired(now));
        assert!(deadline.remaining(now).is_some());
        assert_eq!(deadline.shortened_to(now).instant(), now);
        let fields = ["email", "name"];
        let mask = FieldMaskView::new(&fields);
        assert!(mask.allows("email"));
        assert_eq!(mask.iter().count(), 2);
        let obligations = ObligationsView::new(Some(RowScope::Tenant), mask);
        let request = RequestId::parse("request-1").unwrap();
        let principal = PrincipalRef::new(PrincipalKind::Admin, "subject").unwrap();
        let cancel = Never;
        let view = RequestContextView::new(
            Some(&tenant),
            &request,
            &principal,
            deadline,
            Cancellation::observe(&cancel),
            obligations,
        );
        assert_eq!(view.tenant(), Some(&tenant));
        assert_eq!(view.request_id(), &request);
        assert_eq!(view.principal().kind(), PrincipalKind::Admin);
        assert_eq!(view.deadline(), deadline);
        assert!(!view.cancellation().is_cancelled());
        assert_eq!(view.obligations().row_scope(), Some(RowScope::Tenant));
        assert!(format!("{:?}", view.cancellation()).starts_with("Cancellation"));
    }
}
