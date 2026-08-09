#![deny(private_bounds, private_interfaces)]

//! Temporary executable Platform Application waist contract for #2045.
//!
//! This crate freezes signatures and visibility only. It is deliberately not a façade, contains no
//! provider or runtime integration, and is not release/package/consumer evidence. #2049 must move
//! the accepted contract into the real façade and delete this fixture atomically.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

const NAME_MAX_BYTES: usize = 64;
const CONTRACT_ID_MAX_BYTES: usize = 255;
const SHA256_PREFIX: &str = "sha256:";

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ApplicationName(Box<str>);

impl ApplicationName {
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        parse_name(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ModuleName(Box<str>);

impl ModuleName {
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        parse_name(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_name(value: &str) -> Result<Box<str>, IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > NAME_MAX_BYTES {
        return Err(IdentifierError::TooLong);
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(IdentifierError::InvalidFormat);
    }
    Ok(value.into())
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContractId(&'static str);

impl ContractId {
    pub const fn from_static(value: &'static str) -> Self {
        assert!(valid_contract_id(value), "invalid contract id");
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

const fn valid_contract_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > CONTRACT_ID_MAX_BYTES {
        return false;
    }
    let mut index = 0;
    let mut at_segment_start = true;
    while index < bytes.len() {
        let byte = bytes[index];
        if at_segment_start {
            if !byte.is_ascii_lowercase() {
                return false;
            }
            at_segment_start = false;
        } else if byte == b'.' {
            at_segment_start = true;
        } else if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return false;
        }
        index += 1;
    }
    !at_segment_start
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ContractVersion {
    major: u16,
    minor: u16,
}

impl ContractVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SchemaDigest(&'static str);

impl SchemaDigest {
    pub const fn from_static(value: &'static str) -> Self {
        assert!(valid_schema_digest(value), "invalid schema digest");
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

const fn valid_schema_digest(value: &str) -> bool {
    let bytes = value.as_bytes();
    let prefix = SHA256_PREFIX.as_bytes();
    if bytes.len() != prefix.len() + 64 {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')) {
            return false;
        }
        index += 1;
    }
    true
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TenantId(Box<str>);

impl TenantId {
    pub fn parse(value: &str) -> Result<Self, TenantIdError> {
        if value.is_empty() {
            return Err(TenantIdError::Empty);
        }
        if !valid_canonical_uuid(value.as_bytes()) {
            return Err(TenantIdError::InvalidFormat);
        }
        if value.bytes().all(|byte| byte == b'0' || byte == b'-') {
            return Err(TenantIdError::Nil);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_canonical_uuid(bytes: &[u8]) -> bool {
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (*byte >= b'a' && *byte <= b'f')
            }
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IdentifierError {
    Empty,
    TooLong,
    InvalidFormat,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid platform identifier")
    }
}

impl Error for IdentifierError {}

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

pub trait Contract: Send + Sync + 'static {
    type Request: Send + 'static;
    type Response: Send + 'static;

    const ID: ContractId;
    const VERSION: ContractVersion;
    const SCHEMA_DIGEST: SchemaDigest;
}

pub trait Handler<C: Contract>: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        request: C::Request,
        context: RequestContext<'a>,
    ) -> impl Future<Output = C::Response> + Send + 'a;
}

pub struct RequestContext<'a> {
    principal: VerifiedPrincipal<'a>,
    tenant: VerifiedTenant<'a>,
    request_id: &'a str,
    correlation_id: Option<&'a str>,
}

impl<'a> RequestContext<'a> {
    pub fn principal(&self) -> VerifiedPrincipal<'_> {
        VerifiedPrincipal {
            kind: self.principal.kind,
            subject: self.principal.subject,
        }
    }

    pub fn tenant(&self) -> VerifiedTenant<'_> {
        VerifiedTenant { id: self.tenant.id }
    }

    pub fn request_id(&self) -> &str {
        self.request_id
    }

    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id
    }
}

pub struct VerifiedPrincipal<'a> {
    kind: PrincipalKind,
    subject: &'a str,
}

impl VerifiedPrincipal<'_> {
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    pub fn matches_subject(&self, candidate: &str) -> bool {
        self.subject == candidate
    }
}

pub struct VerifiedTenant<'a> {
    id: &'a TenantId,
}

impl VerifiedTenant<'_> {
    pub fn id(&self) -> &TenantId {
        self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrincipalKind {
    User,
    Service,
    Device,
    Admin,
    SuperAdmin,
    Anonymous,
}

pub struct ApplicationModule {
    name: ModuleName,
}

impl ApplicationModule {
    pub fn new(name: ModuleName) -> Self {
        Self { name }
    }

    pub fn name(&self) -> &ModuleName {
        &self.name
    }

    pub fn handler<C, H>(self, handler: H) -> Self
    where
        C: Contract,
        H: Handler<C>,
    {
        let _ = handler;
        self
    }
}

pub mod profile {
    #[allow(
        dead_code,
        reason = "private field makes the #2045 typestate marker non-mintable"
    )]
    pub struct Core {
        pub(crate) private: (),
    }

    #[allow(
        dead_code,
        reason = "private field makes the #2045 typestate marker non-mintable"
    )]
    pub struct Eventing {
        pub(crate) private: (),
    }
}

pub struct ApplicationBuilder<P> {
    name: ApplicationName,
    modules: Vec<ApplicationModule>,
    profile: PhantomData<P>,
}

pub fn core(name: ApplicationName) -> ApplicationBuilder<profile::Core> {
    ApplicationBuilder {
        name,
        modules: Vec::new(),
        profile: PhantomData,
    }
}

pub fn eventing(name: ApplicationName) -> ApplicationBuilder<profile::Eventing> {
    ApplicationBuilder {
        name,
        modules: Vec::new(),
        profile: PhantomData,
    }
}

macro_rules! profile_builder {
    ($profile:ty) => {
        impl ApplicationBuilder<$profile> {
            pub fn module(mut self, module: ApplicationModule) -> Self {
                self.modules.push(module);
                self
            }

            pub fn build(self) -> Result<Application<$profile>, BuildError> {
                let _ = (self.name, self.modules);
                Ok(Application {
                    profile: PhantomData,
                })
            }
        }
    };
}

profile_builder!(profile::Core);
profile_builder!(profile::Eventing);

pub struct Application<P> {
    profile: PhantomData<P>,
}

macro_rules! profile_application {
    ($profile:ty) => {
        impl Application<$profile> {
            pub async fn start(self) -> Result<RuntimeHandle, StartError> {
                let _ = self;
                unimplemented!("#2049 owns the real façade and runtime adapter")
            }
        }
    };
}

profile_application!(profile::Core);
profile_application!(profile::Eventing);

pub struct RuntimeHandle {
    _private: (),
}

impl RuntimeHandle {
    pub fn conditions(&self) -> ConditionsSnapshot {
        unimplemented!("#2049 owns runtime condition projection")
    }

    pub fn diagnostics(&self) -> DiagnosticsSnapshot {
        unimplemented!("#2049 owns runtime diagnostic projection")
    }

    pub async fn shutdown(self) -> Result<ShutdownReport, ShutdownError> {
        let _ = self;
        unimplemented!("#2049 owns bounded shutdown")
    }
}

#[derive(Clone)]
pub struct ConditionsSnapshot {
    conditions: Box<[Condition]>,
}

impl ConditionsSnapshot {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Condition> {
        self.conditions.iter()
    }

    pub fn get(&self, code: ConditionCode) -> Option<&Condition> {
        self.conditions
            .iter()
            .find(|condition| condition.code == code)
    }
}

#[derive(Clone)]
pub struct Condition {
    code: ConditionCode,
    status: ConditionStatus,
}

impl Condition {
    pub fn code(&self) -> ConditionCode {
        self.code
    }

    pub fn status(&self) -> ConditionStatus {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConditionCode {
    ProfileSelected,
    ModulesRegistered,
    ContractsAdmitted,
    RuntimeReady,
    ShutdownComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConditionStatus {
    Satisfied,
    Unsatisfied,
    Unknown,
}

#[derive(Clone)]
pub struct DiagnosticsSnapshot {
    diagnostics: Box<[Diagnostic]>,
}

impl DiagnosticsSnapshot {
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Diagnostic> {
        self.diagnostics.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

#[derive(Clone)]
pub struct Diagnostic {
    code: DiagnosticCode,
    retryable: bool,
    details: Box<[StoredDiagnosticDetail]>,
}

impl Diagnostic {
    pub fn code(&self) -> DiagnosticCode {
        self.code
    }

    pub fn retryable(&self) -> bool {
        self.retryable
    }

    pub fn details(&self) -> impl ExactSizeIterator<Item = DiagnosticDetail<'_>> {
        self.details.iter().map(StoredDiagnosticDetail::as_public)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticCode {
    InvalidApplication,
    UnsupportedProfile,
    ModuleConflict,
    ContractRejected,
    InvalidConfiguration,
    StartupFailed,
    RuntimeFailed,
    ShutdownFailed,
}

#[derive(Clone)]
#[allow(
    dead_code,
    reason = "#2049 owns construction from vetted internal diagnostics"
)]
enum StoredDiagnosticDetail {
    Application(ApplicationName),
    Module(ModuleName),
    Contract(ContractId),
    Profile(ProfileKind),
    Condition(ConditionCode),
    Count(u32),
    Duration(Duration),
}

impl StoredDiagnosticDetail {
    fn as_public(&self) -> DiagnosticDetail<'_> {
        match self {
            Self::Application(value) => DiagnosticDetail::Application(value),
            Self::Module(value) => DiagnosticDetail::Module(value),
            Self::Contract(value) => DiagnosticDetail::Contract(*value),
            Self::Profile(value) => DiagnosticDetail::Profile(*value),
            Self::Condition(value) => DiagnosticDetail::Condition(*value),
            Self::Count(value) => DiagnosticDetail::Count(*value),
            Self::Duration(value) => DiagnosticDetail::Duration(*value),
        }
    }
}

#[non_exhaustive]
pub enum DiagnosticDetail<'a> {
    Application(&'a ApplicationName),
    Module(&'a ModuleName),
    Contract(ContractId),
    Profile(ProfileKind),
    Condition(ConditionCode),
    Count(u32),
    Duration(Duration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileKind {
    Core,
    Eventing,
}

pub struct ShutdownReport {
    conditions: ConditionsSnapshot,
    diagnostics: DiagnosticsSnapshot,
}

impl ShutdownReport {
    pub fn conditions(&self) -> &ConditionsSnapshot {
        &self.conditions
    }

    pub fn diagnostics(&self) -> &DiagnosticsSnapshot {
        &self.diagnostics
    }
}

macro_rules! stage_error {
    ($name:ident, $display:literal) => {
        pub struct $name {
            diagnostics: DiagnosticsSnapshot,
        }

        impl $name {
            pub fn diagnostics(&self) -> &DiagnosticsSnapshot {
                &self.diagnostics
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($display)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($display)
            }
        }

        impl Error for $name {}
    };
}

stage_error!(BuildError, "platform application build failed");
stage_error!(StartError, "platform application start failed");
stage_error!(ShutdownError, "platform application shutdown failed");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_parsers_are_bounded_and_canonical() {
        assert!(ApplicationName::parse("core_app").is_ok());
        assert!(ApplicationName::parse("Core-App").is_err());
        assert!(ContractId::from_static("identity.read").as_str() == "identity.read");
        assert!(TenantId::parse("8b117a90-752f-4f2a-85f1-00c7c4e1f41c").is_ok());
        assert!(matches!(TenantId::parse(""), Err(TenantIdError::Empty)));
        assert!(matches!(
            TenantId::parse("00000000-0000-0000-0000-000000000000"),
            Err(TenantIdError::Nil),
        ));
        assert!(TenantId::parse("8B117A90-752F-4F2A-85F1-00C7C4E1F41C").is_err());
    }

    #[test]
    fn stage_errors_have_no_source_and_constant_safe_text() {
        let diagnostics = DiagnosticsSnapshot {
            diagnostics: Box::new([]),
        };
        let error = BuildError { diagnostics };
        assert_eq!(error.to_string(), "platform application build failed");
        assert_eq!(format!("{error:?}"), "platform application build failed");
        assert!(error.source().is_none());
        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .is_none(),
            "stage errors must not expose a source that can be downcast",
        );
    }

    #[test]
    fn stored_details_project_only_registered_public_values() {
        let details = [
            StoredDiagnosticDetail::Application(ApplicationName::parse("app").unwrap()),
            StoredDiagnosticDetail::Module(ModuleName::parse("module").unwrap()),
            StoredDiagnosticDetail::Contract(ContractId::from_static("identity.read")),
            StoredDiagnosticDetail::Profile(ProfileKind::Core),
            StoredDiagnosticDetail::Condition(ConditionCode::RuntimeReady),
            StoredDiagnosticDetail::Count(1),
            StoredDiagnosticDetail::Duration(Duration::from_secs(1)),
        ];
        assert_eq!(details.len(), 7);
        for detail in &details {
            let _ = detail.as_public();
        }
    }
}
