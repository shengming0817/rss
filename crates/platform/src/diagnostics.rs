use std::error::Error;
use std::fmt;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConditionCode {
    HandlersAdmitted,
    AcceptingDispatch,
    Draining,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConditionStatus {
    True,
    False,
}

pub struct Condition {
    code: ConditionCode,
    status: ConditionStatus,
}
impl Condition {
    pub(crate) const fn new(code: ConditionCode, status: ConditionStatus) -> Self {
        Self { code, status }
    }
    pub const fn code(&self) -> ConditionCode {
        self.code
    }
    pub const fn status(&self) -> ConditionStatus {
        self.status
    }
}

pub struct ConditionsSnapshot {
    conditions: Box<[Condition]>,
}
impl ConditionsSnapshot {
    pub(crate) fn new(conditions: Vec<Condition>) -> Self {
        Self {
            conditions: conditions.into_boxed_slice(),
        }
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Condition> {
        self.conditions.iter()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticCode {
    DuplicateHandler,
    DuplicateModule,
    MissingTrustedIssuer,
    InvalidTrustedIssuer,
    InvalidCredential,
    MissingHandler,
    PermissionDenied,
    RuntimeDraining,
    RuntimeStopped,
    HandlerFailed,
    ShutdownTimedOut,
    ShutdownComplete,
}

#[derive(Clone)]
enum StoredDetail {
    Count(usize),
    Duration(Duration),
}

pub enum DiagnosticDetail<'a> {
    Count(usize),
    Duration(&'a Duration),
}

#[derive(Clone)]
pub struct Diagnostic {
    code: DiagnosticCode,
    detail: Option<StoredDetail>,
}
impl Diagnostic {
    pub(crate) const fn new(code: DiagnosticCode) -> Self {
        Self { code, detail: None }
    }
    pub(crate) const fn count(code: DiagnosticCode, count: usize) -> Self {
        Self {
            code,
            detail: Some(StoredDetail::Count(count)),
        }
    }
    pub(crate) const fn duration(code: DiagnosticCode, duration: Duration) -> Self {
        Self {
            code,
            detail: Some(StoredDetail::Duration(duration)),
        }
    }
    pub const fn code(&self) -> DiagnosticCode {
        self.code
    }
    pub fn detail(&self) -> Option<DiagnosticDetail<'_>> {
        match self.detail.as_ref()? {
            StoredDetail::Count(value) => Some(DiagnosticDetail::Count(*value)),
            StoredDetail::Duration(value) => Some(DiagnosticDetail::Duration(value)),
        }
    }
}

pub struct DiagnosticsSnapshot {
    diagnostics: Box<[Diagnostic]>,
}
impl DiagnosticsSnapshot {
    pub(crate) fn new(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            diagnostics: diagnostics.into_boxed_slice(),
        }
    }
    pub(crate) fn one(diagnostic: Diagnostic) -> Self {
        Self::new(vec![diagnostic])
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Diagnostic> {
        self.diagnostics.iter()
    }
}

macro_rules! safe_error {
    ($name:ident, $text:literal) => {
        pub struct $name {
            diagnostics: DiagnosticsSnapshot,
        }
        impl $name {
            pub(crate) fn new(diagnostics: DiagnosticsSnapshot) -> Self {
                Self { diagnostics }
            }
            pub fn diagnostics(&self) -> &DiagnosticsSnapshot {
                &self.diagnostics
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($text)
            }
        }
        impl Error for $name {}
    };
}

safe_error!(BuildError, "platform application build failed");
safe_error!(VerifyError, "platform access verification failed");
safe_error!(DispatchError, "platform dispatch failed");
safe_error!(ShutdownError, "platform application shutdown failed");
