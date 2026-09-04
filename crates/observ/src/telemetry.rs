use std::fmt;

/// Sink-neutral application identity supplied once by the consumer-owned composition root.
///
/// All fields are private and validated as non-empty. Telemetry sinks consume the named accessors
/// and cannot depend on positional attribute ordering.
///
/// INVARIANT: TELEMETRY-RESOURCE-CLOSED-01 { level = "Hard", exec = "native-compile", source = "code", native = "private non-optional fields plus checked complete constructor and named accessors" } -- a blank or partially initialized telemetry identity cannot be represented, and sinks cannot reinterpret positional values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TelemetryResource {
    service_name: String,
    assembly_fingerprint: String,
    runtime_plan_fingerprint: String,
}

impl TelemetryResource {
    /// Construct the complete application identity; blank identities are rejected.
    pub fn try_new(
        service_name: impl Into<String>,
        assembly_fingerprint: impl Into<String>,
        runtime_plan_fingerprint: impl Into<String>,
    ) -> Result<Self, TelemetryResourceError> {
        let resource = Self {
            service_name: service_name.into(),
            assembly_fingerprint: assembly_fingerprint.into(),
            runtime_plan_fingerprint: runtime_plan_fingerprint.into(),
        };
        if [
            resource.service_name.as_str(),
            resource.assembly_fingerprint.as_str(),
            resource.runtime_plan_fingerprint.as_str(),
        ]
        .into_iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(TelemetryResourceError);
        }
        Ok(resource)
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn assembly_fingerprint(&self) -> &str {
        &self.assembly_fingerprint
    }

    pub fn runtime_plan_fingerprint(&self) -> &str {
        &self.runtime_plan_fingerprint
    }
}

/// A telemetry identity was structurally incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelemetryResourceError;

impl fmt::Display for TelemetryResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("telemetry resource identity must be non-empty")
    }
}

impl std::error::Error for TelemetryResourceError {}
