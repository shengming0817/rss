//! Strict owned projection of the workspace-level positive Release Surface selection.

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

const RELEASE_SELECTION_SUBJECT: &str = "workspace.metadata.release-surface";

/// Public Rust API owner. This is a product boundary, not a package maturity declaration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum PublicApiOwner {
    StandaloneComponent,
    FoundationPublic,
    PlatformPublic,
}

/// Compatibility posture of the selected API; intentionally excludes release/RC status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ApiStability {
    Experimental,
    Stable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ReleasePackageSelection {
    package: String,
    #[serde(default)]
    version_line: Option<String>,
    public_api_owner: PublicApiOwner,
    api_stability: ApiStability,
}

impl ReleasePackageSelection {
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    #[must_use]
    pub fn version_line(&self) -> Option<&str> {
        self.version_line.as_deref()
    }

    #[must_use]
    pub const fn public_api_owner(&self) -> PublicApiOwner {
        self.public_api_owner
    }

    #[must_use]
    pub const fn api_stability(&self) -> ApiStability {
        self.api_stability
    }
}

/// Positive selection only: anything absent remains internal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ReleaseSelection {
    packages: Vec<ReleasePackageSelection>,
}

impl ReleaseSelection {
    #[must_use]
    pub fn packages(&self) -> &[ReleasePackageSelection] {
        &self.packages
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{subject}: {detail}")]
pub struct ReleaseSelectionError {
    subject: String,
    detail: &'static str,
}

impl ReleaseSelectionError {
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

pub fn parse_release_selection(
    workspace_metadata: &Value,
) -> Result<Option<ReleaseSelection>, ReleaseSelectionError> {
    let Some(selection) = workspace_metadata.get("release-surface") else {
        return Ok(None);
    };
    let bytes = serde_json::to_vec(selection).map_err(|_| ReleaseSelectionError {
        subject: RELEASE_SELECTION_SUBJECT.to_owned(),
        detail: "invalid release selection shape or closed value",
    })?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    serde_path_to_error::deserialize(&mut deserializer)
        .map(Some)
        .map_err(|error| {
            let path = error.path().to_string();
            let subject = if path.is_empty() || path == "." {
                RELEASE_SELECTION_SUBJECT.to_owned()
            } else {
                format!("{RELEASE_SELECTION_SUBJECT}.{path}")
            };
            ReleaseSelectionError {
                subject,
                detail: "invalid release selection shape or closed value",
            }
        })
}
