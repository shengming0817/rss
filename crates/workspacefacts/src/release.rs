//! Strict owned projection of the workspace-level positive Release Surface selection.

use serde::{Deserialize, Deserializer, de};
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

/// Official profiles currently admitted by ADR-024 for Release Surface selection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum OfficialProfile {
    Core,
}

impl OfficialProfile {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateProfileArtifactSelection {
    profile: OfficialProfile,
    assembly: String,
}

impl CandidateProfileArtifactSelection {
    #[must_use]
    pub const fn profile(&self) -> OfficialProfile {
        self.profile
    }

    #[must_use]
    pub fn assembly(&self) -> &str {
        &self.assembly
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveProfileArtifactSelection {
    profile: OfficialProfile,
    assembly: String,
    activation_receipt: String,
    t3_owner: String,
}

impl ActiveProfileArtifactSelection {
    #[must_use]
    pub const fn profile(&self) -> OfficialProfile {
        self.profile
    }

    #[must_use]
    pub fn assembly(&self) -> &str {
        &self.assembly
    }

    #[must_use]
    pub fn activation_receipt(&self) -> &str {
        &self.activation_receipt
    }

    #[must_use]
    pub fn t3_owner(&self) -> &str {
        &self.t3_owner
    }
}

/// One closed official-profile artifact state. Candidate values cannot carry activation/T3 data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OfficialProfileArtifactSelection {
    Candidate(CandidateProfileArtifactSelection),
    Active(ActiveProfileArtifactSelection),
}

impl OfficialProfileArtifactSelection {
    #[must_use]
    pub const fn profile(&self) -> OfficialProfile {
        match self {
            Self::Candidate(candidate) => candidate.profile(),
            Self::Active(active) => active.profile(),
        }
    }

    #[must_use]
    pub fn assembly(&self) -> &str {
        match self {
            Self::Candidate(candidate) => candidate.assembly(),
            Self::Active(active) => active.assembly(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProfileArtifactState {
    Candidate,
    Active,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawProfileArtifactSelection {
    state: ProfileArtifactState,
    profile: OfficialProfile,
    assembly: String,
    activation_receipt: Option<String>,
    t3_owner: Option<String>,
}

impl<'de> Deserialize<'de> for OfficialProfileArtifactSelection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProfileArtifactSelection::deserialize(deserializer)?;
        match (raw.state, raw.activation_receipt, raw.t3_owner) {
            (ProfileArtifactState::Candidate, None, None) => {
                Ok(Self::Candidate(CandidateProfileArtifactSelection {
                    profile: raw.profile,
                    assembly: raw.assembly,
                }))
            }
            (ProfileArtifactState::Active, Some(activation_receipt), Some(t3_owner))
                if !activation_receipt.trim().is_empty() && !t3_owner.trim().is_empty() =>
            {
                Ok(Self::Active(ActiveProfileArtifactSelection {
                    profile: raw.profile,
                    assembly: raw.assembly,
                    activation_receipt,
                    t3_owner,
                }))
            }
            (ProfileArtifactState::Candidate, _, _) => Err(de::Error::custom(
                "candidate profile artifact cannot carry activation or T3 authority",
            )),
            (ProfileArtifactState::Active, _, _) => Err(de::Error::custom(
                "active profile artifact requires non-empty activation-receipt and t3-owner",
            )),
        }
    }
}

/// Positive selection only: anything absent remains internal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ReleaseSelection {
    packages: Vec<ReleasePackageSelection>,
    #[serde(rename = "official-profile-artifacts")]
    official_profile_artifacts: Vec<OfficialProfileArtifactSelection>,
}

impl ReleaseSelection {
    #[must_use]
    pub fn packages(&self) -> &[ReleasePackageSelection] {
        &self.packages
    }

    #[must_use]
    pub fn official_profile_artifacts(&self) -> &[OfficialProfileArtifactSelection] {
        &self.official_profile_artifacts
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
