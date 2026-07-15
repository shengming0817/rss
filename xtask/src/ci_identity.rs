#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CiIdentityKey {
    JobKey,
    SourceRevision,
    PlanDigest,
    RunId,
    RunAttempt,
    HeadRevision,
    EventName,
    StepSummary,
}

impl CiIdentityKey {
    pub(crate) const LOCALTX_REQUIRED: [Self; 6] = [
        Self::JobKey,
        Self::SourceRevision,
        Self::PlanDigest,
        Self::RunId,
        Self::RunAttempt,
        Self::HeadRevision,
    ];

    pub(crate) const fn env_name(self) -> &'static str {
        match self {
            Self::JobKey => "RSS_CI_JOB_KEY",
            Self::SourceRevision => "RSS_CI_SOURCE_REVISION",
            Self::PlanDigest => "RSS_CI_PLAN_DIGEST",
            Self::RunId => "GITHUB_RUN_ID",
            Self::RunAttempt => "GITHUB_RUN_ATTEMPT",
            Self::HeadRevision => "GITHUB_SHA",
            Self::EventName => "GITHUB_EVENT_NAME",
            Self::StepSummary => "GITHUB_STEP_SUMMARY",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localtx_required_identity_keys_match_external_protocol_golden() {
        assert_eq!(
            CiIdentityKey::LOCALTX_REQUIRED.map(CiIdentityKey::env_name),
            [
                "RSS_CI_JOB_KEY",
                "RSS_CI_SOURCE_REVISION",
                "RSS_CI_PLAN_DIGEST",
                "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT",
                "GITHUB_SHA",
            ]
        );
    }

    #[test]
    fn production_consumers_use_typed_identity_keys() {
        for source in [
            include_str!("localtx_evidence.rs"),
            include_str!("ci_gate.rs"),
            include_str!("ci_impact.rs"),
        ] {
            for env_name in ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"] {
                assert!(
                    !source.contains(&format!("std::env::var(\"{env_name}\")")),
                    "production lookup for {env_name} must use CiIdentityKey"
                );
            }
        }
    }
}
