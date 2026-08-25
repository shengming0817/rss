use crate::{
    config::SnapshotConfig,
    plan::{RuntimePlanError, is_kebab_case_workload},
};
use assembly_schema::{
    CanonicalAssemblyManifestV2, RepositoryVerifiedAssemblyLock, RuntimePlanV4Input,
};

pub(super) fn append(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &RepositoryVerifiedAssemblyLock,
    config: SnapshotConfig<'_>,
    input: &mut RuntimePlanV4Input,
) -> Result<(), RuntimePlanError> {
    let default_workload = lock.identity().name();
    let required_listeners = input
        .plan_kind()
        .official_profile()
        .and_then(|profile| manifest.official_profile(profile))
        .map(|profile| profile.required_listeners());
    let mut placements = manifest
        .domains()
        .iter()
        .copied()
        .filter(|domain| {
            required_listeners.is_none_or(|listeners| {
                manifest.listeners().iter().any(|listener| {
                    listeners.contains(&listener.kind) && listener.domains.contains(domain)
                })
            })
        })
        .collect::<Vec<_>>();
    placements.sort_by_key(|domain| domain.as_str());
    for domain in placements {
        let env = format!(
            "RSS_{}_DOMAIN_PLACEMENT_WORKLOAD",
            domain.as_str().to_ascii_uppercase()
        );
        let workload = match config.value(&env) {
            None => default_workload.to_owned(),
            Some(raw) => {
                let trimmed = raw.trim();
                if !is_kebab_case_workload(trimmed) {
                    return Err(RuntimePlanError::PlacementWorkload { env });
                }
                trimmed.to_owned()
            }
        };
        input.placement(domain, workload);
    }
    Ok(())
}
