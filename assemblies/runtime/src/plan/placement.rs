use crate::{
    config::SnapshotConfig,
    plan::{RuntimePlanError, is_kebab_case_workload},
};
use assembly_schema::{CanonicalAssemblyManifestV2, ExecutableAssemblyLock, RuntimePlanV2Input};

pub(super) fn append(
    manifest: &CanonicalAssemblyManifestV2,
    lock: &ExecutableAssemblyLock,
    config: SnapshotConfig<'_>,
    input: &mut RuntimePlanV2Input,
) -> Result<(), RuntimePlanError> {
    let default_workload = lock.identity().name();
    let mut placements = manifest.domains().to_vec();
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
