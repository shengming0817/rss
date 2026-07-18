use assembly_schema::{CanonicalAssemblyManifestV1, ParsedAssemblyLock, RuntimePlanV1Input};

pub(super) fn append(
    manifest: &CanonicalAssemblyManifestV1,
    lock: &ParsedAssemblyLock,
    input: &mut RuntimePlanV1Input,
) {
    let mut placements = manifest.domains().to_vec();
    placements.sort_by_key(|domain| domain.as_str());
    for domain in placements {
        input.placement(domain, lock.identity().name());
    }
}
