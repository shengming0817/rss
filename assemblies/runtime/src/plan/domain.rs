use assembly_schema::{CanonicalAssemblyManifestV2, RuntimePlanV3Input};

pub(super) fn append(manifest: &CanonicalAssemblyManifestV2, input: &mut RuntimePlanV3Input) {
    for domain in manifest.domains() {
        input.domain(*domain);
    }
}
