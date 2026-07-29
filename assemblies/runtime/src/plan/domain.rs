use assembly_schema::{CanonicalAssemblyManifestV2, RuntimePlanV2Input};

pub(super) fn append(manifest: &CanonicalAssemblyManifestV2, input: &mut RuntimePlanV2Input) {
    for domain in manifest.domains() {
        input.domain(*domain);
    }
}
