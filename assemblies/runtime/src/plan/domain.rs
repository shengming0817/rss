use assembly_schema::{CanonicalAssemblyManifestV1, RuntimePlanV1Input};

pub(super) fn append(manifest: &CanonicalAssemblyManifestV1, input: &mut RuntimePlanV1Input) {
    for domain in manifest.domains() {
        input.domain(*domain);
    }
}
