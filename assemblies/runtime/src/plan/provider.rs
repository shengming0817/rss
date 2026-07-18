use assembly_schema::{CanonicalAssemblyManifestV1, RuntimePlanV1Input};

pub(super) fn append(manifest: &CanonicalAssemblyManifestV1, input: &mut RuntimePlanV1Input) {
    let mut providers = manifest.diport_providers().iter().collect::<Vec<_>>();
    providers.sort_by(|left, right| left.id.cmp(&right.id));
    for provider in providers {
        input.provider(&provider.id, provider.provider, provider.outputs.clone());
    }
}
