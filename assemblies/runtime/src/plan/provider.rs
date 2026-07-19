use assembly_schema::{CanonicalAssemblyManifestV1, RuntimePlanV1Input};

pub(super) fn append(manifest: &CanonicalAssemblyManifestV1, input: &mut RuntimePlanV1Input) {
    let mut providers = manifest.diport_providers().iter().collect::<Vec<_>>();
    providers.sort_by_key(|provider| provider.id.as_str());
    for provider in providers {
        input.provider(
            provider.id.as_str(),
            provider.provider,
            provider.outputs.clone(),
        );
    }
}
