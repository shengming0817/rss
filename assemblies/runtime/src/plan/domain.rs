use assembly_schema::{CanonicalAssemblyManifestV2, RuntimePlanV4Input};

pub(super) fn append(manifest: &CanonicalAssemblyManifestV2, input: &mut RuntimePlanV4Input) {
    let required_listeners = input
        .plan_kind()
        .official_profile()
        .and_then(|profile| manifest.official_profile(profile))
        .map(|profile| profile.required_listeners());
    for domain in manifest.domains().iter().filter(|domain| {
        required_listeners.is_none_or(|listeners| {
            manifest.listeners().iter().any(|listener| {
                listeners.contains(&listener.kind) && listener.domains.contains(domain)
            })
        })
    }) {
        input.domain(*domain);
    }
}
