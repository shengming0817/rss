use crate::{
    config::{
        AccessTokenProfileSelection, InternalAuthSelection, SnapshotConfig, TokenProfilesConfig,
    },
    plan::RuntimePlanError,
};
use assembly_schema::{
    AssemblyListenerKind, CanonicalAssemblyManifestV2, ListenerAuth, RuntimePlanV4Input,
};

pub(super) fn append(
    manifest: &CanonicalAssemblyManifestV2,
    config: SnapshotConfig<'_>,
    input: &mut RuntimePlanV4Input,
) -> Result<(), RuntimePlanError> {
    let (primary, admin, internal) = TokenProfilesConfig::listener_selections(config)
        .map_err(|_| RuntimePlanError::ListenerAuth)?;
    let mut listeners = manifest
        .listeners()
        .iter()
        .filter(|listener| {
            input
                .plan_kind()
                .official_profile()
                .and_then(|profile| manifest.official_profile(profile))
                .is_none_or(|profile| profile.required_listeners().contains(&listener.kind))
        })
        .map(|listener| {
            let auth = match listener.kind {
                AssemblyListenerKind::Primary => access_auth(primary),
                AssemblyListenerKind::Admin => access_auth(admin),
                AssemblyListenerKind::Internal => match internal {
                    InternalAuthSelection::Mtls => ListenerAuth::Mtls,
                    InternalAuthSelection::ServiceToken => ListenerAuth::ServiceToken,
                },
                AssemblyListenerKind::Health => ListenerAuth::NoAuth,
            };
            Ok((listener.kind, auth, listener.domains.clone()))
        })
        .collect::<Result<Vec<_>, RuntimePlanError>>()?;
    listeners.sort_by_key(|(kind, _, _)| kind.as_str());
    for (kind, auth, domains) in listeners {
        input.listener(kind, auth, domains);
    }
    Ok(())
}

const fn access_auth(selection: AccessTokenProfileSelection) -> ListenerAuth {
    match selection {
        AccessTokenProfileSelection::RssAccess => ListenerAuth::RssAccessToken,
        AccessTokenProfileSelection::FederatedAccess => ListenerAuth::FederatedAccessToken,
    }
}
