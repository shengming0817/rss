use crate::{config::SnapshotConfig, plan::RuntimePlanError, routes};
use assembly_schema::{
    AssemblyListenerKind, CanonicalAssemblyManifestV1, ListenerAuth, RuntimePlanV1Input,
};
use primitives::{AuthScheme, ListenerKind};

pub(super) fn append(
    manifest: &CanonicalAssemblyManifestV1,
    config: SnapshotConfig<'_>,
    input: &mut RuntimePlanV1Input,
) -> Result<(), RuntimePlanError> {
    let mut listeners = manifest
        .listeners()
        .iter()
        .map(|listener| {
            let kind = primitive_kind(listener.kind);
            let auth = routes::auth_scheme(config, kind)
                .map_err(|_| RuntimePlanError::ListenerAuth)
                .and_then(plan_auth)?;
            Ok((listener.kind, auth, listener.domains.clone()))
        })
        .collect::<Result<Vec<_>, RuntimePlanError>>()?;
    listeners.sort_by_key(|(kind, _, _)| kind.as_str());
    for (kind, auth, domains) in listeners {
        input.listener(kind, auth, domains);
    }
    Ok(())
}

fn primitive_kind(kind: AssemblyListenerKind) -> ListenerKind {
    match kind {
        AssemblyListenerKind::Primary => ListenerKind::Primary,
        AssemblyListenerKind::Internal => ListenerKind::Internal,
        AssemblyListenerKind::Admin => ListenerKind::Admin,
        AssemblyListenerKind::Health => ListenerKind::Health,
    }
}

fn plan_auth(auth: AuthScheme) -> Result<ListenerAuth, RuntimePlanError> {
    match auth {
        AuthScheme::NoAuth => Ok(ListenerAuth::NoAuth),
        AuthScheme::Jwt => Ok(ListenerAuth::Jwt),
        AuthScheme::Mtls => Ok(ListenerAuth::Mtls),
        AuthScheme::ServiceToken => Ok(ListenerAuth::ServiceToken),
        _ => Err(RuntimePlanError::ListenerAuth),
    }
}
