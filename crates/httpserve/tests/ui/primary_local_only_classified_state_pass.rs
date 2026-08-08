use axum::extract::State;

#[derive(Clone)]
struct ReadState;

impl httpserve::ClassifiedRouteState for ReadState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

#[derive(Clone)]
struct AuthState;

impl httpserve::ClassifiedRouteState for AuthState {
    type Effect = diport::AuthEffect;
    type Privilege = diport::LocalPrivilege;
}

enum ReadRouteMarker {}
enum AuthRouteMarker {}

fn main() {
    let read_binding =
        vocab::HttpRouteBinding::<ReadRouteMarker, vocab::http::LocalOnly>::from_static(
            vocab::HttpContractOwner::domain("test"),
            vocab::ContractBinding::from_static(
                "test",
                "ui.primary-local-only-read",
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "/read",
            "GET",
            &[],
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::ServiceOwned,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Read]),
        );
    let _read = httpserve::GeneratedPrimaryEndpoint::new(
        read_binding,
        |_: httpserve::ContractMarker<ReadRouteMarker>, State(_): State<ReadState>| async {},
    )
    .unwrap()
    .with_classified_state(ReadState);

    let auth_binding =
        vocab::HttpRouteBinding::<AuthRouteMarker, vocab::http::LocalOnly>::from_static(
            vocab::HttpContractOwner::domain("test"),
            vocab::ContractBinding::from_static(
                "test",
                "ui.primary-local-only-auth",
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "/auth",
            "GET",
            &[],
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::ServiceOwned,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(&[vocab::HttpEffectKind::Read]),
        );
    let _auth = httpserve::GeneratedPrimaryEndpoint::new(
        auth_binding,
        |_: httpserve::ContractMarker<AuthRouteMarker>, State(_): State<AuthState>| async {},
    )
    .unwrap()
    .with_classified_state(AuthState);
}
