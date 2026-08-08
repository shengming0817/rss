#[derive(Clone)]
struct ReadState;

impl httpserve::ClassifiedRouteState for ReadState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

enum FirstRoute {}
enum SecondRoute {}

fn main() {
    let binding = vocab::HttpRouteBinding::<FirstRoute, vocab::http::LocalOnly>::from_static(
        vocab::HttpContractOwner::domain("test"),
        vocab::ContractBinding::from_static(
            "test",
            "ui.local-only-proof-marker",
            "v1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        "/x",
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
    let routes = httpserve::UnfinalizedRoutes::empty();
    let _: httpserve::LocalOnlyMountedRouteProof<SecondRoute, ReadState> =
        ::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(&routes, &binding)
            .unwrap();
}
