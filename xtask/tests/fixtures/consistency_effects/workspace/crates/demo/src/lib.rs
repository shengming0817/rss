mod ports;
use std::sync::Arc;
use ports::DynReadRepo;
struct ReadState { repo: Arc<DynReadRepo> }
impl ::httpserve::ClassifiedRouteState for ReadState {
    type Effect = ::diport::ReadEffect;
    type Privilege = ::diport::LocalPrivilege;
}
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::safe::RouteMarker>) {}
struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, registry: &mut ::bootstrap::Registry) -> Result<(), ::httpserve::Error> {
        let state = ReadState { repo: unimplemented!() };
        registry.route_group(|router| {
            Ok(router.mount(
                ::httpserve::GeneratedPrimaryEndpoint::new(::generated::http::demo_v1::safe::ROUTE, handler)?
                    .with_classified_state(state),
            )?)
        })?;
        Ok(())
    }
}
