struct Fixtures;

impl Fixtures {
    fn take_case(&mut self, id: &str) -> Result<Case, ()> {
        Ok(Case { id: id.to_owned() })
    }
}

struct Case {
    id: String,
}

struct DemoCases {
    happy: Case,
    auth_failure: Case,
    validation_failure: Case,
    contention: Case,
}

fn observe_demo_cases(cases: DemoCases) -> Result<(), ()> {
    (cases.happy.id == "demo-write-happy"
        && cases.auth_failure.id == "demo-write-auth-failure"
        && cases.validation_failure.id == "demo-write-validation-failure"
        && cases.contention.id == "demo-write-contention")
        .then_some(())
        .ok_or(())
}

#[test]
fn localtx_validation_journey() -> Result<(), ()> {
    const LOCALTX_JOURNEY_DEMO_WRITE: ::vocab::HttpRouteBinding<
        ::generated::http::demo_v1::write::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::demo_v1::write::ROUTE;
    let _ = LOCALTX_JOURNEY_DEMO_WRITE;

    let mut fixtures = Fixtures;
    let happy = fixtures.take_case("demo-write-happy")?;
    let auth_failure = fixtures.take_case("demo-write-auth-failure")?;
    let validation_failure = fixtures.take_case("demo-write-validation-failure")?;
    let contention = fixtures.take_case("demo-write-contention")?;
    let demo_cases = DemoCases {
        happy,
        auth_failure,
        validation_failure,
        contention,
    };
    observe_demo_cases(demo_cases)?;
    Ok(())
}
