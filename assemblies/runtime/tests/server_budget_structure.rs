//! Cross-crate structure guard for the complete inbound HTTP server budget.
//!
//! INVARIANT: SERVER-REQUEST-BUDGET-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "guard_rejects_partial_or_transport_specific_budget", anti_vacuity = "production_boundary_has_one_mandatory_budget_funnel" }.

fn compact(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn complete_budget_boundary(routes: &str, phase_launch: &str, launch: &str, httpd: &str) -> bool {
    let routes = compact(routes);
    let phase_launch = compact(phase_launch);
    let launch = compact(launch);
    let httpd = compact(httpd);

    routes.contains(
        "pubfninto_make_service(self,budget:crate::ServerRequestBudget)->ServerMakeService",
    ) && routes.contains(
        ".layer(axum::middleware::from_fn_with_state(budget,crate::middleware::server_request_budget,))",
    ) && phase_launch.contains(
        "letrequest_budget=crate::launch::server_request_budget(context.config())",
    ) && phase_launch.contains(
        "crate::launch::launch(context.config(),request_budget,launch_plan)",
    )
        && launch.contains("routes.into_make_service(budget)")
        && httpd.matches("svc:httpserve::ServerMakeService").count() >= 5
        && !httpd.contains("svc:IntoMakeServiceWithConnectInfo")
}

#[test]
fn guard_rejects_partial_or_transport_specific_budget() {
    let routes = r#"
        pub fn into_make_service(self, budget: crate::ServerRequestBudget) -> ServerMakeService {
            let _ = budget;
            ServerMakeService::new(self.router)
        }
    "#;
    let launch = r#"
        let svc = routes.into_make_service(budget);
    "#;
    let phase_launch = r#"
        let request_budget = crate::launch::server_request_budget(context.config())?;
        crate::launch::launch(context.config(), request_budget, launch_plan);
    "#;
    let httpd = r#"
        pub fn serve(self, svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>) {}
        pub fn serve_mtls(self, svc: httpserve::ServerMakeService) {}
    "#;
    assert!(!complete_budget_boundary(
        routes,
        phase_launch,
        launch,
        httpd
    ));

    let routes = r#"
        pub fn into_make_service(self, budget: crate::ServerRequestBudget) -> ServerMakeService {}
        router.layer(axum::middleware::from_fn_with_state(
            budget,
            crate::middleware::server_request_budget,
        ));
    "#;
    assert!(!complete_budget_boundary(
        routes,
        phase_launch,
        "let svc = routes.into_make_service(budget);",
        httpd
    ));
}

#[test]
fn production_boundary_has_one_mandatory_budget_funnel() {
    assert!(complete_budget_boundary(
        include_str!("../../../crates/httpserve/src/routes.rs"),
        include_str!("../src/phase/launch.rs"),
        include_str!("../src/launch.rs"),
        include_str!("../../../adapters/httpd/src/lib.rs"),
    ));
}
