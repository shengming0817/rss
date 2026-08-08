//! Cross-crate structure guard for the complete inbound HTTP server budget.
//!
//! INVARIANT: SERVER-REQUEST-BUDGET-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "guard_rejects_partial_or_transport_specific_budget", anti_vacuity = "production_boundary_has_one_mandatory_budget_funnel" }.

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
        "pubfninto_server_service(self,budget:crate::ServerRequestBudget)->ServerService",
    ) && routes.contains(
        ".layer(axum::middleware::from_fn_with_state(budget,crate::middleware::server_request_budget,))",
    ) && phase_launch.contains(
        "letresult=matchcrate::launch::server_request_budget(context.config()).context(\"resolveHTTPserverrequestbudget\"){",
    ) && phase_launch.contains(
        "Err(error)=>Err(provider_build.abort(error).await),",
    ) && phase_launch.contains(
        "Ok(request_budget)=>{",
    ) && phase_launch.contains(
        "letlifecycle_batches=provider_build.into_launch_batches();",
    ) && phase_launch.contains(
        "letadapter=crate::launch::RuntimeLaunchAdapter::new(listeners,request_budget,",
    ) && phase_launch.contains(
        "inventory_publisher,);",
    ) && phase_launch.contains(
        "letlaunch_plan=runtimeexec::LaunchPlan::new(adapter,probe_receipt,|inventory|asyncmove{crate::launch::log_ready(inventory)},trace_exporter,lifecycle_batches,crate::launch::total_drain_budget()?,);",
    ) && phase_launch.contains(
        "runtimeexec::launch(launch_plan).await",
    )
        && launch.contains("budget:httpserve::ServerRequestBudget")
        && launch.contains("Self{listeners,budget,addr_resolver,inventory_publisher,}")
        && launch.contains("routes.into_server_service(budget)")
        && httpd.matches("svc:httpserve::ServerService").count() >= 5
        && !httpd.contains("svc:IntoMakeServiceWithConnectInfo")
}

#[test]
fn guard_rejects_partial_or_transport_specific_budget() {
    let routes = r#"
        pub fn into_server_service(self, budget: crate::ServerRequestBudget) -> ServerService {
            let _ = budget;
            ServerService::new(self.router)
        }
    "#;
    let launch = r#"
        let svc = routes.into_server_service(budget);
    "#;
    let phase_launch = r#"
        let request_budget = crate::launch::server_request_budget(context.config())?;
        let adapter = crate::launch::RuntimeLaunchAdapter::new(listeners, request_budget, resolver);
        let launch_plan = runtimeexec::LaunchPlan::new(adapter, probe_receipt, on_ready);
        runtimeexec::launch(launch_plan).await;
    "#;
    let httpd = r#"
        pub fn serve(self, svc: IntoMakeServiceWithConnectInfo<Router, SocketAddr>) {}
        pub fn serve_mtls(self, svc: httpserve::ServerService) {}
    "#;
    assert!(!complete_budget_boundary(
        routes,
        phase_launch,
        launch,
        httpd
    ));

    let routes = r#"
        pub fn into_server_service(self, budget: crate::ServerRequestBudget) -> ServerService {}
        router.layer(axum::middleware::from_fn_with_state(
            budget,
            crate::middleware::server_request_budget,
        ));
    "#;
    assert!(!complete_budget_boundary(
        routes,
        phase_launch,
        "let svc = routes.into_server_service(budget);",
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
