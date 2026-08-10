#![allow(clippy::expect_used, clippy::panic)]
// Test assertions intentionally fail at the exact construction or boundary under test.

use std::sync::{Arc, Barrier};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rss_platform::contracts::{
    InventoryValueErrorCode, RuntimeActivatedProjection, RuntimeActivatedWorkflow,
    RuntimeAuthScheme, RuntimeDomain, RuntimeEndpointScheme, RuntimeInventory,
    RuntimeInventoryData, RuntimeInventoryRequest, RuntimeInventoryResponse, RuntimeListener,
    RuntimeListenerEndpoint, RuntimeListenerKind, RuntimePlacement, RuntimePlacementMode,
    RuntimePlacementReadiness, RuntimeProjectionActivation, RuntimeProviderPosture,
    RuntimeProviderState, Sha256Fingerprint,
};
use rss_platform::{
    AccessToken, ApplicationBuilder, ApplicationModule, ApplicationName, ConditionCode,
    ConditionStatus, DiagnosticCode, Handler, HandlerError, ModuleName, RequestContext, RequestId,
    TrustedIssuer,
};

const TENANT: &str = "8b117a90-752f-4f2a-85f1-00c7c4e1f41c";

struct InventoryHandler;
impl Handler<RuntimeInventory> for InventoryHandler {
    fn handle(
        &self,
        _: RuntimeInventoryRequest,
        context: RequestContext<'_>,
    ) -> Result<RuntimeInventoryResponse, HandlerError> {
        assert_eq!(context.request_id().as_str(), "request-1");
        assert!(context.principal().matches_subject("user-42"));
        assert!(
            context
                .tenant()
                .is_some_and(|tenant| tenant.id().as_str() == TENANT)
        );
        assert!(context.allows_permission("runtime:inventory:read"));
        let fingerprint = Sha256Fingerprint::parse(&format!("sha256:{}", "a".repeat(64)))
            .map_err(|_| HandlerError::new())?;
        let plan = Sha256Fingerprint::parse(&format!("sha256:{}", "b".repeat(64)))
            .map_err(|_| HandlerError::new())?;
        let data = RuntimeInventoryData::new(fingerprint, plan, vec![RuntimeDomain::Identity])
            .map_err(|_| HandlerError::new())?;
        Ok(RuntimeInventoryResponse::new(data))
    }
}

#[test]
fn verified_typed_dispatch_and_bounded_shutdown_are_one_real_flow() {
    let (issuer, signing) = issuer();
    let handle =
        ApplicationBuilder::new(ApplicationName::parse("inventory_app").expect("valid app"))
            .trusted_issuer(issuer)
            .module(
                ApplicationModule::new(ModuleName::parse("runtime").expect("valid module"))
                    .handler::<RuntimeInventory, _>(InventoryHandler),
            )
            .build()
            .expect("valid application")
            .start();
    let dispatcher = handle.dispatcher();
    let token = token(&signing, "ES256", "at+jwt", "key-1", base_claims());
    let access = dispatcher.verify(&token, now()).expect("valid access");
    let response = dispatcher
        .dispatch::<RuntimeInventory>(
            &access,
            RequestId::parse("request-1").expect("valid request id"),
            RuntimeInventoryRequest,
        )
        .expect("typed dispatch");
    assert_eq!(response.data().domains(), &[RuntimeDomain::Identity]);
    assert!(has_condition(
        &dispatcher,
        ConditionCode::AcceptingDispatch,
        ConditionStatus::True
    ));
    let report = handle
        .shutdown(Duration::from_secs(1))
        .expect("bounded shutdown");
    assert!(
        report
            .diagnostics()
            .iter()
            .any(|item| item.code() == DiagnosticCode::ShutdownComplete)
    );
    assert!(
        dispatcher
            .dispatch::<RuntimeInventory>(
                &access,
                RequestId::parse("request-1").expect("valid request id"),
                RuntimeInventoryRequest
            )
            .is_err()
    );
}

#[test]
fn verified_access_cannot_be_reused_after_expiry() {
    let (issuer, signing) = issuer();
    let handle = ApplicationBuilder::new(ApplicationName::parse("freshness_app").expect("app"))
        .trusted_issuer(issuer)
        .module(
            ApplicationModule::new(ModuleName::parse("runtime").expect("module"))
                .handler::<RuntimeInventory, _>(InventoryHandler),
        )
        .build()
        .expect("application")
        .start();
    let dispatcher = handle.dispatcher();
    let current = now_secs();
    let mut claims = base_claims();
    claims["iat"] = (current - 100).into();
    claims["exp"] = (current - 1).into();
    let token = token(&signing, "ES256", "at+jwt", "key-1", claims);
    let access = dispatcher
        .verify(&token, UNIX_EPOCH + Duration::from_secs(current - 50))
        .expect("credential was valid at verification time");
    let error = match dispatcher.dispatch::<RuntimeInventory>(
        &access,
        RequestId::parse("request-1").expect("request"),
        RuntimeInventoryRequest,
    ) {
        Ok(_) => panic!("expired authority must fail closed at dispatch"),
        Err(error) => error,
    };
    assert_eq!(
        error.diagnostics().iter().next().map(|item| item.code()),
        Some(DiagnosticCode::PermissionDenied)
    );
    handle.shutdown(Duration::from_secs(1)).expect("shutdown");
}

#[test]
fn generated_inventory_values_enforce_canonical_collections() {
    let duplicate_domains = RuntimeInventoryData::new(
        inventory_fingerprint('a'),
        inventory_fingerprint('b'),
        vec![RuntimeDomain::Identity, RuntimeDomain::Identity],
    );
    assert!(matches!(
        duplicate_domains,
        Err(error) if error.code() == InventoryValueErrorCode::DomainsDuplicate
    ));

    let workflow = || {
        RuntimeActivatedWorkflow::Projection(
            RuntimeActivatedProjection::new(
                "projection.one",
                "v1",
                inventory_fingerprint('c'),
                RuntimeProjectionActivation::Active,
            )
            .expect("valid workflow"),
        )
    };
    assert!(matches!(
        inventory_data().with_activated_workflows(vec![workflow(), workflow()]),
        Err(error) if error.code() == InventoryValueErrorCode::WorkflowsDuplicate
    ));
}

#[test]
fn generated_inventory_values_enforce_stable_key_order() {
    let unobserved = RuntimeProviderPosture::new("z", RuntimeProviderState::Unobserved)
        .expect("valid unobserved provider");
    assert_eq!(unobserved.state(), RuntimeProviderState::Unobserved);
    let listener = |id| {
        RuntimeListener::new(
            id,
            RuntimeListenerKind::Primary,
            RuntimeListenerEndpoint::new(RuntimeEndpointScheme::Https, "example.test", 443)
                .expect("valid endpoint"),
            RuntimeAuthScheme::FederatedAccessToken,
        )
        .expect("valid listener")
    };
    assert!(matches!(
        inventory_data().with_listeners(vec![listener("z"), listener("a")]),
        Err(error) if error.code() == InventoryValueErrorCode::ListenersNotCanonical
    ));
    assert!(matches!(
        inventory_data().with_provider_posture(vec![
            unobserved,
            RuntimeProviderPosture::new("a", RuntimeProviderState::Ready)
                .expect("valid provider"),
        ]),
        Err(error) if error.code() == InventoryValueErrorCode::ProvidersNotCanonical
    ));
    let placement = |domain, workload| {
        RuntimePlacement::new(
            domain,
            workload,
            RuntimePlacementMode::Local,
            RuntimePlacementReadiness::Ready,
        )
        .expect("valid placement")
    };
    assert!(matches!(
        inventory_data().with_placements(vec![
            placement(RuntimeDomain::Settings, "a"),
            placement(RuntimeDomain::Identity, "z"),
        ]),
        Err(error) if error.code() == InventoryValueErrorCode::PlacementsNotCanonical
    ));
}

#[test]
fn verification_matrix_is_fail_closed_and_redacted() {
    let (issuer, signing) = issuer();
    let handle = ApplicationBuilder::new(ApplicationName::parse("verify_app").expect("valid app"))
        .trusted_issuer(issuer)
        .build()
        .expect("valid application")
        .start();
    let dispatcher = handle.dispatcher();
    let mut cases = Vec::new();
    cases.push(token(&signing, "none", "at+jwt", "key-1", base_claims()));
    cases.push(token(&signing, "ES256", "JWT", "key-1", base_claims()));
    cases.push(token(&signing, "ES256", "at+jwt", "missing", base_claims()));
    let wrong_signing = SigningKey::from_bytes((&[8_u8; 32]).into()).expect("valid wrong key");
    cases.push(token(
        &wrong_signing,
        "ES256",
        "at+jwt",
        "key-1",
        base_claims(),
    ));
    let mut wrong_issuer = base_claims();
    wrong_issuer["iss"] = "wrong-issuer".into();
    cases.push(token(&signing, "ES256", "at+jwt", "key-1", wrong_issuer));
    let mut wrong_audience = base_claims();
    wrong_audience["aud"] = "wrong-audience".into();
    cases.push(token(&signing, "ES256", "at+jwt", "key-1", wrong_audience));
    let current = now_secs();
    let mut expired = base_claims();
    expired["exp"] = (current - 1).into();
    expired["iat"] = (current - 100).into();
    cases.push(token(&signing, "ES256", "at+jwt", "key-1", expired));
    let mut future = base_claims();
    future["nbf"] = (current + 60).into();
    cases.push(token(&signing, "ES256", "at+jwt", "key-1", future));
    let mut bad_shape = base_claims();
    bad_shape["kind"] = "superAdmin".into();
    cases.push(token(&signing, "ES256", "at+jwt", "key-1", bad_shape));
    let mut no_permission = base_claims();
    no_permission["permissions"] = serde_json::json!([]);
    cases.push(token(&signing, "ES256", "at+jwt", "key-1", no_permission));
    cases.push(token_with_header(
        &signing,
        serde_json::json!({"alg":"ES256","typ":"at+jwt","kid":"key-1","crit":null}),
        base_claims(),
    ));
    for candidate in cases {
        let error = match dispatcher.verify(&candidate, now()) {
            Ok(_) => panic!("must reject"),
            Err(error) => error,
        };
        let rendered = format!("{error:?} {error}");
        assert_eq!(
            rendered,
            "platform access verification failed platform access verification failed"
        );
        assert!(!rendered.contains("user-42") && !rendered.contains(TENANT));
    }
    handle.shutdown(Duration::from_secs(1)).expect("shutdown");
}

#[test]
fn duplicate_missing_and_permission_failures_are_closed_values() {
    let duplicate_module =
        ApplicationBuilder::new(ApplicationName::parse("duplicate_module_app").expect("valid app"))
            .trusted_issuer(issuer().0)
            .module(ApplicationModule::new(
                ModuleName::parse("same").expect("valid module"),
            ))
            .module(ApplicationModule::new(
                ModuleName::parse("same").expect("valid module"),
            ))
            .build();
    let duplicate_module = match duplicate_module {
        Ok(_) => panic!("duplicate module"),
        Err(error) => error,
    };
    assert!(
        duplicate_module
            .diagnostics()
            .iter()
            .any(|item| item.code() == DiagnosticCode::DuplicateModule)
    );

    let duplicate =
        ApplicationBuilder::new(ApplicationName::parse("duplicate_app").expect("valid app"))
            .trusted_issuer(issuer().0)
            .module(
                ApplicationModule::new(ModuleName::parse("a").expect("valid module"))
                    .handler::<RuntimeInventory, _>(InventoryHandler),
            )
            .module(
                ApplicationModule::new(ModuleName::parse("b").expect("valid module"))
                    .handler::<RuntimeInventory, _>(InventoryHandler),
            )
            .build();
    let duplicate = match duplicate {
        Ok(_) => panic!("duplicate contract handler"),
        Err(error) => error,
    };
    assert!(
        duplicate
            .diagnostics()
            .iter()
            .any(|item| item.code() == DiagnosticCode::DuplicateHandler)
    );

    let (issuer, signing) = issuer();
    let handle = ApplicationBuilder::new(ApplicationName::parse("missing_app").expect("valid app"))
        .trusted_issuer(issuer)
        .build()
        .expect("valid application")
        .start();
    let dispatcher = handle.dispatcher();
    let access = dispatcher
        .verify(
            &token(&signing, "ES256", "at+jwt", "key-1", base_claims()),
            now(),
        )
        .expect("valid access");
    assert!(
        dispatcher
            .dispatch::<RuntimeInventory>(
                &access,
                RequestId::parse("request-1").expect("valid request id"),
                RuntimeInventoryRequest
            )
            .is_err()
    );
    assert!(
        handle
            .diagnostics()
            .iter()
            .any(|item| item.code() == DiagnosticCode::MissingHandler)
    );
    handle.shutdown(Duration::from_secs(1)).expect("shutdown");

    let (permission_issuer, permission_signing) = issuer_with_key(7);
    let permission_handle =
        ApplicationBuilder::new(ApplicationName::parse("permission_app").expect("valid app"))
            .trusted_issuer(permission_issuer)
            .module(
                ApplicationModule::new(ModuleName::parse("runtime").expect("valid module"))
                    .handler::<RuntimeInventory, _>(InventoryHandler),
            )
            .build()
            .expect("valid permission application")
            .start();
    let permission_dispatcher = permission_handle.dispatcher();
    let mut wrong_permission = base_claims();
    wrong_permission["permissions"] = serde_json::json!(["settings:read"]);
    let wrong_access = permission_dispatcher
        .verify(
            &token(
                &permission_signing,
                "ES256",
                "at+jwt",
                "key-1",
                wrong_permission,
            ),
            now(),
        )
        .expect("valid access with another permission");
    let denied = match permission_dispatcher.dispatch::<RuntimeInventory>(
        &wrong_access,
        RequestId::parse("request-permission").expect("valid request id"),
        RuntimeInventoryRequest,
    ) {
        Ok(_) => panic!("marker permission must be enforced"),
        Err(error) => error,
    };
    assert!(
        denied
            .diagnostics()
            .iter()
            .any(|item| item.code() == DiagnosticCode::PermissionDenied)
    );
    permission_handle
        .shutdown(Duration::from_secs(1))
        .expect("shutdown");

    let foreign =
        ApplicationBuilder::new(ApplicationName::parse("foreign_app").expect("valid app"))
            .trusted_issuer(issuer_with_key(8).0)
            .module(
                ApplicationModule::new(ModuleName::parse("runtime").expect("valid module"))
                    .handler::<RuntimeInventory, _>(InventoryHandler),
            )
            .build()
            .expect("valid foreign application")
            .start();
    assert!(
        foreign
            .dispatcher()
            .dispatch::<RuntimeInventory>(
                &access,
                RequestId::parse("request-2").expect("valid request id"),
                RuntimeInventoryRequest,
            )
            .is_err()
    );
    foreign.shutdown(Duration::from_secs(1)).expect("shutdown");
}

struct BlockingHandler {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}
impl Handler<RuntimeInventory> for BlockingHandler {
    fn handle(
        &self,
        _: RuntimeInventoryRequest,
        _: RequestContext<'_>,
    ) -> Result<RuntimeInventoryResponse, HandlerError> {
        self.entered.wait();
        self.release.wait();
        let fingerprint = Sha256Fingerprint::parse(&format!("sha256:{}", "a".repeat(64)))
            .map_err(|_| HandlerError::new())?;
        let data = RuntimeInventoryData::new(
            fingerprint.clone(),
            fingerprint,
            vec![RuntimeDomain::Identity],
        )
        .map_err(|_| HandlerError::new())?;
        Ok(RuntimeInventoryResponse::new(data))
    }
}

#[test]
fn drain_rejects_new_work_and_waits_for_inflight_handler() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let (issuer, signing) = issuer();
    let handle = ApplicationBuilder::new(ApplicationName::parse("drain_app").expect("valid app"))
        .trusted_issuer(issuer)
        .module(
            ApplicationModule::new(ModuleName::parse("runtime").expect("valid module"))
                .handler::<RuntimeInventory, _>(BlockingHandler {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        )
        .build()
        .expect("valid application")
        .start();
    let dispatcher = handle.dispatcher();
    let worker_dispatcher = dispatcher.clone();
    let worker_token = token(&signing, "ES256", "at+jwt", "key-1", base_claims());
    let worker = std::thread::spawn(move || {
        let access = worker_dispatcher
            .verify(&worker_token, now())
            .expect("valid access");
        worker_dispatcher.dispatch::<RuntimeInventory>(
            &access,
            RequestId::parse("request-1").expect("valid request id"),
            RuntimeInventoryRequest,
        )
    });
    entered.wait();
    let shutdown = std::thread::spawn(move || handle.shutdown(Duration::from_secs(2)));
    while !has_condition(&dispatcher, ConditionCode::Draining, ConditionStatus::True) {
        std::thread::yield_now();
    }
    let access = dispatcher
        .verify(
            &token(&signing, "ES256", "at+jwt", "key-1", base_claims()),
            now(),
        )
        .expect("valid while draining");
    assert!(
        dispatcher
            .dispatch::<RuntimeInventory>(
                &access,
                RequestId::parse("request-1").expect("valid request id"),
                RuntimeInventoryRequest
            )
            .is_err()
    );
    release.wait();
    assert!(worker.join().expect("worker joined").is_ok());
    assert!(shutdown.join().expect("shutdown joined").is_ok());
    assert!(has_condition(
        &dispatcher,
        ConditionCode::Stopped,
        ConditionStatus::True
    ));
}

#[test]
fn shutdown_timeout_stops_new_work_without_leaking_inflight_state() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let (issuer, signing) = issuer();
    let handle = ApplicationBuilder::new(ApplicationName::parse("timeout_app").expect("valid app"))
        .trusted_issuer(issuer)
        .module(
            ApplicationModule::new(ModuleName::parse("runtime").expect("valid module"))
                .handler::<RuntimeInventory, _>(BlockingHandler {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        )
        .build()
        .expect("valid application")
        .start();
    let dispatcher = handle.dispatcher();
    let worker_dispatcher = dispatcher.clone();
    let worker_token = token(&signing, "ES256", "at+jwt", "key-1", base_claims());
    let worker = std::thread::spawn(move || {
        let access = worker_dispatcher
            .verify(&worker_token, now())
            .expect("valid access");
        worker_dispatcher.dispatch::<RuntimeInventory>(
            &access,
            RequestId::parse("request-1").expect("valid request id"),
            RuntimeInventoryRequest,
        )
    });
    entered.wait();
    let error = handle.shutdown(Duration::ZERO);
    assert!(error.is_err());
    assert!(has_condition(
        &dispatcher,
        ConditionCode::Draining,
        ConditionStatus::True
    ));
    assert!(has_condition(
        &dispatcher,
        ConditionCode::Stopped,
        ConditionStatus::False
    ));
    release.wait();
    assert!(worker.join().expect("worker joined").is_ok());
    assert!(has_condition(
        &dispatcher,
        ConditionCode::Stopped,
        ConditionStatus::True
    ));
}

fn issuer() -> (TrustedIssuer, SigningKey) {
    issuer_with_key(7)
}
fn inventory_fingerprint(byte: char) -> Sha256Fingerprint {
    Sha256Fingerprint::parse(&format!("sha256:{}", byte.to_string().repeat(64)))
        .expect("valid fingerprint")
}
fn inventory_data() -> RuntimeInventoryData {
    RuntimeInventoryData::new(
        inventory_fingerprint('a'),
        inventory_fingerprint('b'),
        vec![RuntimeDomain::Identity],
    )
    .expect("valid inventory base")
}
fn issuer_with_key(byte: u8) -> (TrustedIssuer, SigningKey) {
    let signing = SigningKey::from_bytes((&[byte; 32]).into()).expect("valid fixed key");
    let point = signing.verifying_key().to_encoded_point(false);
    let jwks = serde_json::json!({"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"key-1","x":URL_SAFE_NO_PAD.encode(point.x().expect("x")),"y":URL_SAFE_NO_PAD.encode(point.y().expect("y"))}]}).to_string();
    (
        TrustedIssuer::from_jwks_json("https://issuer.example", "rss-platform", &jwks)
            .expect("valid issuer"),
        signing,
    )
}
fn base_claims() -> serde_json::Value {
    let current = now_secs();
    serde_json::json!({"sub":"user-42","iat":current-10,"exp":current+100,"token_use":"access","iss":"https://issuer.example","aud":"rss-platform","kind":"user","tenant_id":TENANT,"permissions":["runtime:inventory:read"]})
}
fn token(
    signing: &SigningKey,
    alg: &str,
    typ: &str,
    kid: &str,
    claims: serde_json::Value,
) -> AccessToken {
    token_with_header(
        signing,
        serde_json::json!({"alg":alg,"typ":typ,"kid":kid}),
        claims,
    )
}
fn token_with_header(
    signing: &SigningKey,
    header: serde_json::Value,
    claims: serde_json::Value,
) -> AccessToken {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let input = format!("{header}.{payload}");
    let signature: Signature = signing.sign(input.as_bytes());
    AccessToken::parse(&format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
    .expect("token shape")
}
#[allow(clippy::disallowed_methods)]
fn now() -> SystemTime {
    SystemTime::now()
}
#[allow(clippy::disallowed_methods)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}
fn has_condition(
    dispatcher: &rss_platform::Dispatcher,
    code: ConditionCode,
    status: ConditionStatus,
) -> bool {
    dispatcher
        .conditions()
        .iter()
        .any(|item| item.code() == code && item.status() == status)
}
