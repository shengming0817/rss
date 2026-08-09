use std::future::{Future, ready};

use platform_application_waist_contract::{
    ApplicationModule, ApplicationName, ConditionCode, Contract, ContractId, ContractVersion,
    DiagnosticCode, Handler, ModuleName, PrincipalKind, RequestContext, SchemaDigest, core,
    eventing,
};

struct ReadRequest;
struct ReadResponse;

struct ReadContract;

impl Contract for ReadContract {
    type Request = ReadRequest;
    type Response = ReadResponse;

    const ID: ContractId = ContractId::from_static("identity.read");
    const VERSION: ContractVersion = ContractVersion::new(1, 0);
    const SCHEMA_DIGEST: SchemaDigest =
        SchemaDigest::from_static(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
}

struct ReadHandler;

impl Handler<ReadContract> for ReadHandler {
    fn handle<'a>(
        &'a self,
        _request: ReadRequest,
        context: RequestContext<'a>,
    ) -> impl Future<Output = ReadResponse> + Send + 'a {
        assert!(matches!(context.principal().kind(), PrincipalKind::User));
        let _ = context.principal().matches_subject("subject-probe");
        let _ = context.tenant().id().as_str();
        let _ = context.request_id();
        let _ = context.correlation_id();
        ready(ReadResponse)
    }
}

fn module(name: &str) -> ApplicationModule {
    ApplicationModule::new(ModuleName::parse(name).unwrap()).handler::<ReadContract, _>(ReadHandler)
}

fn compile_use_principal_kinds() {
    let _: [PrincipalKind; 6] = [
        PrincipalKind::User,
        PrincipalKind::Service,
        PrincipalKind::Device,
        PrincipalKind::Admin,
        PrincipalKind::SuperAdmin,
        PrincipalKind::Anonymous,
    ];
}

async fn compile_use() -> Result<(), Box<dyn std::error::Error>> {
    let core_application = core(ApplicationName::parse("core_app")?)
        .module(module("core_module"))
        .build()?;
    let handle = core_application.start().await?;

    let conditions = handle.conditions();
    let _ = conditions.get(ConditionCode::RuntimeReady);
    for condition in conditions.iter() {
        let _ = (condition.code(), condition.status());
    }

    let diagnostics = handle.diagnostics();
    let _ = diagnostics.is_empty();
    for diagnostic in diagnostics.iter() {
        let _: DiagnosticCode = diagnostic.code();
        let _ = diagnostic.retryable();
        for detail in diagnostic.details() {
            let _ = detail;
        }
    }

    let report = handle.shutdown().await?;
    let _ = (report.conditions(), report.diagnostics());

    let eventing_application = eventing(ApplicationName::parse("eventing_app")?)
        .module(module("eventing_module"))
        .build()?;
    let eventing_handle = eventing_application.start().await?;
    let _ = (eventing_handle.conditions(), eventing_handle.diagnostics());
    let eventing_report = eventing_handle.shutdown().await?;
    let _ = (eventing_report.conditions(), eventing_report.diagnostics());
    Ok(())
}

fn main() {
    let _ = (compile_use, compile_use_principal_kinds);
}
