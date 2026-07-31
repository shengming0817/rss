use consistency::{
    SagaAttempt, SagaContractId, SagaDefinitionIdentity, SagaEffectPhase, SagaId,
    SagaIdempotencyKey, SagaInstanceRef, SagaReceiptFormatVersion, SagaReceiptScope,
    SagaReceiptScopeError, SagaWorkerIdentity,
};
use vocab::{ContractBinding, SagaRetryClass, SagaStepBinding, TenantId};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const HASH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ALTERNATE_HASH: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTRACT: ContractBinding =
    ContractBinding::from_static("billing", "billing.checkout", "v1", HASH);
const STEP: SagaStepBinding = SagaStepBinding::from_static(
    CONTRACT,
    "reserve_funds",
    "reserve.schema.json",
    "billing.reserve-funds",
    "billing.release-funds",
    SagaRetryClass::Transient,
);
const INVALID_NAME_STEP: SagaStepBinding = SagaStepBinding::from_static(
    CONTRACT,
    "reserve-funds",
    "reserve.schema.json",
    "billing.reserve-funds",
    "billing.release-funds",
    SagaRetryClass::Transient,
);
const EMPTY_SCHEMA_STEP: SagaStepBinding = SagaStepBinding::from_static(
    CONTRACT,
    "reserve_funds",
    "",
    "billing.reserve-funds",
    "billing.release-funds",
    SagaRetryClass::Transient,
);

#[derive(Debug, Clone, Copy)]
enum ReceiptScopeErrorCase {
    WorkerOwner,
    WorkerContract,
    DefinitionVersion,
    DefinitionSchema,
    InvalidStepName,
    EmptyReceiptSchema,
    EffectKey,
}

const RECEIPT_SCOPE_ERROR_CASES: [(ReceiptScopeErrorCase, SagaReceiptScopeError); 7] = [
    (
        ReceiptScopeErrorCase::WorkerOwner,
        SagaReceiptScopeError::WorkerOwnerMismatch,
    ),
    (
        ReceiptScopeErrorCase::WorkerContract,
        SagaReceiptScopeError::WorkerContractMismatch,
    ),
    (
        ReceiptScopeErrorCase::DefinitionVersion,
        SagaReceiptScopeError::DefinitionVersionMismatch,
    ),
    (
        ReceiptScopeErrorCase::DefinitionSchema,
        SagaReceiptScopeError::DefinitionSchemaMismatch,
    ),
    (
        ReceiptScopeErrorCase::InvalidStepName,
        SagaReceiptScopeError::InvalidStepName,
    ),
    (
        ReceiptScopeErrorCase::EmptyReceiptSchema,
        SagaReceiptScopeError::EmptyReceiptSchema,
    ),
    (
        ReceiptScopeErrorCase::EffectKey,
        SagaReceiptScopeError::EffectKeyMismatch,
    ),
];

fn fixture() -> TestResult<(SagaInstanceRef, SagaWorkerIdentity, SagaDefinitionIdentity)> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let instance = SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(1924)))?;
    let worker = SagaWorkerIdentity::new(
        CONTRACT.domain(),
        SagaContractId::parse(CONTRACT.contract_id())?,
    )?;
    let definition = SagaDefinitionIdentity::new(
        CONTRACT.contract_id(),
        CONTRACT.version(),
        CONTRACT.schema_hash(),
        CONTRACT.schema_hash(),
    )?;
    Ok((instance, worker, definition))
}

fn scope_error_case(
    case: ReceiptScopeErrorCase,
) -> TestResult<Result<SagaReceiptScope, SagaReceiptScopeError>> {
    let (instance, worker, definition) = fixture()?;
    let (worker, definition, step, phase) = match case {
        ReceiptScopeErrorCase::WorkerOwner => (
            SagaWorkerIdentity::new("payments", SagaContractId::parse(CONTRACT.contract_id())?)?,
            definition,
            STEP,
            SagaEffectPhase::Forward,
        ),
        ReceiptScopeErrorCase::WorkerContract => (
            SagaWorkerIdentity::new(CONTRACT.domain(), SagaContractId::parse("billing.refund")?)?,
            definition,
            STEP,
            SagaEffectPhase::Forward,
        ),
        ReceiptScopeErrorCase::DefinitionVersion => (
            worker,
            SagaDefinitionIdentity::new(
                CONTRACT.contract_id(),
                "v2",
                CONTRACT.schema_hash(),
                CONTRACT.schema_hash(),
            )?,
            STEP,
            SagaEffectPhase::Forward,
        ),
        ReceiptScopeErrorCase::DefinitionSchema => (
            worker,
            SagaDefinitionIdentity::new(
                CONTRACT.contract_id(),
                CONTRACT.version(),
                ALTERNATE_HASH,
                CONTRACT.schema_hash(),
            )?,
            STEP,
            SagaEffectPhase::Forward,
        ),
        ReceiptScopeErrorCase::InvalidStepName => (
            worker,
            definition,
            INVALID_NAME_STEP,
            SagaEffectPhase::Forward,
        ),
        ReceiptScopeErrorCase::EmptyReceiptSchema => (
            worker,
            definition,
            EMPTY_SCHEMA_STEP,
            SagaEffectPhase::Forward,
        ),
        ReceiptScopeErrorCase::EffectKey => {
            (worker, definition, STEP, SagaEffectPhase::Compensation)
        }
    };
    let effect_key = SagaIdempotencyKey::derive(instance, &definition, step, phase);
    Ok(SagaReceiptScope::new(
        instance, worker, definition, step, effect_key,
    ))
}

#[test]
fn receipt_scope_accepts_only_the_canonical_forward_effect_key() -> TestResult {
    let (instance, worker, definition) = fixture()?;
    let forward = SagaIdempotencyKey::derive(instance, &definition, STEP, SagaEffectPhase::Forward);
    let compensation =
        SagaIdempotencyKey::derive(instance, &definition, STEP, SagaEffectPhase::Compensation);

    let scope = SagaReceiptScope::new(instance, worker.clone(), definition.clone(), STEP, forward)?;

    assert_eq!(scope.instance(), instance);
    assert_eq!(scope.worker(), &worker);
    assert_eq!(scope.definition(), &definition);
    assert_eq!(scope.step_name().as_str(), STEP.name());
    assert_eq!(scope.receipt_schema(), STEP.receipt_schema());
    let expected_debug = format!(
        "SagaReceiptScope {{ instance: {:?}, worker: {:?}, definition: {:?}, step_name: {:?}, receipt_schema: {:?}, effect_key: \"<redacted>\" }}",
        scope.instance(),
        scope.worker(),
        scope.definition(),
        scope.step_name(),
        scope.receipt_schema(),
    );
    assert_eq!(format!("{scope:?}"), expected_debug);
    assert_eq!(
        SagaReceiptScope::new(instance, worker, definition, STEP, compensation),
        Err(SagaReceiptScopeError::EffectKeyMismatch)
    );
    Ok(())
}

#[test]
fn receipt_scope_rejects_every_closed_error_case() -> TestResult {
    for (case, expected) in RECEIPT_SCOPE_ERROR_CASES {
        assert_eq!(scope_error_case(case)?, Err(expected), "case {case:?}");
    }
    Ok(())
}

#[test]
fn attempt_is_positive_audit_metadata_and_format_is_closed() -> TestResult {
    assert_eq!(SagaAttempt::new(1)?.get(), 1);
    assert!(SagaAttempt::new(0).is_err());
    assert_eq!(
        SagaReceiptFormatVersion::try_from(1),
        Ok(SagaReceiptFormatVersion::V1)
    );
    assert!(SagaReceiptFormatVersion::try_from(2).is_err());
    Ok(())
}

#[test]
fn idempotency_key_debug_is_redacted() -> TestResult {
    let (instance, _, definition) = fixture()?;
    let key = SagaIdempotencyKey::derive(instance, &definition, STEP, SagaEffectPhase::Forward);
    assert_eq!(format!("{key:?}"), "SagaIdempotencyKey(<redacted>)");
    assert_eq!(key.as_bytes().len(), 32);
    Ok(())
}
