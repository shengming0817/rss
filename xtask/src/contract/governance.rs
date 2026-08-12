//! Canonical typed contract-governance catalog and validated repository IR.
//!
//! INVARIANT: CONTRACT-GOVERNANCE-IR-01 { level = "Hard", exec = "native-compile", source = "code", native = "closed rule catalog and private validated IR construction", facet = "single-catalog" } -- stable rule identity, ownership, step, source, enforcement and execution binding are declared once.
//! INVARIANT: CONTRACT-GOVERNANCE-SOURCE-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "source_funnel::tests::source_funnel_rejects_parallel_repository_loaders", anti_vacuity = "tests::real_workspace_loads_through_governance_ir" } -- this module is the sole xtask repository source owner; the lower assembly-schema loader and its sealed AssemblyLock runtime verifier are the only library-level owners.

use anyhow::{Context, Result, bail};
use assembly_schema::repository_contract::{
    RepositoryContract, SchemaJsonErrorCategory, SchemaSourceIssueKind,
    inspect_contract_repository, verify_contract_repository_unchanged,
};
use assembly_schema::{ContractOwner, contract_manifest::ContractManifest};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use vocab::StepName;

use crate::ci_lanes::GateId;
use crate::execution_profiles::ExecutionProfile;

/// Rule ownership policy. Per-contract rules resolve to the canonical manifest-backed owner;
/// catalog rules are framework-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleOwner {
    Contract,
    Framework,
}

impl RuleOwner {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Framework => "framework",
        }
    }
}

/// Governance phase that owns the rule's stable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleStage {
    Validation,
    Breaking,
}

/// Closed execution step shape used to derive validation plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleStep {
    SourceInspection,
    PerContract,
    Catalog,
    BreakingSchema,
    BreakingManifest,
    BreakingRepository,
}

pub(crate) type PerContractValidationHandler =
    fn(&RepositoryContract, &str) -> Vec<super::validate::Finding>;
pub(crate) type CatalogValidationHandler =
    fn(&[RepositoryContract]) -> Vec<super::validate::Finding>;
type SourceInspectionHandler =
    fn(&assembly_schema::repository_contract::SchemaSourceIssue, &Path) -> super::validate::Finding;

#[derive(Debug, Clone, Copy)]
enum RuleExecution {
    ValidationSource(SourceInspectionHandler),
    ValidationPerContract(PerContractValidationHandler),
    ValidationCatalog(CatalogValidationHandler),
    Breaking(BreakingDetector),
}

impl RuleExecution {
    const fn step(self) -> RuleStep {
        match self {
            Self::ValidationSource(_) => RuleStep::SourceInspection,
            Self::ValidationPerContract(_) => RuleStep::PerContract,
            Self::ValidationCatalog(_) => RuleStep::Catalog,
            Self::Breaking(BreakingDetector::Schema) => RuleStep::BreakingSchema,
            Self::Breaking(BreakingDetector::Manifest) => RuleStep::BreakingManifest,
            Self::Breaking(BreakingDetector::Repository) => RuleStep::BreakingRepository,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BreakingDetector {
    Repository,
    Manifest,
    Schema,
}

/// Source material inspected by a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleSource {
    Manifest,
    Schema,
    Repository,
    RustSource,
}

impl RuleSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Schema => "schema",
            Self::Repository => "repository",
            Self::RustSource => "rust-source",
        }
    }
}

/// Actual enforcement strength of the rule carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Enforcement {
    Medium,
    Lifecycle,
    ReviewOnly,
}

/// The stage-qualified identity of one catalog node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GovernanceRuleId {
    Validation(ContractRuleId),
    Breaking(BreakingRule),
}

impl GovernanceRuleId {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Validation(rule) => rule.as_str(),
            Self::Breaking(rule) => rule.id(),
        }
    }

    pub(crate) const fn symbol(self) -> &'static str {
        match self {
            Self::Validation(rule) => rule.symbol(),
            Self::Breaking(rule) => rule.symbol(),
        }
    }
}

/// One immutable governance-rule node. The execution profile is projected from `gate`, never
/// duplicated as an independently editable catalog field.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ContractRuleSpec {
    id: GovernanceRuleId,
    stage: RuleStage,
    owner: RuleOwner,
    execution: RuleExecution,
    source: RuleSource,
    enforcement: Enforcement,
    gate: GateId,
    doc: &'static str,
}

impl ContractRuleSpec {
    pub(crate) const fn id(self) -> GovernanceRuleId {
        self.id
    }

    pub(crate) const fn stage(self) -> RuleStage {
        self.stage
    }

    pub(crate) const fn owner(self) -> RuleOwner {
        self.owner
    }

    pub(crate) const fn step(self) -> RuleStep {
        self.execution.step()
    }

    pub(crate) const fn source(self) -> RuleSource {
        self.source
    }

    pub(crate) const fn enforcement(self) -> Enforcement {
        self.enforcement
    }

    pub(crate) const fn gate(self) -> GateId {
        self.gate
    }

    pub(crate) fn profile(self) -> ExecutionProfile {
        self.gate.spec().primary_owner()
    }

    pub(crate) const fn doc(self) -> &'static str {
        self.doc
    }
}

macro_rules! contract_governance_catalog {
    (
        validation {
            $( $validation_variant:ident => ($validation_id:literal, $validation_owner:ident, $validation_step:ident($validation_handler:path), $validation_source:ident, $validation_enforcement:ident, $validation_doc:literal), )+
        }
        breaking {
            $( $breaking_variant:ident => ($breaking_id:literal, $breaking_owner:ident, $breaking_detector:ident, $breaking_source:ident, $breaking_enforcement:ident, $breaking_doc:literal), )+
        }
    ) => {
        /// Stable contract validation identity. IDs are append-only and never derived from order.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum ContractRuleId { $( $validation_variant, )+ }

        impl ContractRuleId {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$validation_variant,)+];

            pub(crate) const fn as_str(self) -> &'static str {
                match self { $(Self::$validation_variant => $validation_id,)+ }
            }

            pub(crate) const fn symbol(self) -> &'static str {
                match self { $(Self::$validation_variant => stringify!($validation_variant),)+ }
            }

            pub(crate) const fn spec(self) -> &'static ContractRuleSpec {
                match self {
                    $(Self::$validation_variant => &ContractRuleSpec {
                        id: GovernanceRuleId::Validation(Self::$validation_variant),
                        stage: RuleStage::Validation,
                        owner: RuleOwner::$validation_owner,
                        execution: RuleExecution::$validation_step($validation_handler),
                        source: RuleSource::$validation_source,
                        enforcement: Enforcement::$validation_enforcement,
                        gate: GateId::ContractValidate,
                        doc: $validation_doc,
                    },)+
                }
            }
        }

        impl std::fmt::Debug for ContractRuleId {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        /// Stable contract breaking identity. IDs and policy are projected from this catalog.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum BreakingRule { $( $breaking_variant, )+ }

        impl BreakingRule {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$breaking_variant,)+];

            pub(crate) const fn id(self) -> &'static str {
                match self { $(Self::$breaking_variant => $breaking_id,)+ }
            }

            pub(crate) const fn symbol(self) -> &'static str {
                match self { $(Self::$breaking_variant => stringify!($breaking_variant),)+ }
            }

            pub(crate) const fn spec(self) -> &'static ContractRuleSpec {
                match self {
                    $(Self::$breaking_variant => &ContractRuleSpec {
                        id: GovernanceRuleId::Breaking(Self::$breaking_variant),
                        stage: RuleStage::Breaking,
                        owner: RuleOwner::$breaking_owner,
                        execution: RuleExecution::Breaking(BreakingDetector::$breaking_detector),
                        source: RuleSource::$breaking_source,
                        enforcement: Enforcement::$breaking_enforcement,
                        gate: GateId::ContractBreaking,
                        doc: $breaking_doc,
                    },)+
                }
            }
        }
    };
}

contract_governance_catalog! {
    validation {
        SagaConsistency => ("R1", Contract, ValidationPerContract(super::validate::execute_saga_consistency), Manifest, Medium, "Saga 契约的 consistencyLevel 必须为 WorkflowEventual"),
        CommandConsistency => ("R15", Contract, ValidationPerContract(super::validate::execute_command_consistency), Manifest, Medium, "期望 kind=command 的 consistencyLevel=OutboxFact；拒绝任何使用其他 consistencyLevel 的 Command 契约"),
        CommandPolicy => ("R24", Contract, ValidationPerContract(super::validate::execute_command_policy), Manifest, Medium, "kind=command 当且仅当声明完整 [command] journal policy"),
        FrameworkKind => ("R2", Contract, ValidationPerContract(super::validate::execute_framework_kind), Manifest, Medium, "owner=_framework 仅可用于 framework 允许的契约 kind"),
        PathMismatch => ("R3", Contract, ValidationPerContract(super::validate::execute_path_mismatch), Repository, Medium, "磁盘 kind/domain/version/slug 必须与 manifest 身份精确一致"),
        SchemaShape => ("R4", Contract, ValidationPerContract(super::validate::execute_schema_shape), Manifest, Medium, "每种 contract kind 只能声明其闭合 schema slot 形状"),
        MissingSchema => ("R5", Contract, ValidationSource(project_r5_source_issue), Schema, Medium, "每个已声明 schema source 必须存在且 JSON 良构；source inspection 按物理路径只投影一次 canonical finding"),
        UnsafeSchemaPath => ("R6", Contract, ValidationSource(project_r6_source_issue), Schema, Medium, "schema 文件名必须是安全的单路径段且不得逃逸契约目录"),
        IdentSyntax => ("R7", Contract, ValidationPerContract(super::validate::execute_ident_syntax), Manifest, Medium, "domain/id/version/topic 等 authoring 标识必须符合各自 canonical grammar"),
        PerKindActiveFields => ("R8", Contract, ValidationPerContract(super::validate::execute_per_kind_active_fields), Manifest, Medium, "期望 active HTTP 有 path+method、active Event 有 topic+delivery、active Command 有 topic；拒绝任一 active 契约缺其发布接线字段"),
        PerKindFieldScope => ("R9", Contract, ValidationPerContract(super::validate::execute_per_kind_field_scope), Manifest, Medium, "kind 专属字段只能出现在对应 kind，禁止跨 kind 残留"),
        ManifestWireMetadata => ("R26", Contract, ValidationPerContract(super::validate::execute_manifest_wire_metadata), Manifest, Medium, "HTTP success status、subscription identity/effect 与 wire metadata 必须闭合一致"),
        HttpAuth => ("R18", Contract, ValidationPerContract(super::validate::execute_http_auth), Manifest, Medium, "active HTTP 必须声明闭合授权模式及其 permission/scope 参数"),
        HttpTenantSource => ("R19", Contract, ValidationPerContract(super::validate::execute_http_tenant_source), Schema, Medium, "HTTP tenant authority 只能来自认证上下文或声明式受保护 header"),
        HttpProjectionCoverage => ("R23", Contract, ValidationPerContract(super::validate::execute_http_projection_coverage), Schema, Medium, "HTTP projection 声明字段必须由响应 schema 精确覆盖"),
        SagaBlock => ("R10", Contract, ValidationPerContract(super::validate::execute_saga_block), Manifest, Medium, "Saga 必须有非空 typed steps、唯一 StepName、完整 receipt/effect/retry/compensation policy"),
        ActiveDeliverySupported => ("R11", Contract, ValidationPerContract(super::validate::execute_active_delivery_supported), Manifest, Medium, "active Event 仅允许 delivery=at-least-once"),
        SchemaTitle => ("R13", Contract, ValidationPerContract(super::validate::execute_schema_title), Schema, Medium, "期望每个 declared schema 的 root title 为 string、全部 title 为 PascalCase 且契约内唯一；拒绝缺 root title、非法 title 或契约内重复"),
        IdentityAbacOperatorSsot => ("R27", Framework, ValidationCatalog(super::validate::execute_identity_abac_operator_ssot), Schema, Medium, "active identity schema 的 operator 属性必须直接引用唯一 Common ABAC component，且 repository 必须存在至少一个 canonical consumer"),
        SchemaRedaction => ("R16", Contract, ValidationPerContract(super::validate::execute_schema_redaction), Schema, Medium, "敏感 schema 字段必须声明闭合 redaction policy"),
        SchemaProtection => ("R17", Contract, ValidationPerContract(super::validate::execute_schema_protection), Schema, Medium, "敏感持久化字段必须声明闭合 at-rest protection policy"),
        ActiveSubscriber => ("R14", Contract, ValidationPerContract(super::validate::execute_active_subscriber), Manifest, Medium, "active Event 必须至少声明一个完整 subscription consumer"),
        SlugSyntax => ("R20", Contract, ValidationPerContract(super::validate::execute_slug_syntax), Repository, Medium, "嵌套 contract slug 必须符合安全 canonical segment grammar"),
        DuplicateId => ("R12", Framework, ValidationCatalog(super::validate::execute_duplicate_id), Repository, Medium, "整个 repository 的 contract id 必须全局唯一"),
        SlugMixing => ("R21", Framework, ValidationCatalog(super::validate::execute_slug_mixing), Repository, Medium, "同一 kind/domain/version 不得混用 flat 与 nested contract layout"),
        ConsistencyCapability => ("R22", Framework, ValidationCatalog(super::validate::execute_consistency_capability), RustSource, Medium, "consistency level、outbox/workflow/device capability 与生产 carrier 必须闭合"),
        DeviceCertificateHttpClosure => ("R25", Framework, ValidationCatalog(super::validate::execute_device_certificate_http_closure), Repository, Medium, "device certificate policy/status HTTP 与 command/event/reconcile 契约必须精确闭合"),
    }
    breaking {
        FieldNoDelete => ("FIELD_NO_DELETE", Contract, Schema, Schema, Lifecycle, "existing schema field removal"),
        RequiredFieldAdded => ("REQUIRED_FIELD_ADDED", Contract, Schema, Schema, Lifecycle, "required input field addition"),
        FieldTypeChanged => ("FIELD_TYPE_CHANGED", Contract, Schema, Schema, Lifecycle, "schema field type narrowing"),
        FieldFormatChanged => ("FIELD_FORMAT_CHANGED", Contract, Schema, Schema, Lifecycle, "schema field format change"),
        ConstValueChanged => ("CONST_VALUE_CHANGED", Contract, Schema, Schema, Lifecycle, "schema const value change"),
        ResolvedSchemaHashChanged => ("RESOLVED_SCHEMA_HASH_CHANGED", Contract, Schema, Schema, Lifecycle, "durable wire resolved schema hash rotation"),
        StringLengthUnitTightened => ("STRING_LENGTH_UNIT_TIGHTENED", Contract, Schema, Schema, Lifecycle, "string length unit tightening"),
        EnumValueDeleted => ("ENUM_VALUE_DELETED", Contract, Schema, Schema, Lifecycle, "schema enum value removal"),
        AdditionalPropsTightened => ("ADDITIONAL_PROPS_TIGHTENED", Contract, Schema, Schema, Lifecycle, "additional properties tightening"),
        NullableRemoved => ("NULLABLE_REMOVED", Contract, Schema, Schema, Lifecycle, "nullable input removal"),
        NullableAdded => ("NULLABLE_ADDED", Contract, Schema, Schema, Lifecycle, "nullable output addition"),
        RequiredFieldRemoved => ("REQUIRED_FIELD_REMOVED", Contract, Schema, Schema, Lifecycle, "required output field removal"),
        EnumValueAdded => ("ENUM_VALUE_ADDED", Contract, Schema, Schema, Lifecycle, "output enum value addition"),
        EnumConstraintRemoved => ("ENUM_CONSTRAINT_REMOVED", Contract, Schema, Schema, Lifecycle, "output enum constraint removal"),
        FieldAddedToOutput => ("FIELD_ADDED_TO_OUTPUT", Contract, Schema, Schema, Lifecycle, "output field addition"),
        AdditionalPropsLoosened => ("ADDITIONAL_PROPS_LOOSENED", Contract, Schema, Schema, Lifecycle, "output additional properties loosening"),
        RedactionPolicyChanged => ("REDACTION_POLICY_CHANGED", Contract, Schema, Schema, Lifecycle, "redaction policy change"),
        ProtectionPolicyChanged => ("PROTECTION_POLICY_CHANGED", Contract, Schema, Schema, Lifecycle, "at-rest protection policy change"),
        HttpStatusCodeChanged => ("HTTP_STATUS_CODE_CHANGED", Contract, Manifest, Manifest, Lifecycle, "HTTP status code change"),
        HttpPathChanged => ("HTTP_PATH_CHANGED", Contract, Manifest, Manifest, Lifecycle, "HTTP path change"),
        HttpMethodChanged => ("HTTP_METHOD_CHANGED", Contract, Manifest, Manifest, Lifecycle, "HTTP method change"),
        AuthRequirementChanged => ("AUTH_REQUIREMENT_CHANGED", Contract, Manifest, Manifest, Lifecycle, "authorization requirement change"),
        AuthScopeChanged => ("AUTH_SCOPE_CHANGED", Contract, Manifest, Manifest, Lifecycle, "authorization scope change"),
        ResourceSharingChanged => ("RESOURCE_SHARING_CHANGED", Contract, Manifest, Manifest, Lifecycle, "resource sharing change"),
        IdempotencyLevelChanged => ("IDEMPOTENCY_LEVEL_CHANGED", Contract, Manifest, Manifest, Lifecycle, "idempotency level change"),
        TopicChanged => ("TOPIC_CHANGED", Contract, Manifest, Manifest, Lifecycle, "event topic change"),
        DeliveryChanged => ("DELIVERY_CHANGED", Contract, Manifest, Manifest, Lifecycle, "event delivery change"),
        ConsistencyLevelChanged => ("CONSISTENCY_LEVEL_CHANGED", Contract, Manifest, Manifest, Lifecycle, "consistency level change"),
        LocalOnlyBoundaryChanged => ("LOCAL_ONLY_BOUNDARY_CHANGED", Contract, Manifest, Manifest, ReviewOnly, "local-only boundary review"),
        EffectAdded => ("EFFECT_ADDED", Contract, Manifest, Manifest, ReviewOnly, "effect addition review"),
        EffectRemoved => ("EFFECT_REMOVED", Contract, Manifest, Manifest, ReviewOnly, "effect removal review"),
        OutboxRoleChanged => ("OUTBOX_ROLE_CHANGED", Contract, Manifest, Manifest, Lifecycle, "outbox role change"),
        OutboxAtomicityChanged => ("OUTBOX_ATOMICITY_CHANGED", Contract, Manifest, Manifest, Lifecycle, "outbox atomicity change"),
        OutboxEmitsChanged => ("OUTBOX_EMITS_CHANGED", Contract, Manifest, Manifest, Lifecycle, "outbox emits change"),
        DeviceLatentResourceKindChanged => ("DEVICE_LATENT_RESOURCE_KIND_CHANGED", Contract, Manifest, Manifest, Lifecycle, "device-latent resource kind change"),
        DeviceLatentLinkChanged => ("DEVICE_LATENT_LINK_CHANGED", Contract, Manifest, Manifest, Lifecycle, "device-latent link change"),
        SubscriptionSetChanged => ("SUBSCRIPTION_SET_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription set change"),
        SubscriptionConsumerChanged => ("SUBSCRIPTION_CONSUMER_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription consumer change"),
        SubscriptionGroupChanged => ("SUBSCRIPTION_GROUP_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription group change"),
        SubscriptionTopologyChanged => ("SUBSCRIPTION_TOPOLOGY_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription topology change"),
        SubscriptionExecutionChanged => ("SUBSCRIPTION_EXECUTION_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription execution change"),
        SubscriptionEffectChanged => ("SUBSCRIPTION_EFFECT_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription effect change"),
        SubscriptionExternalEffectPolicyChanged => ("SUBSCRIPTION_EXTERNAL_EFFECT_POLICY_CHANGED", Contract, Manifest, Manifest, Lifecycle, "subscription external-effect policy change"),
        ContractKindChanged => ("CONTRACT_KIND_CHANGED", Framework, Repository, Repository, Lifecycle, "contract kind change"),
        LifecycleDowngraded => ("LIFECYCLE_DOWNGRADED", Framework, Repository, Repository, Lifecycle, "active lifecycle downgrade"),
        ContractRemoved => ("CONTRACT_REMOVED", Framework, Repository, Repository, Lifecycle, "contract removal"),
    }
}

pub(crate) fn rule_specs() -> impl Iterator<Item = &'static ContractRuleSpec> {
    ContractRuleId::ALL.iter().map(|id| id.spec())
}

fn source_inspection_plan() -> impl Iterator<Item = (ContractRuleId, SourceInspectionHandler)> {
    ContractRuleId::ALL
        .iter()
        .filter_map(|rule| match rule.spec().execution {
            RuleExecution::ValidationSource(handler) => Some((*rule, handler)),
            RuleExecution::ValidationPerContract(_)
            | RuleExecution::ValidationCatalog(_)
            | RuleExecution::Breaking(_) => None,
        })
}

pub(crate) fn per_contract_validation_plan()
-> impl Iterator<Item = (ContractRuleId, PerContractValidationHandler)> {
    ContractRuleId::ALL
        .iter()
        .filter_map(|rule| match rule.spec().execution {
            RuleExecution::ValidationPerContract(handler) => Some((*rule, handler)),
            RuleExecution::ValidationSource(_)
            | RuleExecution::ValidationCatalog(_)
            | RuleExecution::Breaking(_) => None,
        })
}

pub(crate) fn catalog_validation_plan()
-> impl Iterator<Item = (ContractRuleId, CatalogValidationHandler)> {
    ContractRuleId::ALL
        .iter()
        .filter_map(|rule| match rule.spec().execution {
            RuleExecution::ValidationCatalog(handler) => Some((*rule, handler)),
            RuleExecution::ValidationSource(_)
            | RuleExecution::ValidationPerContract(_)
            | RuleExecution::Breaking(_) => None,
        })
}

const CODEGEN_FIXTURE_CATALOG_EXCLUSIONS: &[ContractRuleId] = &[
    ContractRuleId::IdentityAbacOperatorSsot,
    ContractRuleId::DeviceCertificateHttpClosure,
];

/// Canonical catalog-rule view for isolated codegen fixtures. New catalog rules are included by
/// default and therefore fail closed; only production canonical-family/owner anti-vacuity rules
/// may be explicitly excluded here.
pub(crate) fn codegen_fixture_catalog_validation_plan()
-> impl Iterator<Item = (ContractRuleId, CatalogValidationHandler)> {
    catalog_validation_plan().filter(|(rule, _)| !CODEGEN_FIXTURE_CATALOG_EXCLUSIONS.contains(rule))
}

pub(crate) fn breaking_execution_plan() -> Vec<BreakingDetector> {
    let mut detectors = breaking_rule_specs()
        .filter_map(|spec| match spec.execution {
            RuleExecution::Breaking(detector) => Some(detector),
            RuleExecution::ValidationSource(_)
            | RuleExecution::ValidationPerContract(_)
            | RuleExecution::ValidationCatalog(_) => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    detectors.sort();
    detectors
}

pub(crate) fn breaking_rule_specs() -> impl Iterator<Item = &'static ContractRuleSpec> {
    BreakingRule::ALL.iter().map(|id| id.spec())
}

fn governance_rule_specs() -> impl Iterator<Item = &'static ContractRuleSpec> {
    rule_specs().chain(breaking_rule_specs())
}

pub(crate) fn render_rule_docs() -> String {
    let mut output = String::from(
        "校验规则由 `Contract Governance IR` 单向投影；编号是稳定身份，handler/owner/source 与文档在同一 catalog 条目绑定。\n\n| ID | Rule | Owner | Source | 说明 |\n|---|---|---|---|---|\n",
    );
    for spec in rule_specs() {
        output.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | {} |\n",
            spec.id().as_str(),
            spec.id().symbol(),
            spec.owner().as_str(),
            spec.source().as_str(),
            spec.doc()
        ));
    }
    output
}

/// Read-only discovery snapshot plus semantic diagnostics. Consumers that need to explain invalid
/// input use this projection instead of bypassing the canonical repository loader.
#[derive(Debug, Clone)]
pub(crate) struct ContractGovernanceInspection {
    contracts_root: PathBuf,
    source_count: usize,
    repository: Vec<RepositoryContract>,
    findings: Vec<super::validate::Finding>,
}

impl ContractGovernanceInspection {
    #[cfg(test)]
    pub(crate) fn sources(&self) -> &[RepositoryContract] {
        &self.repository
    }

    pub(crate) const fn source_count(&self) -> usize {
        self.source_count
    }

    pub(crate) fn findings(&self) -> &[super::validate::Finding] {
        &self.findings
    }
}

/// One validated contract node. Construction and the raw repository snapshot remain private to
/// `ContractGovernanceIr`; production consumers can only observe typed, validated projections.
#[derive(Debug, Clone)]
pub(crate) struct GovernedContract {
    source: RepositoryContract,
    steps: Vec<StepName>,
}

impl GovernedContract {
    pub(crate) fn id(&self) -> &str {
        &self.source.manifest().id
    }

    pub(crate) fn owner(&self) -> &ContractOwner {
        self.source.owner()
    }

    pub(crate) fn steps(&self) -> &[StepName] {
        &self.steps
    }

    pub(crate) fn manifest(&self) -> &ContractManifest {
        self.source.manifest()
    }

    pub(crate) fn dir(&self) -> &Path {
        self.source.dir()
    }

    pub(crate) fn path_kind(&self) -> &str {
        self.source.path_kind()
    }

    pub(crate) fn path_domain(&self) -> &str {
        self.source.path_domain()
    }

    pub(crate) fn path_version(&self) -> &str {
        self.source.path_version()
    }

    pub(crate) fn slug(&self) -> Option<&str> {
        self.source.slug()
    }

    pub(crate) fn manifest_path(&self) -> &Path {
        self.source.manifest_path()
    }

    pub(crate) fn manifest_bytes(&self) -> &[u8] {
        self.source.manifest_bytes()
    }

    pub(crate) fn schema(
        &self,
        file: &str,
    ) -> Option<&assembly_schema::repository_contract::ResolvedSchema> {
        self.source.schema(file)
    }

    pub(crate) fn declared_schema(
        &self,
        file: &str,
    ) -> Option<assembly_schema::repository_contract::DeclaredSchema<'_>> {
        self.source.declared_schema(file)
    }

    pub(crate) fn schema_hash(&self) -> &str {
        self.source.schema_hash()
    }
}

pub(crate) fn validate_workflow_activations(
    manifest: &assembly_schema::CanonicalAssemblyManifestV2,
    contracts: &[GovernedContract],
) -> Result<()> {
    let repository = contracts
        .iter()
        .map(|contract| contract.source.clone())
        .collect::<Vec<_>>();
    assembly_schema::repository_contract::validate_workflow_activations(manifest, &repository)
        .map_err(anyhow::Error::new)
}

/// Minimal typed projection for CI impact planning from either working-tree or git-ref bytes.
/// Raw manifest owner parsing is confined to the governance source owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContractImpact {
    id: String,
    owner: Option<String>,
    subscribers: Vec<String>,
}

impl ContractImpact {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    pub(crate) fn subscribers(&self) -> &[String] {
        &self.subscribers
    }
}

pub(crate) fn contract_impact_from_manifest(source: &str) -> Result<ContractImpact> {
    let manifest = ContractManifest::from_toml_str(source).context("parse impacted contract")?;
    let id = manifest.id.clone();
    let owner = manifest.owner_domain().map(str::to_owned);
    let subscribers = manifest
        .subscriptions
        .into_iter()
        .map(|subscription| subscription.consumer)
        .collect();
    Ok(ContractImpact {
        id,
        owner,
        subscribers,
    })
}

/// Complete validated repository contract IR.
#[derive(Debug, Clone)]
pub(crate) struct ContractGovernanceIr {
    contracts_root: PathBuf,
    contracts: Vec<GovernedContract>,
}

impl ContractGovernanceIr {
    /// Production and test builds execute the exact same complete workspace validation funnel.
    pub(crate) fn load_consumer_workspace(root: &Path) -> Result<Self> {
        Self::from_inspection(Self::inspect_workspace(root)?, true)
    }

    /// Load and validate the complete workspace, including workspace-only prerequisites.
    #[cfg(test)]
    pub(crate) fn load_workspace(root: &Path) -> Result<Self> {
        Self::from_inspection(Self::inspect_workspace(root)?, true)
    }

    /// Load and validate an isolated `contracts/` root used by contract-only fixtures and tools.
    #[cfg(test)]
    pub(crate) fn load_contracts_root(contracts_root: &Path) -> Result<Self> {
        Self::from_inspection(Self::inspect_contracts_root(contracts_root)?, true)
    }

    /// Breaking comparison is the sole production operation allowed to represent an empty working
    /// repository, because the empty side is required to detect deletion of every base contract.
    pub(crate) fn load_breaking_working_root(contracts_root: &Path) -> Result<Self> {
        let inspection = Self::inspect_root(contracts_root, false)?;
        if inspection.repository.is_empty() {
            return Self::from_repository(inspection.contracts_root, inspection.repository, false);
        }
        Self::from_inspection(inspection, false)
    }

    /// Load the checked-in testkit contract fixture root consumed only by code generation.
    ///
    /// Fixture contracts deliberately do not participate in production workspace governance or
    /// owner enrollment; they still pass the complete isolated-contract semantic validator before
    /// entering the canonical typed IR.
    pub(crate) fn load_codegen_fixture_root(contracts_root: &Path) -> Result<Self> {
        let repository = load_nonempty_repository(contracts_root)?;
        let findings = super::validate::validate_discovered_codegen_fixtures(&repository);
        Self::from_inspection(
            ContractGovernanceInspection {
                contracts_root: contracts_root.to_path_buf(),
                source_count: repository.len(),
                repository,
                findings,
            },
            true,
        )
    }

    /// Explicit test-only seam for focused consumer fixtures. The name makes the skipped semantic
    /// corpus validation visible at every call site; production APIs never change under cfg(test).
    #[cfg(test)]
    pub(crate) fn load_test_fixture_root(contracts_root: &Path) -> Result<Self> {
        let inspection = inspect_contract_repository(contracts_root).map_err(anyhow::Error::new)?;
        let repository = inspection.promote().map_err(anyhow::Error::new)?;
        Self::from_repository(contracts_root.to_path_buf(), repository, false)
    }

    /// Inspect the complete workspace without discarding the typed snapshot when semantic
    /// validation produces findings.
    pub(crate) fn inspect_workspace(root: &Path) -> Result<ContractGovernanceInspection> {
        let contracts_root = root.join("contracts");
        let (source_count, repository, source_findings) =
            inspect_repository(&contracts_root, true)?;
        if !source_findings.is_empty() {
            return Ok(ContractGovernanceInspection {
                contracts_root,
                source_count,
                repository,
                findings: source_findings,
            });
        }
        let (_, findings) = super::validate::validate_discovered_workspace(root, &repository)?;
        Ok(ContractGovernanceInspection {
            contracts_root,
            source_count,
            repository,
            findings,
        })
    }

    /// Inspect one isolated contract repository without workspace-only prerequisites.
    pub(crate) fn inspect_contracts_root(
        contracts_root: &Path,
    ) -> Result<ContractGovernanceInspection> {
        Self::inspect_root(contracts_root, true)
    }

    fn inspect_root(
        contracts_root: &Path,
        require_nonempty: bool,
    ) -> Result<ContractGovernanceInspection> {
        let (source_count, repository, source_findings) =
            inspect_repository(contracts_root, require_nonempty)?;
        let findings = if source_findings.is_empty() {
            super::validate::validate_discovered_contracts(&repository)
        } else {
            source_findings
        };
        Ok(ContractGovernanceInspection {
            contracts_root: contracts_root.to_path_buf(),
            source_count,
            repository,
            findings,
        })
    }

    fn from_inspection(
        inspection: ContractGovernanceInspection,
        require_nonempty: bool,
    ) -> Result<Self> {
        if !inspection.findings.is_empty() {
            let all = inspection
                .findings
                .iter()
                .map(crate::diagnostic::format_finding)
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "contract governance rejected {} finding(s). Run `cargo xtask contract validate` for the canonical report:\n{}",
                inspection.findings.len(),
                all,
            );
        }

        Self::from_repository(
            inspection.contracts_root,
            inspection.repository,
            require_nonempty,
        )
    }

    fn from_repository(
        contracts_root: PathBuf,
        repository: Vec<RepositoryContract>,
        require_nonempty: bool,
    ) -> Result<Self> {
        if require_nonempty && repository.is_empty() {
            bail!("contract governance workspace contains no contracts");
        }
        let contracts = repository
            .into_iter()
            .map(|source| GovernedContract {
                steps: source
                    .manifest()
                    .saga
                    .as_ref()
                    .map(|saga| saga.steps.iter().map(|step| step.name.clone()).collect())
                    .unwrap_or_default(),
                source,
            })
            .collect();
        let ir = Self {
            contracts_root,
            contracts,
        };
        ir.validate_projection()?;
        Ok(ir)
    }

    /// Execute one read/plan operation against the closed snapshot. Both checks are mandatory and
    /// cannot be forgotten by individual consumers.
    pub(crate) fn read<T>(
        &self,
        operation: impl FnOnce(&[GovernedContract]) -> Result<T>,
    ) -> Result<T> {
        self.verify_unchanged()?;
        let output = operation(&self.contracts)?;
        self.verify_unchanged()?;
        Ok(output)
    }

    /// Guard a pre-planned side effect with the same mandatory source closeout. Callers that write
    /// multiple files must provide their own rollback transaction and roll it back on any error,
    /// including the final stale-snapshot check returned here.
    pub(crate) fn commit<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.verify_unchanged()?;
        let output = operation()?;
        self.verify_unchanged()?;
        Ok(output)
    }

    fn verify_unchanged(&self) -> Result<()> {
        verify_contract_repository_unchanged(
            &self.contracts_root,
            self.contracts.iter().map(|contract| &contract.source),
        )
        .map_err(anyhow::Error::new)
    }

    fn validate_projection(&self) -> Result<()> {
        let mut ids = BTreeSet::new();
        for contract in &self.contracts {
            if !ids.insert(contract.id().to_owned()) {
                bail!(
                    "validated contract IR contains duplicate id={}",
                    contract.id()
                );
            }
            if contract.manifest().id != contract.id() {
                bail!("validated contract IR identity projection drifted");
            }
            if contract.owner().as_str().is_empty() {
                bail!("validated contract IR contains an empty owner");
            }
            if contract.steps().iter().any(|step| step.as_str().is_empty()) {
                bail!("validated contract IR contains an empty saga step");
            }
        }
        Ok(())
    }
}

fn load_nonempty_repository(contracts_root: &Path) -> Result<Vec<RepositoryContract>> {
    let (_, repository, findings) = inspect_repository(contracts_root, true)?;
    if !findings.is_empty() {
        bail!("contract governance fixture contains invalid schema sources");
    }
    Ok(repository)
}

fn inspect_repository(
    contracts_root: &Path,
    require_nonempty: bool,
) -> Result<(
    usize,
    Vec<RepositoryContract>,
    Vec<super::validate::Finding>,
)> {
    require_real_directory(contracts_root)?;
    let inspection = inspect_contract_repository(contracts_root).map_err(anyhow::Error::new)?;
    let source_count = inspection.len();
    if require_nonempty && source_count == 0 {
        bail!(
            "contract governance repository contains no contracts: {}",
            contracts_root.display()
        );
    }
    if !inspection.issues().is_empty() {
        let findings = inspection
            .issues()
            .iter()
            .map(|issue| {
                let rule = match issue.kind() {
                    SchemaSourceIssueKind::Missing | SchemaSourceIssueKind::Malformed => {
                        ContractRuleId::MissingSchema
                    }
                    SchemaSourceIssueKind::UnsafeName => ContractRuleId::UnsafeSchemaPath,
                };
                let RuleExecution::ValidationSource(project) = rule.spec().execution else {
                    unreachable!("source-owned contract rule must bind a source projector")
                };
                project(issue, contracts_root)
            })
            .collect();
        return Ok((source_count, Vec::new(), findings));
    }
    let repository = inspection.promote().map_err(anyhow::Error::new)?;
    if repository.is_empty() {
        return Ok((source_count, repository, Vec::new()));
    }
    Ok((source_count, repository, Vec::new()))
}

fn source_issue_subject(
    issue: &assembly_schema::repository_contract::SchemaSourceIssue,
    _contracts_root: &Path,
) -> String {
    issue.path().display().to_string()
}

fn project_r5_source_issue(
    issue: &assembly_schema::repository_contract::SchemaSourceIssue,
    contracts_root: &Path,
) -> super::validate::Finding {
    let detail = match issue.kind() {
        SchemaSourceIssueKind::Missing => {
            format!("schema source 缺失: {} ({})", issue.file(), issue.message())
        }
        SchemaSourceIssueKind::Malformed => format!(
            "schema JSON 非良构: {} category={} line={} column={}: {}",
            issue.file(),
            issue
                .category()
                .map_or("unknown", SchemaJsonErrorCategory::as_str),
            issue.line(),
            issue.column(),
            issue.message()
        ),
        SchemaSourceIssueKind::UnsafeName => {
            unreachable!("unsafe schema filename belongs to the R6 source projector")
        }
    };
    crate::diagnostic::finding(
        ContractRuleId::MissingSchema,
        source_issue_subject(issue, contracts_root),
        detail,
    )
}

fn project_r6_source_issue(
    issue: &assembly_schema::repository_contract::SchemaSourceIssue,
    contracts_root: &Path,
) -> super::validate::Finding {
    assert_eq!(issue.kind(), SchemaSourceIssueKind::UnsafeName);
    crate::diagnostic::finding(
        ContractRuleId::UnsafeSchemaPath,
        source_issue_subject(issue, contracts_root),
        format!("schema 文件名不是安全单路径段: {:?}", issue.file()),
    )
}

fn require_real_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "contract governance repository root is missing: {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "contract governance repository root must be a real directory: {}",
            path.display()
        );
    }
    Ok(())
}

pub(crate) fn validate_catalog() -> Result<()> {
    let catalog_ids = governance_rule_specs()
        .map(|spec| spec.id().as_str())
        .collect::<Vec<_>>();
    if catalog_ids.iter().copied().collect::<BTreeSet<_>>().len() != catalog_ids.len() {
        bail!("contract governance stable IDs contain duplicates");
    }

    let validation_catalog = governance_rule_specs()
        .filter(|spec| spec.stage() == RuleStage::Validation)
        .map(|spec| spec.id().as_str())
        .collect::<Vec<_>>();
    let validation_plan = per_contract_validation_plan()
        .map(|(id, _)| id.as_str())
        .chain(source_inspection_plan().map(|(id, _)| id.as_str()))
        .chain(catalog_validation_plan().map(|(id, _)| id.as_str()))
        .collect::<Vec<_>>();
    exact_id_projection(
        "contract validation execution plan",
        &validation_catalog,
        &validation_plan,
    )?;

    let breaking_detectors = breaking_execution_plan();
    if breaking_detectors
        != [
            BreakingDetector::Repository,
            BreakingDetector::Manifest,
            BreakingDetector::Schema,
        ]
    {
        bail!("contract breaking detector execution plan is incomplete: {breaking_detectors:?}");
    }

    let breaking_catalog = governance_rule_specs()
        .filter(|spec| spec.stage() == RuleStage::Breaking)
        .map(|spec| spec.id().as_str())
        .collect::<Vec<_>>();
    let breaking_plan = BreakingRule::ALL
        .iter()
        .map(|id| id.id())
        .collect::<Vec<_>>();
    exact_id_projection(
        "contract breaking policy plan",
        &breaking_catalog,
        &breaking_plan,
    )?;

    for spec in governance_rule_specs() {
        if spec.doc().is_empty() {
            bail!(
                "contract rule {} has empty documentation",
                spec.id().as_str()
            );
        }
        if spec.profile() != ExecutionProfile::Check {
            bail!(
                "contract rule {} must execute in check profile",
                spec.id().as_str()
            );
        }
        match spec.stage() {
            RuleStage::Validation => {
                if spec.gate() != GateId::ContractValidate
                    || spec.enforcement() != Enforcement::Medium
                    || !matches!(
                        spec.step(),
                        RuleStep::SourceInspection | RuleStep::PerContract | RuleStep::Catalog
                    )
                {
                    bail!(
                        "contract validation rule {} has an invalid execution binding",
                        spec.id().as_str()
                    );
                }
                if !matches!(
                    spec.execution,
                    RuleExecution::ValidationSource(_)
                        | RuleExecution::ValidationPerContract(_)
                        | RuleExecution::ValidationCatalog(_)
                ) {
                    bail!(
                        "contract validation rule {} has no typed handler",
                        spec.id().as_str()
                    );
                }
            }
            RuleStage::Breaking => {
                if spec.gate() != GateId::ContractBreaking
                    || !matches!(
                        spec.enforcement(),
                        Enforcement::Lifecycle | Enforcement::ReviewOnly
                    )
                    || !matches!(
                        spec.step(),
                        RuleStep::BreakingSchema
                            | RuleStep::BreakingManifest
                            | RuleStep::BreakingRepository
                    )
                {
                    bail!(
                        "contract breaking rule {} has an invalid execution binding",
                        spec.id().as_str()
                    );
                }
                if !matches!(spec.execution, RuleExecution::Breaking(_)) {
                    bail!(
                        "contract breaking rule {} has no detector binding",
                        spec.id().as_str()
                    );
                }
            }
        }
    }
    Ok(())
}

fn exact_id_projection(name: &str, canonical: &[&str], projection: &[&str]) -> Result<()> {
    let canonical_set = canonical.iter().copied().collect::<BTreeSet<_>>();
    if canonical_set.len() != canonical.len() {
        bail!("{name}: canonical stable IDs contain duplicates");
    }
    let projection_set = projection.iter().copied().collect::<BTreeSet<_>>();
    if projection_set.len() != projection.len() {
        bail!("{name}: projected stable IDs contain duplicates");
    }

    let missing = canonical_set
        .difference(&projection_set)
        .copied()
        .collect::<Vec<_>>();
    let extra = projection_set
        .difference(&canonical_set)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() || !extra.is_empty() {
        bail!("{name}: projection drift missing={missing:?} extra={extra:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_snapshot_fixture(contracts_root: &Path) -> Result<(PathBuf, PathBuf)> {
        let contract_dir = contracts_root.join("event/identity/v1/changed");
        std::fs::create_dir_all(&contract_dir)?;
        let manifest = contract_dir.join("contract.toml");
        let schema = contract_dir.join("payload.schema.json");
        std::fs::write(
            &manifest,
            r#"
id = "identity.changed"
kind = "event"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "OutboxFact"
lifecycle = "draft"
topic = "identity.changed"
delivery = "at-least-once"

[schemas]
payload = "payload.schema.json"

[capabilities.outbox]
role = "fact"
"#,
        )?;
        std::fs::write(&schema, r#"{"title":"IdentityChanged","type":"object"}"#)?;
        Ok((manifest, schema))
    }

    #[test]
    fn catalog_is_unique_closed_and_projects_to_check() -> Result<()> {
        validate_catalog()
    }

    #[test]
    fn codegen_fixture_catalog_plan_has_an_explicit_exact_partition() {
        let included = codegen_fixture_catalog_validation_plan()
            .map(|(rule, _)| rule)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            included,
            BTreeSet::from([
                ContractRuleId::DuplicateId,
                ContractRuleId::SlugMixing,
                ContractRuleId::ConsistencyCapability,
            ])
        );
        assert_eq!(
            CODEGEN_FIXTURE_CATALOG_EXCLUSIONS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ContractRuleId::IdentityAbacOperatorSsot,
                ContractRuleId::DeviceCertificateHttpClosure,
            ])
        );
        assert_eq!(
            included.len() + CODEGEN_FIXTURE_CATALOG_EXCLUSIONS.len(),
            catalog_validation_plan().count(),
            "every catalog rule must be explicitly classified for fixture codegen"
        );
    }

    #[test]
    fn catalog_projects_every_required_field() {
        for spec in governance_rule_specs() {
            assert!(!spec.id().as_str().is_empty());
            assert!(!spec.doc().is_empty());
            let _ = (
                spec.stage(),
                spec.owner(),
                spec.step(),
                spec.source(),
                spec.enforcement(),
                spec.gate(),
            );
        }
    }

    #[test]
    fn critical_validation_docs_are_exact_actionable_contracts() {
        let expected = [
            (
                ContractRuleId::PerKindActiveFields,
                "期望 active HTTP 有 path+method、active Event 有 topic+delivery、active Command 有 topic；拒绝任一 active 契约缺其发布接线字段",
            ),
            (
                ContractRuleId::SchemaTitle,
                "期望每个 declared schema 的 root title 为 string、全部 title 为 PascalCase 且契约内唯一；拒绝缺 root title、非法 title 或契约内重复",
            ),
            (
                ContractRuleId::CommandConsistency,
                "期望 kind=command 的 consistencyLevel=OutboxFact；拒绝任何使用其他 consistencyLevel 的 Command 契约",
            ),
        ];

        for (rule, expected_doc) in expected {
            assert_eq!(
                rule.spec().doc(),
                expected_doc,
                "{} doc drifted",
                rule.as_str()
            );
        }
    }

    #[test]
    fn readme_governance_section_is_exact_catalog_projection() -> Result<()> {
        const BEGIN: &str = "<!-- @generated:contract-governance:start -->\n";
        const END: &str = "<!-- @generated:contract-governance:end -->";

        let readme = std::fs::read_to_string(crate::workspace_root()?.join("contracts/README.md"))?;
        let projected = readme
            .split_once(BEGIN)
            .and_then(|(_, rest)| rest.split_once(END).map(|(section, _)| section))
            .expect("contracts/README.md must contain one governance projection block");

        assert_eq!(projected, render_rule_docs());
        Ok(())
    }

    #[test]
    fn validation_diagnostics_and_ir_bail_share_canonical_rule_identity() {
        let finding = crate::diagnostic::finding(
            ContractRuleId::PathMismatch,
            "contracts/event/identity/v1/changed",
            "path identity drifted",
        );
        let canonical = crate::diagnostic::format_finding(&finding);
        assert_eq!(
            canonical,
            "  [R3] contracts/event/identity/v1/changed: path identity drifted"
        );

        let inspection = ContractGovernanceInspection {
            contracts_root: PathBuf::from("contracts"),
            source_count: 0,
            repository: Vec::new(),
            findings: vec![finding],
        };
        let error = ContractGovernanceIr::from_inspection(inspection, false)
            .expect_err("semantic finding must reject governed IR")
            .to_string();
        assert!(error.contains(&canonical), "{error}");
        assert!(!error.contains("PathMismatch"), "{error}");
    }

    #[test]
    fn exact_relation_rejects_duplicate_ids_before_set_collapse() {
        let error = exact_id_projection("synthetic", &["a", "b"], &["a", "a"])
            .expect_err("duplicate projection must fail");
        assert!(
            error
                .to_string()
                .contains("projected stable IDs contain duplicates")
        );

        let error = exact_id_projection("synthetic", &["a", "a"], &["a"])
            .expect_err("duplicate canonical IDs must fail");
        assert!(
            error
                .to_string()
                .contains("canonical stable IDs contain duplicates")
        );
    }

    #[test]
    fn exact_relation_reports_missing_and_extra_ids() {
        let error = exact_id_projection("synthetic", &["a", "b", "c"], &["a", "d"])
            .expect_err("missing and extra IDs must fail");
        let message = error.to_string();
        assert!(message.contains("missing=[\"b\", \"c\"]"), "{message}");
        assert!(message.contains("extra=[\"d\"]"), "{message}");
    }

    #[test]
    fn exact_relation_rejects_equal_cardinality_wrong_id() {
        let error = exact_id_projection("synthetic", &["a", "b"], &["a", "c"])
            .expect_err("equal cardinality does not prove closure");
        let message = error.to_string();
        assert!(message.contains("missing=[\"b\"]"), "{message}");
        assert!(message.contains("extra=[\"c\"]"), "{message}");
    }

    #[test]
    fn exact_relation_accepts_projection_closure_independent_of_order() -> Result<()> {
        exact_id_projection("synthetic", &["a", "b", "c"], &["c", "a", "b"])
    }

    #[test]
    fn contract_root_inspection_preserves_snapshot_and_semantic_findings() -> Result<()> {
        let contracts_root = crate::testutil::unique_tmp("contract-governance-inspection");
        let contract_dir = contracts_root.join("http/identity/v1");
        std::fs::create_dir_all(&contract_dir)?;
        std::fs::write(
            contract_dir.join("contract.toml"),
            r#"
id = "identity.changed"
kind = "event"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "OutboxFact"
lifecycle = "draft"
topic = "identity.changed"
delivery = "at-least-once"

[schemas]
payload = "payload.schema.json"

[capabilities.outbox]
role = "fact"
"#,
        )?;
        std::fs::write(
            contract_dir.join("payload.schema.json"),
            r#"{"title":"IdentityChanged","type":"object"}"#,
        )?;

        let inspection = ContractGovernanceIr::inspect_contracts_root(&contracts_root)?;
        assert_eq!(inspection.sources().len(), 1);
        assert!(
            inspection
                .findings()
                .iter()
                .any(|finding| finding.rule == ContractRuleId::PathMismatch),
            "{:?}",
            inspection.findings()
        );
        let error = ContractGovernanceIr::load_contracts_root(&contracts_root)
            .expect_err("semantic findings must block validated IR construction");
        assert!(
            error.to_string().contains("  [R3] http/identity/v1:"),
            "{error}"
        );

        std::fs::remove_dir_all(contracts_root)?;
        Ok(())
    }

    #[test]
    fn malformed_schema_yields_one_canonical_source_finding() -> Result<()> {
        let contracts_root = crate::testutil::unique_tmp("contract-schema-parse-once-red");
        let (manifest, schema) = write_snapshot_fixture(&contracts_root)?;
        let manifest_source = std::fs::read_to_string(&manifest)?;
        std::fs::write(
            &manifest,
            manifest_source.replace("kind = \"event\"", "kind = \"http\""),
        )?;
        std::fs::write(&schema, br#"{"title":"IdentityChanged""#)?;

        let inspection = ContractGovernanceIr::inspect_contracts_root(&contracts_root)?;
        assert_eq!(
            inspection.findings().len(),
            1,
            "source-stage failure must suppress downstream semantic noise: {:?}",
            inspection.findings()
        );
        let parse_findings = inspection
            .findings()
            .iter()
            .filter(|finding| finding.rule == ContractRuleId::MissingSchema)
            .collect::<Vec<_>>();
        assert_eq!(parse_findings.len(), 1, "{:?}", inspection.findings());
        assert_eq!(
            parse_findings[0].subject,
            "event/identity/v1/changed/payload.schema.json"
        );
        assert!(
            parse_findings[0].detail.contains("JSON")
                && parse_findings[0].detail.contains("payload.schema.json"),
            "{:?}",
            parse_findings[0]
        );
        assert!(
            parse_findings[0].detail.contains("category=eof")
                && parse_findings[0].detail.contains("line=1 column="),
            "{:?}",
            parse_findings[0]
        );

        std::fs::remove_dir_all(contracts_root)?;
        Ok(())
    }

    #[test]
    fn missing_and_unsafe_schema_sources_are_owned_by_source_stage() -> Result<()> {
        let contracts_root = crate::testutil::unique_tmp("contract-schema-source-stage");
        let (manifest, schema) = write_snapshot_fixture(&contracts_root)?;
        std::fs::remove_file(&schema)?;

        let missing = ContractGovernanceIr::inspect_contracts_root(&contracts_root)?;
        assert_eq!(missing.sources().len(), 0);
        assert_eq!(missing.findings().len(), 1, "{:?}", missing.findings());
        assert_eq!(missing.findings()[0].rule, ContractRuleId::MissingSchema);

        std::fs::write(&schema, r#"{"title":"IdentityChanged","type":"object"}"#)?;
        let source = std::fs::read_to_string(&manifest)?;
        std::fs::write(
            &manifest,
            source.replace(
                "payload = \"payload.schema.json\"",
                "payload = \"../payload.schema.json\"",
            ),
        )?;
        let unsafe_name = ContractGovernanceIr::inspect_contracts_root(&contracts_root)?;
        assert_eq!(unsafe_name.sources().len(), 0);
        assert_eq!(
            unsafe_name.findings().len(),
            1,
            "{:?}",
            unsafe_name.findings()
        );
        assert_eq!(
            unsafe_name.findings()[0].rule,
            ContractRuleId::UnsafeSchemaPath
        );

        std::fs::remove_dir_all(contracts_root)?;
        Ok(())
    }

    #[test]
    fn codegen_fixture_loader_rejects_invalid_saga_semantics() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = root.join("crates/testkit/fixtures/contracts/saga/test/v1/primary");
        let contracts_root = crate::testutil::unique_tmp("codegen-fixture-semantic-red");
        let target = contracts_root.join("saga/test/v1/primary");
        std::fs::create_dir_all(&target)?;
        for name in [
            "contract.toml",
            "payload.schema.json",
            "prepare.schema.json",
            "commit.schema.json",
        ] {
            std::fs::copy(source.join(name), target.join(name))?;
        }
        let manifest_path = target.join("contract.toml");
        let manifest =
            std::fs::read_to_string(&manifest_path)?.replace("maxAttempts = 2", "maxAttempts = 0");
        std::fs::write(&manifest_path, manifest)?;

        let error = ContractGovernanceIr::load_codegen_fixture_root(&contracts_root)
            .expect_err("invalid Saga retry semantics must block fixture codegen");
        assert!(error.to_string().contains("maxAttempts"), "{error}");

        std::fs::remove_dir_all(contracts_root)?;
        Ok(())
    }

    #[test]
    fn real_workspace_loads_through_governance_ir() -> Result<()> {
        let root = crate::workspace_root()?;
        let inspection = ContractGovernanceIr::inspect_workspace(&root)?;
        assert!(inspection.findings().is_empty());
        let discovered_ids = inspection
            .sources()
            .iter()
            .map(|source| source.manifest().id.as_str())
            .collect::<Vec<_>>();
        assert!(!discovered_ids.is_empty());

        let ir = ContractGovernanceIr::load_workspace(&root)?;
        let governed_ids = ir.read(|contracts| {
            Ok(contracts
                .iter()
                .map(|contract| contract.id().to_owned())
                .collect::<Vec<_>>())
        })?;
        assert!(!governed_ids.is_empty());
        let governed_ids = governed_ids.iter().map(String::as_str).collect::<Vec<_>>();
        exact_id_projection("real workspace contracts", &discovered_ids, &governed_ids)?;
        assert!(rule_specs().next().is_some());
        assert!(breaking_rule_specs().next().is_some());
        Ok(())
    }

    #[test]
    fn production_workspace_rejects_missing_and_empty_contract_roots() -> Result<()> {
        let missing = crate::testutil::unique_tmp("contract-governance-missing-root");
        std::fs::create_dir_all(&missing)?;
        let missing_error = ContractGovernanceIr::load_consumer_workspace(&missing)
            .expect_err("missing contracts root must fail");
        assert!(missing_error.to_string().contains("root is missing"));

        let empty = crate::testutil::unique_tmp("contract-governance-empty-root");
        std::fs::create_dir_all(empty.join("contracts"))?;
        let empty_error = ContractGovernanceIr::load_consumer_workspace(&empty)
            .expect_err("empty contracts root must fail");
        assert!(empty_error.to_string().contains("contains no contracts"));

        let breaking = ContractGovernanceIr::load_breaking_working_root(&empty.join("contracts"))?;
        assert_eq!(breaking.read(|contracts| Ok(contracts.len()))?, 0);
        std::fs::remove_dir_all(missing)?;
        std::fs::remove_dir_all(empty)?;
        Ok(())
    }

    #[test]
    fn mandatory_closeout_rejects_manifest_schema_and_universe_mutation() -> Result<()> {
        for mutation in ["manifest", "schema", "universe"] {
            let contracts_root =
                crate::testutil::unique_tmp(&format!("contract-governance-closeout-{mutation}"));
            let (manifest, schema) = write_snapshot_fixture(&contracts_root)?;
            let governance = ContractGovernanceIr::load_test_fixture_root(&contracts_root)?;
            let error = governance
                .read(|_| {
                    match mutation {
                        "manifest" => std::fs::write(&manifest, "changed")?,
                        "schema" => std::fs::write(&schema, r#"{"changed":true}"#)?,
                        "universe" => {
                            let added = contracts_root.join("event/identity/v2/added");
                            std::fs::create_dir_all(&added)?;
                            std::fs::write(added.join("contract.toml"), "added")?;
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                })
                .expect_err("source mutation must fail the mandatory closeout");
            assert!(
                format!("{error:#}").contains("changed after snapshot")
                    || format!("{error:#}").contains("universe differs"),
                "mutation={mutation} error={error:#}"
            );
            std::fs::remove_dir_all(contracts_root)?;
        }
        Ok(())
    }
}
