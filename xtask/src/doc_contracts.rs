//! `doc-contracts` —— 文档契约片段 + migration carry-over ledger 漂移门（AI-robust Medium 内容扫描门）。
//!
//! INVARIANT: DOC-CONTRACTS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_content_rejects_removed_event_topology_and_entry_symbols", anti_vacuity = "tests::scan_content_accepts_current_event_topology_and_entry_symbols" }—— tenant + actor aware command /
//! outbox envelope 签名已经进入 codegen 与 runtime；规则 / spec 文档与相关 public rustdoc 不得残留 tenantless /
//! actorless 旧片段，也不得引用已删除的 event topology / entry symbols。
//! 该门只锁已知高风险签名片段，避免宽泛词扫描误伤历史散文；同时从冻结来源机器派生
//! carry-over 全集，以闭值状态、审计 PBI registry、仓内证据与 proof registry 守住唯一现行迁移索引。
//!
//! INVARIANT: OUTBOX-DELIVERY-SEMANTICS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_content_rejects_false_outbox_delivery_guarantees", anti_vacuity = "tests::scan_content_accepts_correct_and_scoped_delivery_semantics" }—— Outbox relay transport 只承诺 at-least-once；规则/spec、crash-matrix 说明与生产 rustdoc 不得把 CAS/lease fencing 误写成 broker at-most-once/exactly-once。负向扫描与 canonical 三 facet 完整性共同防止错误语义被 AI 复制或整段删除。
//!
//! INVARIANT: LOCALONLY-BUSINESS-EFFECT-SEMANTICS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_content_rejects_legacy_localonly_effect_semantics", anti_vacuity = "tests::scan_content_accepts_current_localonly_business_effect_semantics" }—— active 文档与生产 rustdoc 只使用 business-qualified 写/事务词汇；LocalOnly 证明业务持久化/outbox/publish 为零，但允许 provider-owned read-path transaction。负向语义扫描、显式 carrier 清单与 canonical facets 共同阻断旧 token/API 和“完全无事务/等同纯函数”的回流或整段删除。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, bail};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const CONTENT_ROOTS: &[(&str, &str)] = &[
    ("docs/rules", "md"),
    ("docs/spec", "md"),
    ("contracts", "toml"),
    ("journeys", "toml"),
];
const SEMANTIC_DOC_FILES: &[&str] =
    &["docs/architecture/202607111257-1673-l2-outbox-crash-matrix.md"];
const LOCALONLY_SEMANTIC_DOC_FILES: &[&str] = &[
    "docs/rules/consistency-l0.md",
    "docs/runbooks/202607141556-1771-local-only-proof.md",
    "contracts/README.md",
    "CLAUDE.md",
    ".claude/rules/rss/rust-standards.md",
    "docs/rules/architecture.md",
    "docs/rules/audit-ledger.md",
    "docs/spec/consistency-runtime/spec.md",
    "docs/spec/006-l0-l1-consistency-hardening/spec.md",
];
const RUSTDOC_ROOTS: &[&str] = &[
    "crates",
    "adapters",
    "assemblies",
    "bins",
    "generated",
    "journeys",
    "journeys-fault-matrix",
    "examples",
];
const OUTBOX_CANONICAL_FILE: &str = "docs/rules/eventbus.md";
const OUTBOX_CANONICAL_FACETS: &[(&str, &str)] = &[
    (
        "transport-at-least-once",
        "relay transport 是 **at-least-once**",
    ),
    (
        "publish-before-settle-duplicate",
        "publish 成功、settle 前崩溃允许 broker duplicate",
    ),
    (
        "consumer-transactional-dedupe",
        "tenant-scoped `Inbox` / `ConsumerTx` 收口重复数据库副作用",
    ),
];
const LOCALONLY_CANONICAL_FILE: &str = "docs/rules/consistency-l0.md";
const LOCALONLY_CANONICAL_HEADING: &str = "LocalOnly business effect 语义";
const LOCALONLY_CANONICAL_FACETS: &[(&str, &str)] = &[
    (
        "qualified-vocabulary-and-admission",
        "HTTP effect vocabulary 仅使用 `business-write` / `business-transaction`；LocalOnly 准入仍只允许 `auth` / `read` / `projection`",
    ),
    (
        "typed-marker-and-observer",
        "port marker 是 `BusinessWriteEffect`，runtime observer 使用 `BusinessWrite` / `business_writes`",
    ),
    (
        "zero-business-effects",
        "LocalOnly 证明的是业务持久化、outbox、publish 为零",
    ),
    (
        "provider-owned-read-transaction",
        "LocalOnly 允许 provider-owned read-path transaction",
    ),
    (
        "postgres-non-guarantees",
        "`tenant_scoped_read*` 不承诺 PostgreSQL `READ ONLY` 或稳定 snapshot",
    ),
    (
        "operational-exclusions",
        "correctness cache、metrics/trace、auth security audit 不计入 business effect",
    ),
    (
        "durable-cross-tenant-audit",
        "跨租户 durable audit 仍声明 `business-write + business-transaction + cross-tenant-audit` 并保持 LocalTx",
    ),
];
const CARRYOVER_DOC_FILE: &str =
    "docs/migration-from-gocell/202607101035-1444-persistence-migration-carry-over.md";
const EVENTEXEC_TASKS_FILE: &str = "docs/spec/002-eventexec-data-eventing/tasks.md";
const REWRITE_SEQUENCE_FILE: &str = "docs/migration-from-gocell/gocell-rewrite-sequence.md";
const GAP_006_FILE: &str =
    "docs/migration-from-gocell/202606240130-006-gocell-rss-capability-gaps.md";
const SCHEDULE_607_FILE: &str =
    "docs/migration-from-gocell/202606232040-607-p1p2-capability-gap-and-schedule.md";
const CRATE_MAPPING_FILE: &str = "docs/migration-from-gocell/gocell-rust-crate-mapping.md";
const CARRYOVER_MARKER: &str = "<!-- carry-over-schema: v1 -->";
const CARRYOVER_HEADER: &str = "| Source Set | Source ID | Capability | Resolution | Canonical Work Item | Duplicate | New PBI | Commit | Evidence Path | Proof | Scope Note |";
const CARRYOVER_SEPARATOR: &str = "|---|---|---|---|---|---|---|---|---|---|---|";
const DEVELOP_EVIDENCE_COMMITS: &[&str] = &["8d2768d5dd9cdea6cd798b08be506fa12a1724c2"];

#[derive(Debug, Clone, Copy)]
struct SourceAnchor {
    path: &'static str,
    needle: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct CodeFollowup {
    id: &'static str,
    anchor: Option<SourceAnchor>,
}

// Historical commit anchors and tracker-only leaves intentionally have no live-file anchor. Every
// current code comment that still carries residual scope is bounded to its exact file + phrase, so
// deleting the comment cannot silently shrink the carry-over universe.
const CODE_FOLLOWUPS: &[CodeFollowup] = &[
    CodeFollowup {
        id: "acecf759:consumer.rs:119",
        anchor: None,
    },
    CodeFollowup {
        id: "acecf759:projection.rs:18",
        anchor: None,
    },
    CodeFollowup {
        id: "current:consumer.rs:#1301",
        anchor: Some(SourceAnchor {
            path: "crates/eventexec/src/consumer.rs",
            needle: "生命周期落地（follow-up #1301）",
        }),
    },
    CodeFollowup {
        id: "current:consumer_worker.rs:#1142",
        anchor: Some(SourceAnchor {
            path: "crates/eventexec/src/consumer_worker.rs",
            needle: "settle/dlx 失败降级需 loop 内钩子 = 改 #1142 接缝",
        }),
    },
    CodeFollowup {
        id: "current:reconcile.rs:#1221",
        anchor: Some(SourceAnchor {
            path: "crates/eventexec/src/reconcile.rs",
            needle: "见 reconcile follow-up issue",
        }),
    },
    CodeFollowup {
        id: "current:cotx.rs:#1579",
        anchor: Some(SourceAnchor {
            path: "adapters/postgres/src/cotx/mod.rs",
            needle: "rss_app（dual-pool follow-up）后 DB 层 RLS 方强制生效",
        }),
    },
    CodeFollowup {
        id: "current:module.rs:#1541",
        anchor: None,
    },
    CodeFollowup {
        id: "tracker:#1406",
        anchor: None,
    },
    CodeFollowup {
        id: "tracker:#1681",
        anchor: None,
    },
    CodeFollowup {
        id: "current:publisher.rs:topology-provisioning",
        anchor: Some(SourceAnchor {
            path: "adapters/amqp/src/publisher.rs",
            needle: "topology provisioning port）属组合根，OOS follow-up",
        }),
    },
    CodeFollowup {
        id: "current:0012_enable_tenant_rls.sql:dual-pool",
        anchor: Some(SourceAnchor {
            path: "adapters/postgres/migrations/0012_enable_tenant_rls.sql",
            needle: "dual-pool 接线属 follow-up（bootstrap 接线本身未落地）",
        }),
    },
    CodeFollowup {
        id: "current:integration_tests.rs:envelope-metadata",
        anchor: Some(SourceAnchor {
            path: "adapters/postgres/src/integration_tests.rs",
            needle: "trace / correlation / principal 为后续 follow-up 空接缝",
        }),
    },
    CodeFollowup {
        id: "current:runtime-lib.rs:audit-tail-verify",
        anchor: Some(SourceAnchor {
            path: "assemblies/runtime/src/lib.rs",
            needle: "bootstrap 启动 tail-verify（跨租户全量巡检）defer 到 Part B",
        }),
    },
];

// Tracker state is external to `cargo xtask verify`; current open/closed state is queried only via
// forge. These typed provenance registries are the immutable audit snapshot taken at 2026-07-10
// from source commit 8d2768d5dd9cdea6cd798b08be506fa12a1724c2. Work item kind is retained:
// Canonical Work Item may preserve historical Feature provenance, while New PBI remains leaf-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkItemKind {
    ProductBacklogItem,
    Feature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkItemSnapshot {
    id: &'static str,
    kind: WorkItemKind,
}

impl WorkItemSnapshot {
    const fn pbi(id: &'static str) -> Self {
        Self {
            id,
            kind: WorkItemKind::ProductBacklogItem,
        }
    }

    const fn feature(id: &'static str) -> Self {
        Self {
            id,
            kind: WorkItemKind::Feature,
        }
    }
}

const AUDITED_EVIDENCE_WORK_ITEMS: &[WorkItemSnapshot] = &[
    WorkItemSnapshot::feature("#1013"),
    WorkItemSnapshot::pbi("#1100"),
    WorkItemSnapshot::pbi("#1114"),
    WorkItemSnapshot::pbi("#1115"),
    WorkItemSnapshot::pbi("#1116"),
    WorkItemSnapshot::pbi("#1117"),
    WorkItemSnapshot::pbi("#1118"),
    WorkItemSnapshot::pbi("#1119"),
    WorkItemSnapshot::pbi("#1120"),
    WorkItemSnapshot::pbi("#1121"),
    WorkItemSnapshot::pbi("#1122"),
    WorkItemSnapshot::pbi("#1123"),
    WorkItemSnapshot::pbi("#1124"),
    WorkItemSnapshot::pbi("#1137"),
    WorkItemSnapshot::pbi("#1142"),
    WorkItemSnapshot::pbi("#1187"),
    WorkItemSnapshot::pbi("#1213"),
    WorkItemSnapshot::pbi("#1249"),
    WorkItemSnapshot::pbi("#1251"),
    WorkItemSnapshot::pbi("#1347"),
    WorkItemSnapshot::pbi("#1422"),
    WorkItemSnapshot::pbi("#1423"),
    WorkItemSnapshot::pbi("#1424"),
    WorkItemSnapshot::pbi("#1425"),
    WorkItemSnapshot::pbi("#1426"),
    WorkItemSnapshot::pbi("#1429"),
    WorkItemSnapshot::pbi("#1430"),
    WorkItemSnapshot::pbi("#1431"),
    WorkItemSnapshot::pbi("#1433"),
    WorkItemSnapshot::pbi("#1434"),
    WorkItemSnapshot::pbi("#1435"),
    WorkItemSnapshot::pbi("#1437"),
    WorkItemSnapshot::pbi("#1438"),
    WorkItemSnapshot::pbi("#1440"),
    WorkItemSnapshot::pbi("#1441"),
    WorkItemSnapshot::pbi("#1442"),
    WorkItemSnapshot::pbi("#1443"),
    WorkItemSnapshot::feature("#1465"),
    WorkItemSnapshot::feature("#1466"),
    WorkItemSnapshot::feature("#1467"),
    WorkItemSnapshot::pbi("#1479"),
    WorkItemSnapshot::pbi("#1579"),
    WorkItemSnapshot::pbi("#1614"),
    WorkItemSnapshot::pbi("#1615"),
    WorkItemSnapshot::pbi("#1617"),
    WorkItemSnapshot::pbi("#1618"),
    WorkItemSnapshot::pbi("#1619"),
    WorkItemSnapshot::pbi("#1620"),
    WorkItemSnapshot::pbi("#1621"),
    WorkItemSnapshot::pbi("#1623"),
    WorkItemSnapshot::pbi("#1625"),
    WorkItemSnapshot::pbi("#1626"),
    WorkItemSnapshot::pbi("#1627"),
    WorkItemSnapshot::pbi("#1628"),
    WorkItemSnapshot::pbi("#1629"),
    WorkItemSnapshot::pbi("#1631"),
    WorkItemSnapshot::pbi("#1632"),
    WorkItemSnapshot::pbi("#1634"),
    WorkItemSnapshot::pbi("#1635"),
    WorkItemSnapshot::pbi("#1636"),
    WorkItemSnapshot::pbi("#1637"),
    WorkItemSnapshot::pbi("#1638"),
    WorkItemSnapshot::pbi("#1640"),
    WorkItemSnapshot::pbi("#1641"),
    WorkItemSnapshot::pbi("#1642"),
    WorkItemSnapshot::pbi("#1646"),
    WorkItemSnapshot::pbi("#1651"),
];
const AUDITED_ABSORPTION_WORK_ITEMS: &[WorkItemSnapshot] = &[
    WorkItemSnapshot::pbi("#1221"),
    WorkItemSnapshot::pbi("#1301"),
    WorkItemSnapshot::pbi("#1406"),
    WorkItemSnapshot::pbi("#1541"),
    WorkItemSnapshot::pbi("#1681"),
    WorkItemSnapshot::pbi("#1684"),
];
const AUDIT_CREATED_CARRYOVER_WORK_ITEMS: &[WorkItemSnapshot] = &[
    WorkItemSnapshot::pbi("#1714"),
    WorkItemSnapshot::pbi("#1715"),
    WorkItemSnapshot::pbi("#1716"),
    WorkItemSnapshot::pbi("#1717"),
    WorkItemSnapshot::pbi("#1718"),
    WorkItemSnapshot::pbi("#1720"),
];

#[derive(Debug, Clone, Copy)]
struct SplitSource {
    source_set: SourceSet,
    base_id: &'static str,
    atoms: &'static [&'static str],
}

// A split source is an explicit audit decision, not an open-ended suffix convention. Exact atoms
// prevent one surviving `.a` row from masking deletion of its `.b` sibling after parent folding.
const SPLIT_SOURCES: &[SplitSource] = &[
    SplitSource {
        source_set: SourceSet::Spec002,
        base_id: "T003.4",
        atoms: &["T003.4.a", "T003.4.b"],
    },
    SplitSource {
        source_set: SourceSet::Spec002,
        base_id: "T006.4",
        atoms: &["T006.4.a", "T006.4.b"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P0",
        atoms: &["P0.a", "P0.b"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P1",
        atoms: &["P1.a", "P1.b"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P2",
        atoms: &["P2.a", "P2.b", "P2.c"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P3",
        atoms: &["P3.a", "P3.b", "P3.c", "P3.d"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P5",
        atoms: &["P5.a", "P5.b"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P6",
        atoms: &["P6.a", "P6.b", "P6.c"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P7",
        atoms: &["P7.a", "P7.b", "P7.c", "P7.d", "P7.e", "P7.f", "P7.g"],
    },
    SplitSource {
        source_set: SourceSet::Rewrite,
        base_id: "P8",
        atoms: &["P8.a", "P8.b", "P8.c"],
    },
    SplitSource {
        source_set: SourceSet::Gap006,
        base_id: "P1-3",
        atoms: &["P1-3.a", "P1-3.b"],
    },
    SplitSource {
        source_set: SourceSet::Gap006,
        base_id: "P2-1",
        atoms: &["P2-1.a", "P2-1.b"],
    },
    SplitSource {
        source_set: SourceSet::Gap006,
        base_id: "P2-2",
        atoms: &["P2-2.a", "P2-2.b", "P2-2.c", "P2-2.d"],
    },
    SplitSource {
        source_set: SourceSet::Gap006,
        base_id: "P2-5",
        atoms: &["P2-5.a", "P2-5.b"],
    },
    SplitSource {
        source_set: SourceSet::Gap006,
        base_id: "P2-6",
        atoms: &["P2-6.a", "P2-6.b"],
    },
    SplitSource {
        source_set: SourceSet::Gap006,
        base_id: "P2-7",
        atoms: &["P2-7.a", "P2-7.b"],
    },
    SplitSource {
        source_set: SourceSet::Schedule607,
        base_id: "#1008",
        atoms: &["#1008.a", "#1008.b"],
    },
    SplitSource {
        source_set: SourceSet::Schedule607,
        base_id: "#1137",
        atoms: &["#1137.a", "#1137.b", "#1137.c"],
    },
    SplitSource {
        source_set: SourceSet::CrateMapping,
        base_id: "AMQP / MQTT",
        atoms: &["AMQP / MQTT.amqp", "AMQP / MQTT.mqtt"],
    },
    SplitSource {
        source_set: SourceSet::CrateMapping,
        base_id: "加密 / 证书 / TLS",
        atoms: &[
            "加密 / 证书 / TLS.field-protection",
            "加密 / 证书 / TLS.pki",
        ],
    },
    SplitSource {
        source_set: SourceSet::CrateMapping,
        base_id: "可观测性",
        atoms: &["可观测性.adapters", "可观测性.consistency"],
    },
    SplitSource {
        source_set: SourceSet::CrateMapping,
        base_id: "测试",
        atoms: &["测试.rstest", "测试.mockall", "测试.insta"],
    },
];

#[derive(Debug, Clone, Copy)]
struct GateProof {
    proof: &'static str,
    carriers: &'static [SourceAnchor],
}

// `gate:` is a closed vocabulary. The first carrier is the row's exact Evidence Path; every
// carrier also names a stable executable invariant/plan anchor, so a surviving empty or unrelated
// file cannot masquerade as proof.
const GATE_PROOFS: &[GateProof] = &[
    GateProof {
        proof: "gate: active subscriber contract",
        carriers: &[SourceAnchor {
            path: "xtask/src/contract_binding_guard.rs",
            needle: "CONTRACT-BINDING-FUNNEL-01",
        }],
    },
    GateProof {
        proof: "gate: cargo xtask migrations",
        carriers: &[SourceAnchor {
            path: "xtask/src/migrations.rs",
            needle: "MIGRATION-SERIAL-UNIQUE-01",
        }],
    },
    GateProof {
        proof: "gate: command-symmetry",
        carriers: &[SourceAnchor {
            path: "xtask/src/command_symmetry.rs",
            needle: "COMMAND-SYMMETRY-01",
        }],
    },
    GateProof {
        proof: "gate: consistency fault matrix",
        carriers: &[SourceAnchor {
            path: "xtask/src/verify.rs",
            needle: "fn step_consistency_fault_matrix_run()",
        }],
    },
    GateProof {
        proof: "gate: contract topology and command symmetry",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/contract/validate.rs",
                needle: "CONTRACT-FANOUT-01",
            },
            SourceAnchor {
                path: "xtask/src/command_symmetry.rs",
                needle: "COMMAND-SYMMETRY-01",
            },
        ],
    },
    GateProof {
        proof: "gate: contract validate",
        carriers: &[SourceAnchor {
            path: "xtask/src/contract/validate.rs",
            needle: "CONTRACT-FANOUT-01",
        }],
    },
    GateProof {
        proof: "gate: contract validate and command symmetry",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/contract/validate.rs",
                needle: "CONTRACT-FANOUT-01",
            },
            SourceAnchor {
                path: "xtask/src/command_symmetry.rs",
                needle: "COMMAND-SYMMETRY-01",
            },
        ],
    },
    GateProof {
        proof: "gate: contract validate and topology",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/contract/validate.rs",
                needle: "CONTRACT-FANOUT-01",
            },
            SourceAnchor {
                path: "xtask/src/contract_binding_guard.rs",
                needle: "CONTRACT-BINDING-FUNNEL-01",
            },
        ],
    },
    GateProof {
        proof: "gate: event transport and ops runbook",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/event_transport_guard.rs",
                needle: "EVENT-TRANSPORT-PG-INBOX-01",
            },
            SourceAnchor {
                path: "docs/rules/eventbus.md",
                needle: "## DLX 与幂等",
            },
        ],
    },
    GateProof {
        proof: "gate: event-transport-guard",
        carriers: &[SourceAnchor {
            path: "xtask/src/event_transport_guard.rs",
            needle: "EVENT-TRANSPORT-PG-INBOX-01",
        }],
    },
    GateProof {
        proof: "gate: inbox-cutover-guard",
        carriers: &[SourceAnchor {
            path: "xtask/src/inbox_cutover_guard.rs",
            needle: "INBOX-RECEIPTS-CUTOVER-01",
        }],
    },
    GateProof {
        proof: "gate: layer-deps and workspace verify",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/layerdeps.rs",
                needle: "LAYER-DEPS-01",
            },
            SourceAnchor {
                path: "xtask/src/verify.rs",
                needle: "VERIFY-AGGREGATE-01",
            },
        ],
    },
    GateProof {
        proof: "gate: outbox-atomicity contract validation",
        carriers: &[SourceAnchor {
            path: "xtask/src/contract/validate.rs",
            needle: "CAP_OUTBOX_ATOMICITY",
        }],
    },
    GateProof {
        proof: "gate: persistence hard closeout matrix",
        carriers: &[SourceAnchor {
            path: "xtask/src/pg_tenant_tx_guard.rs",
            needle: "TENANCY-PG-TX-FUNNEL-01",
        }],
    },
    GateProof {
        proof: "gate: projection append-only",
        carriers: &[SourceAnchor {
            path: "lints/rss_projection_append_only/src/lib.rs",
            needle: "PROJECTION-APPEND-ONLY-01",
        }],
    },
    GateProof {
        proof: "gate: reconcile outbox command",
        carriers: &[SourceAnchor {
            path: "xtask/src/reconcile_outbox_command_guard.rs",
            needle: "RECONCILE-COMMAND-OUTBOX-SEAM-01",
        }],
    },
    GateProof {
        proof: "gate: repository conformance and tenancy closeout",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/repo_scope_guard.rs",
                needle: "TENANCY-REPO-SCOPE-SIGNATURE-01",
            },
            SourceAnchor {
                path: "xtask/src/tenancy_closeout.rs",
                needle: "TENANCY-CLOSEOUT-REVERSE-01",
            },
        ],
    },
    GateProof {
        proof: "gate: runtime dependencies",
        carriers: &[SourceAnchor {
            path: "xtask/src/runtime_deps_guard.rs",
            needle: "WIRING-DEPS-INFRA-ONLY-01",
        }],
    },
    GateProof {
        proof: "gate: saga contract",
        carriers: &[SourceAnchor {
            path: "xtask/src/contract/validate.rs",
            needle: "SAGA-CONTRACT-01",
        }],
    },
    GateProof {
        proof: "gate: tenancy-closeout",
        carriers: &[SourceAnchor {
            path: "xtask/src/tenancy_closeout.rs",
            needle: "TENANCY-CLOSEOUT-REVERSE-01",
        }],
    },
    GateProof {
        proof: "gate: tenancy-closeout and reconcile-command guard",
        carriers: &[
            SourceAnchor {
                path: "xtask/src/tenancy_closeout.rs",
                needle: "TENANCY-CLOSEOUT-REVERSE-01",
            },
            SourceAnchor {
                path: "xtask/src/reconcile_outbox_command_guard.rs",
                needle: "RECONCILE-COMMAND-OUTBOX-SEAM-01",
            },
        ],
    },
    GateProof {
        proof: "gate: workspace verify",
        carriers: &[SourceAnchor {
            path: "xtask/src/verify.rs",
            needle: "VERIFY-AGGREGATE-01",
        }],
    },
];

const FORBIDDEN: &[ForbiddenPattern] = &[
    ForbiddenPattern {
        rule: Rule::RemovedSymbol,
        needle: "`SUBSCRIPTIONS`",
        detail: "event topology root is `EVENTS`; per-contract subscribers come from `SPEC.subscriptions()`",
    },
    ForbiddenPattern {
        rule: Rule::RemovedSymbol,
        needle: "generated SUBSCRIPTIONS",
        detail: "event topology root is generated `EVENTS`; per-contract subscribers come from `SPEC.subscriptions()`",
    },
    ForbiddenPattern {
        rule: Rule::RemovedSymbol,
        needle: "generated::event::SUBSCRIPTIONS",
        detail: "event topology root is `generated::event::EVENTS`",
    },
    ForbiddenPattern {
        rule: Rule::RemovedSymbol,
        needle: "consistency::Entry",
        detail: "producer authoring uses EventEntry; persisted relay rows use StoredOutboxEntry",
    },
    ForbiddenPattern {
        rule: Rule::RemovedSymbol,
        needle: "outbox::Entry",
        detail: "producer authoring uses EventEntry; persisted relay rows use StoredOutboxEntry",
    },
    ForbiddenPattern {
        rule: Rule::RemovedSymbol,
        needle: "Vec<Entry>",
        detail: "persisted relay batches use Vec<StoredOutboxEntry>",
    },
    ForbiddenPattern {
        rule: Rule::CommandWrapper,
        needle: "emit_async(emitter, request, subject_id, idempotency_key)",
        detail: "command wrapper 必须显式接收 tenant + actor: emit_async(emitter, request, tenant, subject_id, actor, idempotency_key)",
    },
    ForbiddenPattern {
        rule: Rule::CommandWrapper,
        needle: "emit_async(emitter, request, tenant, subject_id, idempotency_key)",
        detail: "command wrapper 必须显式接收 actor: emit_async(emitter, request, tenant, subject_id, actor, idempotency_key)",
    },
    ForbiddenPattern {
        rule: Rule::RuntimeCommandEmit,
        needle: "eventexec::command::emit_async(emitter, dispatch_id, topic, contract_id, payload, subject)",
        detail: "runtime command emit 必须透传 typed contract + tenant + actor: emit_async(..., contract, tenant, payload, subject_id, actor)",
    },
    ForbiddenPattern {
        rule: Rule::RuntimeCommandEmit,
        needle: "eventexec::command::emit_async(emitter, dispatch_id, topic, contract, tenant, payload, subject_id)",
        detail: "runtime command emit 必须透传 actor: emit_async(..., contract, tenant, payload, subject_id, actor)",
    },
    ForbiddenPattern {
        rule: Rule::OutboxEnvelope,
        needle: "OutboxEnvelopeParts::new(CONTRACT, subject)",
        detail: "outbox envelope parts 必须显式接收 tenant + actor: OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor)",
    },
    ForbiddenPattern {
        rule: Rule::OutboxEnvelope,
        needle: "OutboxEnvelopeParts::new(CONTRACT, tenant, subject)",
        detail: "outbox envelope parts 必须显式接收 actor: OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor)",
    },
    ForbiddenPattern {
        rule: Rule::ProducerSignature,
        needle: "request: <Cmd>Request, subject_id: String, idempotency_key: Option<String>",
        detail: "producer wrapper spec 必须使用 typed subject/actor，不得暴露 String subject_id 旧签名",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "saga_journal / projection_events 是**无 `tenant_id` 列的全局表**",
        detail: "saga_journal 已是 tenant-scoped 表；文档不得回退为 tenantless global saga journal",
    },
    ForbiddenPattern {
        rule: Rule::SagaTenantScope,
        needle: "saga 投影资源选型（journal / checkpoint / dead-letter / locker",
        detail: "saga runtime 已是 direct tenant-scoped instance/journal path，不得回退为 projection worker + locker 叙述",
    },
    ForbiddenPattern {
        rule: Rule::SagaTenantScope,
        needle: "bootstrap::sagaprojectiondeps::resolve(ctx, clk, topo, cfg)",
        detail: "saga 资源文档不得引用旧 sagaprojectiondeps resolver；应描述 instance/journal/checkpoint/dead-letter 注入",
    },
    ForbiddenPattern {
        rule: Rule::SagaTenantScope,
        needle: "journal::GlobalReader",
        detail: "saga_journal 已 tenant-scoped，文档不得回退到 GlobalReader 投影输入",
    },
    ForbiddenPattern {
        rule: Rule::SagaTenantScope,
        needle: "distlock::Locker",
        detail: "direct saga run/resume/status 不引入 leader locker",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "outbox 当前为无 `tenant_id` 的全局表",
        detail: "outbox 已是 tenant-scoped 表；文档不得保留旧 future-work 描述",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "outbox/inbox 不引入 tenant_id 维度属本 feature 显式范围决策",
        detail: "outbox 已引入 tenant_id；仅 inbox 仍维持现有去重维度",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "outbox 表无 `tenant_id` 列、无 RLS",
        detail: "outbox 已是 tenant-scoped RLS 表；文档不得保留旧无 tenant_id 描述",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "`partition_key` **必须自带 tenant scope**",
        detail: "outbox gate 已按 (tenant_id, domain, partition_key) 判队头；partition_key 不得再被描述为自带 tenant scope 的授权边界",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "partition_key 必须自带 tenant scope",
        detail: "outbox gate 已按 (tenant_id, domain, partition_key) 判队头；partition_key 不得再被描述为自带 tenant scope 的授权边界",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "设置时同 `(domain, partition_key)`",
        detail: "outbox gate 已按 (tenant_id, domain, partition_key) 判队头；public rustdoc 不得保留 tenantless gate 描述",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "gating：同 `(domain, partition_key)`",
        detail: "outbox gate 已按 (tenant_id, domain, partition_key) 判队头；public rustdoc 不得保留 tenantless gate 描述",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "tenant-scoped key",
        detail: "partition_key 不再需要自带 tenant；tenant scope 由 typed tenant_id 列承载",
    },
    ForbiddenPattern {
        rule: Rule::OutboxTenantScope,
        needle: "issue **#1405**",
        detail: "outbox tenant_id/RLS 已落地；规则文档不得继续指向 #1405 future-work",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    RemovedSymbol,
    CommandWrapper,
    RuntimeCommandEmit,
    OutboxEnvelope,
    ProducerSignature,
    OutboxTenantScope,
    SagaTenantScope,
    OutboxDeliverySemantics,
    LocalOnlyBusinessEffects,
    MigrationCarryover,
}

#[derive(Debug, Clone, Copy)]
struct ForbiddenPattern {
    rule: Rule,
    needle: &'static str,
    detail: &'static str,
}

pub(crate) struct DocContracts;

impl GovernanceCheck for DocContracts {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "doc-contracts"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (scanned, localonly_carriers, rustdoc_files, carryover_summary, findings) =
            scan_docs(&root)?;
        if scanned < 3 {
            bail!(
                "doc-contracts: 仅扫到 {scanned} 个文档文件，疑似 docs/rules 或 docs/spec 结构异常"
            );
        }
        Ok((
            format_doc_contracts_summary(
                scanned,
                localonly_carriers,
                rustdoc_files,
                &carryover_summary,
            ),
            findings,
        ))
    }
}

fn format_doc_contracts_summary(
    scanned: usize,
    localonly_carriers: usize,
    rustdoc_files: usize,
    carryover_summary: &str,
) -> String {
    format!(
        "{scanned} docs/source 文件扫描，command/outbox tenant-aware 片段无漂移；LocalOnly semantic carriers={localonly_carriers}、canonical 完整性与 production rustdoc files={rustdoc_files} 已检查；carry-over {carryover_summary}"
    )
}

fn scan_docs(root: &Path) -> Result<(usize, usize, usize, String, Vec<Finding>)> {
    let mut files = Vec::new();
    for (dir, extension) in CONTENT_ROOTS {
        let mut found = content_files(&root.join(dir), extension)?;
        if found.is_empty() {
            bail!("doc-contracts: {dir} 下无 .{extension} 文件，fail-closed");
        }
        files.append(&mut found);
    }
    for rel in SEMANTIC_DOC_FILES {
        let path = root.join(rel);
        if !path.is_file() {
            bail!("doc-contracts: semantic 文档 {rel} 缺失，fail-closed");
        }
        files.push(path);
    }
    let mut localonly_files = Vec::new();
    for rel in LOCALONLY_SEMANTIC_DOC_FILES {
        let path = root.join(rel);
        if !path.is_file() {
            bail!("doc-contracts: LocalOnly semantic 文档 {rel} 缺失，fail-closed");
        }
        localonly_files.push(path);
    }
    files.sort();
    files.dedup();

    let mut findings = Vec::new();
    for path in &files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("doc-contracts: 读 {} 失败: {e}", path.display()))?;
        let rel = path.strip_prefix(root).unwrap_or(path);
        findings.extend(scan_content(rel, &content));
        if rel == Path::new(OUTBOX_CANONICAL_FILE) {
            findings.extend(scan_outbox_canonical_semantics(&content));
        }
        if rel == Path::new(LOCALONLY_CANONICAL_FILE) {
            findings.extend(scan_localonly_canonical_semantics(&content));
        }
    }
    let mut extra_localonly_files = 0;
    for path in &localonly_files {
        if files.binary_search(path).is_ok() {
            continue;
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("doc-contracts: 读 {} 失败: {e}", path.display()))?;
        let rel = path.strip_prefix(root).unwrap_or(path);
        findings.extend(scan_localonly_business_effect_semantics(rel, &content));
        extra_localonly_files += 1;
    }
    let mut rustdoc_files = Vec::new();
    for dir in RUSTDOC_ROOTS {
        rustdoc_files.extend(content_files(&root.join(dir), "rs")?);
    }
    rustdoc_files.sort();
    rustdoc_files.dedup();
    for path in &rustdoc_files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("doc-contracts: 读 {} 失败: {e}", path.display()))?;
        let rel = path.strip_prefix(root).unwrap_or(path);
        findings.extend(scan_false_outbox_delivery_guarantees(rel, &content));
        findings.extend(scan_localonly_business_effect_semantics(rel, &content));
    }
    let (carryover_summary, carryover_findings) = scan_carryover(root)?;
    findings.extend(carryover_findings);
    Ok((
        files.len() + extra_localonly_files + rustdoc_files.len() + 1,
        localonly_files.len(),
        rustdoc_files.len(),
        carryover_summary,
        findings,
    ))
}

// INVARIANT: MIGRATION-CARRYOVER-COVERAGE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::carryover_rejects_missing_source_and_duplicate_key", anti_vacuity = "tests::carryover_accepts_complete_typed_ledger" }
//
// Historical planning prose and external tracker state cannot be made unrepresentable by Rust's
// type system. The strongest local carrier is therefore a fail-closed, typed content gate: the
// ledger's source universe is derived from the frozen source documents, while row semantics are
// checked with closed enums and evidence requirements. Tracker liveness remains an external audit
// boundary and is snapshotted in the ledger rather than queried from `cargo xtask verify`.
fn scan_carryover(root: &Path) -> Result<(String, Vec<Finding>)> {
    let path = root.join(CARRYOVER_DOC_FILE);
    if !path.is_file() {
        bail!("doc-contracts: carry-over ledger {CARRYOVER_DOC_FILE} 缺失，fail-closed");
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("doc-contracts: 读 {CARRYOVER_DOC_FILE} 失败: {e}"))?;
    let rows = parse_carryover_table(&content)?;
    let universe = SourceUniverse::from_workspace(root)?;
    let summary = universe.coverage_summary();
    let mut violations = validate_carryover_rows(&rows, &universe, root);
    if let Err(error) = validate_exact_source_counts(&universe) {
        violations.push(CarryoverViolation::document(
            "Source Set",
            error.to_string(),
            "restore the frozen source universe before updating its audited count",
        ));
    }
    let findings = violations
        .into_iter()
        .map(|violation| {
            finding(
                Rule::MigrationCarryover,
                violation.subject(),
                violation.finding_detail(),
            )
        })
        .collect();
    Ok((summary, findings))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SourceSet {
    Spec002,
    Rewrite,
    Gap006,
    Schedule607,
    CrateMapping,
    CodeFollowup,
}

impl SourceSet {
    const ALL: [Self; 6] = [
        Self::Spec002,
        Self::Rewrite,
        Self::Gap006,
        Self::Schedule607,
        Self::CrateMapping,
        Self::CodeFollowup,
    ];

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "spec-002" => Some(Self::Spec002),
            "rewrite" => Some(Self::Rewrite),
            "gap-006" => Some(Self::Gap006),
            "schedule-607" => Some(Self::Schedule607),
            "crate-mapping" => Some(Self::CrateMapping),
            "code-followup" => Some(Self::CodeFollowup),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Spec002 => "spec-002",
            Self::Rewrite => "rewrite",
            Self::Gap006 => "gap-006",
            Self::Schedule607 => "schedule-607",
            Self::CrateMapping => "crate-mapping",
            Self::CodeFollowup => "code-followup",
        }
    }

    fn coverage_id(self, source_id: &str) -> &str {
        match self {
            Self::Spec002 => source_id
                .rsplit_once('.')
                .filter(|(_, suffix)| {
                    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_lowercase())
                })
                .map_or(source_id, |v| v.0),
            Self::Rewrite | Self::Gap006 | Self::Schedule607 | Self::CrateMapping => {
                source_id.split_once('.').map_or(source_id, |v| v.0)
            }
            Self::CodeFollowup => source_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceBinding {
    source_set: SourceSet,
    source_id: &'static str,
    evidence_path: &'static str,
    proof: &'static str,
}

impl EvidenceBinding {
    const fn new(
        source_set: SourceSet,
        source_id: &'static str,
        evidence_path: &'static str,
        proof: &'static str,
    ) -> Self {
        Self {
            source_set,
            source_id,
            evidence_path,
            proof,
        }
    }
}

// Closed audit attestation: every done-evidence source atom owns one exact path/proof tuple. This
// prevents a registered gate or an unrelated real test from being substituted across source rows.
const EVIDENCE_BINDINGS: &[EvidenceBinding] = &[
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T001.1",
        "crates/consistency/src/outbox.rs",
        "test: disposition_as_label_distinct",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T001.2",
        "crates/consistency/src/error.rs",
        "test: engine_error_kind_message_distinct",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T001.3",
        "crates/consistency/src/idempotency.rs",
        "test: state_machine_claim_commit_then_duplicate",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T001.4",
        "crates/consistency/src/outbox.rs",
        "test: disposition_as_label_distinct",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T001.5",
        "xtask/src/verify.rs",
        "gate: workspace verify",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T002.1",
        "crates/consistency/src/saga.rs",
        "test: saga_definition_rejects_empty_invalid_and_duplicate_steps",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T002.2",
        "crates/consistency/src/saga.rs",
        "test: saga_definition_rejects_empty_invalid_and_duplicate_steps",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T002.3",
        "crates/consistency/src/reconcile.rs",
        "test: diff_classifies_desired_actual_presence_matrix",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T002.4",
        "crates/consistency/src/projection.rs",
        "test: projection_checkpoint_rejects_regression",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T002.5",
        "xtask/src/verify.rs",
        "gate: workspace verify",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T003.1",
        "adapters/postgres/src/integration_tests.rs",
        "tests: pool_connects_and_shuts_down,transaction_commit_persists_and_rollback_discards,migrator_applies_and_is_idempotent",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T003.2",
        "adapters/postgres/src/lib.rs",
        "test: pg_store_guard_shutdown_lazy_pool_ok",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T003.3",
        "xtask/src/migrations.rs",
        "gate: cargo xtask migrations",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T003.4.a",
        "adapters/postgres/tests/tx_capability_trybuild.rs",
        "test: tx_capability_ui",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T003.5",
        "xtask/src/layerdeps.rs",
        "gate: layer-deps and workspace verify",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T004.1",
        "crates/eventexec/src/relay.rs",
        "test: relay_tick_recovers_to_healthy_after_clean_round",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T004.2",
        "xtask/src/tenancy_closeout.rs",
        "gate: tenancy-closeout",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T004.3",
        "adapters/postgres/src/outbox.rs",
        "test: envelope_new_and_fields",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T004.4",
        "crates/eventexec/src/relay.rs",
        "test: t8_shutdown_drains_in_flight_entries",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T004.5",
        "crates/eventexec/src/relay.rs",
        "tests: t12_probe_names_parse_and_no_ready_suffix,t10a_worker_stopped_health_unhealthy",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T004.6",
        "xtask/src/contract/validate.rs",
        "gate: outbox-atomicity contract validation",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T005.1",
        "adapters/postgres/src/inbox.rs",
        "test: concurrent_try_claim_same_receipt_single_fresh_winner",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T005.2",
        "adapters/postgres/src/inbox.rs",
        "test: commit_makes_key_permanently_duplicate",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T005.3",
        "adapters/redis/src/lib.rs",
        "test: new_accepts_1ms_ttl",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T005.4",
        "crates/bootstrap/src/replaydeps.rs",
        "test: durable_isolated_missing_redis_fails_closed",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T005.5",
        "xtask/src/inbox_cutover_guard.rs",
        "gate: inbox-cutover-guard",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T006.1",
        "crates/bootstrap/src/eventtransport.rs",
        "test: isolated_missing_per_domain_fails_closed_no_fallback",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T006.2",
        "adapters/amqp/src/publisher.rs",
        "test: transport_metadata_goes_to_headers_and_sensitive_metadata_is_excluded",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T006.3",
        "xtask/src/event_transport_guard.rs",
        "gate: event-transport-guard",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T006.4.a",
        "adapters/amqp/tests/integration.rs",
        "test: integration_publish_subscribe_roundtrip",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T007.1",
        "crates/eventexec/src/consumer.rs",
        "test: tc1_handler_ack_commit_once_no_dlx",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T007.2",
        "adapters/postgres/src/dead_letter.rs",
        "test: write_dead_letter_roundtrips",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T007.3",
        "crates/eventexec/src/consumer.rs",
        "test: tc1_handler_ack_commit_once_no_dlx",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T007.4",
        "xtask/src/contract_binding_guard.rs",
        "gate: active subscriber contract",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T007.5",
        "crates/eventexec/src/consumer.rs",
        "test: tc5_dlx_tracing_fields_and_no_payload_leak",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T007.6",
        "xtask/src/verify.rs",
        "gate: workspace verify",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T008.1",
        "journeys/tests/identity_login_audit_durable_journey.rs",
        "test: login_audit_durable_topology",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T008.2",
        "crates/identity/src/application/mod.rs",
        "test: login_success_persists_once_and_response_correct",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T008.3",
        "crates/audit/src/application.rs",
        "test: session_created_appends_verifiable_chain_entry",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T008.4",
        "journeys/tests/identity_login_audit_durable_journey.rs",
        "test: login_audit_durable_topology",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T008.5",
        "xtask/src/verify.rs",
        "gate: consistency fault matrix",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.1",
        "crates/eventexec/src/saga/tests.rs",
        "test: run_three_steps_all_succeed_journal_order",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.2",
        "adapters/postgres/src/checkpoint.rs",
        "test: checkpoint_cas_rejects_stale_version",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.3",
        "adapters/postgres/src/saga.rs",
        "test: saga_instance_lease_and_journal_roundtrip",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.4",
        "crates/eventexec/src/saga/tests.rs",
        "test: resume_from_step2_checkpoint_skips_step1",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.5",
        "crates/bootstrap/src/sagaprojectiondeps.rs",
        "test: durable_shared_with_postgres_and_redis_urls_resolves_durable",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.6",
        "crates/eventexec/src/saga/tests.rs",
        "test: compensation_failure_logs_fields",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.7",
        "crates/eventexec/src/saga_worker.rs",
        "test: worker_shutdown_marks_health_unhealthy",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T009.8",
        "xtask/src/contract/validate.rs",
        "gate: saga contract",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T010.1",
        "crates/eventexec/src/projection.rs",
        "test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T010.2",
        "adapters/postgres/src/projection_events.rs",
        "test: projection_events_migration_append_only_and_no_rls",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T010.3",
        "crates/eventexec/src/projection.rs",
        "test: resume_skips_consumed_prefix",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T010.4",
        "lints/rss_projection_append_only/src/lib.rs",
        "gate: projection append-only",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T010.5",
        "adapters/postgres/src/projection_events.rs",
        "test: projection_events_migration_append_only_and_no_rls",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T010.6",
        "crates/eventexec/src/projection.rs",
        "test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T011.1",
        "crates/eventexec/src/reconcile.rs",
        "test: reconcile_worker_records_transient_attempt_result",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T011.2",
        "adapters/postgres/src/reconcile.rs",
        "test: migration_locks_reconcile_rls_and_cas_predicates",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T011.3",
        "crates/eventexec/src/reconcile.rs",
        "test: attempt_scope_records_action_and_command_through_single_store_call",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T011.4",
        "xtask/src/reconcile_outbox_command_guard.rs",
        "gate: reconcile outbox command",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T012.1",
        "crates/eventexec/src/command.rs",
        "test: register_rejects_schema_hash_mismatch_before_claim",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T012.2",
        "xtask/src/contract/validate.rs",
        "gate: contract validate",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T012.3",
        "crates/eventexec/src/command.rs",
        "test: register_decodes_typed_and_acks",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T012.4",
        "xtask/src/codegen.rs",
        "test: command_glue_with_wrappers_emitted",
    ),
    EvidenceBinding::new(
        SourceSet::Spec002,
        "T012.5",
        "xtask/src/command_symmetry.rs",
        "gate: command-symmetry",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P0.a",
        "xtask/src/contract/validate.rs",
        "gate: contract validate and topology",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P1.a",
        "xtask/src/verify.rs",
        "gate: workspace verify",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P2.a",
        "xtask/src/runtime_deps_guard.rs",
        "gate: runtime dependencies",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P3.a",
        "crates/eventexec/src/relay.rs",
        "test: relay_tick_recovers_to_healthy_after_clean_round",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P3.b",
        "xtask/src/migrations.rs",
        "gate: cargo xtask migrations",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P3.c",
        "adapters/vault/src/transit.rs",
        "test: encrypt_sends_context_not_associated_data_and_encodes_key_path",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P4",
        "journeys/tests/identity_login_audit_durable_journey.rs",
        "test: login_audit_durable_topology",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P5.a",
        "crates/settings/src/application.rs",
        "test: publish_config_creates_v1_and_emits",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P6.a",
        "crates/eventexec/src/saga/tests.rs",
        "test: run_three_steps_all_succeed_journal_order",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P7.a",
        "crates/eventexec/src/reconcile.rs",
        "test: attempt_scope_records_action_and_command_through_single_store_call",
    ),
    EvidenceBinding::new(
        SourceSet::Rewrite,
        "P8.a",
        "xtask/src/event_transport_guard.rs",
        "gate: event transport and ops runbook",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P0-9",
        "xtask/src/tenancy_closeout.rs",
        "gate: tenancy-closeout and reconcile-command guard",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P1-9",
        "adapters/vault/src/transit.rs",
        "test: encrypt_sends_context_not_associated_data_and_encodes_key_path",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P2-1.a",
        "crates/eventexec/src/saga/tests.rs",
        "test: policy_retries_forward_action_until_success_within_budget",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P2-2.a",
        "adapters/postgres/src/projection_control.rs",
        "test: shadow_checkpoint_must_catch_up_to_source_high_water",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P2-5.a",
        "adapters/postgres/src/inbox.rs",
        "test: extend_held_then_lost_on_takeover",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P2-6.a",
        "crates/eventexec/src/relay_metrics.rs",
        "test: metrics_facade_emits_publish_and_dlx_on_reject",
    ),
    EvidenceBinding::new(
        SourceSet::Gap006,
        "P2-7.a",
        "xtask/src/contract/validate.rs",
        "gate: contract topology and command symmetry",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1013",
        "crates/settings/src/application.rs",
        "test: publish_config_creates_v1_and_emits",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1092",
        "xtask/src/repo_scope_guard.rs",
        "gate: repository conformance and tenancy closeout",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1100",
        "journeys/tests/identity_login_audit_durable_journey.rs",
        "test: login_audit_durable_topology",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1114",
        "crates/consistency/src/outbox.rs",
        "test: disposition_as_label_distinct",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1115",
        "crates/consistency/src/saga.rs",
        "test: saga_definition_rejects_empty_invalid_and_duplicate_steps",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1116",
        "adapters/postgres/src/lib.rs",
        "test: pg_store_guard_shutdown_lazy_pool_ok",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1117",
        "crates/eventexec/src/relay.rs",
        "test: relay_tick_recovers_to_healthy_after_clean_round",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1118",
        "adapters/postgres/src/inbox.rs",
        "test: concurrent_try_claim_same_receipt_single_fresh_winner",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1119",
        "adapters/amqp/tests/integration.rs",
        "test: integration_publish_subscribe_roundtrip",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1120",
        "crates/eventexec/src/consumer.rs",
        "test: tc1_handler_ack_commit_once_no_dlx",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1121",
        "crates/eventexec/src/saga/tests.rs",
        "test: run_three_steps_all_succeed_journal_order",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1122",
        "crates/eventexec/src/projection.rs",
        "test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1123",
        "crates/eventexec/src/reconcile.rs",
        "test: attempt_scope_records_action_and_command_through_single_store_call",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1124",
        "crates/eventexec/src/command.rs",
        "test: register_decodes_typed_and_acks",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1136",
        "crates/testkit/tests/harness.rs",
        "test: ok_response_deserializes_into_typed_schema",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1137.a",
        "adapters/postgres/src/integration_tests.rs",
        "test: pool_connects_and_shuts_down",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1137.b",
        "adapters/redis/tests/integration_claimer.rs",
        "test: integration_first_check_is_fresh_then_duplicate",
    ),
    EvidenceBinding::new(
        SourceSet::Schedule607,
        "#1137.c",
        "adapters/amqp/tests/integration.rs",
        "test: integration_publish_subscribe_roundtrip",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "契约 codegen",
        "xtask/src/contract/validate.rs",
        "gate: contract validate and command symmetry",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "错误",
        "crates/consistency/src/error.rs",
        "test: engine_error_kind_message_distinct",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "Postgres",
        "adapters/postgres/src/lib.rs",
        "test: pg_store_guard_shutdown_lazy_pool_ok",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "Redis",
        "adapters/redis/src/lib.rs",
        "test: new_accepts_1ms_ttl",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "AMQP / MQTT.amqp",
        "adapters/amqp/tests/integration.rs",
        "test: integration_publish_subscribe_roundtrip",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "加密 / 证书 / TLS.field-protection",
        "adapters/vault/src/transit.rs",
        "test: encrypt_sends_context_not_associated_data_and_encodes_key_path",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "可观测性.consistency",
        "crates/eventexec/src/relay_metrics.rs",
        "test: metrics_facade_emits_publish_and_dlx_on_reject",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "配置",
        "crates/settings/src/application.rs",
        "test: publish_config_creates_v1_and_emits",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "newtype/sealed",
        "xtask/src/pg_tenant_tx_guard.rs",
        "gate: persistence hard closeout matrix",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "测试.rstest",
        "crates/identity/src/domain/abac.rs",
        "test: operator_cases",
    ),
    EvidenceBinding::new(
        SourceSet::CrateMapping,
        "测试.mockall",
        "crates/settings/src/ports.rs",
        "test: config_repo_impls_load_into_dyn_wrapper",
    ),
    EvidenceBinding::new(
        SourceSet::CodeFollowup,
        "acecf759:projection.rs:18",
        "crates/eventexec/src/projection.rs",
        "test: shadow_replay_journey_keeps_active_pointer_until_swap_and_rollback",
    ),
    EvidenceBinding::new(
        SourceSet::CodeFollowup,
        "current:cotx.rs:#1579",
        "xtask/src/tenancy_closeout.rs",
        "gate: tenancy-closeout",
    ),
    EvidenceBinding::new(
        SourceSet::CodeFollowup,
        "current:0012_enable_tenant_rls.sql:dual-pool",
        "assemblies/runtime/src/infra/pg.rs",
        "test: pg_migrator_config_uses_dedicated_credentials",
    ),
];

const EXPECTED_SOURCE_COUNTS: &[(SourceSet, usize)] = &[
    (SourceSet::Spec002, 65),
    (SourceSet::Rewrite, 9),
    (SourceSet::Gap006, 30),
    (SourceSet::Schedule607, 59),
    (SourceSet::CrateMapping, 16),
    (SourceSet::CodeFollowup, 13),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    DoneEvidence,
    AbsorbedBy,
    NeedsIssue,
    OutOfScope,
}

impl Resolution {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "done-evidence" => Some(Self::DoneEvidence),
            "absorbed-by" => Some(Self::AbsorbedBy),
            "needs-issue" => Some(Self::NeedsIssue),
            "out-of-scope" => Some(Self::OutOfScope),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CarryoverRow {
    line_number: usize,
    source_set: SourceSet,
    source_id: String,
    capability: String,
    resolution: Resolution,
    canonical_work_item: String,
    duplicate: bool,
    new_pbi: String,
    commit: String,
    evidence_path: String,
    proof: String,
    scope_note: String,
}

#[derive(Debug, Clone, Default)]
struct SourceUniverse(BTreeMap<SourceSet, BTreeSet<String>>);

impl SourceUniverse {
    #[cfg(test)]
    fn from_pairs<'a>(pairs: impl IntoIterator<Item = (SourceSet, &'a str)>) -> Self {
        let mut out = Self::default();
        for (set, id) in pairs {
            out.insert(set, id);
        }
        out
    }

    fn insert(&mut self, set: SourceSet, id: impl Into<String>) {
        self.0.entry(set).or_default().insert(id.into());
    }

    fn ids(&self, set: SourceSet) -> BTreeSet<String> {
        self.0.get(&set).cloned().unwrap_or_default()
    }

    #[cfg(test)]
    fn remove(&mut self, set: SourceSet, id: &str) {
        if let Some(ids) = self.0.get_mut(&set) {
            ids.remove(id);
        }
    }

    fn coverage_summary(&self) -> String {
        EXPECTED_SOURCE_COUNTS
            .iter()
            .map(|(set, expected)| {
                let actual = self.0.get(set).map_or(0, BTreeSet::len);
                format!("{}={actual}/{expected}", set.as_str())
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn from_workspace(root: &Path) -> Result<Self> {
        let mut out = Self::default();
        let tasks = read_required(root, EVENTEXEC_TASKS_FILE)?;
        for id in extract_task_ids(&tasks) {
            out.insert(SourceSet::Spec002, id);
        }
        let rewrite = read_required(root, REWRITE_SEQUENCE_FILE)?;
        for id in extract_rewrite_ids(&rewrite) {
            out.insert(SourceSet::Rewrite, id);
        }
        let gaps = read_required(root, GAP_006_FILE)?;
        for id in extract_gap_ids(&gaps) {
            out.insert(SourceSet::Gap006, id);
        }
        let schedule = read_required(root, SCHEDULE_607_FILE)?;
        for id in extract_issue_references(&schedule) {
            out.insert(SourceSet::Schedule607, id);
        }
        let mapping = read_required(root, CRATE_MAPPING_FILE)?;
        for id in extract_crate_mapping_ids(&mapping) {
            out.insert(SourceSet::CrateMapping, id);
        }
        validate_code_followup_anchors(root)?;
        for followup in CODE_FOLLOWUPS {
            out.insert(SourceSet::CodeFollowup, followup.id);
        }
        Ok(out)
    }
}

fn validate_exact_source_counts(universe: &SourceUniverse) -> Result<()> {
    for &(set, expected) in EXPECTED_SOURCE_COUNTS {
        let actual = universe.0.get(&set).map_or(0, BTreeSet::len);
        if actual != expected {
            bail!(
                "doc-contracts: {} source universe has {actual} item(s), expected exactly {expected}",
                set.as_str()
            );
        }
    }
    Ok(())
}

fn validate_code_followup_anchors(root: &Path) -> Result<()> {
    for followup in CODE_FOLLOWUPS {
        let Some(anchor) = followup.anchor else {
            continue;
        };
        let content = read_required(root, anchor.path)?;
        if !content.contains(anchor.needle) {
            bail!(
                "doc-contracts: code follow-up {} anchor missing from {}: {:?}",
                followup.id,
                anchor.path,
                anchor.needle
            );
        }
    }
    Ok(())
}

fn read_required(root: &Path, rel: &str) -> Result<String> {
    let path = root.join(rel);
    if !path.is_file() {
        bail!("doc-contracts: carry-over source {rel} 缺失，fail-closed");
    }
    std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("doc-contracts: 读 carry-over source {rel} 失败: {e}"))
}

fn extract_task_ids(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            if !line.starts_with("- [") {
                return None;
            }
            line.split_whitespace()
                .find(|token| is_task_item(token))
                .map(str::to_string)
        })
        .collect()
}

fn is_task_item(raw: &str) -> bool {
    let Some((task, item)) = raw.split_once('.') else {
        return false;
    };
    task.len() == 4
        && task.starts_with('T')
        && task[1..].chars().all(|ch| ch.is_ascii_digit())
        && !item.is_empty()
        && item.chars().all(|ch| ch.is_ascii_digit())
}

fn extract_rewrite_ids(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("### P")?;
            let digit = rest.chars().next()?;
            (digit.is_ascii_digit() && rest[1..].starts_with(" ·")).then(|| format!("P{digit}"))
        })
        .collect()
}

fn extract_gap_ids(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|line| {
            let first = line.trim().trim_matches('|').split('|').next()?.trim();
            is_gap_id(first).then(|| first.to_string())
        })
        .collect()
}

fn is_gap_id(raw: &str) -> bool {
    let Some((priority, number)) = raw.split_once('-') else {
        return false;
    };
    matches!(priority, "P0" | "P1" | "P2")
        && !number.is_empty()
        && number.chars().all(|ch| ch.is_ascii_digit())
}

fn extract_issue_references(content: &str) -> BTreeSet<String> {
    let normalized = content.replace('–', "-");
    let chars: Vec<char> = normalized.chars().collect();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '#' || i + 1 >= chars.len() || !chars[i + 1].is_ascii_digit() {
            i += 1;
            continue;
        }
        i += 1;
        let Some((mut current, next)) = parse_number(&chars, i) else {
            continue;
        };
        i = next;
        insert_issue(&mut out, current);
        loop {
            let connector_start = i;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            if i >= chars.len() || !matches!(chars[i], '/' | '-') {
                i = connector_start;
                break;
            }
            let connector = chars[i];
            i += 1;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            if i < chars.len() && chars[i] == '#' {
                i += 1;
            }
            let Some((value, next)) = parse_number(&chars, i) else {
                i = connector_start;
                break;
            };
            i = next;
            if connector == '-' && value >= current && value - current <= 100 {
                for issue in current..=value {
                    insert_issue(&mut out, issue);
                }
            } else {
                insert_issue(&mut out, value);
            }
            current = value;
        }
    }
    out
}

fn parse_number(chars: &[char], mut i: usize) -> Option<(u32, usize)> {
    let start = i;
    while i < chars.len() && chars[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    let value = chars[start..i]
        .iter()
        .collect::<String>()
        .parse::<u32>()
        .ok()?;
    Some((value, i))
}

fn insert_issue(out: &mut BTreeSet<String>, issue: u32) {
    if issue >= 900 {
        out.insert(format!("#{issue}"));
    }
}

fn extract_crate_mapping_ids(content: &str) -> BTreeSet<String> {
    let Some(section) = content.split("## 一、按关注点的 crate 映射").nth(1) else {
        return BTreeSet::new();
    };
    section
        .split("\n## ")
        .next()
        .unwrap_or(section)
        .lines()
        .filter_map(|line| {
            let cells: Vec<_> = line.trim().trim_matches('|').split('|').collect();
            if cells.len() != 4 {
                return None;
            }
            let id = cells[0].trim().trim_matches('*').trim_matches('`');
            (!id.is_empty() && id != "关注点" && !id.chars().all(|ch| matches!(ch, '-' | ':')))
                .then(|| id.to_string())
        })
        .collect()
}

fn parse_carryover_table(content: &str) -> Result<Vec<CarryoverRow>> {
    let context = CARRYOVER_DOC_FILE;
    let lines = content.lines().collect::<Vec<_>>();
    let marker_count = content.matches(CARRYOVER_MARKER).count();
    if marker_count != 1 {
        bail!(
            "{context}: carry-over ledger must contain exactly one schema marker, found {marker_count}"
        );
    }
    let header_count = content.matches(CARRYOVER_HEADER).count();
    if header_count != 1 {
        bail!(
            "{context}: carry-over ledger must contain exactly one table header, found {header_count}"
        );
    }
    let marker_index = lines
        .iter()
        .position(|line| line.contains(CARRYOVER_MARKER))
        .ok_or_else(|| anyhow::anyhow!("{context}: carry-over ledger missing schema marker"))?;
    if lines[marker_index].trim() != CARRYOVER_MARKER {
        bail!(
            "{context}:{}: schema marker must occupy its own line",
            marker_index + 1
        );
    }
    let header_index = lines
        .iter()
        .position(|line| line.contains(CARRYOVER_HEADER))
        .ok_or_else(|| {
            anyhow::anyhow!("{context}: carry-over ledger missing exact table header")
        })?;
    if header_index <= marker_index {
        bail!(
            "{context}:{}: table header must follow schema marker",
            header_index + 1
        );
    }
    if lines[header_index].trim() != CARRYOVER_HEADER {
        bail!(
            "{context}:{}: table header must occupy its own line",
            header_index + 1
        );
    }
    if lines[marker_index + 1..header_index]
        .iter()
        .any(|line| !line.trim().is_empty())
    {
        bail!(
            "{context}:{}: non-whitespace content between schema marker and table header",
            marker_index + 2
        );
    }
    let separator_index = (header_index + 1..lines.len())
        .find(|index| !lines[*index].trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{context}: carry-over ledger missing table separator"))?;
    if lines[separator_index].trim() != CARRYOVER_SEPARATOR {
        bail!(
            "{context}:{}: carry-over ledger has invalid table separator",
            separator_index + 1
        );
    }
    let mut rows = Vec::new();
    for (index, line) in lines.iter().enumerate().skip(separator_index + 1) {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('|') || !line.ends_with('|') {
            bail!("{context}:{line_number}: carry-over ledger has trailing non-table content");
        }
        let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() != 11 {
            bail!(
                "{context}:{line_number}: carry-over ledger row has {} columns, expected 11",
                cells.len()
            );
        }
        let source_set = SourceSet::parse(cells[0]).ok_or_else(|| {
            anyhow::anyhow!(
                "{context}:{line_number}: source {} has unknown source set {:?}",
                cells[1],
                cells[0]
            )
        })?;
        let resolution = Resolution::parse(cells[3]).ok_or_else(|| {
            anyhow::anyhow!(
                "{context}:{line_number}: {}:{} has unknown resolution {:?}",
                source_set.as_str(),
                cells[1],
                cells[3]
            )
        })?;
        let duplicate = match cells[5] {
            "yes" => true,
            "no" => false,
            other => bail!(
                "{context}:{line_number}: {}:{} has invalid duplicate flag {other:?}",
                source_set.as_str(),
                cells[1]
            ),
        };
        rows.push(CarryoverRow {
            line_number,
            source_set,
            source_id: cells[1].to_string(),
            capability: cells[2].to_string(),
            resolution,
            canonical_work_item: cells[4].to_string(),
            duplicate,
            new_pbi: cells[6].to_string(),
            commit: cells[7].to_string(),
            evidence_path: cells[8].to_string(),
            proof: cells[9].to_string(),
            scope_note: cells[10].to_string(),
        });
    }
    if rows.is_empty() {
        bail!("{context}: carry-over ledger has no data rows");
    }
    Ok(rows)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CarryoverViolation {
    line: usize,
    field: &'static str,
    detail: String,
    help: String,
}

impl CarryoverViolation {
    fn row(
        row: &CarryoverRow,
        field: &'static str,
        detail: impl Into<String>,
        help: impl Into<String>,
    ) -> Self {
        Self {
            line: row.line_number,
            field,
            detail: detail.into(),
            help: help.into(),
        }
    }

    fn document(field: &'static str, detail: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            line: 1,
            field,
            detail: detail.into(),
            help: help.into(),
        }
    }

    fn subject(&self) -> String {
        format!("{CARRYOVER_DOC_FILE}:{}", self.line)
    }

    fn finding_detail(&self) -> String {
        format!("field={}: {}; help={}", self.field, self.detail, self.help)
    }

    #[cfg(test)]
    fn contains(&self, pattern: &str) -> bool {
        self.subject().contains(pattern) || self.finding_detail().contains(pattern)
    }
}

fn validate_carryover_rows(
    rows: &[CarryoverRow],
    universe: &SourceUniverse,
    root: &Path,
) -> Vec<CarryoverViolation> {
    let mut violations = Vec::new();
    let mut keys = BTreeSet::new();
    let mut actual: BTreeMap<SourceSet, BTreeSet<String>> = BTreeMap::new();
    let mut actual_atoms: BTreeMap<(SourceSet, String), BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let key = (row.source_set, row.source_id.as_str());
        if !keys.insert(key) {
            violations.push(CarryoverViolation::row(
                row,
                "Source ID",
                format!(
                    "duplicate source key {}:{}",
                    row.source_set.as_str(),
                    row.source_id
                ),
                "keep exactly one ledger row for each source atom",
            ));
        }
        let coverage_id = row.source_set.coverage_id(&row.source_id).to_string();
        actual
            .entry(row.source_set)
            .or_default()
            .insert(coverage_id.clone());
        actual_atoms
            .entry((row.source_set, coverage_id))
            .or_default()
            .insert(row.source_id.clone());
        validate_row(row, root, &mut violations);
    }
    for set in SourceSet::ALL {
        let expected = universe.ids(set);
        let found = actual.remove(&set).unwrap_or_default();
        for missing in expected.difference(&found) {
            violations.push(CarryoverViolation::document(
                "Source ID",
                format!("missing source {}:{missing}", set.as_str()),
                "add the missing source row or restore the frozen source input",
            ));
        }
        for extra in found.difference(&expected) {
            violations.push(CarryoverViolation::document(
                "Source ID",
                format!("unexpected source {}:{extra}", set.as_str()),
                "remove the unregistered row or add it to the audited source universe",
            ));
        }
        for base_id in expected {
            let found_atoms = actual_atoms
                .remove(&(set, base_id.clone()))
                .unwrap_or_default();
            let expected_atoms: BTreeSet<String> = SPLIT_SOURCES
                .iter()
                .find(|split| split.source_set == set && split.base_id == base_id)
                .map_or_else(
                    || [base_id.clone()].into_iter().collect(),
                    |split| split.atoms.iter().map(|atom| (*atom).to_string()).collect(),
                );
            for missing in expected_atoms.difference(&found_atoms) {
                violations.push(CarryoverViolation::document(
                    "Source ID",
                    format!(
                        "missing split atom {}:{missing} for source {base_id}",
                        set.as_str()
                    ),
                    "restore every atom from the closed split-source registry",
                ));
            }
            for extra in found_atoms.difference(&expected_atoms) {
                violations.push(CarryoverViolation::document(
                    "Source ID",
                    format!(
                        "unexpected split atom {}:{extra} for source {base_id}",
                        set.as_str()
                    ),
                    "use only atoms from the closed split-source registry",
                ));
            }
        }
    }
    violations
}

fn validate_row(row: &CarryoverRow, root: &Path, violations: &mut Vec<CarryoverViolation>) {
    let key = format!("{}:{}", row.source_set.as_str(), row.source_id);
    if !is_present(&row.capability) {
        violations.push(CarryoverViolation::row(
            row,
            "Capability",
            format!("{key}: capability is required"),
            "describe the bounded capability carried by this source atom",
        ));
    }
    if !is_present(&row.scope_note) {
        violations.push(CarryoverViolation::row(
            row,
            "Scope Note",
            format!("{key}: scope note is required"),
            "record the audited disposition or residual scope",
        ));
    }
    match row.resolution {
        Resolution::DoneEvidence => validate_done_evidence_row(row, root, &key, violations),
        Resolution::AbsorbedBy => validate_absorbed_row(row, &key, violations),
        Resolution::NeedsIssue => validate_needs_issue_row(row, &key, violations),
        Resolution::OutOfScope => validate_out_of_scope_row(row, &key, violations),
    }
}

fn validate_done_evidence_row(
    row: &CarryoverRow,
    root: &Path,
    key: &str,
    violations: &mut Vec<CarryoverViolation>,
) {
    if !audited_work_item_list(&row.canonical_work_item, &[AUDITED_EVIDENCE_WORK_ITEMS]) {
        violations.push(CarryoverViolation::row(
            row,
            "Canonical Work Item",
            format!(
                "{key}: done-evidence canonical work item must be in the audited evidence snapshot"
            ),
            "use an exact PBI/Feature provenance ID from the 2026-07-10 audit snapshot",
        ));
    }
    if row.duplicate {
        violations.push(CarryoverViolation::row(
            row,
            "Duplicate",
            format!("{key}: done-evidence must not be marked duplicate"),
            "set Duplicate to no",
        ));
    }
    if row.new_pbi != "-" {
        violations.push(CarryoverViolation::row(
            row,
            "New PBI",
            format!("{key}: done-evidence cannot create a new PBI"),
            "set New PBI to -",
        ));
    }
    let valid_commit =
        is_commit(&row.commit) && DEVELOP_EVIDENCE_COMMITS.contains(&row.commit.as_str());
    if !valid_commit {
        violations.push(CarryoverViolation::row(
            row,
            "Commit",
            format!("{key}: commit must be a full audited develop snapshot identifier"),
            "use the develop commit recorded by the immutable audit snapshot",
        ));
    } else if !valid_done_evidence(root, row) {
        violations.push(CarryoverViolation::row(
            row,
            "Proof",
            format!(
                "{key}: safe repository evidence and registered proof must exist in the declared commit"
            ),
            "use the exact path/proof attestation registered for this source atom",
        ));
    }
}

fn validate_absorbed_row(row: &CarryoverRow, key: &str, violations: &mut Vec<CarryoverViolation>) {
    if !row.duplicate {
        violations.push(CarryoverViolation::row(
            row,
            "Duplicate",
            format!("{key}: absorbed-by must be marked duplicate"),
            "set Duplicate to yes",
        ));
    }
    if !audited_work_item_list(
        &row.canonical_work_item,
        &[AUDITED_EVIDENCE_WORK_ITEMS, AUDITED_ABSORPTION_WORK_ITEMS],
    ) {
        violations.push(CarryoverViolation::row(
            row,
            "Canonical Work Item",
            format!("{key}: absorbed-by requires an audited work item provenance reference"),
            "use an exact PBI/Feature ID from the evidence or absorption audit snapshot",
        ));
    }
    require_empty_evidence_fields(
        row,
        key,
        "absorbed-by",
        &[
            ("New PBI", row.new_pbi.as_str()),
            ("Commit", row.commit.as_str()),
            ("Evidence Path", row.evidence_path.as_str()),
            ("Proof", row.proof.as_str()),
        ],
        violations,
    );
}

fn validate_needs_issue_row(
    row: &CarryoverRow,
    key: &str,
    violations: &mut Vec<CarryoverViolation>,
) {
    if row.duplicate {
        violations.push(CarryoverViolation::row(
            row,
            "Duplicate",
            format!("{key}: needs-issue must not be marked duplicate"),
            "set Duplicate to no",
        ));
    }
    if !audited_pbi_list(&row.canonical_work_item, AUDIT_CREATED_CARRYOVER_WORK_ITEMS) {
        violations.push(CarryoverViolation::row(
            row,
            "Canonical Work Item",
            format!("{key}: needs-issue requires an audit-created PBI leaf"),
            "use a Product Backlog Item, never an Epic or Feature container",
        ));
    }
    if !audited_pbi_list(&row.new_pbi, AUDIT_CREATED_CARRYOVER_WORK_ITEMS) {
        violations.push(CarryoverViolation::row(
            row,
            "New PBI",
            format!("{key}: New PBI must be an audit-created PBI leaf"),
            "use a Product Backlog Item from the immutable audit snapshot",
        ));
    }
    if row.canonical_work_item != row.new_pbi {
        violations.push(CarryoverViolation::row(
            row,
            "New PBI",
            format!("{key}: Canonical Work Item and New PBI must match"),
            "copy the newly created PBI leaf ID into both columns",
        ));
    }
    require_empty_evidence_fields(
        row,
        key,
        "needs-issue",
        &[
            ("Commit", row.commit.as_str()),
            ("Evidence Path", row.evidence_path.as_str()),
            ("Proof", row.proof.as_str()),
        ],
        violations,
    );
}

fn validate_out_of_scope_row(
    row: &CarryoverRow,
    key: &str,
    violations: &mut Vec<CarryoverViolation>,
) {
    if row.duplicate {
        violations.push(CarryoverViolation::row(
            row,
            "Duplicate",
            format!("{key}: out-of-scope must not be marked duplicate"),
            "set Duplicate to no",
        ));
    }
    require_empty_evidence_fields(
        row,
        key,
        "out-of-scope",
        &[
            ("Canonical Work Item", row.canonical_work_item.as_str()),
            ("New PBI", row.new_pbi.as_str()),
            ("Commit", row.commit.as_str()),
            ("Evidence Path", row.evidence_path.as_str()),
            ("Proof", row.proof.as_str()),
        ],
        violations,
    );
}

fn require_empty_evidence_fields(
    row: &CarryoverRow,
    key: &str,
    resolution: &str,
    fields: &[(&'static str, &str)],
    violations: &mut Vec<CarryoverViolation>,
) {
    for &(field, value) in fields {
        if value != "-" {
            violations.push(CarryoverViolation::row(
                row,
                field,
                format!("{key}: {resolution} does not carry repository evidence"),
                format!("set {field} to -"),
            ));
        }
    }
}

fn is_present(raw: &str) -> bool {
    !raw.trim().is_empty() && raw.trim() != "-"
}

fn audited_work_item_list(raw: &str, registries: &[&[WorkItemSnapshot]]) -> bool {
    audited_item_list(raw, |item| {
        registries
            .iter()
            .flat_map(|registry| registry.iter())
            .any(|snapshot| snapshot.id == item)
    })
}

fn audited_pbi_list(raw: &str, registry: &[WorkItemSnapshot]) -> bool {
    audited_item_list(raw, |item| {
        registry.iter().any(|snapshot| {
            snapshot.id == item && snapshot.kind == WorkItemKind::ProductBacklogItem
        })
    })
}

fn audited_item_list(raw: &str, allowed: impl Fn(&str) -> bool) -> bool {
    if raw == "-" || raw.trim().is_empty() {
        return false;
    }
    let mut unique = BTreeSet::new();
    raw.split(',')
        .map(str::trim)
        .all(|item| !item.is_empty() && unique.insert(item) && allowed(item))
}

fn valid_done_evidence(root: &Path, row: &CarryoverRow) -> bool {
    let Some(binding) = EVIDENCE_BINDINGS.iter().find(|binding| {
        binding.source_set == row.source_set
            && binding.source_id == row.source_id
            && binding.evidence_path == row.evidence_path
            && binding.proof == row.proof
    }) else {
        return false;
    };
    if let Some(test_selectors) = parse_test_proof(binding.proof) {
        return valid_test_evidence(root, &row.commit, binding.evidence_path, &test_selectors);
    }
    let Some(gate) = GATE_PROOFS.iter().find(|gate| gate.proof == binding.proof) else {
        return false;
    };
    valid_gate_carriers(root, &row.commit, binding.evidence_path, gate.carriers)
}

fn valid_test_evidence(root: &Path, commit: &str, evidence_path: &str, selectors: &[&str]) -> bool {
    let Some(content) = read_commit_blob(root, commit, Path::new(evidence_path)) else {
        return false;
    };
    !selectors.is_empty()
        && selectors
            .iter()
            .all(|selector| has_concrete_test(&content, selector))
}

fn parse_test_proof(proof: &str) -> Option<Vec<&str>> {
    let (selectors, composite) = proof
        .strip_prefix("test: ")
        .map(|selector| (selector, false))
        .or_else(|| {
            proof
                .strip_prefix("tests: ")
                .map(|selectors| (selectors, true))
        })?;
    let selectors = selectors.split(',').map(str::trim).collect::<Vec<_>>();
    let unique = selectors.iter().copied().collect::<BTreeSet<_>>();
    (!selectors.is_empty()
        && (!composite || selectors.len() >= 2)
        && unique.len() == selectors.len()
        && selectors
            .iter()
            .all(|selector| valid_test_selector(selector)))
    .then_some(selectors)
}

fn valid_gate_carriers(
    root: &Path,
    commit: &str,
    evidence_path: &str,
    carriers: &[SourceAnchor],
) -> bool {
    if carriers
        .first()
        .is_none_or(|carrier| carrier.path != evidence_path)
    {
        return false;
    }
    carriers.iter().all(|carrier| {
        read_commit_blob(root, commit, Path::new(carrier.path))
            .is_some_and(|content| content.contains(carrier.needle))
    })
}

fn has_concrete_test(content: &str, selector: &str) -> bool {
    if !valid_test_selector(selector) {
        return false;
    }
    let Ok(file) = syn::parse_file(content) else {
        return false;
    };
    has_concrete_test_item(&file.items, selector, false)
}

fn valid_test_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        && !selector.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

fn has_concrete_test_item(items: &[syn::Item], selector: &str, ignored_parent: bool) -> bool {
    items.iter().any(|item| match item {
        syn::Item::Fn(function) => {
            !ignored_parent
                && function.sig.ident == selector
                && has_test_attribute(&function.attrs)
                && !has_disabled_test_attribute(&function.attrs)
        }
        syn::Item::Mod(module) => module.content.as_ref().is_some_and(|(_, nested)| {
            has_concrete_test_item(
                nested,
                selector,
                ignored_parent || has_disabled_test_attribute(&module.attrs),
            )
        }),
        _ => false,
    })
}

fn has_test_attribute(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let path = attribute.path();
        path.is_ident("test")
            || path.is_ident("rstest")
            || path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .eq(["tokio", "test"].into_iter().map(str::to_string))
            || path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .eq(["rstest", "rstest"].into_iter().map(str::to_string))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfgValue {
    AlwaysTrue,
    AlwaysFalse,
    Unknown,
}

fn has_disabled_test_attribute(attributes: &[syn::Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| meta_disables_test(&attribute.meta))
}

fn meta_disables_test(meta: &syn::Meta) -> bool {
    if meta.path().is_ident("ignore") {
        return true;
    }
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let Some(items) = parse_meta_items(list) else {
        return list.path.is_ident("cfg") || list.path.is_ident("cfg_attr");
    };
    if list.path.is_ident("cfg") {
        return single_cfg_value(&items) == CfgValue::AlwaysFalse;
    }
    if !list.path.is_ident("cfg_attr") {
        return false;
    }
    let mut items = items.iter();
    let Some(condition) = items.next() else {
        return true;
    };
    cfg_value(condition) == CfgValue::AlwaysTrue && items.any(meta_disables_test)
}

fn single_cfg_value(items: &syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>) -> CfgValue {
    if items.len() != 1 {
        return CfgValue::Unknown;
    }
    items.first().map_or(CfgValue::Unknown, cfg_value)
}

fn cfg_value(meta: &syn::Meta) -> CfgValue {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => CfgValue::AlwaysTrue,
        syn::Meta::Path(path) if path.is_ident("false") || path.is_ident("FALSE") => {
            CfgValue::AlwaysFalse
        }
        syn::Meta::List(list) if list.path.is_ident("not") => parse_meta_items(list)
            .map_or(CfgValue::Unknown, |items| negate(single_cfg_value(&items))),
        syn::Meta::List(list) if list.path.is_ident("all") => {
            parse_meta_items(list).map_or(CfgValue::Unknown, |items| cfg_all(items.iter()))
        }
        syn::Meta::List(list) if list.path.is_ident("any") => {
            parse_meta_items(list).map_or(CfgValue::Unknown, |items| cfg_any(items.iter()))
        }
        syn::Meta::Path(_) | syn::Meta::List(_) | syn::Meta::NameValue(_) => CfgValue::Unknown,
    }
}

fn parse_meta_items(
    list: &syn::MetaList,
) -> Option<syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>> {
    list.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .ok()
}

fn negate(value: CfgValue) -> CfgValue {
    match value {
        CfgValue::AlwaysTrue => CfgValue::AlwaysFalse,
        CfgValue::AlwaysFalse => CfgValue::AlwaysTrue,
        CfgValue::Unknown => CfgValue::Unknown,
    }
}

fn cfg_all<'a>(items: impl Iterator<Item = &'a syn::Meta>) -> CfgValue {
    let values = items.map(cfg_value).collect::<Vec<_>>();
    if values.contains(&CfgValue::AlwaysFalse) {
        CfgValue::AlwaysFalse
    } else if values.iter().all(|value| *value == CfgValue::AlwaysTrue) {
        CfgValue::AlwaysTrue
    } else {
        CfgValue::Unknown
    }
}

fn cfg_any<'a>(items: impl Iterator<Item = &'a syn::Meta>) -> CfgValue {
    let values = items.map(cfg_value).collect::<Vec<_>>();
    if values.contains(&CfgValue::AlwaysTrue) {
        CfgValue::AlwaysTrue
    } else if values.iter().all(|value| *value == CfgValue::AlwaysFalse) {
        CfgValue::AlwaysFalse
    } else {
        CfgValue::Unknown
    }
}

fn read_commit_blob(root: &Path, commit: &str, relative: &Path) -> Option<String> {
    if !is_commit(commit) || !safe_repository_relative_path(relative) {
        return None;
    }
    let relative = relative.to_str()?;
    let object = format!("{commit}:{relative}");
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["show", object.as_str()],
        &[],
        Some(root),
    )
    .output()
    .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn safe_repository_relative_path(relative: &Path) -> bool {
    !relative.as_os_str().is_empty()
        && !relative.is_absolute()
        && relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_commit(raw: &str) -> bool {
    (7..=40).contains(&raw.len()) && raw.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn content_files(dir: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        bail!("doc-contracts: 目录 {} 缺失，fail-closed", dir.display());
    }
    let mut out = Vec::new();
    collect_content(dir, extension, &mut out)?;
    Ok(out)
}

fn collect_content(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("doc-contracts: 读目录 {} 失败: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| anyhow::anyhow!("doc-contracts: 遍历目录项失败: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_content(&path, extension, out)?;
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
    Ok(())
}

fn scan_content(path: &Path, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for p in FORBIDDEN {
            if line.contains(p.needle) {
                findings.push(finding(
                    p.rule,
                    format!("{}:{}", path.display(), idx + 1),
                    p.detail,
                ));
            }
        }
    }
    findings.extend(scan_false_outbox_delivery_guarantees(path, content));
    findings.extend(scan_localonly_business_effect_semantics(path, content));
    findings
}

fn scan_localonly_business_effect_semantics(path: &Path, content: &str) -> Vec<Finding> {
    let prose_lines = if path.extension().is_some_and(|extension| extension == "rs") {
        rustdoc_prose_lines(content)
    } else {
        content
            .lines()
            .enumerate()
            .map(|(index, line)| (index + 1, line.to_owned()))
            .collect()
    };
    let mut findings = prose_lines
        .into_iter()
        .filter(|(_, line)| contains_legacy_localonly_effect_term(path, line))
        .map(|(line, _)| {
            finding(
                Rule::LocalOnlyBusinessEffects,
                format!("{}:{line}", path.display()),
                "现行语义必须使用 business-write/business-transaction、BusinessWriteEffect、BusinessWrite/business_writes；旧 token、marker、observer API 已删除",
            )
        })
        .collect::<Vec<_>>();

    findings.extend(
        semantic_clauses(path, content)
            .into_iter()
            .filter(|clause| contains_false_localonly_transaction_claim(&clause.text))
            .map(|clause| {
                finding(
                    Rule::LocalOnlyBusinessEffects,
                    format!("{}:{}", path.display(), clause.line),
                    "LocalOnly 只排除业务持久化/outbox/publish；允许 provider-owned read-path transaction，不得写成完全无事务或等同纯函数",
                )
            }),
    );
    findings.sort_by(|left, right| left.subject.cmp(&right.subject));
    findings.dedup_by(|left, right| left.subject == right.subject && left.rule == right.rule);
    findings
}

fn contains_legacy_localonly_effect_term(path: &Path, line: &str) -> bool {
    const LEGACY_API_PATTERNS: &[&str] = &[
        "diport::WriteEffect",
        "testkit::local_only::Write",
        "ProviderCounter::write",
        "ForbiddenEffects.writes",
    ];
    if LEGACY_API_PATTERNS
        .iter()
        .any(|pattern| line.contains(pattern))
    {
        return true;
    }
    if [
        "WriteEffect",
        "EffectKind::Write",
        "EffectKind::Transaction",
        "HttpEffectKind::Write",
        "HttpEffectKind::Transaction",
    ]
    .iter()
    .any(|symbol| contains_symbol(line, symbol))
        || (is_localonly_observer_carrier(path, line) && line.contains("`Write`"))
    {
        return true;
    }
    if is_localonly_observer_carrier(path, line) && contains_legacy_writes_field(line) {
        return true;
    }

    let lower = line.to_lowercase();
    let mentions_effect_carrier = is_localonly_observer_carrier(path, line)
        || lower.contains("localonly")
        || lower.contains("local only")
        || lower.contains("effect")
        || lower.contains("contract");
    mentions_effect_carrier
        && (line.contains("`write`")
            || line.contains("`transaction`")
            || lower.contains("\"write\"")
            || lower.contains("\"transaction\""))
}

fn contains_symbol(line: &str, symbol: &str) -> bool {
    line.match_indices(symbol).any(|(offset, matched)| {
        let left = offset == 0
            || line[..offset]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        let right = line[offset + matched.len()..]
            .chars()
            .next()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        left && right
    })
}

fn is_localonly_observer_carrier(path: &Path, line: &str) -> bool {
    let display = path.to_string_lossy().to_lowercase();
    line.to_lowercase().contains("localonly")
        || display.contains("local_only")
        || display.contains("local-only")
        || LOCALONLY_SEMANTIC_DOC_FILES
            .iter()
            .any(|carrier| path == Path::new(carrier))
}

fn contains_legacy_writes_field(line: &str) -> bool {
    line.match_indices("writes").any(|(offset, word)| {
        let boundary = offset == 0
            || line[..offset]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_');
        boundary && line[offset + word.len()..].trim_start().starts_with('=')
    })
}

fn contains_false_localonly_transaction_claim(text: &str) -> bool {
    let normalized = normalize_semantic_text(text);
    let compact = normalized
        .chars()
        .filter(|character| !character.is_whitespace() && !"`*_".contains(*character))
        .collect::<String>();
    let has_localonly_context = compact.contains("localonly")
        || compact.contains("l0localonly")
        || is_standalone_l0_definition(&normalized);
    has_localonly_context
        && [
            "完全没有事务",
            "没有事务",
            "无事务",
            "不启动本地事务边界",
            "等同纯函数",
            "是纯函数",
            "本地纯计算",
            "pure local",
            "purelocal",
            "pure function",
            "purefunction",
            "no local transaction boundary",
            "nolocaltransactionboundary",
        ]
        .iter()
        .any(|claim| normalized.contains(claim) && !guarantee_is_denied(&normalized, claim))
}

fn is_standalone_l0_definition(text: &str) -> bool {
    let trimmed = text.trim_start_matches(|character: char| {
        character.is_whitespace() || "`*_#>-".contains(character)
    });
    let Some(after_l0) = trimmed.strip_prefix("l0") else {
        return false;
    };
    after_l0
        .chars()
        .next()
        .is_some_and(|character| !character.is_ascii_alphanumeric() && character != '_')
}

fn scan_outbox_canonical_semantics(content: &str) -> Vec<Finding> {
    let visible = visible_outbox_canonical_section(content);
    OUTBOX_CANONICAL_FACETS
        .iter()
        .filter(|(_, needle)| {
            let normalized_needle = normalize_semantic_text(needle);
            !visible.lines().any(|line| {
                let normalized_line = normalize_semantic_text(line);
                normalized_line.contains(&normalized_needle)
                    && !guarantee_is_denied(&normalized_line, &normalized_needle)
            })
        })
        .map(|(facet, needle)| {
            finding(
                Rule::OutboxDeliverySemantics,
                OUTBOX_CANONICAL_FILE,
                format!("canonical Outbox delivery semantics 缺少 {facet} facet: {needle:?}"),
            )
        })
        .collect()
}

fn scan_localonly_canonical_semantics(content: &str) -> Vec<Finding> {
    let visible = visible_canonical_section(content, LOCALONLY_CANONICAL_HEADING);
    LOCALONLY_CANONICAL_FACETS
        .iter()
        .filter(|(_, needle)| {
            let normalized_needle = normalize_semantic_text(needle);
            !visible.lines().any(|line| {
                let normalized_line = normalize_semantic_text(line);
                normalized_line.contains(&normalized_needle)
                    && !guarantee_is_denied(&normalized_line, &normalized_needle)
            })
        })
        .map(|(facet, needle)| {
            finding(
                Rule::LocalOnlyBusinessEffects,
                LOCALONLY_CANONICAL_FILE,
                format!("canonical LocalOnly business effect 语义缺少 {facet} facet: {needle:?}"),
            )
        })
        .collect()
}

fn visible_outbox_canonical_section(content: &str) -> String {
    visible_canonical_section(content, "Outbox relay 投递语义")
}

fn visible_canonical_section(content: &str, heading: &str) -> String {
    let mut in_section = false;
    let mut section_level = 0;
    let mut open_fence = None;
    let mut in_comment = false;
    let mut visible = String::new();

    for raw in content.lines() {
        let trimmed = raw.trim();
        if !in_section {
            let level = trimmed
                .chars()
                .take_while(|character| *character == '#')
                .count();
            let title = trimmed[level..].trim_start();
            in_section = level > 0 && title.starts_with(heading);
            if in_section {
                section_level = level;
            }
            continue;
        }
        if let Some(fence) = open_fence {
            if is_fence_closer(raw, fence) {
                open_fence = None;
            }
            continue;
        }
        let heading_level = trimmed
            .chars()
            .take_while(|character| *character == '#')
            .count();
        if heading_level > 0 && heading_level <= section_level {
            break;
        }
        if let Some(fence) = fence_opening(raw) {
            open_fence = Some(fence);
            continue;
        }
        // CommonMark indented code + any open fence stay invisible (unclosed = fail-closed).
        if trimmed.starts_with('>') || is_indented_code_line(raw) {
            continue;
        }
        let mut remainder = raw;
        loop {
            if in_comment {
                let Some((_, after)) = remainder.split_once("-->") else {
                    break;
                };
                in_comment = false;
                remainder = after;
                continue;
            }
            let Some((before, after)) = remainder.split_once("<!--") else {
                visible.push_str(remainder);
                visible.push('\n');
                break;
            };
            visible.push_str(before);
            if let Some((_, tail)) = after.split_once("-->") {
                remainder = tail;
            } else {
                in_comment = true;
                break;
            }
        }
    }
    visible
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fence {
    marker: char,
    run_len: usize,
}

fn fence_open_marker(trimmed: &str) -> Option<char> {
    fence_opening(trimmed).map(|fence| fence.marker)
}

fn fence_opening(raw: &str) -> Option<Fence> {
    let candidate = commonmark_fence_candidate(raw)?;
    let (fence, remainder) = fence_run(candidate)?;
    if fence.run_len < 3 || (fence.marker == '`' && remainder.contains('`')) {
        return None;
    }
    Some(fence)
}

fn is_fence_closer(raw: &str, opening: Fence) -> bool {
    let Some(candidate) = commonmark_fence_candidate(raw) else {
        return false;
    };
    let Some((closing, remainder)) = fence_run(candidate) else {
        return false;
    };
    closing.marker == opening.marker
        && closing.run_len >= opening.run_len
        && remainder.chars().all(char::is_whitespace)
}

fn commonmark_fence_candidate(raw: &str) -> Option<&str> {
    let indent = raw
        .chars()
        .take_while(|character| *character == ' ')
        .count();
    if indent > 3 || raw.starts_with('\t') {
        return None;
    }
    Some(&raw[indent..])
}

fn fence_run(candidate: &str) -> Option<(Fence, &str)> {
    let marker = candidate.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let run_len = candidate
        .chars()
        .take_while(|character| *character == marker)
        .count();
    let byte_len = marker.len_utf8() * run_len;
    Some((Fence { marker, run_len }, &candidate[byte_len..]))
}

fn is_indented_code_line(raw: &str) -> bool {
    raw.starts_with("    ") || raw.starts_with('\t')
}

#[derive(Debug)]
struct ProseClause {
    line: usize,
    text: String,
    fragments: Vec<(usize, String)>,
    starts_paragraph: bool,
}

fn scan_false_outbox_delivery_guarantees(path: &Path, content: &str) -> Vec<Finding> {
    let mut paragraph_context = false;
    semantic_clauses(path, content)
        .into_iter()
        .filter_map(|clause| {
            let normalized = normalize_semantic_text(&clause.text);
            if clause.starts_paragraph {
                paragraph_context = false;
            }
            let local_context = has_outbox_delivery_context(path, &normalized);
            if local_context {
                paragraph_context = true;
            }
            if !paragraph_context {
                return None;
            }
            let guarantee = false_delivery_guarantees(&normalized)
                .find(|guarantee| !guarantee_is_denied(&normalized, guarantee))?;
            let line = guarantee_line(&clause, guarantee);
            Some(finding(
                Rule::OutboxDeliverySemantics,
                format!("{}:{line}", path.display()),
                "Outbox CAS/lease 只围栏状态写回；transport 必须表述为 at-least-once，publish-before-settle 允许 duplicate",
            ))
        })
        .collect()
}

fn semantic_clauses(path: &Path, content: &str) -> Vec<ProseClause> {
    let rustdoc_only = path.extension().is_some_and(|extension| extension == "rs");
    let mut clauses = Vec::new();
    let mut pending = String::new();
    let mut pending_fragments = Vec::new();
    let mut pending_line = 0;
    let mut next_starts_paragraph = true;

    let prose_lines = if rustdoc_only {
        rustdoc_prose_lines(content)
    } else {
        content
            .lines()
            .enumerate()
            .map(|(index, raw)| (index + 1, raw.to_owned()))
            .collect()
    };

    for (line, raw) in prose_lines {
        let prose = raw.trim();
        if prose.is_empty() {
            flush_clause(
                &mut clauses,
                &mut pending,
                &mut pending_fragments,
                pending_line,
                next_starts_paragraph,
            );
            pending_line = 0;
            next_starts_paragraph = true;
            continue;
        }

        let structural = prose.starts_with('#')
            || prose.starts_with('|')
            || fence_open_marker(prose).is_some()
            || prose.starts_with("- ");
        if structural {
            flush_clause(
                &mut clauses,
                &mut pending,
                &mut pending_fragments,
                pending_line,
                next_starts_paragraph,
            );
            pending_line = 0;
            next_starts_paragraph = true;
        }

        for fragment in prose.split_inclusive(['。', '；', ';', '！', '!', '？', '?', '.']) {
            if pending.is_empty() {
                pending_line = line;
            } else {
                pending.push(' ');
            }
            pending.push_str(fragment.trim());
            pending_fragments.push((line, fragment.trim().to_owned()));
            if fragment
                .chars()
                .last()
                .is_some_and(|character| "。；;！!？?.".contains(character))
            {
                let started = next_starts_paragraph;
                flush_clause(
                    &mut clauses,
                    &mut pending,
                    &mut pending_fragments,
                    pending_line,
                    started,
                );
                pending_line = 0;
                next_starts_paragraph = false;
            }
        }
        if structural {
            flush_clause(
                &mut clauses,
                &mut pending,
                &mut pending_fragments,
                pending_line,
                next_starts_paragraph,
            );
            pending_line = 0;
            next_starts_paragraph = true;
        }
    }
    flush_clause(
        &mut clauses,
        &mut pending,
        &mut pending_fragments,
        pending_line,
        next_starts_paragraph,
    );
    clauses
}

/// Extract rustdoc prose for every supported surface form: `///`/`//!`, `#[doc = "..."]`,
/// `/** ... */`, and `/*! ... */`. A line/block lexer is used (not syn expansion) so
/// docs inside unexpanded macro inputs remain visible to the gate.
fn rustdoc_prose_lines(content: &str) -> Vec<(usize, String)> {
    rustdoc_prose_lines_lexer(content)
}

fn rustdoc_prose_lines_lexer(content: &str) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let mut block: Option<BlockDocKind> = None;
    for (index, raw) in content.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim_start();
        if let Some(kind) = block {
            if let Some(prose) = block_doc_continuation(trimmed, kind) {
                match prose {
                    BlockDocPiece::Text(text) => lines.push((line, text)),
                    BlockDocPiece::Closed { text } => {
                        if !text.is_empty() {
                            lines.push((line, text));
                        }
                        block = None;
                    }
                }
            } else {
                block = None;
            }
            continue;
        }
        if let Some((kind, first)) = open_block_doc(trimmed) {
            match first {
                BlockDocPiece::Text(text) => {
                    lines.push((line, text));
                    block = Some(kind);
                }
                BlockDocPiece::Closed { text, .. } => {
                    if !text.is_empty() {
                        lines.push((line, text));
                    }
                }
            }
            continue;
        }
        if let Some(prose) = trimmed
            .strip_prefix("//!")
            .or_else(|| trimmed.strip_prefix("///"))
        {
            lines.push((line, prose.to_owned()));
            continue;
        }
        if let Some(prose) = parse_doc_attribute_line(trimmed) {
            lines.push((line, prose));
        }
    }
    lines
}

#[derive(Clone, Copy)]
enum BlockDocKind {
    Inner,
    Outer,
}

enum BlockDocPiece {
    Text(String),
    Closed { text: String },
}

fn open_block_doc(trimmed: &str) -> Option<(BlockDocKind, BlockDocPiece)> {
    let (kind, rest) = if let Some(rest) = trimmed.strip_prefix("/*!") {
        (BlockDocKind::Inner, rest)
    } else if let Some(rest) = trimmed.strip_prefix("/**") {
        // Avoid matching `/***`-style non-doc comments that aren't rustdoc outer docs.
        if rest.starts_with('*') && !rest.starts_with("*/") {
            return None;
        }
        (BlockDocKind::Outer, rest)
    } else {
        return None;
    };
    Some((kind, close_or_continue_block(rest)))
}

fn block_doc_continuation(trimmed: &str, kind: BlockDocKind) -> Option<BlockDocPiece> {
    let _ = kind;
    let rest = trimmed
        .strip_prefix('*')
        .map(str::trim_start)
        .unwrap_or(trimmed);
    Some(close_or_continue_block(rest))
}

fn close_or_continue_block(rest: &str) -> BlockDocPiece {
    if let Some(text) = rest.strip_suffix("*/") {
        BlockDocPiece::Closed {
            text: text.trim().to_owned(),
        }
    } else {
        BlockDocPiece::Text(rest.trim().to_owned())
    }
}

fn parse_doc_attribute_line(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("#[doc")?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let (literal, after) = split_rust_string_literal(rest)?;
    let after = after.trim_start();
    if after == "]" || after.starts_with(']') {
        Some(literal)
    } else {
        None
    }
}

fn split_rust_string_literal(input: &str) -> Option<(String, &str)> {
    let mut rest = input;
    let raw = if let Some(stripped) = rest.strip_prefix('r') {
        let hashes = stripped
            .chars()
            .take_while(|character| *character == '#')
            .count();
        rest = &stripped[hashes..];
        Some(hashes)
    } else {
        None
    };
    let rest = rest.strip_prefix('"')?;
    if let Some(hashes) = raw {
        let closer = format!("\"{}", "#".repeat(hashes));
        let index = rest.find(&closer)?;
        Some((rest[..index].to_owned(), &rest[index + closer.len()..]))
    } else {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(character) = chars.next() {
            match character {
                '\\' => {
                    let escaped = chars.next()?;
                    out.push(match escaped {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '0' => '\0',
                        '\\' | '\'' | '"' => escaped,
                        character => character,
                    });
                }
                '"' => return Some((out, chars.as_str())),
                character => out.push(character),
            }
        }
        None
    }
}

fn flush_clause(
    clauses: &mut Vec<ProseClause>,
    pending: &mut String,
    fragments: &mut Vec<(usize, String)>,
    line: usize,
    starts_paragraph: bool,
) {
    if !pending.trim().is_empty() {
        clauses.push(ProseClause {
            line,
            text: std::mem::take(pending),
            fragments: std::mem::take(fragments),
            starts_paragraph,
        });
    }
}

fn normalize_semantic_text(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|character| match character {
            '-' | '_' | '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}'
            | '\u{2015}' | '\u{2212}' => ' ',
            character => character,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn has_outbox_delivery_context(path: &Path, text: &str) -> bool {
    ["outbox", "relay", "broker publish", "broker delivery"]
        .iter()
        .any(|context| text.contains(context))
        || text.contains("acquire lease")
        || (text.contains("settle") && text.contains("cas"))
        || (is_outbox_source_path(path)
            && ["lease", "settle", "cas"]
                .iter()
                .any(|context| text.contains(context)))
}

fn is_outbox_source_path(path: &Path) -> bool {
    let display = path.to_string_lossy().to_lowercase();
    path.extension().is_some_and(|extension| extension == "rs")
        && (display.contains("outbox") || display.contains("relay"))
        || SEMANTIC_DOC_FILES
            .iter()
            .any(|candidate| path == Path::new(candidate))
}

fn false_delivery_guarantees(text: &str) -> impl Iterator<Item = &'static str> + '_ {
    const GUARANTEES: &[&str] = &[
        "at most once",
        "exactly once",
        "至多 publish 一次",
        "只 publish 一次",
        "仅 publish 一次",
        "恰好 publish 一次",
        "至多发布一次",
        "只发布一次",
        "仅发布一次",
        "恰好发布一次",
        "至多投递一次",
        "只投递一次",
        "仅投递一次",
        "只会投递一次",
        "仅会投递一次",
        "恰好投递一次",
        "精确一次",
    ];
    GUARANTEES
        .iter()
        .copied()
        .filter(move |guarantee| text.contains(guarantee))
}

fn guarantee_is_denied(text: &str, guarantee: &str) -> bool {
    text.match_indices(guarantee).all(|(offset, _)| {
        // Conjunctions like `and` are not claim boundaries: shared denials must
        // cover coordinated guarantees (`does not guarantee X and exactly-once`).
        const BOUNDARIES: &[&str] = &[
            ",",
            "，",
            " but ",
            " yet ",
            " however ",
            " while ",
            " whereas ",
            " although ",
            "但",
            "却",
            "同时",
            "而",
        ];
        let prefix = &text[..offset];
        let claim_start = BOUNDARIES
            .iter()
            .filter_map(|boundary| prefix.rfind(boundary).map(|index| index + boundary.len()))
            .max()
            .unwrap_or(0);
        let guarantee_end = offset + guarantee.len();
        let claim_end = BOUNDARIES
            .iter()
            .filter_map(|boundary| {
                text[guarantee_end..]
                    .find(boundary)
                    .map(|index| guarantee_end + index)
            })
            .min()
            .unwrap_or(text.len());
        let claim_prefix = &text[claim_start..guarantee_end];
        let claim = &text[claim_start..claim_end];
        let marked_quote = [
            "错误表述",
            "错误引用",
            "误写",
            "incorrect claim",
            "false claim",
        ]
        .iter()
        .any(|marker| claim_prefix.contains(marker));
        let direct_denial = [
            "不提供",
            "不保证",
            "不能保证",
            "不得声称",
            "并非",
            "不是",
            "不等同",
            "不再声明",
            "无运行时保证",
            "does not guarantee",
            "doesn't guarantee",
            "is not",
            "isn't",
            "not equivalent to",
            "no guarantee",
            "must not claim",
            "cannot guarantee",
            "can't guarantee",
            "never guarantees",
        ]
        .iter()
        .any(|denial| claim_prefix.contains(denial));
        let no_guarantee_form = claim.contains(&format!("no {guarantee} guarantee"));
        let trailing_denial = ["不成立", "is false", "is incorrect", "is unsupported"]
            .iter()
            .any(|denial| text[guarantee_end..claim_end].contains(denial));
        marked_quote || direct_denial || no_guarantee_form || trailing_denial
    })
}

fn guarantee_line(clause: &ProseClause, guarantee: &str) -> usize {
    if let Some((line, _)) = clause
        .fragments
        .iter()
        .find(|(_, fragment)| normalize_semantic_text(fragment).contains(guarantee))
    {
        return *line;
    }
    let anchor = guarantee
        .split_whitespace()
        .max_by_key(|word| word.len())
        .unwrap_or(guarantee);
    clause
        .fragments
        .iter()
        .find(|(_, fragment)| normalize_semantic_text(fragment).contains(anchor))
        .map(|(line, _)| *line)
        .unwrap_or(clause.line)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CARRYOVER: &str = r#"
<!-- carry-over-schema: v1 -->

| Source Set | Source ID | Capability | Resolution | Canonical Work Item | Duplicate | New PBI | Commit | Evidence Path | Proof | Scope Note |
|---|---|---|---|---|---|---|---|---|---|---|
| spec-002 | T001.1 | parse values | done-evidence | #1114 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | implemented |
| rewrite | P4 | identity journey | out-of-scope | - | no | - | - | - | - | governance-only |
| gap-006 | P0-1 | device enrollment | absorbed-by | #1301 | yes | - | - | - | - | supervised restart remains |
| schedule-607 | #1114 | old work item | done-evidence | #1114 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | old tracker |
| crate-mapping | Postgres | sqlx mapping | done-evidence | #1116 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | adapters/postgres/src/lib.rs | test: pg_store_guard_shutdown_lazy_pool_ok | implemented |
| code-followup | acecf759:consumer.rs:119 | worker lifecycle | needs-issue | #1714 | no | #1714 | - | - | - | new tracker created |
"#;

    fn minimal_universe() -> SourceUniverse {
        SourceUniverse::from_pairs([
            (SourceSet::Spec002, "T001.1"),
            (SourceSet::Rewrite, "P4"),
            (SourceSet::Gap006, "P0-1"),
            (SourceSet::Schedule607, "#1114"),
            (SourceSet::CrateMapping, "Postgres"),
            (SourceSet::CodeFollowup, "acecf759:consumer.rs:119"),
        ])
    }

    #[test]
    fn carryover_accepts_complete_typed_ledger() -> Result<()> {
        let rows = parse_carryover_table(VALID_CARRYOVER)?;
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(violations.is_empty(), "{violations:#?}");
        Ok(())
    }

    #[test]
    fn carryover_accepts_complete_workspace_ledger() -> Result<()> {
        let root = crate::workspace_root()?;
        let content = read_required(&root, CARRYOVER_DOC_FILE)?;
        let rows = parse_carryover_table(&content)?;
        let universe = SourceUniverse::from_workspace(&root)?;
        let violations = validate_carryover_rows(&rows, &universe, &root);
        assert!(violations.is_empty(), "{violations:#?}");
        Ok(())
    }

    #[test]
    fn evidence_binding_registry_is_bijective_with_done_rows() -> Result<()> {
        let root = crate::workspace_root()?;
        let content = read_required(&root, CARRYOVER_DOC_FILE)?;
        let rows = parse_carryover_table(&content)?;
        let row_bindings = rows
            .iter()
            .filter(|row| row.resolution == Resolution::DoneEvidence)
            .map(|row| {
                (
                    row.source_set,
                    row.source_id.as_str(),
                    row.evidence_path.as_str(),
                    row.proof.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        let registry_bindings = EVIDENCE_BINDINGS
            .iter()
            .map(|binding| {
                (
                    binding.source_set,
                    binding.source_id,
                    binding.evidence_path,
                    binding.proof,
                )
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(registry_bindings.len(), EVIDENCE_BINDINGS.len());
        assert_eq!(row_bindings, registry_bindings);
        Ok(())
    }

    #[test]
    fn carryover_source_universe_has_exact_frozen_counts() -> Result<()> {
        let root = crate::workspace_root()?;
        let universe = SourceUniverse::from_workspace(&root)?;
        assert_eq!(universe.ids(SourceSet::Spec002).len(), 65);
        let parents: BTreeSet<_> = universe
            .ids(SourceSet::Spec002)
            .into_iter()
            .filter_map(|id| id.split_once('.').map(|parts| parts.0.to_string()))
            .collect();
        assert_eq!(parents.len(), 12);
        assert_eq!(universe.ids(SourceSet::Rewrite).len(), 9);
        assert_eq!(universe.ids(SourceSet::Gap006).len(), 30);
        assert_eq!(universe.ids(SourceSet::Schedule607).len(), 59);
        assert_eq!(universe.ids(SourceSet::CrateMapping).len(), 16);
        assert_eq!(universe.ids(SourceSet::CodeFollowup).len(), 13);
        Ok(())
    }

    #[test]
    fn carryover_exact_count_rejects_synchronized_source_and_ledger_deletion() -> Result<()> {
        let root = crate::workspace_root()?;
        let content = read_required(&root, CARRYOVER_DOC_FILE)?;
        let mut rows = parse_carryover_table(&content)?;
        let mut universe = SourceUniverse::from_workspace(&root)?;
        universe.remove(SourceSet::Spec002, "T001.1");
        rows.retain(|row| {
            !(row.source_set == SourceSet::Spec002
                && row.source_set.coverage_id(&row.source_id) == "T001.1")
        });

        let violations = validate_carryover_rows(&rows, &universe, &root);
        assert!(
            violations
                .iter()
                .all(|violation| !violation.contains("source spec-002:T001.1")),
            "source/ledger synchronized deletion should evade set equality before the count canary: {violations:#?}"
        );
        let Some(err) = validate_exact_source_counts(&universe).err() else {
            bail!("exact count canary must reject synchronized deletion");
        };
        assert!(err.to_string().contains("expected exactly 65"), "{err:#}");
        Ok(())
    }

    #[test]
    fn spec_source_split_suffix_charges_unsuffixed_checkbox() {
        assert_eq!(SourceSet::Spec002.coverage_id("T010.1"), "T010.1");
        assert_eq!(SourceSet::Spec002.coverage_id("T010.1.a"), "T010.1");
        assert_eq!(SourceSet::Spec002.coverage_id("T010.1.b"), "T010.1");
    }

    #[test]
    fn schedule_source_split_suffix_charges_unsuffixed_work_item() {
        assert_eq!(SourceSet::Schedule607.coverage_id("#1008.a"), "#1008");
        assert_eq!(SourceSet::Schedule607.coverage_id("#1008.b"), "#1008");
    }

    #[test]
    fn carryover_split_atom_registry_rejects_deleted_siblings() -> Result<()> {
        let root = crate::workspace_root()?;
        let content = read_required(&root, CARRYOVER_DOC_FILE)?;
        let rows = parse_carryover_table(&content)?;
        let universe = SourceUniverse::from_workspace(&root)?;

        for removed in ["#1008.b", "P7.d"] {
            let reduced = rows
                .iter()
                .filter(|row| row.source_id != removed)
                .cloned()
                .collect::<Vec<_>>();
            let violations = validate_carryover_rows(&reduced, &universe, &root);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("missing split atom")
                        && violation.contains(removed)),
                "removed={removed}: {violations:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn source_count_diagnostic_preserves_changed_source_id() -> Result<()> {
        let root = crate::workspace_root()?;
        let content = read_required(&root, CARRYOVER_DOC_FILE)?;
        let rows = parse_carryover_table(&content)?;
        let mut universe = SourceUniverse::from_workspace(&root)?;
        universe.insert(SourceSet::Spec002, "T999.1");

        let violations = validate_carryover_rows(&rows, &universe, &root);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("missing source spec-002:T999.1")),
            "{violations:#?}"
        );
        let Some(count_error) = validate_exact_source_counts(&universe).err() else {
            bail!("count canary unexpectedly accepted an added source");
        };
        assert!(count_error.to_string().contains("66 item(s)"));
        Ok(())
    }

    #[test]
    fn code_followup_manifest_has_all_new_bounded_anchors() -> Result<()> {
        let root = crate::workspace_root()?;
        validate_code_followup_anchors(&root)?;
        let ids: BTreeSet<_> = CODE_FOLLOWUPS.iter().map(|followup| followup.id).collect();
        for expected in [
            "current:publisher.rs:topology-provisioning",
            "current:0012_enable_tenant_rls.sql:dual-pool",
            "current:integration_tests.rs:envelope-metadata",
            "current:runtime-lib.rs:audit-tail-verify",
        ] {
            assert!(ids.contains(expected), "missing {expected}");
        }
        Ok(())
    }

    #[test]
    fn carryover_parser_rejects_duplicate_marker_header_and_bad_separator() -> Result<()> {
        let duplicate_marker = format!("{VALID_CARRYOVER}\n{CARRYOVER_MARKER}\n");
        let Some(marker_err) = parse_carryover_table(&duplicate_marker).err() else {
            bail!("duplicate marker must fail");
        };
        assert!(marker_err.to_string().contains("exactly one schema marker"));

        let duplicate_header = format!("{VALID_CARRYOVER}\n{CARRYOVER_HEADER}\n");
        let Some(header_err) = parse_carryover_table(&duplicate_header).err() else {
            bail!("duplicate header must fail");
        };
        assert!(header_err.to_string().contains("exactly one table header"));

        let bad_separator = VALID_CARRYOVER.replace(CARRYOVER_SEPARATOR, "|---|---|");
        let Some(separator_err) = parse_carryover_table(&bad_separator).err() else {
            bail!("short separator must fail");
        };
        assert!(
            separator_err
                .to_string()
                .contains("invalid table separator")
        );
        Ok(())
    }

    #[test]
    fn carryover_parser_rejects_trailing_content_and_second_table() -> Result<()> {
        let trailing = format!("{VALID_CARRYOVER}\ntrailing prose\n");
        let Some(trailing_err) = parse_carryover_table(&trailing).err() else {
            bail!("non-table tail must fail");
        };
        assert!(
            trailing_err
                .to_string()
                .contains("trailing non-table content")
        );

        let second_table = format!(
            "{VALID_CARRYOVER}\n{CARRYOVER_HEADER}\n{CARRYOVER_SEPARATOR}\n| spec-002 | T001.1 | contradiction | out-of-scope | - | no | - | - | - | - | hidden |\n"
        );
        let Some(second_table_err) = parse_carryover_table(&second_table).err() else {
            bail!("second table must fail");
        };
        assert!(
            second_table_err
                .to_string()
                .contains("exactly one table header")
        );
        Ok(())
    }

    #[test]
    fn carryover_rejects_missing_source_and_duplicate_key() -> Result<()> {
        let duplicate = VALID_CARRYOVER.replace(
            "| rewrite | P4 |",
            "| spec-002 | T001.1 | duplicate | done-evidence | #1114 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | implemented |\n| rewrite | P4 |",
        );
        let rows = parse_carryover_table(&duplicate)?;
        let mut universe = minimal_universe();
        universe.insert(SourceSet::Spec002, "T010.1");
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &universe, &root);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("duplicate source key")),
            "{violations:#?}"
        );
        assert!(
            violations.iter().any(|v| v.contains("missing source")),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn carryover_rejects_epic_only_done_and_missing_evidence() -> Result<()> {
        let invalid = VALID_CARRYOVER.replace(
            "| #1114 | no | - | 8d2768d5dd9cdea6cd798b08be506fa12a1724c2 | crates/consistency/src/outbox.rs | test: disposition_as_label_distinct | implemented |",
            "| #1644 | no | - | - | - | - | implemented |",
        );
        let rows = parse_carryover_table(&invalid)?;
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("audited evidence snapshot")),
            "{violations:#?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("commit must be a full audited develop snapshot identifier")),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn carryover_rejects_needs_issue_without_created_pbi() -> Result<()> {
        let invalid = VALID_CARRYOVER.replace(
            "| #1714 | no | #1714 | - | - | - | new tracker created |",
            "| - | no | - | - | - | - | tracker missing |",
        );
        let rows = parse_carryover_table(&invalid)?;
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("needs-issue requires an audit-created PBI leaf")),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn carryover_rejects_unrelated_and_nonexistent_pbis() -> Result<()> {
        let root = crate::workspace_root()?;
        for issue in ["#1700", "#999999"] {
            let invalid = VALID_CARRYOVER.replace("#1714", issue);
            let rows = parse_carryover_table(&invalid)?;
            let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("audit-created PBI")),
                "{issue}: {violations:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn carryover_rejects_created_pbi_as_absorbed_and_duplicate_done() -> Result<()> {
        let root = crate::workspace_root()?;
        let created_absorbed = VALID_CARRYOVER.replace(
            "| #1301 | yes | - | - | - | - | supervised restart remains |",
            "| #1714 | yes | - | - | - | - | supervised restart remains |",
        );
        let rows = parse_carryover_table(&created_absorbed)?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("audited work item provenance reference")),
            "{violations:#?}"
        );

        let duplicate_done =
            VALID_CARRYOVER.replacen("| #1114 | no | - |", "| #1114 | yes | - |", 1);
        let rows = parse_carryover_table(&duplicate_done)?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains("must not be marked duplicate")),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn carryover_rejects_unsafe_evidence_paths_and_fake_proofs() -> Result<()> {
        let root = crate::workspace_root()?;
        let cases = [
            (
                "crates/consistency/src/outbox.rs",
                "/etc/passwd",
                "test: disposition_as_label_distinct",
            ),
            (
                "crates/consistency/src/outbox.rs",
                "../Cargo.toml",
                "test: disposition_as_label_distinct",
            ),
            (
                "crates/consistency/src/outbox.rs",
                "./crates/consistency/src/outbox.rs",
                "test: disposition_as_label_distinct",
            ),
            (
                "crates/consistency/src/outbox.rs",
                "Cargo.toml",
                "test: disposition_as_label_distinct",
            ),
            (
                "crates/consistency/src/outbox.rs",
                "crates/consistency/src/outbox.rs",
                "gate: invented",
            ),
            (
                "crates/consistency/src/outbox.rs",
                "crates/consistency/src/outbox.rs",
                "test: not_a_real_test_selector",
            ),
            (
                "crates/consistency/src/outbox.rs",
                "crates/consistency/src/outbox.rs",
                "proof: free text",
            ),
        ];
        for (old_path, new_path, proof) in cases {
            let invalid = VALID_CARRYOVER.replacen(
                &format!("| {old_path} | test: disposition_as_label_distinct |"),
                &format!("| {new_path} | {proof} |"),
                1,
            );
            let rows = parse_carryover_table(&invalid)?;
            let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("safe repository evidence")),
                "path={new_path} proof={proof}: {violations:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn carryover_rejects_another_sources_real_test() -> Result<()> {
        let invalid = VALID_CARRYOVER.replacen(
            "| crates/consistency/src/outbox.rs | test: disposition_as_label_distinct |",
            "| crates/consistency/src/error.rs | test: engine_error_kind_message_distinct |",
            1,
        );
        let rows = parse_carryover_table(&invalid)?;
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations.iter().any(|violation| {
                violation.contains("registered proof") && violation.contains("spec-002:T001.1")
            }),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn concrete_test_proof_rejects_attributes_and_non_test_functions() {
        let content = r#"
#[cfg(test)]
mod tests {
    #[test]
    fn preceding_real_test() {}
    fn helper_after_test() {}

    fn helper_only() {}

    #[tokio::test]
    async fn durable_roundtrip() {}
}
"#;
        assert!(!has_concrete_test(content, "#[cfg(test)]"));
        assert!(!has_concrete_test(content, "#[test]"));
        assert!(!has_concrete_test(content, "helper_only"));
        assert!(!has_concrete_test(content, "helper_after_test"));
        assert!(!has_concrete_test(content, "durable"));
        assert!(has_concrete_test(content, "durable_roundtrip"));
    }

    #[test]
    fn concrete_test_proof_rejects_comment_raw_string_and_ignored_bait() {
        let content = r####"
/*
#[test]
fn block_comment_bait() {}
*/

const RAW_STRING_BAIT: &str = r#"
#[test]
fn raw_string_bait() {}
"#;

#[test]
#[ignore = "not executable proof"]
fn ignored_bait() {}

#[cfg(any())]
#[test]
fn never_cfg_bait() {}

#[cfg(FALSE)]
#[test]
fn false_cfg_bait() {}
"####;

        assert!(!has_concrete_test(content, "block_comment_bait"));
        assert!(!has_concrete_test(content, "raw_string_bait"));
        assert!(!has_concrete_test(content, "ignored_bait"));
        assert!(!has_concrete_test(content, "never_cfg_bait"));
        assert!(!has_concrete_test(content, "false_cfg_bait"));
    }

    #[test]
    fn concrete_test_proof_rejects_recursive_cfg_and_cfg_attr_bait() {
        let content = r#"
#[cfg(not(all()))]
#[test]
fn nested_false_cfg_bait() {}

#[cfg_attr(all(), ignore)]
#[test]
fn always_ignored_cfg_attr_bait() {}

#[cfg_attr(all(), cfg_attr(not(any()), ignore))]
#[test]
fn nested_always_ignored_cfg_attr_bait() {}

#[cfg(not(any()))]
#[test]
fn always_enabled_test() {}

#[cfg_attr(any(), ignore)]
#[test]
fn never_ignored_test() {}
"#;

        assert!(!has_concrete_test(content, "nested_false_cfg_bait"));
        assert!(!has_concrete_test(content, "always_ignored_cfg_attr_bait"));
        assert!(!has_concrete_test(
            content,
            "nested_always_ignored_cfg_attr_bait"
        ));
        assert!(has_concrete_test(content, "always_enabled_test"));
        assert!(has_concrete_test(content, "never_ignored_test"));
    }

    #[test]
    fn done_evidence_is_read_from_declared_commit_blob() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "rss-doc-contracts-history-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root)?;
        let git = |args: &[&str]| -> Result<std::process::Output> {
            let output = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                args,
                &[],
                Some(&root),
            )
            .output()?;
            if !output.status.success() {
                bail!(
                    "git {:?} failed: {}",
                    args,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(output)
        };
        git(&["init", "--quiet"])?;
        std::fs::write(root.join("proof.rs"), "fn helper() {}\n")?;
        git(&["add", "proof.rs"])?;
        git(&[
            "-c",
            "user.name=doc-contracts-test",
            "-c",
            "user.email=doc-contracts-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "baseline",
        ])?;
        let commit = String::from_utf8(git(&["rev-parse", "HEAD"])?.stdout)?
            .trim()
            .to_string();

        std::fs::write(root.join("proof.rs"), "#[test]\nfn worktree_only() {}\n")?;
        let row = CarryoverRow {
            line_number: 7,
            source_set: SourceSet::Spec002,
            source_id: "T001.1".to_string(),
            capability: "history binding".to_string(),
            resolution: Resolution::DoneEvidence,
            canonical_work_item: "#1114".to_string(),
            duplicate: false,
            new_pbi: "-".to_string(),
            commit,
            evidence_path: "proof.rs".to_string(),
            proof: "test: worktree_only".to_string(),
            scope_note: "test".to_string(),
        };

        assert!(
            !valid_test_evidence(&root, &row.commit, "proof.rs", &["worktree_only"]),
            "a test added only after the declared commit must not satisfy historical evidence"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn canonical_work_item_preserves_feature_kind_and_pbi_consumers_reject_it() {
        assert!(audited_work_item_list(
            "#1013",
            &[AUDITED_EVIDENCE_WORK_ITEMS]
        ));
        for feature in ["#1013", "#1465", "#1466", "#1467"] {
            assert!(
                !audited_pbi_list(feature, AUDITED_EVIDENCE_WORK_ITEMS),
                "Feature {feature} must not be accepted as a Product Backlog Item"
            );
        }
    }

    #[test]
    fn row_diagnostic_carries_ledger_line_and_field() -> Result<()> {
        let invalid = VALID_CARRYOVER.replacen(
            "8d2768d5dd9cdea6cd798b08be506fa12a1724c2",
            "not-a-commit",
            1,
        );
        let Some(expected_line) = invalid
            .lines()
            .position(|line| line.contains("not-a-commit"))
            .map(|index| index + 1)
        else {
            bail!("synthetic row missing");
        };
        let rows = parse_carryover_table(&invalid)?;
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations.iter().any(|violation| {
                violation.contains(&format!("{CARRYOVER_DOC_FILE}:{expected_line}"))
                    && violation.contains("field=Commit")
            }),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn gate_proof_requires_exact_evidence_and_every_semantic_anchor() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "rss-doc-contracts-gate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("gate.rs"), "INVARIANT: GATE-01")?;
        std::fs::write(root.join("runbook.md"), "## Recovery")?;
        let git = |args: &[&str]| -> Result<std::process::Output> {
            let output = crate::cmd::external_cmd(
                crate::cmd::ExternalProgram::SystemGit,
                args,
                &[],
                Some(&root),
            )
            .output()?;
            if !output.status.success() {
                bail!(
                    "git {:?} failed: {}",
                    args,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Ok(output)
        };
        git(&["init", "--quiet"])?;
        git(&["add", "gate.rs", "runbook.md"])?;
        git(&[
            "-c",
            "user.name=doc-contracts-test",
            "-c",
            "user.email=doc-contracts-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "complete gate",
        ])?;
        let complete_commit = String::from_utf8(git(&["rev-parse", "HEAD"])?.stdout)?
            .trim()
            .to_string();
        let carriers = [
            SourceAnchor {
                path: "gate.rs",
                needle: "GATE-01",
            },
            SourceAnchor {
                path: "runbook.md",
                needle: "## Recovery",
            },
        ];

        assert!(valid_gate_carriers(
            &root,
            &complete_commit,
            "gate.rs",
            &carriers
        ));
        assert!(!valid_gate_carriers(
            &root,
            &complete_commit,
            "runbook.md",
            &carriers
        ));
        std::fs::write(root.join("gate.rs"), "gate implementation removed")?;
        assert!(
            valid_gate_carriers(&root, &complete_commit, "gate.rs", &carriers),
            "worktree changes must not alter the declared historical proof"
        );
        git(&["add", "gate.rs"])?;
        git(&[
            "-c",
            "user.name=doc-contracts-test",
            "-c",
            "user.email=doc-contracts-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "remove gate anchor",
        ])?;
        let incomplete_commit = String::from_utf8(git(&["rev-parse", "HEAD"])?.stdout)?
            .trim()
            .to_string();
        assert!(!valid_gate_carriers(
            &root,
            &incomplete_commit,
            "gate.rs",
            &carriers
        ));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn carryover_evidence_rejects_unsafe_repository_paths() {
        assert!(!safe_repository_relative_path(Path::new("")));
        assert!(!safe_repository_relative_path(Path::new("/etc/passwd")));
        assert!(!safe_repository_relative_path(Path::new("../Cargo.toml")));
        assert!(!safe_repository_relative_path(Path::new(
            "crates/../Cargo.toml"
        )));
        assert!(safe_repository_relative_path(Path::new(
            "crates/consistency/src/outbox.rs"
        )));
    }

    #[test]
    fn carryover_rejects_unexpanded_issue_range() -> Result<()> {
        let invalid =
            VALID_CARRYOVER.replace("| schedule-607 | #1114 |", "| schedule-607 | #1114–#1124 |");
        let rows = parse_carryover_table(&invalid)?;
        let mut universe = minimal_universe();
        universe.insert(SourceSet::Schedule607, "#1124");
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &universe, &root);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("missing source schedule-607:#1114")),
            "{violations:#?}"
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("unexpected source schedule-607:#1114–#1124")),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn carryover_rejects_illegal_resolution() -> Result<()> {
        let invalid = VALID_CARRYOVER.replace("| done-evidence |", "| partial |");
        let Some(err) = parse_carryover_table(&invalid).err() else {
            bail!("partial unexpectedly parsed as a valid resolution");
        };
        let message = err.to_string();
        let Some(expected_line) = invalid
            .lines()
            .position(|line| line.contains("| partial |"))
            .map(|index| index + 1)
        else {
            bail!("partial row missing from synthetic ledger");
        };
        assert!(message.contains("unknown resolution"), "{err:#}");
        assert!(message.contains(CARRYOVER_DOC_FILE), "{err:#}");
        assert!(message.contains(&format!(":{expected_line}:")), "{err:#}");
        assert!(message.contains("spec-002:T001.1"), "{err:#}");
        Ok(())
    }

    #[test]
    fn carryover_rejects_open_pbi_as_done_evidence() -> Result<()> {
        let invalid = VALID_CARRYOVER.replace("| #1114 | no |", "| #1301 | no |");
        let rows = parse_carryover_table(&invalid)?;
        let root = crate::workspace_root()?;
        let violations = validate_carryover_rows(&rows, &minimal_universe(), &root);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("audited evidence snapshot")),
            "{violations:#?}"
        );
        Ok(())
    }

    #[test]
    fn issue_reference_expansion_handles_ranges_and_slash_lists() {
        let refs = extract_issue_references("#1114–1124 and #1002/1003/1004/1006 plus #1405–#1407");
        assert!(refs.contains("#1114"));
        assert!(refs.contains("#1124"));
        assert!(refs.contains("#1003"));
        assert!(refs.contains("#1006"));
        assert!(refs.contains("#1406"));
        assert_eq!(refs.len(), 18);
    }

    #[test]
    fn scan_content_rejects_removed_event_topology_and_entry_symbols() {
        let src = "generated `SUBSCRIPTIONS`\ngenerated::event::SUBSCRIPTIONS\nconsistency::Entry\noutbox::Entry\nVec<Entry>";
        let findings = scan_content(Path::new("docs/rules/eventbus.md"), src);
        assert_eq!(findings.len(), 5);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::RemovedSymbol)
        );
    }

    #[test]
    fn scan_content_accepts_current_event_topology_and_entry_symbols() {
        let src = "generated::event::EVENTS\nSPEC.subscriptions()\nEventEntry\nStoredOutboxEntry";
        assert!(scan_content(Path::new("docs/rules/eventbus.md"), src).is_empty());
    }

    #[test]
    fn scan_content_rejects_legacy_localonly_effect_semantics() {
        let cases = [
            "LocalOnly contract 仍声明 `write`。",
            "LocalOnly contract 仍声明 `transaction`。",
            "- `write`",
            "- `transaction`",
            "LocalOnly port 使用 `WriteEffect` marker。",
            "LocalOnly runtime observer 使用 `testkit::local_only::Write`。",
            "LocalOnly generated 仍暴露 `EffectKind::Write` / `HttpEffectKind::Write`。",
            "LocalOnly generated 仍暴露 `EffectKind::Transaction` / `HttpEffectKind::Transaction`。",
            "LocalOnly runtime observer marker 仍是 `Write`。",
            "LocalOnly provider 调用 `ProviderCounter::write()` 并断言 `writes=0`。",
            "LocalOnly 完全没有事务。",
            "LocalOnly 等同纯函数。",
        ];

        for source in cases {
            let findings = scan_content(Path::new("docs/rules/consistency-l0.md"), source);
            assert_eq!(findings.len(), 1, "source should fail: {source:?}");
            assert_eq!(findings[0].rule, Rule::LocalOnlyBusinessEffects);
        }
    }

    #[test]
    fn legacy_effect_token_scan_does_not_reject_generic_localtx_write_api() {
        let source = "`SecretRepo::save`、adapter factory、generic/legacy `write`、手制 observation 或手工 boundary。";
        assert!(scan_content(Path::new("docs/rules/localtx.md"), source).is_empty());
    }

    #[test]
    fn scan_content_accepts_current_localonly_business_effect_semantics() {
        let source = "\
HTTP effect vocabulary 仅使用 `business-write` / `business-transaction`；LocalOnly 准入仍只允许 `auth` / `read` / `projection`，port 使用 `BusinessWriteEffect` 分类危险能力。
observer 使用 `BusinessWrite` / `business_writes`，证明业务持久化、outbox、publish 为零。
LocalOnly 允许 provider-owned read-path transaction；`tenant_scoped_read*` 不承诺 PostgreSQL `READ ONLY` 或稳定 snapshot。
correctness cache、metrics/trace、auth security audit 不计入 business effect。
跨租户 durable audit 仍是 `business-write + business-transaction + cross-tenant-audit` 且保持 LocalTx。
";

        assert!(scan_content(Path::new("docs/rules/consistency-l0.md"), source).is_empty());
    }

    #[test]
    fn scan_content_accepts_denied_legacy_localonly_claims() {
        for source in [
            "LocalOnly 并非完全没有事务。",
            "LocalOnly 不是无事务。",
            "LocalOnly 不等同纯函数。",
        ] {
            assert!(
                scan_content(Path::new("docs/rules/consistency-l0.md"), source).is_empty(),
                "explicit denial must not be treated as an affirmative legacy claim: {source:?}"
            );
        }
    }

    #[test]
    fn scan_content_rejects_standalone_l0_pure_definition() {
        let findings = scan_content(
            Path::new("crates/contractreg/src/domain/mod.rs"),
            "/// L0 本地纯计算。",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::LocalOnlyBusinessEffects);
        assert!(
            scan_content(
                Path::new("crates/contractreg/src/domain/mod.rs"),
                "/// L0 只约束 business persistence/outbox/publish。",
            )
            .is_empty()
        );
    }

    #[test]
    fn localonly_canonical_semantics_requires_every_visible_facet() {
        let canonical = format!(
            "## {LOCALONLY_CANONICAL_HEADING}\n{}\n",
            LOCALONLY_CANONICAL_FACETS
                .iter()
                .map(|(_, needle)| *needle)
                .collect::<Vec<_>>()
                .join("。\n")
        );
        assert!(scan_localonly_canonical_semantics(&canonical).is_empty());

        for (_, required) in LOCALONLY_CANONICAL_FACETS {
            let incomplete = canonical.replacen(required, "", 1);
            assert_eq!(
                scan_localonly_canonical_semantics(&incomplete).len(),
                1,
                "missing facet should fail: {required:?}"
            );
        }

        let hidden = format!(
            "## {LOCALONLY_CANONICAL_HEADING}\n<!--\n{}\n-->\n",
            LOCALONLY_CANONICAL_FACETS
                .iter()
                .map(|(_, needle)| *needle)
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(
            scan_localonly_canonical_semantics(&hidden).len(),
            LOCALONLY_CANONICAL_FACETS.len()
        );

        let denied = canonical.replacen(
            LOCALONLY_CANONICAL_FACETS[0].1,
            &format!("不再声明 {}", LOCALONLY_CANONICAL_FACETS[0].1),
            1,
        );
        assert_eq!(scan_localonly_canonical_semantics(&denied).len(), 1);
    }

    #[test]
    fn canonical_fences_require_matching_marker_length_and_bare_closer() {
        let facets = LOCALONLY_CANONICAL_FACETS
            .iter()
            .map(|(_, needle)| *needle)
            .collect::<Vec<_>>()
            .join("\n");
        for false_closer in ["```", "````text", "~~~"] {
            let hidden = format!(
                "## {LOCALONLY_CANONICAL_HEADING}\n````text\ndecoy\n{false_closer}\n{facets}\n````\n"
            );
            assert_eq!(
                scan_localonly_canonical_semantics(&hidden).len(),
                LOCALONLY_CANONICAL_FACETS.len(),
                "false closer must not expose fenced facets: {false_closer:?}"
            );
        }

        let hidden_with_longer_closer =
            format!("## {LOCALONLY_CANONICAL_HEADING}\n```text\n{facets}\n````\n");
        assert_eq!(
            scan_localonly_canonical_semantics(&hidden_with_longer_closer).len(),
            LOCALONLY_CANONICAL_FACETS.len()
        );
    }

    #[test]
    fn doc_contracts_summary_names_localonly_semantic_canonical_and_rustdoc_checks() {
        let summary = format_doc_contracts_summary(321, 9, 87, "ledger ok");
        assert!(summary.contains("321 docs/source 文件扫描"));
        assert!(summary.contains("LocalOnly semantic carriers=9"));
        assert!(summary.contains("canonical 完整性"));
        assert!(summary.contains("production rustdoc files=87"));
        assert!(summary.ends_with("carry-over ledger ok"));
    }

    #[test]
    fn scan_content_reports_tenantless_command_and_envelope_fragments() {
        let src = "\
generated::command::<cmd>::emit_async(emitter, request, subject_id, idempotency_key)
OutboxEnvelopeParts::new(CONTRACT, subject)
";
        let findings = scan_content(Path::new("docs/rules/eventbus.md"), src);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule, Rule::CommandWrapper);
        assert_eq!(findings[1].rule, Rule::OutboxEnvelope);
    }

    #[test]
    fn scan_content_reports_actorless_command_and_envelope_fragments() {
        let src = "\
generated::command::<cmd>::emit_async(emitter, request, tenant, subject_id, idempotency_key)
eventexec::command::emit_async(emitter, dispatch_id, topic, contract, tenant, payload, subject_id)
OutboxEnvelopeParts::new(CONTRACT, tenant, subject)
";
        let findings = scan_content(Path::new("docs/rules/eventbus.md"), src);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].rule, Rule::CommandWrapper);
        assert_eq!(findings[1].rule, Rule::RuntimeCommandEmit);
        assert_eq!(findings[2].rule, Rule::OutboxEnvelope);
    }

    #[test]
    fn scan_content_accepts_actor_aware_fragments() {
        let src = "\
generated::command::<cmd>::emit_async(emitter, request, tenant, subject_id, actor, idempotency_key)
eventexec::command::emit_async(emitter, dispatch_id, topic, contract, tenant, payload, subject_id, actor)
OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor)
";
        assert!(scan_content(Path::new("docs/rules/eventbus.md"), src).is_empty());
    }

    #[test]
    fn scan_content_rejects_false_outbox_delivery_guarantees() {
        let cases = [
            "relay 幂等 CAS 保证即使重投也至多 publish 一次。",
            "at-most-once 正确性由 acquire_lease CAS 保证。",
            "Outbox transport guarantees at-most-once delivery.",
            "Outbox broker publish guarantees exactly once.",
            "Outbox relay guarantees\nexactly-once delivery.",
            "Outbox lease 保证恰好发布一次。",
            "Outbox relay guarantees exactly‑once delivery.",
            "Outbox relay 确保消息只会投递一次。",
            "Outbox relay 确保消息仅会投递一次。",
            "Outbox relay 确保消息恰好投递一次。",
            "Outbox relay must not lose messages and guarantees exactly-once delivery.",
            "Outbox CAS 不保证 lease 永不失效，却保证 exactly-once broker delivery。",
            "Outbox relay 不保证低延迟，同时保证 exactly-once delivery。",
            "Outbox relay does not guarantee availability while guaranteeing exactly-once delivery.",
        ];

        for source in cases {
            let findings = scan_content(Path::new("docs/rules/eventbus.md"), source);
            assert_eq!(findings.len(), 1, "source should fail: {source:?}");
        }
    }

    #[test]
    fn scan_content_accepts_correct_and_scoped_delivery_semantics() {
        let cases = [
            "Outbox relay transport is at-least-once; publish 成功、settle 前允许 duplicate。",
            "Outbox CAS 不提供 broker exactly-once。",
            "Outbox transport is not exactly-once.",
            "Outbox relay has no at-most-once guarantee.",
            "不得声称 Outbox transport guarantees at-most-once delivery。",
            "错误表述：relay 幂等 CAS 保证即使重投也至多 publish 一次。",
            "任何依赖‘CAS 使 broker 至多 publish 一次’的假设都不成立。",
            "Subscriber + MessageStream 是 at-most-once demo consumer。",
            "并发两个有效 relay 中，publisher 在该 lease 窗口至多调用一次。",
            "Saga lease CAS guarantees exactly-once compensation.",
        ];

        for source in cases {
            assert!(
                scan_content(Path::new("docs/rules/tenancy.md"), source).is_empty(),
                "source should pass: {source:?}"
            );
        }
        assert!(
            scan_content(
                Path::new("docs/rules/eventbus.md"),
                "Saga lease CAS guarantees exactly-once compensation.",
            )
            .is_empty()
        );
    }

    #[test]
    fn outbox_false_guarantee_reports_the_guarantee_line() {
        let findings = scan_content(
            Path::new("crates/eventexec/src/relay.rs"),
            "/// Outbox relay guarantees\n/// exactly-once delivery.",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "crates/eventexec/src/relay.rs:2");

        let findings = scan_content(
            Path::new("crates/eventexec/src/relay.rs"),
            "/// Outbox relay is at-least-once but incorrectly claims\n/// at-most-once delivery.",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].subject, "crates/eventexec/src/relay.rs:2");
    }

    #[test]
    fn canonical_outbox_semantics_requires_every_faceted_statement() {
        let canonical = "\
## Outbox relay 投递语义（at-least-once）
relay transport 是 **at-least-once**。
publish 成功、settle 前崩溃允许 broker duplicate。
tenant-scoped `Inbox` / `ConsumerTx` 收口重复数据库副作用。
";
        assert!(scan_outbox_canonical_semantics(canonical).is_empty());

        for required in [
            "relay transport 是 **at-least-once**。\n",
            "publish 成功、settle 前崩溃允许 broker duplicate。\n",
            "tenant-scoped `Inbox` / `ConsumerTx` 收口重复数据库副作用。\n",
        ] {
            let incomplete = canonical.replace(required, "");
            assert_eq!(
                scan_outbox_canonical_semantics(&incomplete).len(),
                1,
                "missing facet should fail: {required:?}"
            );
        }

        let hidden_in_comment = format!(
            "## Outbox relay 投递语义（at-least-once）\n<!--\n{}\n{}\n{}\n-->\n",
            OUTBOX_CANONICAL_FACETS[0].1,
            OUTBOX_CANONICAL_FACETS[1].1,
            OUTBOX_CANONICAL_FACETS[2].1,
        );
        assert_eq!(scan_outbox_canonical_semantics(&hidden_in_comment).len(), 3);

        let hidden_in_fence = format!(
            "## Outbox relay 投递语义（at-least-once）\n```text\n{}\n{}\n{}\n```\n",
            OUTBOX_CANONICAL_FACETS[0].1,
            OUTBOX_CANONICAL_FACETS[1].1,
            OUTBOX_CANONICAL_FACETS[2].1,
        );
        assert_eq!(scan_outbox_canonical_semantics(&hidden_in_fence).len(), 3);

        let hidden_in_tilde_fence = format!(
            "## Outbox relay 投递语义（at-least-once）\n~~~text\n{}\n{}\n{}\n~~~\n",
            OUTBOX_CANONICAL_FACETS[0].1,
            OUTBOX_CANONICAL_FACETS[1].1,
            OUTBOX_CANONICAL_FACETS[2].1,
        );
        assert_eq!(
            scan_outbox_canonical_semantics(&hidden_in_tilde_fence).len(),
            3
        );

        let hidden_in_indented_code = format!(
            "## Outbox relay 投递语义（at-least-once）\n\n    {}\n    {}\n    {}\n",
            OUTBOX_CANONICAL_FACETS[0].1,
            OUTBOX_CANONICAL_FACETS[1].1,
            OUTBOX_CANONICAL_FACETS[2].1,
        );
        assert_eq!(
            scan_outbox_canonical_semantics(&hidden_in_indented_code).len(),
            3
        );

        let hidden_in_unclosed_fence = format!(
            "## Outbox relay 投递语义（at-least-once）\n```text\n{}\n{}\n{}\n",
            OUTBOX_CANONICAL_FACETS[0].1,
            OUTBOX_CANONICAL_FACETS[1].1,
            OUTBOX_CANONICAL_FACETS[2].1,
        );
        assert_eq!(
            scan_outbox_canonical_semantics(&hidden_in_unclosed_fence).len(),
            3
        );

        let denied = canonical.replacen(
            OUTBOX_CANONICAL_FACETS[0].1,
            &format!("不再声明 {}", OUTBOX_CANONICAL_FACETS[0].1),
            1,
        );
        assert_eq!(scan_outbox_canonical_semantics(&denied).len(), 1);
    }

    #[test]
    fn outbox_false_guarantee_keeps_paragraph_context_across_sentences() {
        let findings = scan_content(
            Path::new("docs/rules/eventbus.md"),
            "Outbox relay uses CAS. This guarantees exactly-once delivery.",
        );
        assert_eq!(
            findings.len(),
            1,
            "cross-sentence outbox context must stay in scope"
        );
    }

    #[test]
    fn outbox_shared_negation_with_and_is_not_a_false_positive() {
        assert!(
            scan_content(
                Path::new("docs/rules/eventbus.md"),
                "Outbox does not guarantee ordering and exactly-once delivery.",
            )
            .is_empty(),
            "shared denial before `and` must cover the guarantee claim"
        );
    }

    #[test]
    fn outbox_false_guarantee_does_not_leak_across_paragraphs() {
        assert!(
            scan_content(
                Path::new("docs/rules/eventbus.md"),
                "Outbox relay uses CAS.\n\nUnrelated module guarantees exactly-once delivery.",
            )
            .is_empty(),
            "outbox context must reset on paragraph break"
        );
    }

    #[test]
    fn outbox_false_guarantee_detects_doc_attribute_and_block_docs() {
        let cases = [
            "#[doc = \"Outbox relay guarantees exactly-once delivery.\"]\nfn sample() {}\n",
            "/** Outbox relay guarantees exactly-once delivery. */\nfn sample() {}\n",
            "/*! Outbox relay guarantees exactly-once delivery. */\n",
        ];
        for source in cases {
            let findings = scan_content(Path::new("crates/eventexec/src/relay.rs"), source);
            assert_eq!(
                findings.len(),
                1,
                "rustdoc surface form should fail: {source:?}"
            );
        }
    }

    #[test]
    fn workspace_rustdoc_discovery_covers_outbox_and_relay_sources() -> Result<()> {
        let root = crate::workspace_root()?;
        let mut files = Vec::new();
        for dir in RUSTDOC_ROOTS {
            files.extend(content_files(&root.join(dir), "rs")?);
        }
        let relative = files
            .iter()
            .filter_map(|path| path.strip_prefix(&root).ok())
            .collect::<BTreeSet<_>>();
        for expected in [
            Path::new("crates/eventexec/src/relay.rs"),
            Path::new("crates/eventexec/src/relay_metrics.rs"),
            Path::new("assemblies/runtime/src/event_transport.rs"),
            Path::new("adapters/amqp/src/publisher.rs"),
            Path::new("adapters/mqtt/src/publisher.rs"),
        ] {
            assert!(
                relative.contains(expected),
                "missing rustdoc source {expected:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn scan_content_reports_tenantless_outbox_doc_fragments() {
        let src = "\
outbox / saga_journal / projection_events 是**无 `tenant_id` 列的全局表**
outbox/inbox 不引入 tenant_id 维度属本 feature 显式范围决策
outbox 表无 `tenant_id` 列、无 RLS
`partition_key` **必须自带 tenant scope**
partition_key 必须自带 tenant scope
设置时同 `(domain, partition_key)`
gating：同 `(domain, partition_key)`
tenant-scoped key
issue **#1405**
";
        let findings = scan_content(Path::new("docs/rules/tenancy.md"), src);
        assert_eq!(findings.len(), 9);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::OutboxTenantScope)
        );
    }

    #[test]
    fn scan_content_reports_legacy_saga_projection_fragments() {
        let src = "\
## saga 投影资源选型（journal / checkpoint / dead-letter / locker，topology-gated）
bootstrap::sagaprojectiondeps::resolve(ctx, clk, topo, cfg)
journal::GlobalReader
distlock::Locker
";
        let findings = scan_content(Path::new("docs/rules/eventbus.md"), src);
        assert_eq!(findings.len(), 4);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::SagaTenantScope)
        );
    }
}
