# L3 requirements → canonical PBI → 最低充分验证 owner

本表保留外部 requirement ID，但每行只指定一个 canonical Azure PBI 和一个最低充分验证 owner。依赖 PBI 可以协作
实施，却不成为第二 owner。T1/T2/T3 的定义、去重和执行边界只引用
[`project-scope.md` 的验证范围矩阵](../../rules/project-scope.md#验证范围矩阵)；本表不复制测试、provider、assembly
或 CI job inventory。

| Requirement | 归一化意图 | Canonical PBI | 最低充分验证 owner |
|---|---|---:|---|
| FR-001 | lifecycle 与 assembly activation 分离 | #1913 | T1 assembly schema/codegen closed model |
| FR-002 | Projection activation 闭值 | #1913 | T1 assembly manifest parser/schema red-green |
| FR-003 | Saga activation 闭值 | #1913 | T1 assembly manifest parser/schema red-green |
| FR-004 | omitted/disabled 零副作用 | #1914 | T3 omitted/disabled assembly runtime、DB capture、worker、route、serving 零副作用 journey |
| FR-005 | draft+active fail-closed | #1913 | T1 lifecycle×activation validation |
| FR-006 | Projection capability coverage | #1920 | T3 production startup missing-capability journey；#1914 提供 T1 exact-set startup compiler 前置 |
| FR-007 | Saga capability coverage | #1926 | T3 production startup exact resource-closure missing-capability journey |
| FR-008 | definition catalog 不决定部署 | #1914 | T1 assembly-plan-only construction guard |
| FR-009 | 删除 production blanket unsupported | #1914 | T1 production registry construction guard |
| FR-010 | Projection capability/role 分离 | #1915 | T2 PostgreSQL privilege conformance |
| FR-011 | serving 禁读 raw source | #1915 | T2 PostgreSQL negative privilege test |
| FR-012 | tenant/projection/binding scoped source | #1916 | T2 real PostgreSQL scoped-source conformance |
| FR-013 | fixed-query high-water | #1916 | T2 query-plan/capacity regression |
| FR-014 | SECURITY DEFINER hardening | #1915 | T2 migration privilege/search_path negative test |
| FR-015 | Settings metadata-only model | #1918 | T2 migration/schema static + repository integration test |
| FR-016 | Settings RLS/uniqueness | #1918 | T2 real PostgreSQL RLS/constraint test |
| FR-017 | mutation+dedupe same transaction | #1918 | T2 transaction atomicity/commit-unknown test |
| FR-018 | ProjectionTarget conformance | #1917 | T2 canonical ProjectionTarget suite |
| FR-019 | Projection worker assembly lifecycle | #1920 | T3 production start/readiness/drain journey |
| FR-020 | fatal exit 可见 | #1920 | T3 worker-exit/readiness journey |
| FR-021 | 低基数 Projection 指标 | #1922 | T1 metric descriptor/label test |
| FR-022 | promote preconditions | #1921 | T3 caught-up/health/schema negative journey |
| FR-023 | pointer CAS/fencing | #1921 | T2 pointer-store concurrency conformance |
| FR-024 | v3 typed generation resolver | #1921 | T3 Settings v3 serving journey |
| FR-025 | per-request generation snapshot | #1921 | T3 concurrent query/promote journey |
| FR-026 | Settings v4 authoritative 不变 | #1921 | T3 v4 authoritative regression journey |
| FR-027 | 受控 operator surface | #1922 | T3 operator authz/audit/replay journey |
| FR-028 | commit-order redesign 条件触发 | #1922 | T2 reproducible capacity benchmark |
| FR-029 | effectful step typed policy | #1923 | T1 contract schema/codegen negative fixtures |
| FR-030 | deterministic idempotency key | #1923 | T1 canonical vector/property test |
| FR-031 | protected durable receipt | #1924 | T2 real PostgreSQL receipt-store conformance |
| FR-032 | receipt+journal atomic visibility | #1924 | T2 transaction/commit-unknown integration test |
| FR-033 | receipt conflict fail-closed | #1924 | T2 duplicate/conflict conformance |
| FR-034 | resume from receipt | #1925 | T2 Saga executor recovery conformance |
| FR-035 | unknown outcome policy | #1925 | T2 provider probe/repair conformance |
| FR-036 | pinned definition identity | #1923 | T1 schema/codegen exact identity test |
| FR-037 | bounded retry classification | #1923 | T1 policy state-machine/property test |
| FR-038 | stale lease/epoch fence | #1925 | T2 stale-writer concurrency conformance |
| FR-039 | billing draft/未激活 | #1926 | T3 disabled-billing zero-side-effect journey |
| FR-040 | 无 active/runtime exactly-once 声明 | #1925 | T1 contract/source semantic guards |
| FR-041 | Projection 独立 fault hazards | #1927 | T3 Projection real-backend fault owner |
| FR-042 | Saga 独立 fault hazards | #1928 | T3 Saga PostgreSQL/Redis fault owner |
| FR-043 | fixture/runner/evidence exact parity | #1929 | T1 typed evidence registry exact-set guard |
| FR-044 | affected L3 验证选择 | #1929 | T1 typed impact-planner red-green tests |
| FR-045 | 条件式 same-head required aggregate | #1929 | T1 aggregate receipt/same-head gate test |
| FR-046 | LOC 仅作设计预算 | #1912 | 人工 plan/review；明确不设 enforcement |
| NFR-001 | tenant/security fail-closed | #1929 | T1 exact security-receipt aggregation：Projection access、Saga stale-writer、两侧 operator |
| NFR-002 | 敏感数据最小化与脱敏 | #1929 | T1 exact privacy-receipt aggregation：read model、receipt、log/Debug、metric labels |
| NFR-003 | crash 可见与旧 generation 可用 | #1929 | T1 exact availability-receipt aggregation：worker failure/readiness + failed-promote old-generation serving |
| NFR-004 | Projection/Saga 可恢复 | #1929 | T1 exact recovery-receipt aggregation：#1927 Projection rebuild + #1928 Saga pinned recovery |
| NFR-005 | fixed-query 与 resolver SLO | #1922 | T2 reproducible query/latency benchmark |
| NFR-006 | lock/fairness/latency 容量 | #1922 | T2 capacity benchmark owner |
| NFR-007 | 窄 operator 可运维性 | #1929 | T1 exact operator-receipt aggregation：Projection 与 Saga authn/authz/audit/fencing |
| NFR-008 | Settings v4 compatibility | #1921 | T3 v4 authoritative regression owner |
| NFR-009 | generation/definition 可演进 | #1929 | T1 exact identity-receipt aggregation：Projection generation + Saga definition version/digest |
| NFR-010 | owner/evidence 可追踪、无 prose/LOC gate | #1929 | T1 typed planner/evidence owner |

## Azure 结构与 predecessor

- #1911 是 Epic，#1912–#1929 是直接 PBI 子项；不创建 Feature 层。
- 当前 predecessor DAG 由 #1911 最新 `pm:epic-wave` 评论滚动维护，本文件不复制动态 wave。
- 条件项 X01/X02/X03 只保留 Epic Trigger；触发前不创建 speculative PBI。
- #1929 是复合 NFR 的唯一验证 owner：它只接受上表点名的 typed receipt exact-set，不替代 #1915–#1928
  对各独立 hazard 的真实 adapter/journey 主证明，也不使依赖 PBI 成为该 NFR 的第二 canonical owner。
- 旧条目 #1269、#1415、#1566、#1652、#1714、#1684、#1246、#1268、#1267、#1718、#1746、
  #1850 已由新 PBI body 指明承接关系，不重开旧条目。
