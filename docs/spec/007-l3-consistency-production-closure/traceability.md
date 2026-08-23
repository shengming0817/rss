# L3 requirements → canonical PBI → 最低充分验证 owner

本表保留外部 requirement ID，但每行只指定一个 canonical Azure PBI 和一个最低充分验证 owner。依赖 PBI 可以协作
实施，却不成为第二 owner。T1/T2/T3 的定义、去重和执行边界只引用
ADR-024；本表不复制测试、provider、assembly
或 CI job inventory。

| Requirement | 归一化意图 | Canonical PBI | 最低充分验证 owner |
|---|---|---:|---|
| FR-001 | lifecycle 与 assembly activation 分离 | #1913 | T1 assembly schema/codegen closed model |
| FR-002 | Projection activation 闭值 | #1913 | T1 assembly manifest parser/schema red-green |
| FR-003 | Saga activation 闭值 | #1913 | T1 assembly manifest parser/schema red-green |
| FR-004 | omitted/disabled 零副作用 | #1914 | T3 omitted/disabled assembly runtime、DB capture、worker、route、serving 零副作用 journey |
| FR-005 | draft+active fail-closed | #1913 | T1 lifecycle×activation validation |
| FR-006 | Projection capability coverage | #1920 | T3 production startup missing-capability journey；#1914 提供 T1 exact-set startup compiler 前置 |
| FR-007 | Saga capability coverage | #1926 | synthetic assembly/operator T2 closure；独立条件项 #1968 只在产品激活条件满足后建立真实 production startup/adopter T3，不成为本行第二 owner |
| FR-008 | definition catalog 不决定部署 | #1914 | T1 assembly-plan-only construction guard |
| FR-009 | 删除 production blanket unsupported | #1914 | T1 production registry construction guard |
| FR-010 | Projection capability/role 分离 | #1915 | T2 PostgreSQL privilege conformance |
| FR-011 | serving 禁读 raw source | #1915 | T2 PostgreSQL negative privilege test |
| FR-012 | tenant/projection/binding scoped source | #1916 | T2 real PostgreSQL full-scope/read/replay conformance：operator-issued 30-second single-use tenant capability、bounded orphan sweep、DB-side payload filter、cross-tenant/binding/expired/token-replay negative |
| FR-013 | fixed-query high-water | #1916 | T2 capability-gated fixed function semantics + 100,000-row query-plan/buffer regression：invalid scope typed fail-closed、valid empty `NULL`、per-static-binding indexed tail seek |
| FR-014 | SECURITY DEFINER hardening | #1915 | T2 migration privilege/search_path negative test |
| FR-015 | Settings metadata-only model | #1918 | T2 migration/schema static + repository integration test |
| FR-016 | Settings RLS/uniqueness | #1918 | T2 real PostgreSQL RLS/constraint test |
| FR-017 | mutation+dedupe same transaction | #1918 | T2 transaction atomicity/commit-unknown test |
| FR-018 | ProjectionTarget conformance | #1917 | T2 canonical ProjectionTarget suite |
| FR-019 | Projection worker assembly lifecycle | #1920 | T3 production start/readiness/drain journey |
| FR-020 | fatal exit 可见 | #1920 | T3 worker-exit/readiness journey |
| FR-021 | 低基数 Projection 指标 | #2010 | T1 metric descriptor/label test：active/shadow worker 导出 lag、checkpoint freshness、apply failure、Projection DLQ backlog、processed throughput；无 dashboard/alert/SLO；CLI replay 不发 worker metric |
| FR-022 | promote preconditions | #1921 | T2 real PostgreSQL swap negative conformance：identity/high-water/quarantine 漂移均拒绝且旧 selection 不变 |
| FR-023 | pointer CAS/fencing | #1921 | T2 real PostgreSQL single-transaction CAS + deterministic append/swap concurrency conformance |
| FR-024 | v3 typed generation resolver | #1921 | T2 Settings typed port ↔ fixed PostgreSQL resolver、RLS/ACL 与 cross-tenant conformance |
| FR-025 | per-request generation snapshot | #1921 | T1 resolve-once request snapshot state/concurrency component test |
| FR-025a | active bind 与长期 typed consumer 同一 callable service | #1921 | T1 move-only plan handoff + concrete `Arc::ptr_eq` + callable metadata consumer test |
| FR-026 | Settings v4 authoritative 不变 | #1921 | T1 authoritative handler/repository regression + projection resolver zero-call guard |
| FR-027 | 受控 operator surface | #1922 | #1921 先以 T1 SettingsOnly sealed maintenance registry reachability 闭合 activation prerequisite；#1922 持既有 status/replay/swap operator surface（pause/resume/容量），不持有 T3 operator journey |
| FR-028 | commit-order redesign 条件触发 | #1922 | T2 reproducible capacity benchmark |
| FR-029 | effectful step typed policy | #1923 | T1 contract/codegen negative fixtures + trybuild typestate/receipt compile-fail |
| FR-030 | deterministic idempotency key | #1923 | T1 domain-separated canonical vectors：identity/scope 敏感、attempt 不敏感、Debug 不泄露 |
| FR-031 | protected durable receipt | #1924 | T2 real PostgreSQL receipt-store conformance |
| FR-032 | receipt+completion atomic visibility | #1924 | T2 transaction/commit-unknown integration test |
| FR-033 | receipt conflict fail-closed | #1924 | T2 duplicate/conflict conformance |
| FR-034 | single-store journal-cursor resume + typed receipt hydrate | #1925 | T2 Saga executor recovery conformance |
| FR-035 | unknown 不 retry；typed probe/operator decision | #1925 | T2 provider probe/repair conformance |
| FR-036 | pinned definition identity | #1923 | T1 schema/codegen identity + memory/PostgreSQL register/read/list parity + exact registry start/resume |
| FR-037 | bounded retry classification | #1923 | T1 attempt/time 双预算、饱和 backoff/jitter 与五类闭合状态机 property test |
| FR-038 | single durable store lease/epoch fence | #1925 | T2 stale-writer concurrency conformance |
| FR-039 | billing draft/未激活 | #1923 | T1 draft fixture + production runtime view/DB rows/worker/probe/route 全空 regression；#1926 只提供 synthetic T2 seam，不声明 active Saga production capability |
| FR-040 | active/runtime 只承诺 at-least-once，无 exactly-once 声明 | #1925 | T1 source semantic + durable recovery AST guards |
| FR-041 | Projection multi-worker concurrent checkpoint fencing | #1927 | hazard→owner exact-set：commit-unknown→#1917/#1918；pointer/promote/rollback/generation→#1921；cross-tenant→#1916/#1918/#1921；checkpoint/DLQ split + assembly lifecycle→#1920；multi-worker checkpoint fencing→#1927。#1927 证据：**T1** `eventexec`::`projection_workers_competing_for_same_generation_checkpoint_converge_and_fence_stale_writer`（runner：barrier + 内存 CAS → Completed/Fenced、CountingDlx=0）；**T2** `postgres`::`settings_projection_dual_worker_same_generation_checkpoint_fences_stale_writer`（双 `rss_projection_worker` capability、worker-scoped shadow checkpoint CAS、Settings 行/收据/high-water 唯一收敛、`dead_letter`=0）；**T3=N/A**。T2 不重复 T1 runner 状态机；T1 不宣称真实 PG/worker ACL |
| FR-042 | Saga 独立 fault hazards | #1928 | T2 真实 PostgreSQL durable store + Redis external effect/probe fault owner；Redis 不承担 Saga lease/journal/receipt，T3 adopter 留给 #1968 |
| FR-043 | fixture/runner/evidence exact parity | #1928 | T1 typed fixture/runner/test/provider-evidence exact-set guard；#1929 只做 same-head verification-only 回读，不新建 evidence registry |
| FR-044 | affected L3 验证选择 | #1929 | T1 typed selector red-green tests |
| FR-045 | 条件式 same-head required aggregate | #1929 | T1 aggregate receipt/same-head gate test |
| FR-046 | LOC 仅作设计预算 | #1912 | 人工 plan/review；明确不设 enforcement |
| NFR-001 | tenant/security fail-closed | #1929 | verification-only：回读既有 Projection access、Saga stale-writer、两侧 operator 安全证明 |
| NFR-002 | 敏感数据最小化与脱敏 | #1929 | verification-only：回读既有 read model、receipt、log/Debug、metric labels 隐私证明 |
| NFR-003 | crash 可见与旧 generation 可用 | #1929 | verification-only：回读既有 worker failure/readiness + failed-promote old-generation serving 证明 |
| NFR-004 | Projection/Saga 可恢复 | #1929 | verification-only：回读既有 #1917/#1918/#1919/#1921 Projection rebuild 与 #1928 Saga pinned recovery 证明 |
| NFR-005 | fixed-query 与 resolver SLO | #1922 | T2 reproducible query/latency benchmark |
| NFR-006 | lock/fairness/latency 容量 | #1922 | T2 capacity benchmark owner |
| NFR-007 | 窄 operator 可运维性 | #1929 | verification-only：回读既有 Projection 与 Saga authn/authz/audit/fencing 证明 |
| NFR-008 | Settings v4 compatibility | #1921 | T1 v4 contract/handler/repository authoritative regression owner |
| NFR-009 | generation/definition 可演进 | #1929 | verification-only：回读既有 Projection generation + Saga definition version/digest 证明 |
| NFR-010 | owner/evidence 可追踪、无 prose/LOC gate | #1929 | verification-only：回读 typed selector/owner |

## Azure 结构与 predecessor

- #1911 是 Epic，#1912–#1929 是直接 PBI 子项；不创建 Feature 层。
- 当前 predecessor DAG 由 #1911 最新 `pm:epic-wave` 评论滚动维护，本文件不复制动态 wave。
- 条件项 X01/X02/X03 只保留 Epic Trigger；触发前不创建 speculative PBI。
- #1929 是 verification-only：回读既有 selector/fixed Job 与上表点名证明的 same-head 结果，不持有复合 NFR
  主证明面，不替代 #1915–#1928 对各独立 hazard 的真实 adapter/journey 主证明，也不创建 evidence registry。
- #2010 持 FR-021 Projection worker 低基数指标 T1（active/shadow 五类；无 dashboard/alert/SLO；CLI replay 不发
  worker metric）。#1927 仍只持 multi-worker concurrent checkpoint fencing T1/T2（T3=N/A）。#1922 不持有
  T3 operator journey。
- #1923 的 exact resume 只表示按 instance pinned identity 解析旧 factory；崩溃后的 receipt 恢复不在其证明面。
  FR-031–FR-033 的 protected receipt/completion atomicity 由 #1924 持有；#1925 持有单一 durable store/lease、
  journal cursor、typed hydrate/probe/operator，以及 unknown 不进入 retry 的恢复证明。
- #1916 只持 scoped source 与 fixed-cost high-water 的 T2 owner，并保留全局 commit-order advisory xact lock；
  checkpoint/target 归 #1917，#1921 通过同一事务的 lock→high-water→fenced pointer CAS 闭合 TOCTOU，lock wait、
  tenant fairness、throughput、业务事务延迟与 X01 阈值仍归 #1922。#1921 的 FR-022–FR-026（含 FR-025a）/NFR-008 只使用
  最低充分 T1/T2，不新增 production journey、T3 carrier 或 CI gate。FR-041 各 hazard 拆分 owner：commit-unknown
  归 #1917/#1918；pointer/promote/rollback/generation 归 #1921；cross-tenant 归既有 #1916/#1918/#1921 安全收据；
  checkpoint/DLQ split 与 assembly lifecycle 归 #1920；#1927 仅持 multi-worker concurrent checkpoint fencing
  T1/T2 残差（T3=N/A），不是全量 Projection fault matrix owner。
- 旧条目 #1269、#1415、#1566、#1652、#1714、#1684、#1246、#1268、#1267、#1718、#1746、
  #1850 已由新 PBI body 指明承接关系，不重开旧条目。
