# LocalTx 规则

本文件只写 L1/LocalTx 的声明、执行与验证边界。机器真源是 `xtask` typed manifest / R22、
`vocab::LocalTx*` 闭值、compiled `generated::http::LOCAL_TX_SPECS`、typed route/provider marker、
`workspacefacts` 拥有的 Cargo package/path/target/direct-dependency facts、conformance、Postgres runner、
metrics 与 active journey；本文不维护平行 gate inventory，也不复述 runner 与 lint 的实现细节。

## Proof chain

采用顺序固定为：contract LocalTx evidence → compiled `LOCAL_TX_SPECS` → owner/production route → domain
conformance → typed backend profile/provider probes → Postgres runner settlement/telemetry → active journey。

任一层缺失、重复、未知、孤立、伪造或 route/provider 身份不一致都 fail-closed。

各级验证的覆盖面不得互相冒充：

- `verify --fast` 门集（真源 `xtask/src/verify.rs`）不拥有 LocalTx 证明。静态闭环由 affected
  `make ci` 的 Consistency domain 选择，或显式运行 `localtx-coverage`；两者都不运行 conformance、
  不连接 Postgres。
- 完整 `verify` 额外执行 conformance 与 integration-target compile-only；**编译成功不等于真实事务矩阵已执行**。
- 真实后端证据只由 Postgres integration job 产出；required tooling、服务启动与编译后测试 inventory 均
  fail-closed，closeout 不允许跳过缺失工具。
- receipt 只在 typed batches 全部成功且 canonical inventory 完整时铸造，并对 artifact、HEAD、plan digest、
  run/attempt 做 exact match。静态 proof/report 不进入真实后端证据槽位；report 也不是新的 enforcement carrier。

## Contract evidence

`consistencyLevel = "LocalTx"` 必须是 `kind = "http"`，并声明完整 `[capabilities.localTx]`。
字段与取值均为闭集，旧的 boundary-only 形态不再接受。

```toml
[capabilities.localTx]
boundary = "single-domain"
txModel = "tenant-scoped-uow"   # 或 "repo-atomic-cas"
retry = "bounded-transient"
commitUnknown = "not-retryable"
```

- `boundary = "single-domain"`：一个 LocalTx 只覆盖单一域 crate 拥有的本地持久化边界。
- `txModel` 是闭合执行模型，必须与执行体一致：
  - `tenant-scoped-uow`：显式 Unit of Work 承载事务生命周期。
  - `repo-atomic-cas`：单次 repository mutation 以原子 compare-and-set 完成；冲突不得写入，handler 不自动重试。
  - 两种模型的 tenant scope 都必须来自上下文/注入边界，不得从 HTTP body 取得。
- `retry = "bounded-transient"` 按模型解释：UoW 只允许有界瞬态重试且每次重试必须重建完整 transaction scope；
  CAS 模型的 handler 不自动重试冲突，冲突返回调用方由其基于新版本重新发起。
- `commitUnknown = "not-retryable"`：提交结果未知时不得自动重放整个副作用序列，也不得重放同一条件写——
  第一次调用可能已经提交。
- 载体：`serde` typed struct + closed enum + `deny_unknown_fields` 把缺字段、未知字段与未知枚举 Hard 化；
  R22 是 Medium 条件门（只有 L1 允许 localTx block，且 L1 必须声明完整证据）。
- 四个运行期闭值只在基础层 `vocab` 定义一次，generated 与 consistency 复用同一类型身份，不各自维护镜像 enum。
  新增或改名必须同时通过 Rust 穷举编译、codegen golden 与 public-api 门。

## Runtime meaning

LocalTx 表示一次 HTTP handler 内的单域、租户作用域本地原子写。它**不**表示跨域事务、
**不**表示 outbox 发布已兑现、**不**表示 saga/reconcile/workflow 已接线。

- UoW settlement 语义只描述 `tenant-scoped-uow`，不可外推为 `repo-atomic-cas` 的业务模型：
  后者的 handler 不持有显式 UoW，也不按 UoW 语义重放整条 find→mutate 序列。
- Postgres 的底层 retry 仍可作为 **mutation port 内**单次 CAS 的事务承载：仅对已确认 rollback 的
  transient attempt 有界重试；版本冲突与 commit-unknown 不重试。
- `LocalTxFinalStatus` 把一次 UoW 结算闭合为 `committed` / `rolled_back` / `rollback_failed` /
  `commit_unknown`。只有显式 rollback 成功才能报告 `rolled_back`。
- retry class 与事务结算正交：不能据 `TxRetryFinalStatus` 猜测 rollback 或 commit outcome。
- 多步 handler 不得把两次 port 调用描述成同一显式 UoW。若业务由「读最高版本 → 构造候选 → 单次条件写」
  组成，正确性只由那次条件写保证，contract 必须声明 CAS 模型。
- 跨事务序列（如先 durable append 再另池读取）不得声称同一事务，系统也不自动重试整条序列。
- 每条 route 的 observation 必须由域层封装成 route-specific typed command 交给 adapter；
  adapter 不能把其它 route 的 observation、裸 tenant 或 generic append 接到该事务边界。
  内部 / rollback 路径必须使用互不可换且不携带 HTTP evidence 的 command。

## Backend conformance profiles

- 启用容器的 adapter 集成测试按 `txModel` 组合 provider-agnostic conformance。
  `testkit` 只接受调用方注入的泛型闭包与快照，不依赖 production adapter、domain crate 或 LocalTx canonical enum。
- profile 模型与 required probes 始终由 contract manifest 的 canonical model 推导；
  adapter 不得用字符串、第二套 enum 或 allowlist 重述。
- 每个测试函数只能声明一个 backend profile marker，禁止多个 contract 共用同组 probes。
  同一 contract 可拆多个 shard，required probes 只在 route + provider 二元组完全一致时合计。
- 每个 shard 必须声明匹配的 provider binding 并在测试体内构造真实 provider。
  通用 toy transaction table 与全局事务入口明确禁止作为 backend evidence。
- 缺 enrollment、错用较小 profile、缺 probe、缺 provider binding、单测试多 marker、伪造 dependency
  或孤儿 marker 均阻断 verify。正确 route marker 配错 provider 同样 fail-closed。
- 类型签名承担 Hard 的 route 身份约束；跨 manifest/source/test 的完整闭环评级为 Medium。

`tenant-scoped-uow` profile 必须组合 commit、rollback、validation/authorization no-write、tenant isolation、
retry boundary policy 与两个 no-replay 断言。`repo-atomic-cas` profile 必须组合 commit、
validation/authorization no-write、tenant isolation、CAS conflict、单次 CAS 内部 transient retry 与
unknown-result no replay；它不运行 handler-level rollback settlement。

断言纪律：

- commit-unknown 与 rollback-failed 是两个不可交叉传入的独立类型，只接受 action、预期静态错误类别与
  attempt probe，不接受 snapshot 或 write-count。第一次 attempt 可能已经 durable，
  故只能断言 attempt = 1，**禁止伪断言 no-write**。
- 所有 case 字段私有且只能经构造器建立；action 是 `FnOnce`，防止 harness 自身重放。
- 采样顺序固定为 action → snapshot → count；count 必须是 fixture 隔离的 action-local delta，
  不能使用并发测试可改写的进程全局累计值。
- retry boundary policy 的成功路径 expected attempts 与 exhaustion budget 都必须至少为 2，
  非法阈值在执行任一 action 前 fail-fast。
- 错误分类使用共享闭值分类与 typed stage，只携带闭值与 opaque provider error，不接受自由字符串分类，
  也不格式化 credential、secret、tenant/device payload。

ref: sqlx sqlx-core/src/transaction.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e
ref: sqlx sqlx-core/src/pool/connection.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e

## Postgres runner 约束

实现细节见 `adapters/postgres` 的 `cotx` rustdoc；此处只列不可违反的边界。

- attempt 状态是 crate-private opaque 和式类型，非法的 result/status 组合在类型层不可表达（Hard）。
  生产 mint 构造器只对 settlement funnel 可见，兄弟模块只能消费。
- ConsumerTx 复用同一 opaque `LocalTxAttempt`，只通过私有穷尽 `fold` 投影到
  `eventexec::consumer_tx::ConsumerTxOutcome<PgConsumerTxCommitProof>`。commit ACK 铸造私有 proof；commit ACK
  缺失为 `CommitUnknown`；rollback ACK 缺失为 `RollbackFailed` 并覆盖原始错误/lease 分类；确认 rollback 后
  lease lost 才是 `Fenced`，其余 storage failure 是 `InfrastructureTransient`。不得暴露内部状态、返回
  `(status, Result)`，或用 bool/string 重建结算。
- sealed `TenantDb<ServingWriteLane>` 是 serving tenant scope 与 write transaction capability 的唯一入口；
  maintenance 使用互不兼容的 `TenantDb<MaintenanceWriteLane>`。每次 attempt 内先显式 acquire 连接并立即
  装入默认 armed 的 lease；完成 tenant GUC/timeout setup 后才私有铸造
  `TenantTx<ServingWriteLane>` 或 `TenantTx<MaintenanceWriteLane>`，随后只向 closure 交付
  `IdentityTx`、`SecretTx`、`EventingTx<Concern>`、`ReconcileTx` 等不可互换的 concern capability。
  调用方不能取得通用 `TenantTx`，也不能构造 wrapper、取得 pooled connection / 通用 executor、
  结算 transaction 或跨 attempt 复用授权。
- 只有 commit/rollback 收到明确 ACK，消费式方法才可解除 lease；取消、timeout、未结算与结算失败一律保持
  armed，Drop 时物理关闭连接，不得依赖驱动的 queued rollback 恢复后复用。
- 取消路径没有结算证据，**不得伪造 final status**。
- 显式 rollback 失败必须收口为独立 storage settlement 错误并保留因果链，不得把领域冲突误分类为 transient retry。
- retry operation 只接受 typed attempt：未结算与已回滚仅在分类为 transient 时有界重试；
  rollback-failed 与 commit-unknown 强制不可重试。
- LocalTx contract 必须使用 contract-aware runner 并传 opaque observation；通用 runner 只保留给
  adapter operation boundary。生产 adapter 只能消费 typed command 的解包结果，不得调用 domain factory、
  替换 observation 或手制 evidence。
- 每个 LocalTx generated module 暴露非可选的 LocalTx 常量，非 LocalTx module 不生成该常量。
- 两个 retry runner 复用同一私有 retry core，不以 `Option` context 或 bool 在运行期区分语义。
- 载体：`LOCALTX-PG-RETRY-PLACEMENT-01`（`pg-tenant-tx-guard`，Medium）——HTTP 路径只接受 typed command
  解包出的 marker-preserving observation 与无 boundary 参数的 contract-aware runner 同址形状；
  crate-private operation 类型仅为已知 route marker 实现，错误 route/boundary 配对不可编译。

execution budget 与 deadline：

- 所有 LocalTx retry invocation 使用单一默认预算。预算只保存 `Duration`，零值、零 reserve 或
  `reserve >= total` 无法构造。
- runner 在 invocation 起点只 mint 一组 absolute monotonic deadline，并把同一 opaque deadline 复制给所有
  attempt。token 字段与构造器私有；caller closure 必须立即向下传递 deadline，不能重置预算、读取原始时钟、
  跨 helper 转发或手制 token。
- deadline 分阶段约束 acquire / begin / setup / operation / backoff；到达 reserve 后不再 poll operation
  或启动下一 attempt。server 侧 statement/lock timeout 从剩余量派生，client monotonic deadline 始终为最终约束。
- deadline evidence 只由 settlement funnel 以闭合 stage mint 并直接进入 typed attempt 失败变体，
  不从错误字符串或共享 stage tracker 推断。
- deadline metric 只发闭标签，禁止 tenant、SQL、错误文本与 duration，也不新增 paging alert。
- 连接复用权限由私有 armed lease + borrow-bound transaction wrapper 在类型边界封闭；两个生产 write funnel
  必须有一条符号绑定一致的 acquire→begin→consuming finish 顶层必经数据流，且 finish 必须是 tail expression。
  载体：`PG-LOCALTX-QUARANTINE-TYPE-01`（Hard）+ `PG-LOCALTX-QUARANTINE-FUNNEL-01`（Medium，含 synthetic red）。

observation 纪律：

- observation 从 typed generated route 私有提取 domain / contract id，并在类型中保留 route marker。
- 每个 failed attempt 记录 settlement-safe retry class；invocation 结束只在本轮曾存在真实 settlement 时
  发 final 指标，并保留最后一个已观测状态。后续未结算 attempt 不得擦除它。
- 全程只有未结算状态时没有 transaction outcome，不得映射为 rolled-back 或 commit-unknown。
- `commit_unknown` / `rollback_failed` / retry exhausted 必须在 metrics 与 warn trace 中显式可见。

## Static coverage gate

`cargo xtask localtx-coverage` 是 residual Medium scanner：active LocalTx contract/spec **exact-set** 的唯一
owner 是 compiled `generated::http::LOCAL_TX_SPECS`（按 ID / mount key 与 discovered active LocalTx
manifest 对账；missing / extra / equal-count-wrong-set 均 fail-closed）。manifest 仍用于声明发现与
R22，但**不是** scanner exact-set 的唯一真源；也不再解析 generated Rust 源码重建第二份 registry。

Cargo package / path / target / direct-dependency facts 的唯一 owner 是 `workspacefacts`；xtask 只经
command-scoped `CommandWorkspaceFacts` 注入同一 `&WorkspaceFacts`，成功与失败路径至多加载一次 metadata。
scanner **不**自读成员 `Cargo.toml` 判定 package / dependency identity；source identity 只认
`workspacefacts` 的闭合 `DependencySource`，不得再投影第二套 source 字符串。

residual 继续闭合：owner domain、生产 typed route mount、typed test/journey marker、module/cfg/macro
reachability、board/spec/fixture/runner exact-set，以及真实 workspace non-empty anti-vacuity。
缺失、重复、孤儿或错误 owner 的证据均 fail-closed。

生产 route 证据的形状要求：

- 只接受绝对 typed `impl ::bootstrap::Domain for ...` 的 `init` 方法，registry 参数必须写成绝对路径类型，
  且 route group 必须是该参数在 `init` 顶层语句中的直接调用。
- endpoint 必须 inline 流入 closure router 参数的 mount，或经同 lexical scope 内唯一 local binding 单次流入。
- 普通 helper、未调用 closure、match/child block、同名自定义 group/mount 以及仅构造 endpoint 都不构成证据。
- carrier 身份只认 `WorkspaceFacts` 证明的同名真实 workspace package；package rename、self-alias、
  local shadow 或宏注入均不提供 carrier 身份。

测试 marker 的形状要求：

- 每条 active LocalTx contract 必须在 owner crate 的一个真实测试函数内声明且只声明一个 typed marker，
  且只接受以 `::vocab` / `::generated` 开头的 extern-prelude absolute 语法。
  旧 bare path、alias、注释、字符串、宏或集中 allowlist 均不兼容。

- 第三方测试属性必须由 `WorkspaceFacts::direct_dependencies` 证明其 dependency key 指向真实 registry package。
- marker 所在 lexical block 及其全部 enclosing scope 都不得含 item/statement-position 宏调用：
  这类宏可展开 `use` / `extern crate` / item，静态门无法证明它不会重绑定 carrier namespace，
  因此该 scope 及其 children 都被视为 opaque。表达式位置的宏不能向外层注入 item namespace，可接受。
  需要与断言共处时，把 marker 与测试体放入两个 sibling child block，不要为此改写惯用断言。
- 载体：route 身份由 rustc 编译期强制（`LOCALTX-TEST-MARKER-TYPED-01`，Hard）；
  跨文件存在性由 `localtx-coverage` 阻断（`LOCALTX-COVERAGE-CLOSURE-01`，Medium）。
  该 marker 只锚定至少一个现有 route/domain 测试，**不**表示 rollback、conflict 或 backend conformance 已兑现。

backend profile 的 residual（`LOCALTX-BACKEND-PROFILE-CLOSURE-01`）只保留：

- manifest-derived **required probe set**、typed enrollment、真实 provider 构造、可执行 test target，
  以及 provider-bound action dataflow（canonical 构造器为 dataflow root，经 `?` / 显式 `return` /
  尾表达式决定结果；free function、裸引用、丢弃结果、observer-only 与 synthetic outcome 不计）。
- 单测试单 profile、provider binding 与 route marker 一致、祖先 scope 无 `#[ignore]` /
  `#[should_panic]`；required receipt 只统计绑定真实 Postgres execution unit 的完整 profile。

已退役、改由 typed `testkit` + PostgreSQL T2 behavior 承担的约束：**backend probe body AST 形状**、
helper/name/launder 细节、非协议 journey call-order / 局部语句顺序 / source bait。scanner 不再锁这些形状。

active journey 的闭合要求：

- status board 把全部 active LocalTx HTTP contract 与 spec、fixture、各自唯一的 contract-specific runner
  做 1:1 闭合；该 board/spec/fixture/runner exact-set 与 compiled `LOCAL_TX_SPECS` 对账。新增、遗漏、
  重复或非 active entry 均 fail-closed，不维护 issue allowlist。
- runner 中的具名 journey marker 由 rustc 固定 route 与一致性级身份（Hard）；跨 TOML、compiled spec 与
  runner 的完整性由 `LOCALTX-JOURNEY-CLOSURE-01` 阻断（Medium）。非协议 call-order / source bait 已退役。
- 该闭环拒绝被祖先 `cfg` 禁用的 runner，要求每个 fixture case 唯一流入已执行的 consumer，
  并把 target 固定为唯一 Serial batch；批次显式要求非空测试清单，编译后清单为空即失败。
- durable runner 必须逐请求隔离采集 LocalTx metric，并在结束时确认每个 case 的响应与 accounting 均已被观测，
  拒绝用请求数字面量自证。
- 不暴露业务 CAS conflict 的 contract 必须把该路径显式声明为不适用并给出原因，**不得为满足矩阵伪造 conflict**。
- `commit-unknown` 是 closed journey scenario，只在具备该可观测路径的 journey 中声明；
  仅该 scenario 的 fixture case 可省略 commit 计数，其它 case 必须提供精确 attempts/commits accounting。

## Failure and adoption semantics

LocalTx correctness adoption 需要走通 contract evidence、generated check、typed route marker、backend profile/probes、
active journey 与最低充分 transaction accounting/diagnosis。reference SLO、paging alert、容量测量与运行 runbook 不是
contract 激活自动生成的实施项；它们只在 `project-scope.md` 的 GA-hardening trigger 明确放行后进入范围。
`.specify/templates/overrides/localtx-tasks-template.md` 是 planning entry，其中 operations/runbook 项必须按该 trigger 判定，
不得因 checklist 存在提前实施。trigger 未满足时，这些项必须标记为 `N/A（未授权）`，不得生成 issue、task、实现步骤或
验收要求；模板中对 operations carrier 的分类只描述已有 carrier，不构成新建或扩展 carrier 的授权。

模板只是 planning entry，**不是 enforcement carrier 或成熟度授权**：勾选状态不能当作实现证据，
模板本身也不设门。适用项的结果各自落在对应的 typed / compiled / static gate carrier 中，
少了哪一项由那个 carrier 报，不由模板报。

静态 proof report 的 canonical 入口是 `cargo xtask localtx report --format json|markdown`。
报告与 `localtx-coverage` 共享同一 command-scoped `WorkspaceFacts` 与 typed static inventory，但
**报告不是新的 enforcement carrier**：它只渲染静态源码闭合结果，不替代 `localtx-coverage` 门，
也不替代 required real-backend evidence。静态 source inventory 与 runtime / Postgres 执行证据严格分离。

新建或修改 LocalTx contract 的顺序：选择与实现一致的 `txModel` → 补齐全部闭值 evidence → 生成
`LOCAL_TX_SPECS` → 绑定唯一 owner/production route → 为真实域路径补 conformance → 在需要 Postgres
事务语义时注册一对一的 typed backend profile/provider probes → 进入 active journey。
metrics 与 traces 必须复用闭值 label，不能用自由字符串、第二套 enum、toy transaction 或文档声明替代证据。

结算断言的底线：

- 前置 validation 与 unauthenticated 路径必须证明 no-write。
- 已认证 authorization deny 若契约要求 durable denial audit，只允许写该目标绑定的拒绝审计，
  业务读写仍必须为零且 fixture 必须精确声明 attempts/commits。
- CAS conflict 与 permanent error 恰好一次且零写；transient 只在确认 rollback 后按预算重建 transaction scope。
- `commit_unknown` 与 `rollback_failed` 都只能断言 attempt = 1：第一次 attempt 可能已经 durable，
  禁止 replay，也禁止伪造 snapshot 或 no-write 结论。unknown outcome 不得降格成 confirmed rollback 或零提交。
