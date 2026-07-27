# rss

RSS 是 GoCell 的 Rust 重写——domain-native 治理 + 惯用扁平 Cargo workspace（无 cell/slice 外壳）。

## 结构

扁平 workspace：`crates/`（库 crate，分基础/引擎/服务/域四层）、`adapters/`、`bins/`、`xtask/`、`generated/`。
完整结构树 / 分层 / 命名的**单一事实源**见 [`docs/rules/architecture.md`](docs/rules/architecture.md)；
最高协作规范见 [`CLAUDE.md`](CLAUDE.md)。分层由 crate 依赖图（编译期）+ `deny.toml` wrappers 强制。

## 构建与本地验证

本地和 GitHub Actions 共用同一个 typed `ImpactSet`：本地投影生成 preflight，远端投影从闭合
`CiJobKey` 派生唯一动态 matrix，再由稳定 `ci gate` 核对计划、聚合结果和 evidence v4 回执。
当前承载状态与激活条件见 [`docs/ops/202606231530-001-ci-lane.md`](docs/ops/202606231530-001-ci-lane.md)。

```bash
make ci                                  # 分析 origin/develop...HEAD 的已提交差异并运行本地 preflight
make ci CI_BASE=upstream/develop         # 显式指定比较基准
make ci CI_ARGS='--fail-fast'            # 需要首错停止时显式启用
make ci CI_ARGS='--only test --only clippy' # 仅复验 affected test/clippy（partial）
make verify VERIFY_ARGS='--only runtime-root-guard' # 仅复验一个 typed gate（partial）
make ci-full                             # 显式执行完整本地 CI 门集
./hack/cargo.sh xtask ci local --base origin/develop
./hack/cargo.sh xtask ci full
```

Make 通过 `hack/cargo.sh` 启动 xtask，是本地治理门的受控 bootstrap。直接运行 `cargo xtask ...`
仍执行相同 typed gate plan，并与 wrapper 共用 worktree-local target 默认值；但启动 xtask 的外层 Cargo
不会获得 wrapper 的 build-jobs 默认值、ambient rustc-wrapper 清洗或 sccache 自动策略，因此不是等价入口。

`ci local` 只读取 `<base>...HEAD` 的已提交项目差异，不扫描 untracked、本地工具或额外工作区文件。
无差异直接成功；docs-only 只运行 fast/meta；Rust、contract 与 generated 影响运行反向依赖 check 和直接
影响包 test/clippy。未知路径本地忽略并留痕，但不会抹掉同一 diff 中已知包的定向测试；rename/copy 运行
fast/meta，影响分析失败直接报错。本地 preflight 的 worker 进程组受 600 秒 wall-clock deadline 约束，且不运行
coverage、audit 或真实后端 integration；需要人工诊断无条件全量门时使用 `make ci-full`。

本地 `verify`、`ci local` 与 `ci full` 默认 keep-going：聚合层继续执行后续 gate/stage，Cargo
build/check/clippy 与 cargo test/nextest 同时启用各自的继续执行参数，最后稳定汇总全部失败并返回非零。
`--fail-fast` 可恢复首错停止；600 秒 supervisor 超时和取消信号仍立即终止。推荐修复循环是：先运行默认
完整诊断收齐错误，再用可重复的 `--only` 定向复验，最后不带 `--only` 完整运行一次 affected CI。
任何 `--only` 成功都只是 partial 诊断结果，不代表完整 CI 通过。远端 `ci run --job` 保持 fail-fast。
L0/L1 的采用与故障语义分别见
[`docs/rules/consistency-l0.md`](docs/rules/consistency-l0.md) 与
[`docs/rules/localtx.md`](docs/rules/localtx.md)；精确 gate 成员与顺序只以 typed registry 和
`xtask/src/verify.rs` 派生计划为准。

CI 子命令不保留旧的平铺 lane 入口；空的 `ci` 也会报错。planner、typed executor 与 gate 的接口为：

```bash
./hack/cargo.sh xtask ci plan <planner-options>
./hack/cargo.sh xtask ci run --job ci-meta
./hack/cargo.sh xtask ci run --job ci-local-only --required-evidence-output <report-path>
./hack/cargo.sh xtask ci run --job integration/postgres-domain
./hack/cargo.sh xtask ci run --job audit
./hack/cargo.sh xtask ci gate <gate-options>
```

`integration/postgres-domain` 是 LocalTx required-evidence 的唯一 typed owner。CI 只在该 job 的全部真实
Postgres batch 成功后生成 `integration/localtx-required.json`；`ci gate` 要求它与计划、HEAD、run/attempt
完全一致且 active/journey/backend-profile 三项均为 5。`verify --fast` 与 `localtx report` 只证明静态闭包，
不能替代这份真实后端 receipt。当前 required-check 激活边界及人工验证清单见
[`docs/ops/202607150329-1776-localtx-required-evidence.md`](docs/ops/202607150329-1776-localtx-required-evidence.md)。

`ci-local-only` 是 LocalOnly required-evidence 的唯一 typed owner。它从 static source receipt 的 typed
inventory 单源派生 package、library test target 与 exact filter；全部 nextest 测试成功且
active/source/executed 三集合完全相等后，才原子发布唯一 schema v1 报告。当前 anti-vacuity 基线为 6/6/6。
`verify --fast` 只证明静态 source receipt，不产生或声称产生运行证据；完整 `verify` 与 `ci-local-only`
复用同一个 runner。Azure 窄 build validation 的激活与同一 policy RED/GREEN 验收见
[`docs/ops/202607151200-1815-localonly-execution-evidence.md`](docs/ops/202607151200-1815-localonly-execution-evidence.md)。

以下是常用开发检查，并非 `verify` 内部 typed step 的逐条公开命令；完整本地治理门运行
`make ci-full`，差异感知的 PR 收尾运行 `make ci CI_BASE=<remote>/develop`：

```bash
cargo fmt --all -- --check                             # 格式
cargo xtask contract validate                          # 契约元数据校验
cargo xtask assembly validate                          # assembly 声明与依赖闭包校验
cargo xtask assembly generate-modules --check          # domain modules 生成物漂移门
cargo xtask assembly generate-providers --check        # typed provider catalog 独立漂移门
cargo xtask assembly lock check                        # 全仓 AssemblyLock raw-byte 漂移门
cargo xtask deployment plan check                      # DeploymentPlan + 三 profile Helm 静态/render 漂移门（需 Helm 4.2.0）
cargo xtask deployment policy check                    # 两阶段资源语义 + kubeconform v0.7.0 strict 门
cargo xtask runtime-baseline verify                    # RuntimePlan 四族 live closure 与 wiring golden
cargo xtask runtime-root guard                         # runtime root 单调职责/LOC ratchet
cargo xtask layer-deps                                 # source-centric 分层依赖 lint
cargo xtask codegen --check                            # 契约 codegen 漂移门
./hack/cargo.sh xtask l2-assurance                     # 生成 9 producer + 5 fact 的 L2 assurance inventory
./hack/cargo.sh xtask l2-assurance --check             # 只读检查 committed inventory 的逐字节漂移
./hack/cargo.sh xtask provider-capabilities            # 生成 L2 provider conformance enrollment matrix
./hack/cargo.sh xtask provider-capabilities --check    # 声明、runner、shard 与 committed matrix 漂移门
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
cargo deny check                                       # 分层禁依赖 + license + advisory
cargo dylint --all                                     # AST 级自写 lint（domain 禁 derive serde 等）
```

`deployment plan render|check` 拥有 chart 内三份 DeploymentPlan、`profile+phase` 闭合 values/schema、六份
`helm template` golden 与 migration/serving 的 6+6 core/extension manifests。`check` 使用 Helm 4.2.0 对
runtime/settingsonly/identityaudit × migration/serving 全量 lint/render并复用跨资源 semantic policy；`render`
只在全组合预检成功后原子发布 29 个载体。`deployment policy check` 再验证 rendered/schema exact closure，
并用 kubeconform v0.7.0 对 Kubernetes 1.30 core 与固定 CRD schema做 strict validation。两门均不执行
`helm install/upgrade/rollback`，cluster/kind 运行证据仍由 #1805 所有。

`runtime::operator::*` 是 operator 命令的唯一 Rust API 路径，serving 继续只使用
`runtime::{prepare_runtime, run, shutdown_runtime}`。共享时钟与审计 sink 只从
`runtime::support::{SystemClock, TracingAuthAuditSink}` 导入。旧 root operator/support 路径没有 alias 或兼容 shim；
`runtime-root guard` 的 append-only policy 会拒绝 root LOC、职责或 public surface 回涨。

`providers_gen.rs` 是每个 assembly crate 内部编译的 provider constructor catalog，不是外部
SDK/API，也不读取环境、配置或 secret。它只收 active provider，并通过闭合 role、consumer、factory
symbol 与 `ProviderCatalogEntry::checked` 绑定 canonical registry evidence；现有 `modules_gen.rs`
继续承载 live output composition，不能作为 catalog fallback。两类生成物分别漂移检查，固定聚合顺序为
`assembly validate → modules check → providers check → lock check → graph check`；live provider dispatch、
手写旁路删除和 output bijection 由 #1792 完成。
factory symbol 的 wire、Display 与 JSON Schema ID 统一使用显式 `consumer::factory` 声明；assembly
root 的 compile-link 守卫同时拒绝 crate-level `cfg` 及可递归展开为 `cfg` 的 `cfg_attr`，避免 catalog
引用与 non-empty 断言被条件编译整体移除。

`generated/l2-assurance.json` 是下游读取 L2 assurance inventory 的唯一 committed artifact；其 9 条
producer 与 5 条 fact 记录由 active contract、compiled registry、精确 mounted handler、receipt
execution graph、production composition、Postgres producer transaction closure、subscription
external-effect policy 和 ready fault evidence 共同派生。该文件只允许由 `l2-assurance` 更新，不手工
编辑；`--check` 不写文件，并拒绝缺失、篡改、CRLF 或输入漂移。

JSON v3 的紧凑 wire 约定如下；v2 不再读取或双写：

- 根字段固定为 `schemaVersion: 3`、`producerCount`、`factCount`、`contracts`。
- 每条 contract 共有 `contractId`、`domain`、`version`、`role`、`status`、`evidence`；producer
  另带 `emittedFacts`，fact 另带 `topic` 和
  `subscriptions: [{consumer, group, externalEffectPolicy}]`。
- producer `evidence` 只含 `contract`、`generated`、`execution`、`fault`；不再携带 v2 的
  `runtime/effect` 泛化 bag。`execution` 固定记录 generated route、精确 mounted handler 及按 fact
  排序的 terminals；每个 terminal 记录 domain call path、`Trait::method` port、`Type::method`
  provider、production `wire` 注入、`producer_tx`、`TxCapability`、canonical append 与 settlement。
  terminal fact 集必须与该 producer 的 `emittedFacts` 精确相等。producer `fault` 同样按 fact terminal
  记录 provider/transaction、rollback、commit-unknown、rollback-failed 与生产 no-replay carrier，
  不复用 consumer/relay fixture 冒充 producer settlement 证据。
- fact 继续携带其适用的 `contract/generated/runtime/effect/fault` evidence。普通 facet 是
  `{status, carriers}`，carrier 固定为 `{kind, path, symbol}`。
- 枚举是闭集：`role` 只有 `producer|fact`，record `status` 只有 `closed`，facet `status`
  只有 `complete`，`kind` 只有 `manifest|rust-symbol|fault-fixture`，`externalEffectPolicy`
  只有 `transactional-only|idempotency-key|reconcile|compensated`。
- 输出顺序是协议的一部分：contracts 按 `(contractId, role)`，`emittedFacts` 按 contract ID，
  subscriptions 按 `(consumer, group)`，carriers 按 `(path, symbol, kind)` 升序；pretty JSON 仅一个尾随 LF。
- consumer 必须按 `schemaVersion` 精确分派并拒绝未知字段或枚举值。任何字段、枚举或语义变更
  都必须升级 `schemaVersion`；不为旧版增加 alias、shim 或双写路径。

受控入口只接受以下两种形态；重复 flag、输出路径、兼容别名和其他参数均拒绝：

```bash
./hack/cargo.sh xtask l2-assurance
./hack/cargo.sh xtask l2-assurance --check
```

`generated/provider-capability-matrix.json` 是 L2 provider conformance 的唯一 committed catalog。
provider owner 中的 `provider_conformance_catalog!` 是声明单源：sealed tuple 在编译期固定每个
provider 的适用能力全集与顺序；宏为每项生成 live wrapper，wrapper 只能 await 唯一 canonical
provider behavior，且没有可伪造的 catalog receipt/mint API。`provider-capabilities --check` 再以
Rust AST 精确验证 wrapper→behavior 唯一边、能力专属语义锚点与行为摘要、tracked-source 闭集、
crate-root module/feature 可达性及 typed integration shard 归属。
矩阵 schema v1 的每条 capability 都携带唯一 `{status: enrolled, carrier}` receipt，不把静态 artifact
伪装成当前 checkout 的运行结果；只接受
PostgreSQL 7 项、AMQP 4 项与 S3 3 项共 14 条 enrollment，不读取旧 schema、alias、shim 或双写输出。

受控入口只接受以下两种形态；重复 flag、输出路径、兼容别名和其他参数均拒绝：

```bash
./hack/cargo.sh xtask provider-capabilities
./hack/cargo.sh xtask provider-capabilities --check
```

新 provider / capability enroll 步骤：

1. 在 `crates/testkit/src/eventing_conformance.rs` 扩展闭集枚举、`capabilities()` 与
   `SealedCompleteSet` exact tuple（macro token 用 snake_case，wire 用 kebab-case）。
2. 在对应 adapter owner 源文件调用 `provider_conformance_catalog!`，每项指向唯一 canonical
   behavior；compile-fail 负例放 `crates/testkit/tests/ui/`。
3. 运行 `./hack/cargo.sh xtask provider-capabilities` 重写矩阵，再用 `--check` 验收。
4. 通过 typed integration shard 跑该 provider 的 enrollment wrappers（shard 归属由矩阵
   `carrier.shard` 与 `xtask` integration lane 约束）。

完整语义与不变式见 `docs/rules/eventbus.md` §L2 provider conformance catalog。

工具链由 `rust-toolchain.toml` 钉定（首次进入目录自动安装）。治理工具的版本、安装 backend 与 CI lane
映射由 adapter catalog 单源维护；查看完整精确版本：

```bash
.github/scripts/ci-tool-adapters.sh specs --lane all --backend all
```

Cargo 构建产物遵循 worktree/job 隔离：直接 `cargo` 默认写当前 worktree 的 `.cache/cargo-target`，
受控入口（`make` / `hack/cargo.sh`）默认使用 N 槽串行独占租约池（`N=5`，
`$HOME/.cache/rss-cargo-target-pool/slot-K`）；`RSS_TARGET_POOL_N=off` 退回 worktree-local。
CI 写 `$RUNNER_TEMP/rss-cargo-target`。显式 `CARGO_TARGET_DIR` 在默认池下仍覆盖；与显式
`RSS_TARGET_POOL_N` 同设则 fail-closed。受控入口默认 `CARGO_BUILD_JOBS=2`，可由同名环境变量覆盖。
完整 target 不跨 worktree 或 CI job 共享可变状态；本地膨胀清理、`gc` 与 sccache 验收见
`docs/ops/202607171340-1851-local-target-pool-and-cleanup.md`。

`hack/cargo.sh`、Make 及其启动的 xtask 会清除外部 `RUSTC_WRAPPER`。默认 `auto` 会按 PATH
顺序物理规范化并验证 sccache 候选，跳过无效项，仅在找到首个精确版本 `sccache 0.15.0` 后启用
compiler cache；无合法候选时使用普通 Cargo，`RSS_COMPILER_CACHE=off` 可显式关闭。启用时强制
`CARGO_INCREMENTAL=0`。sccache 只在编译输入和逻辑路径对应的 cache key 相同时复用结果；Rust
hasher 会散列绝对工作目录，因此不承诺 RSS 自有 crate 跨不同绝对路径的 worktree 命中。cache
backend/server 故障只降低命中收益，不改变编译或测试 verdict。

> dylint 须 nightly：`cargo-dylint` / `dylint-link` 版本与 `lints/rust-toolchain.toml` 的 channel +
> `clippy_utils` rev **成对**，升级步骤见 `lints/README.md`（勿单独升任一侧，否则 ABI 不齐编译失败）。

门集 / `--fast` / 缺工具策略单源见 `xtask/src/verify.rs`。
