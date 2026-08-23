# rss

RSS 是 GoCell 的 Rust 重写——domain-native 治理 + 惯用扁平 Cargo workspace（无 cell/slice 外壳）。

## 结构

扁平 workspace：`crates/`（库 crate，分基础/引擎/服务/域四层）、`adapters/`、`bins/`、`xtask/`、`generated/`。
完整结构树 / 分层 / 命名的**单一事实源**见 [`docs/rules/architecture.md`](docs/rules/architecture.md)；
最高协作规范见 [`CLAUDE.md`](CLAUDE.md)。分层由 crate 依赖图（编译期）+ `deny.toml` wrappers 强制。

## 项目治理

- [贡献指南](CONTRIBUTING.md) / [Contributing](CONTRIBUTING.md)
- [安全策略](SECURITY.md) / [Security](SECURITY.md)
- [治理模型](GOVERNANCE.md) / [Governance](GOVERNANCE.md)
- [维护者](MAINTAINERS.md) / [Maintainers](MAINTAINERS.md)
- [发布策略](RELEASES.md) / [Releases](RELEASES.md)
- [行为准则](CODE_OF_CONDUCT.md) / [Code of Conduct](CODE_OF_CONDUCT.md)
- [MIT License](LICENSE)

## 构建与本地验证

gate、test 与 journey 的主要执行归属统一使用闭合的 canonical `ExecutionProfile`：`check`、`test`、
`integration-critical`、`release-check`；前三者只选择自己的 primary owner，`release-check` 是全部 owner
集合的并集，再按 typed subsumption 去重。workspace coverage 是 release-check 的唯一组件测试 owner，
`ComponentTests` nextest 在该 profile 中被 typed proof 吸收。

diff-adaptive `ImpactSet` 是正交的路径影响模型：它记录直接 package 影响、反向依赖闭包、稳定 `IntegrationUnitId`、
治理路径以及 docs/high-impact/unknown-path 状态。本地投影据此运行 `verify --fast` 门集（真源
`xtask/src/verify.rs`）加 affected 域门组成的 `meta`、反向闭包 check、直接 package test/clippy 与治理自测；
远端 preflight 则把同一影响闭包投影到固定 PR Job（Job 名与闭集以 `.github/workflows/ci.yml`
为真源；拓扑说明与运维激活状态见
[`docs/ops/202606231530-001-ci-lane.md`](docs/ops/202606231530-001-ci-lane.md)）。
集成影响直接投影 catalog 的 `IntegrationUnitId`，不维护第二套 generic execution-unit ID。

GitHub pull request 的执行拓扑固定（preflight 只构建一次 xtask，计算规范选择并在 10 分钟内运行有界编译/治理早筛；执行 Job 始终存在并分别消费自己的选择；
`test-affected` 除 affected 组件测试外还始终生产 producer-owned LocalOnly required evidence；gate 只聚合
执行 Job 的最终结果，不解析额外回执）。integration 使用四个显式、非 matrix 的闭合 group 并行 carrier，随后聚合为稳定的
`integration-critical` context；具体 Job 名与闭集以 `.github/workflows/ci.yml` 为真源，不在此手抄闭集。
分析失败、高影响根或保守 rename 会把 PR 选择升级为 `PrComplete`，但不会触发 `ReleaseCheck`。后者只属于
develop、release 或显式 `ci full`。
cargo-nextest profile 只配置 runner 的 timeout、retry、JUnit 与 filter 行为，不等同于 `ExecutionProfile`。
当前承载状态与迁移边界见 [`docs/ops/202606231530-001-ci-lane.md`](docs/ops/202606231530-001-ci-lane.md)。

```bash
make ci                                  # 分析 origin/develop...HEAD 的已提交差异并运行本地 preflight
make ci CI_BASE=upstream/develop         # 显式指定比较基准
make ci CI_ARGS='--fail-fast'            # 需要首错停止时显式启用
make ci CI_ARGS='--only test --only clippy' # 仅复验 affected test/clippy（partial）
make verify-fast                         # 运行 verify --fast 门集（见 xtask/src/verify.rs）
make verify VERIFY_ARGS='--only runtime-root-guard' # 仅复验一个 typed gate（partial）
make ci-full                             # 显式执行 release-check（workspace coverage，不重复 component nextest）
./hack/cargo.sh xtask ci local --base origin/develop
./hack/cargo.sh xtask ci full
```

Make 通过 `hack/cargo.sh` 启动治理命令。`ci local` 是特殊的 snapshot-first 入口：wrapper 在任何 Cargo
启动前转交 Python supervisor，supervisor 固定 base/HEAD/merge-base 并物化 detached committed snapshot，
随后只从 snapshot 的 wrapper 构建一次 xtask；impact planning、gate selection 和 gate execution 均由该唯一
snapshot worker 完成。直接 `cargo xtask ci local` 缺少这一来源边界，因而 fail-closed；使用 `make ci` 或
`./hack/cargo.sh xtask ci local --base ...`。其他 `cargo xtask ...` 仍可直接运行，但不会获得 wrapper 的
build-jobs 默认值、ambient rustc-wrapper 清洗或 sccache 自动策略，因此不是等价入口。

`ci local` 只读取 `<base>...HEAD` 的已提交项目差异，不扫描 untracked、本地工具或额外工作区文件。
无差异直接成功；docs-only 和 unknown-only 只运行 `verify --fast` 门集对应的 `meta`（真源
`xtask/src/verify.rs`）；Rust、contract 与 generated 影响运行反向依赖 check 和直接
影响包 test/clippy；direct package 还会与 canonical internal public-api owner catalog 求交，并由唯一
`PublicApi` gate 精确检查命中的 baseline，即使同一 diff 升级为完整 PR scope 也不会丢失。未知路径本地忽略并留痕，但不会抹掉同一 diff 中已知包的定向测试；rename/copy 运行
affected 域 `meta`（域集由 CI/verify 投影派生，不在此维护数量），影响分析失败直接报错。本地
preflight 的 snapshot checkout、xtask build 与全部 gate 共用一个受 600 秒 wall-clock deadline 约束的
worker 进程组，且不运行
coverage、audit 或真实后端 integration；需要人工诊断无条件全量门时使用 `make ci-full`。

本地 `verify`、`ci local` 与 `ci full` 默认 keep-going：聚合层继续执行后续 gate/stage，Cargo
build/check/clippy 与 cargo test/nextest 同时启用各自的继续执行参数，最后稳定汇总全部失败并返回非零。
`--fail-fast` 可恢复首错停止；600 秒 supervisor 超时和取消信号仍立即终止。每次调用都会执行本次所选
gate/stage；构建复用只由 committed snapshot、target pool、Cargo fingerprint 与 compiler cache 负责。
任何 `--only` 成功都只是 partial 诊断结果，不代表完整 CI 通过。远端固定 Job 保持 fail-fast。
L0/L1 的采用与故障语义分别见
[`docs/rules/consistency-l0.md`](docs/rules/consistency-l0.md) 与
[`docs/rules/localtx.md`](docs/rules/localtx.md)；精确执行成员由 canonical `ExecutionProfile` 与 typed
stable-ID registry 派生，`xtask/src/verify.rs` 只负责将该集合投影为具体执行计划。

CI 子命令不保留旧的平铺 lane 入口；空的 `ci` 也会报错。固定 Job、LocalOnly 与供应链诊断接口为：

```bash
cargo xtask ci run --job check --selection '<canonical SelectionPlan JSON>'
cargo xtask ci run --job test-affected --selection '<canonical SelectionPlan JSON>'
cargo xtask ci run --job integration-critical --integration-group postgres --selection '<canonical SelectionPlan JSON>'
cargo xtask ci localonly-evidence --output <report-path>
cargo xtask ci audit
```

`integration-critical` 必须显式选择 `postgres|transport|runtime|artifact` 之一，根据 preflight 传入的规范
`SelectionPlan` 只运行该 group 拥有的真实后端批次；不存在旧的全组串行入口或 `all` 默认值。
`postgres-domain` 仍是 LocalTx live proof 的 typed owner，且只有 `postgres` group 能构造发布资格。PR gate 只看固定 Job 结果；LocalTx exact-set
由执行单元自身 fail-closed，不能用附加 artifact 把失败 Job 改写为通过。受影响的 `make ci` 会选择
`localtx-coverage`；也可直接运行该 gate 或 `localtx report` 诊断静态闭包，
不能替代真实后端执行。当前 required-check 激活边界及人工验证清单见
[`docs/ops/202607150329-1776-localtx-required-evidence.md`](docs/ops/202607150329-1776-localtx-required-evidence.md)。

`ci localonly-evidence --output ...` 是 LocalOnly required evidence producer 的唯一公开直接入口。远端
`test-affected` 在自身执行计划内调用同一个私有 producer，并拥有报告的成败；报告不是额外 Job，也不由 gate
下载或解释。producer 从 static source receipt 的 typed
inventory 单源派生 package、library test target 与 exact filter；全部 nextest 测试成功且
active/source/executed 三集合完全相等后，才原子发布唯一 schema v2 报告；集合非空作为 anti-vacuity，
具体数量只由 typed inventory 动态输出。
受影响的 `make ci` 会选择静态 source receipt gate，但不产生或声称产生运行证据；完整 `verify` 与该公开入口
也复用同一个 producer。Azure 窄 build validation 的激活与同一 policy RED/GREEN 验收见
[`docs/ops/202607151200-1815-localonly-execution-evidence.md`](docs/ops/202607151200-1815-localonly-execution-evidence.md)。

以下是常用开发检查，并非 `verify` 内部 typed step 的逐条公开命令；完整本地治理门运行
`make ci-full`，差异感知的 PR 收尾运行 `make ci CI_BASE=<remote>/develop`：

```bash
cargo fmt --all -- --check                             # 格式
cargo xtask contract validate                          # 契约元数据校验
cargo xtask assembly validate                          # assembly 声明与依赖闭包校验
cargo xtask assembly generate-modules --check          # domain modules 生成物漂移门
cargo xtask assembly generate-providers --check        # typed provider catalog 独立漂移门
cargo xtask assembly generate-runtime-plans --check    # manifest + lock 派生 RuntimePlan 漂移门
cargo xtask assembly lock check                        # 全仓 AssemblyLock raw-byte 漂移门
cargo xtask verify --only runtime-assembly-residual         # runtime 跨文件 escape residuals（FullOnly）
cargo xtask runtime-root guard                         # runtime root 纯声明 façade 守卫
cargo xtask layer-deps                                 # source-centric 分层依赖 lint
cargo xtask codegen --check                            # 契约 codegen 漂移门
./hack/cargo.sh xtask l2-assurance                     # 校验 active L2 typed assurance closure
./hack/cargo.sh xtask provider-capabilities            # 按需生成 target 下的 provider conformance 诊断报告
./hack/cargo.sh xtask provider-capabilities --check    # 声明、runner、owner、可达性与 shard 语义门
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
cargo deny check -D unused-wrapper                     # 分层闭集 + license + advisory（过期 wrapper 失败）
cargo dylint --all                                     # AST 级自写 lint（domain 禁 derive serde 等）
```

本仓库交付边界是可重复构建的 OCI 镜像、`Dockerfile`、本地 `docker compose` 演示栈，
以及应用自身的 RuntimePlan、typed 配置、health/readiness 和 SIGTERM drain 契约。
生产调度、流量、secret projection、replica/resource policy 和 release provenance 由外部 delivery
系统拥有；该系统应消费不可变镜像并尊重本仓公开的配置、探针和终止语义，不将编排事实反向注入应用启动。
运行 inventory 可成对报告启动方声明的 source revision 与 image digest，但不在进程内验证 OCI/SLSA
provenance，也不把这些声明并入 RuntimePlan、workload 或 deployment fingerprint。

`runtime::operator::*` 是 operator 命令的唯一 Rust API 路径；binary 的 serving、错误报告与进程 panic
边界只使用 `runtime::{prepare_runtime, run, shutdown_runtime, report_process_error,
install_redacted_panic_hook, activate_structured_panic_observation}`，不得直接依赖 `runtimeexec`。共享时钟与审计 sink 只从
`runtime::support::{SystemClock, TracingAuthAuditSink}` 导入。旧 root operator/support 路径没有 alias 或兼容 shim；
`runtime-root guard` 只允许 crate root 包含外置 module 声明与 import/re-export；启动、
关停与错误报告实现必须留在私有 lifecycle owner，不使用 LOC 或当前数量 golden。

`providers_gen.rs` 是每个 assembly crate 内部编译的 provider constructor catalog，不是外部
SDK/API，也不读取环境、配置或 secret。它只收 active provider，并通过闭合 role、consumer、factory
symbol 与 `ProviderCatalogEntry::checked` 绑定 canonical registry evidence；现有 `modules_gen.rs`
继续承载 live output composition，不能作为 catalog fallback。两类生成物分别漂移检查，固定聚合顺序为
`assembly validate → artifacts check → modules check → providers check → lock check → runtime-plan check`；
assembly graph 仅由按需 presentation 命令构建，不注册独立 gate。live provider dispatch、
手写旁路删除和 output bijection 由 #1792 完成。
factory symbol 的 wire、Display 与 JSON Schema ID 统一使用显式 `consumer::factory` 声明；assembly
root 的 compile-link 守卫同时拒绝 crate-level `cfg` 及可递归展开为 `cfg` 的 `cfg_attr`，避免 catalog
引用与 non-empty 断言被条件编译整体移除。

L2 assurance 由 `xtask/src/l2_assurance.rs` 的私有 typed inventory 直接校验。active contract、compiled
HTTP/event registry、generated producer binding、精确 mounted handler、receipt execution graph、production
composition、PostgreSQL producer transaction closure、subscription external-effect policy 与 ready fault
evidence 必须双向闭合；producer execution/fault terminal 的 fact 集必须与 manifest `emits` 完全一致。

该校验不存在 committed JSON、schema 或 reader，也不生成诊断报告。唯一直接入口是：

```bash
./hack/cargo.sh xtask l2-assurance
```

`l2-assurance-check` verify/CI gate 调用同一个 in-process validator；`--check`、输出路径及兼容别名均拒绝。
未来若出现真实外部 consumer，必须另立 versioned artifact contract，不恢复未版本化 presentation baseline。

provider owner 中的 `provider_conformance_catalog!` 是声明单源：sealed tuple 在编译期固定每个
provider 的适用能力全集与顺序；宏为每项生成 live wrapper，wrapper 只能 await 唯一 canonical
provider behavior，且没有可伪造的 catalog receipt/mint API。`provider-capabilities --check` 直接构造
内存语义模型，并以 Rust AST 精确验证 wrapper→behavior 唯一边、能力专属语义锚点与行为摘要、
tracked-source 闭集、crate-root module/feature 可达性及 typed integration shard 归属。

裸 `provider-capabilities` 只把已经验证的模型投影为
`target/xtask/provider-capability-matrix.json` 诊断报告。该 ignored、无版本报告不参与 identity、equality、
receipt 或 gate verdict；不读取旧 schema，不保留 alias、shim、baseline 或双写输出。

受控入口只接受以下两种形态；重复 flag、输出路径、兼容别名和其他参数均拒绝：

```bash
./hack/cargo.sh xtask provider-capabilities
./hack/cargo.sh xtask provider-capabilities --check
```

新 provider / capability enroll 步骤：

1. 在 `crates/testkit/src/eventing_conformance.rs` 扩展闭集枚举、`capabilities()` 与
   `SealedCompleteSet` exact tuple（macro token 用 snake_case，diagnostic label 用 kebab-case）。
2. 在对应 adapter owner 源文件调用 `provider_conformance_catalog!`，每项指向唯一 canonical
   behavior；compile-fail 负例放 `crates/testkit/tests/ui/`。
3. 运行 `./hack/cargo.sh xtask provider-capabilities --check` 验收声明、behavior、owner、可达性与 shard closure；
   需要人工诊断时再运行裸命令生成 ignored target 报告。
4. 通过 typed integration shard 跑该 provider 的 enrollment wrappers；shard 归属由 semantic gate 与
   `xtask` integration lane 共同约束，真实通过状态只来自该 shard 的执行结果。

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
`RSS_TARGET_POOL_N` 同设则 fail-closed。受控入口默认 `CARGO_BUILD_JOBS=6`，兼顾 2–3 个 worktree
并发；机器资源独占时可用 `CARGO_BUILD_JOBS=12 make ci` 显式覆盖。
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
