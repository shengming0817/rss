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
cargo xtask assembly lock check                        # 全仓 AssemblyLock raw-byte 漂移门
cargo xtask layer-deps                                 # source-centric 分层依赖 lint
cargo xtask codegen --check                            # 契约 codegen 漂移门
./hack/cargo.sh xtask l2-assurance                     # 生成 9 producer + 5 fact 的 L2 assurance inventory
./hack/cargo.sh xtask l2-assurance --check             # 只读检查 committed inventory 的逐字节漂移
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
cargo deny check                                       # 分层禁依赖 + license + advisory
cargo dylint --all                                     # AST 级自写 lint（domain 禁 derive serde 等）
```

`generated/l2-assurance.json` 是下游读取 L2 assurance inventory 的唯一 committed artifact；其 9 条
producer 与 5 条 fact 记录由 active contract、compiled registry、runtime/effect wiring 和 ready fault
evidence 共同派生。该文件只允许由 `l2-assurance` 更新，不手工编辑；`--check` 不写文件，并拒绝缺失、篡改、
CRLF 或输入漂移。

JSON v1 的紧凑 wire 约定如下：

- 根字段固定为 `schemaVersion: 1`、`producerCount`、`factCount`、`contracts`。
- 每条 contract 共有 `contractId`、`domain`、`version`、`role`、`status`、`evidence`；producer
  另带 `emittedFacts`，fact 另带 `topic` 和 `subscriptions: [{consumer, group}]`。
- `evidence` 固定包含 `contract`、`generated`、`runtime`、`effect`、`fault` 五个 facet；每个
  facet 都是 `{status, carriers}`，carrier 固定为 `{kind, path, symbol}`。
- 枚举是闭集：`role` 只有 `producer|fact`，record `status` 只有 `closed`，facet `status`
  只有 `complete`，`kind` 只有 `manifest|rust-symbol|fault-fixture`。
- 输出顺序是协议的一部分：contracts 按 `(contractId, role)`，`emittedFacts` 按 contract ID，
  subscriptions 按 `(consumer, group)`，carriers 按 `(path, symbol, kind)` 升序；pretty JSON 仅一个尾随 LF。
- consumer 必须按 `schemaVersion` 精确分派并拒绝未知字段或枚举值。任何字段、枚举或语义变更
  都必须升级 `schemaVersion`；不为旧版增加 alias、shim 或双写路径。

受控入口只接受以下两种形态；重复 flag、输出路径、兼容别名和其他参数均拒绝：

```bash
./hack/cargo.sh xtask l2-assurance
./hack/cargo.sh xtask l2-assurance --check
```

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
