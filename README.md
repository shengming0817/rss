# rss

RSS 是 GoCell 的 Rust 重写——domain-native 治理 + 惯用扁平 Cargo workspace（无 cell/slice 外壳）。

## 结构

扁平 workspace：`crates/`（库 crate，分基础/引擎/服务/域四层）、`adapters/`、`bins/`、`xtask/`、`generated/`。
完整结构树 / 分层 / 命名的**单一事实源**见 [`docs/rules/architecture.md`](docs/rules/architecture.md)；
最高协作规范见 [`CLAUDE.md`](CLAUDE.md)。分层由 crate 依赖图（编译期）+ `deny.toml` wrappers 强制。

## 构建与本地验证

本地保留聚合验证入口；GitHub Actions 由 typed `ci-plan` 从闭合 `CiJobKey` 派生唯一动态 matrix，
执行 `ci-meta`、Core、Security、Coverage、Integration 与 Audit 的合法子集，再由稳定 `ci-gate`
核对计划、聚合结果和 evidence v4 回执。Azure 当前仍是 active PR/Boards forge；GitHub 处于 Shadow
取证阶段并执行完整 14-job catalog，`ci-gate` 尚未配置为 required check。当前状态与激活条件见
[`docs/ops/202607130824-1765-diff-adaptive-ci.md`](docs/ops/202607130824-1765-diff-adaptive-ci.md)：

```bash
make verify                              # 推荐：受控 bootstrap + 完整 verify gate plan
./hack/cargo.sh xtask verify             # 与 make verify 相同的受控入口
./hack/cargo.sh xtask verify --fast      # inner plan 只跑 NoCompile gate；冷缓存时 Cargo 仍会编译 xtask
./hack/cargo.sh xtask verify --allow-missing-tools  # 缺外部工具时显式宽限（默认 fail-closed）
./hack/cargo.sh xtask ci                 # 本地去重兼容聚合；Coverage 取代 Core 的 default-nextest
```

Make 通过 `hack/cargo.sh` 启动 xtask，是本地治理门的受控 bootstrap。直接运行 `cargo xtask ...`
仍执行相同 typed gate plan，并与 wrapper 共用 worktree-local target 默认值；但启动 xtask 的外层 Cargo
不会获得 wrapper 的 build-jobs 默认值、ambient rustc-wrapper 清洗或 sccache 自动策略，因此不是等价入口。

L0/L1 的 canonical 验证分三层：`make verify-fast` 的 inner typed plan 只运行 contract/codegen/静态闭包，
不包含 workspace build/test 编译门；冷缓存或 xtask 变更时，外层 Cargo 仍会构建 xtask 启动器。`make verify`
再加入编译、默认行为测试与 integration target 编译，但不执行真实后端测试；
`./hack/cargo.sh xtask ci-integration --shard postgres-domain` 才实跑 Postgres LocalTx matrix 与 active L1
journey。最终证据不得使用 `--allow-missing-tools` 跳过工具或 Docker。L0/L1 的采用与故障语义分别见
[`docs/rules/consistency-l0.md`](docs/rules/consistency-l0.md) 与
[`docs/rules/localtx.md`](docs/rules/localtx.md)；精确 gate 成员与顺序只以 typed registry 和
`xtask/src/verify.rs` 派生计划为准。

`./hack/cargo.sh xtask ci` 覆盖四类 lane 的兼容 gate 联集，但不复现 typed planner、14 个独立 runner、
artifact 回执或 `ci-gate` 聚合。它不重复运行 Core 的 `ci-core` profile nextest，而 Coverage 复用同一测试
语义。需要逐项运行 Shadow 14-job catalog 对应的 lane 命令（仍不含 GitHub 调度/证据边界）时运行：

```bash
./hack/cargo.sh xtask ci-meta
./hack/cargo.sh xtask ci-core-prerequisites
./hack/cargo.sh xtask ci-core-tests --partition 1/2
./hack/cargo.sh xtask ci-core-tests --partition 2/2
./hack/cargo.sh xtask ci-security
./hack/cargo.sh xtask ci-coverage
./hack/cargo.sh xtask ci-integration --shard postgres-domain
./hack/cargo.sh xtask ci-integration --shard event-transport --partition 1/2
./hack/cargo.sh xtask ci-integration --shard event-transport --partition 2/2
./hack/cargo.sh xtask ci-integration --shard runtime-http-auth --partition 1/2
./hack/cargo.sh xtask ci-integration --shard runtime-http-auth --partition 2/2
./hack/cargo.sh xtask ci-integration --shard consistency-fault
./hack/cargo.sh xtask ci-integration --shard cdc-projection-saga
./hack/cargo.sh xtask audit
```

以下是常用开发检查，并非 `verify` 内部 typed step 的逐条公开命令；完整本地治理门运行
`make verify`，本地完整 Core 用 `./hack/cargo.sh xtask ci-core`，PR 分区测试用 `ci-core-tests`：

```bash
cargo fmt --all -- --check                             # 格式
cargo xtask contract validate                          # 契约元数据校验
cargo xtask assembly validate                          # assembly 声明与依赖闭包校验
cargo xtask assembly generate-modules --check          # domain modules 生成物漂移门
cargo xtask layer-deps                                 # source-centric 分层依赖 lint
cargo xtask codegen --check                            # 契约 codegen 漂移门
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
./hack/cargo.sh xtask ci-core                          # 不分区的完整 Core 测试与证据 typed 漏斗
cargo deny check                                       # 分层禁依赖 + license + advisory
cargo dylint --all                                     # AST 级自写 lint（domain 禁 derive serde 等）
```

工具链由 `rust-toolchain.toml` 钉定（首次进入目录自动安装）。治理工具的版本、安装 backend 与 CI lane
映射由 adapter catalog 单源维护；查看完整精确版本：

```bash
.github/scripts/ci-tool-adapters.sh specs --lane all --backend all
```

Cargo 构建产物遵循 worktree/job 隔离：本地默认写当前 worktree 的 `.cache/cargo-target`，CI 写
`$RUNNER_TEMP/rss-cargo-target`；显式 `CARGO_TARGET_DIR` 仍由 Cargo 原样处理。受控入口默认
`CARGO_BUILD_JOBS=2`，可由同名环境变量覆盖。完整 target 不跨 worktree 或 CI job 持久化。

`hack/cargo.sh`、Make 及其启动的 xtask 会清除外部 `RUSTC_WRAPPER`。默认 `auto` 会按 PATH
顺序物理规范化并验证 sccache 候选，跳过无效项，仅在找到首个精确版本 `sccache 0.15.0` 后启用
compiler cache；无合法候选时使用普通 Cargo，`RSS_COMPILER_CACHE=off` 可显式关闭。启用时强制
`CARGO_INCREMENTAL=0`。sccache 只在编译输入和逻辑路径对应的 cache key 相同时复用结果；Rust
hasher 会散列绝对工作目录，因此不承诺 RSS 自有 crate 跨不同绝对路径的 worktree 命中。cache
backend/server 故障只降低命中收益，不改变编译或测试 verdict。

> dylint 须 nightly：`cargo-dylint` / `dylint-link` 版本与 `lints/rust-toolchain.toml` 的 channel +
> `clippy_utils` rev **成对**，升级步骤见 `lints/README.md`（勿单独升任一侧，否则 ABI 不齐编译失败）。

门集 / `--fast` / 缺工具策略单源见 `xtask/src/verify.rs`。
