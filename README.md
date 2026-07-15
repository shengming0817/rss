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
无差异直接成功；docs-only 只运行 fast/meta；Rust、contract 与 generated 影响运行反向依赖 check、直接
影响包 test/clippy 和已登记 feature gates；未知路径、rename/copy 或解析失败 fail-safe 到完整 `verify`。
本地 preflight 不运行 coverage、audit 或真实后端 integration；需要无条件全量本地门时使用 `make ci-full`。
L0/L1 的采用与故障语义分别见
[`docs/rules/consistency-l0.md`](docs/rules/consistency-l0.md) 与
[`docs/rules/localtx.md`](docs/rules/localtx.md)；精确 gate 成员与顺序只以 typed registry 和
`xtask/src/verify.rs` 派生计划为准。

CI 子命令不保留旧的平铺 lane 入口；空的 `ci` 也会报错。planner、typed executor 与 gate 的接口为：

```bash
./hack/cargo.sh xtask ci plan <planner-options>
./hack/cargo.sh xtask ci run --job ci-meta
./hack/cargo.sh xtask ci run --job integration/postgres-domain
./hack/cargo.sh xtask ci run --job audit
./hack/cargo.sh xtask ci gate <gate-options>
```

以下是常用开发检查，并非 `verify` 内部 typed step 的逐条公开命令；完整本地治理门运行
`make ci-full`，差异感知的 PR 收尾运行 `make ci CI_BASE=<remote>/develop`：

```bash
cargo fmt --all -- --check                             # 格式
cargo xtask contract validate                          # 契约元数据校验
cargo xtask assembly validate                          # assembly 声明与依赖闭包校验
cargo xtask assembly generate-modules --check          # domain modules 生成物漂移门
cargo xtask layer-deps                                 # source-centric 分层依赖 lint
cargo xtask codegen --check                            # 契约 codegen 漂移门
cargo build --workspace                                # 编译全 workspace（分层有环即失败）
cargo clippy --workspace --all-targets -- -D warnings  # lint（clock 注入 / panic 纪律）
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
