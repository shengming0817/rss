# CoverageProjection：Packages vs Workspace

> 状态：实施规格。机器强制见代码 INVARIANT（`COVERAGE-SCOPE-PROJECTION-01`、
> `COVERAGE-SCOPE-NONEMPTY-01` 等）；本文只作运维/设计说明，**不是** Hard carrier。

## 三入口分工

| 入口 | 投影 | Coverage 行为 |
|------|------|----------------|
| `make ci` / `ci local` | `LocalProjection` | 不跑 coverage（preflight 门集不含插桩门；见 DEFERRED） |
| `ci run --job ci-coverage` | `CoverageProjection` | Packages（选择性）或 Workspace（full / unknown / fallback） |
| `make ci-full` / `ci full` | （兼容聚合） | 恒 `CoverageScope::Workspace` |

远端 `ci plan` 由 `RemoteProjection` 决定是否调度 `CiCoverage`；调度前咨询同一
`CoverageProjection`——`Skip` 则不调度。执行路径用同一 `ImpactSet` 投影出
`CoverageScope`，不复制 path map。

## CoverageDecision / CoverageScope 规则

**种子**（进入 Packages 候选）：`Source` | `Generated` | `ContractOwner` | `ContractSubscriber`。
`Manifest` / `Test` **不入种子**。

**扩包**：种子名集的 `reverse_closure` 中 `has_test_targets == true` 的包（含种子自身若有测）。
`has_test_targets` = metadata 目标 kind 含 `test` / `bench` / `lib` / `bin` / `proc-macro`
（与 `cargo test -p` 可执行面一致）。

**投影**：

| ImpactSet | CoverageDecision |
|-----------|------------------|
| `Empty` | `Skip`（计划不调度） |
| `Full(_)` | `Scope(Workspace{cause})` |
| `Selective` + `unknown_paths` 非空 | `Scope(Workspace{UnknownPath})`（与 Remote Full 对齐） |
| `Selective` 有非空 Packages | `Scope(Packages{…})`（经 `CoverageScope::packages`，空则不可构造） |
| `Selective` 滤空后无包 | `Skip` |

**执行入口**（`coverage_scope_for_typed_job`）：`Skip` 或 plan 同级不确定性（event 解析 /
diff / metadata / 非受信 `GITHUB_EVENT_PATH` / shallow）→ `Workspace{FallbackUncertainty}`，
与 plan `FallbackFull` 对齐，避免硬红假失败。

**门**：Packages 下 STRICT 绝对地板仅评 `StrictTouched = STRICT ∩ Packages`；空交集则
`floor=skipped`（diffcov 仍强制）。Workspace 始终评全 STRICT 地板 + diffcov。

## 耗时矩阵（运维说明 / 势差观察）

> 环境：开发机 Darwin / cargo-llvm-cov 可用。下表仅说明 Packages 相对 Workspace 的执行面势差，
> **不作** AI-robust Hard 证据。

| Fixture | 说明 | Packages | Workspace |
|---------|------|----------|-----------|
| leaf-source | 单叶 Source → 种子 + 有测 consumer | ≪ members | 全仓库 |
| consumer-expand | reverse_closure 扩包（有测） | 闭包大小 | 全仓库 |
| strict-touched | STRICT crate Source | STRICT∩Packages | 全 STRICT |

运维边界：`make ci` wall 600s；coverage job SLO 480s——插桩门留在 `ci-coverage` / `ci full`。

## AI-HARD 不变式（代码 carrier；本文仅引用 ID）

- `COVERAGE-SCOPE-PROJECTION-01`（Hard）：CoverageDecision/Scope 仅从 ImpactSet 穷尽投影。
- `COVERAGE-SCOPE-NONEMPTY-01`（Hard）：`CoverageScope::packages` 拒空列表。
- `COVERAGE-ARGV-SCOPE-01`（Hard）：Packages 无 `--workspace`；Workspace 无 `-p`。
- `COVERAGE-REPLAY-SCOPE-01` / `COVERAGE-STRICT-CONDITIONAL-01`（Medium）。
- 保留 `COVERAGE-DIFF-FLOOR-01`、`COVERAGE-STRICT-FLOOR-01`（Workspace 全量路径）。
