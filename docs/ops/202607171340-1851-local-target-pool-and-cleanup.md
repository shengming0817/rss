# 本地 Cargo target N 槽租约池与膨胀治理（#1851）

> 边界：完整 Cargo target **不是** cache（见
> [202607110347-1728-ci-cache-policy.md](202607110347-1728-ci-cache-policy.md)）。
> #1764 / PR #509 确立 worktree/job 隔离；本单在其前提下提供**串行独占**租约池，
> 不恢复跨 worktree 共享可变构建产物。跨路径编译复用靠 sccache，不靠共享完整 target。

## 默认布局（受控入口）

| 入口 | 默认 target |
|------|-------------|
| `make` / `hack/cargo.sh` | N 槽租约池（默认 `N=5`，根 `$HOME/.cache/rss-cargo-target-pool/slot-K`） |
| 直接 `cargo` / `cargo xtask` | worktree-local `.cache/cargo-target`（`.cargo/config.toml`） |
| CI job | `$RUNNER_TEMP/rss-cargo-target`（不受池影响） |

环境变量：

| 变量 | 语义 |
|------|------|
| `RSS_TARGET_POOL_N` 未设置 | 默认 `5`（池 on） |
| `RSS_TARGET_POOL_N=<正整数>` | 使用该硬顶 |
| `RSS_TARGET_POOL_N=0` 或 `off` | 退回 worktree-local `.cache/cargo-target` |
| `RSS_TARGET_POOL_ROOT` | 池根（默认 `$HOME/.cache/rss-cargo-target-pool`） |
| 默认池 + 显式 `CARGO_TARGET_DIR` | env-override 生效，`pool=skipped` |
| **双显式** `RSS_TARGET_POOL_N` + `CARGO_TARGET_DIR` | fail-closed（二选一） |

槽语义：同一时刻一个槽只属于一个 worktree（sticky 热复用）。换租时 wipe 槽内容
（fingerprint 含绝对路径，旧产物对新 worktree 无热复用价值）。池满且无死进程可回收时
fail-closed，提示先跑 `gc`、加大 N 或删除 worktree。

## 回收与 gc

acquire 热路径离线，按优先级：sticky（扫描全部 `slot-*`；越界孤儿释租防双占）→ 空槽 →
worktree 已删 → LRU 且 lease PID 已死 → fail。

本仓 Azure DevOps 使用 squash merge，分支 tip **不会**成为 `develop` 祖先，因此「PR 已合并」
不能用本地 git 祖先判定。手动或池满时运行：

```bash
/usr/bin/python3 hack/target-pool.py gc --pool-root "${RSS_TARGET_POOL_ROOT:-$HOME/.cache/rss-cargo-target-pool}"
```

`gc` 经 `hack/automation/forge.sh branch-pr-merged <branch>` 查询。该 verb 仅在
**无 open/active PR** 且存在已合并 PR 时返回 true（同分支名复用或合并后继续开 PR
时保持 false）。已合并且 worktree 残留时：lease PID 仍存活则 **keep**（避免 wipe 正在构建
的槽）；PID 已死才释槽。forge 不可达时 fail-safe 保持租约（不误删）。

分支名复用语义：squash 合并后若复用短分支名、且无 open PR、lease PID 已死，`gc` 会按
「已合并」回收——继续开发请先开 PR，或保留活跃构建进程。

## 244G 级遗留目录清理顺序

迁移到池之后，各 worktree 下旧的 `.cache/cargo-target`（含主仓历史膨胀）是遗留垃圾，
可按层删除（越靠前越安全、可重复）：

1. **incremental**：`<target>/debug/incremental`、`<target>/release/incremental`
2. **coverage / dylint**：`llvm-cov*`、`dylint` 相关子目录
3. **按 profile**：整份 `debug/` 或 `release/`（下次受控构建会重建）
4. **整目录**：worktree 的 `.cache/cargo-target` 整树删除

示例（确认路径后执行）：

```bash
# 主仓遗留（示例；先 du 再删）
du -sh .cache/cargo-target
rm -rf .cache/cargo-target

# 池槽整清（会丢掉热复用；下次 acquire 重建）
rm -rf "${RSS_TARGET_POOL_ROOT:-$HOME/.cache/rss-cargo-target-pool}"
```

`cargo clean` 只清理**当前** `CARGO_TARGET_DIR`（池模式下是当前槽），不是「只留 develop
fingerprint」，也不是全池 GC。合并后请 `git worktree remove` 对应目录，必要时再跑 `gc`。

## 本地 sccache 0.15.0 验收

工具 catalog 钉住 `sccache 0.15.0`。把精确版本放进 PATH 后：

```bash
./hack/cargo.sh metadata --no-deps --format-version 1 >/dev/null
# 诊断应含：compiler-cache enabled=true version=0.15.0
```

无合法候选时 wrapper 继续普通 Cargo（`enabled=false reason=no-verified-candidate`）。
`RSS_COMPILER_CACHE=off` 显式关闭。sccache 0.15.0 hasher 含绝对 cwd，不承诺跨不同绝对
路径 worktree 命中。

## 退役旁路

若 `~/.zshrc` 仍有指向 `~/.cache/cargo-target/rss` 的 `rss-cargo()` 或类似函数，请删除并改用
仓库受控入口（`make` / `./hack/cargo.sh`）。旁路不会接入租约池、也不会获得 wrapper 的
compiler-cache 策略。

## 实现载体

- `hack/target-pool.py` — 租约算法单源（`acquire` / `gc`）
- `hack/cargo.sh` — 薄 hook
- `hack/cargo.selftest.sh` + `hack/tests/test_target_pool.py` — 机器门（经 `ci local` 的
  CargoWrapper 治理步）
