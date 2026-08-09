# #1958 local CI snapshot-first profiling

## 结论

`make ci` 的旧 committed-snapshot 链路在同一次冷启动中实际编译两次 xtask；snapshot-first
改造后只有一次。相同机器、`CARGO_BUILD_JOBS=6`、无可用 sccache 的定向 meta 场景中，旧链路两个
xtask build 阶段合计 `93.33s`，新链路冷 target 的唯一 build 为 `38.619s`，build 成本下降
`58.6%`。新链路同 HEAD 暖 target 的 build 为 `0.184s`。

## 方法

- 时间：2026-08-09 UTC。
- 工具链：仓库钉定 Rust toolchain；wrapper 输出 `CARGO_BUILD_JOBS=6`、
  `compiler-cache enabled=false reason=no-verified-candidate`。
- 选择：`CI_ARGS='--only meta --fresh --fail-fast'`，只隔离 launcher、snapshot、xtask build 与同一
  meta 前缀，不把 affected package check/test/clippy 混入启动数据。
- 冷 target 使用新建的显式 `CARGO_TARGET_DIR`；采样后通过 `cargo clean --target-dir` 清除。
- 新实现的分段时间使用 `time.monotonic()`；Cargo build 同时启用 `--timings`。
- 当前 develop 的 `assembly-artifacts-check` 在第四个 gate 报既有
  `RUNTIME-LIFECYCLE-BYPASS-01`，所以旧/新链路都在相同 gate 前缀 fail-fast。该失败不影响 build
  阶段比较，也未在本 profiling 中搭车修改。

## 旧链路基线

基准：`develop@04d79ab223876ff2d9434653e70d214d80e92e00`。

```text
Compiling xtask (.../rss/xtask)
Finished dev profile ... in 40.92s
Compiling xtask (.../target/ci-local-sources/.../tree/xtask)
Finished dev profile ... in 52.41s
ci local [1/1] failed ... step 83.8s / inner total 84.4s
outer command wall time 127.7s
```

第一次 build 来自 caller worktree，第二次来自 revision-keyed committed snapshot；两者使用不同
target/source identity。两个 xtask build 阶段合计 `93.33s`。

## snapshot-first 数据

实现 HEAD：

- 主实现：`d58a1de35df9c493a982bcdf45a8703e308b6b70`
- monotonic build profiling 修正：`e11f0f26d1965f6a05681fcaa836f14b355d5fea`

| 场景 | snapshot | xtask build | gate 前缀 | total | 说明 |
|------|----------|-------------|-----------|-------|------|
| 冷 target | `0.058s` | `38.619s` | `25.3s` | `66.220s` | 全新 target，唯一 xtask build |
| 新 HEAD、同 pool slot | `0.522s` | `27.622s` | `30.5s` | `61.142s` | `d58a1de3 → e11f0f26`；revision source path 变化使本地 crate 重建 |
| 同 HEAD、同 pool slot 暖缓存 | `0.072s` | `0.184s` | `27.9s` | `30.253s` | Cargo fingerprint 命中 |

冷 target 总时间相对旧链路的 `127.7s` 降至 `66.220s`，本次样本下降约 `48.1%`。这里不把一次
样本外推为稳定 SLA；机器可判定的验收重点是 invocation 拓扑和 provenance：

- `hack/cargo.selftest.sh` 断言内部 worker 只调用一次
  `cargo build --locked -p xtask --timings`，随后 exec 一个 snapshot xtask；
- target lease 的 worktree/branch/PID 保持 caller identity；
- `ci_impact` 不再构造 nested `CargoSubcommand::Xtask`；
- supervisor synthetic test 证明 dirty path dependency、dirty tool adapter、untracked、ignored 与缓存
  注入文件均不会进入 snapshot worker。

## 方案选择

数据支持采用 snapshot-first，而不是复用 caller 编译的二进制：冷路径直接消除一个 `40.92s` 的 caller
build 和第二次 Cargo orchestration，同时唯一 Rust worker 的 `CARGO_MANIFEST_DIR`、HEAD、base、merge-base
与执行根都绑定 committed snapshot。新 HEAD 仍可能因 revision-keyed source path 触发重建；这是来源隔离的
保守失效条件，不通过跨 revision 复用未证明同一性的二进制规避。
