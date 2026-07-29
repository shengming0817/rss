# #1731 Nextest partition 与测试证据

CI 的 nextest 执行统一经过 `xtask` typed 漏斗。本页的 cargo-nextest `profile` 是 runner 配置：它只拥有
retry、timeout、JUnit、test-group 和必要的 tool filter，不定义 gate、test 或 journey 的主要执行归属。
跨工具执行成员的唯一规范模型是 canonical `ExecutionProfile`（`check`、`test`、
`integration-critical`、`release-check`）；xtask 先从该模型选择 typed execution unit，再映射到合适的
`NextestProfile` 与 invocation 参数。

`ci-core`、`integration`、`fault-matrix` 三个 cargo-nextest profile 均为零重试；任何 retry override、
TOML 调度 selector 或直接 nextest 子进程都会使治理门失败。#1890 不改变这些 tool profile、partition 或
当前 workflow topology，也不实施 #1883 的测试去重、#1884 的关键旅程收敛或 #1887 的固定 Job。

## CI topology

- Core prerequisite 固定运行 `cargo xtask ci run --job ci-core-prerequisites`；Core tests 固定运行
  `cargo xtask ci run --job ci-core-tests/1-of-2` 与 `ci-core-tests/2-of-2`。
- `event-transport`、`runtime-http-auth` 各运行 `1/2` 与 `2/2`；单个 hash bucket 可以合法为空，
  两个 bucket 的并集才是完整验收面。
- `postgres-domain`、`consistency-fault`、`cdc-projection-saga`、`object-storage` 不带 partition。fault matrix 当前只有
  一个顶层测试，使用独立 600 秒 `fault-matrix` profile，不伪装成可均衡拆分。

## Evidence 与重放

每次 invocation 先删除 profile 的 canonical JUnit 临时文件，再把本次结果保存到
`target/nextest-evidence/<invocation-id>.xml`，并原子写入同名 JSON sidecar。JSON 只包含闭合 lane、shard、
profile、outcome、JUnit 相对路径、钉定 nextest 版本、source revision 和闭合 `ReplaySpec`；其中 `profile`
是 cargo-nextest `NextestProfile`，不是 canonical owner。sidecar 不记录环境变量、服务 URL、
secret 或绝对路径。其中 `junitPath` 以下载后的 artifact 根为基准，固定解析到
`nextest/<invocation-id>.xml`。setup/编译失败只写 JSON，不伪造 XML；测试失败先保存证据，再传播原失败。

每个 job 先把 CI evidence 放入 `target/job-evidence/ci/`，把 nextest XML/JSON 放入
`target/job-evidence/nextest/`，再且仅上传这个单一根目录。GitHub artifact 名含 lane、shard、filesystem-safe
partition label（`1-of-2` / `2-of-2`）、run ID 与 attempt，保留 7 天；artifact 名不直接使用含 `/` 的 CLI
partition。下载 artifact 后先按 manifest 查看失败证据；重放命令严格解析 v2 `ReplaySpec`，不执行 artifact
提供的 argv：

```bash
cd <repo-root>
cargo xtask nextest-evidence inspect <artifact-download-dir>
git fetch origin <artifact-run-head-sha>
git worktree add --detach <temporary-worktree> <artifact-run-head-sha>
cd <temporary-worktree>
cargo xtask nextest-evidence replay <artifact-download-dir>/nextest/<invocation-id>.json
```

v2 sidecar 仅含闭合 Core scope、Coverage 或 Integration batch `ReplaySpec`；wrapper 从 typed registry 恢复
命令并要求 `sourceRevision` 等于当前 HEAD。artifact 不记录环境名或值。integration 重放仍需相同
Docker/外部资源能力。输出日志可能来自被测程序，排障
时不得把 secret 或生产 endpoint 复制进 issue/PR。

受保护分支 required checks 应在合入窗口根据 GitHub 实际 checks 核对并原子切换到完整 context。下列
`cargo xtask ...` 是 reusable workflow 的稳定显示名，不是可调用的旧 CLI 入口：
`CI / ci-core-prerequisites / cargo xtask ci-core-prerequisites`、
`CI / ci-core-tests / 1/2 / cargo xtask ci-core-tests` 与
`CI / ci-core-tests / 2/2 / cargo xtask ci-core-tests`。代码不提供旧
aggregate context 的兼容 shim；若 GitHub 展示名与预期不同，以合入窗口实际 check-run context 为准。

Integration 完整 check 名按八行 matrix 展开为
`Integration Tests / integration / <shard> / <partition-label> / cargo xtask integration`；未分区行的 label 为
`unpartitioned`，分区行只使用 filesystem-safe 的 `1-of-2` / `2-of-2`。
