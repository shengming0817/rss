# #1731 Nextest partition 与测试证据

CI 的 nextest 执行统一经过 `xtask` typed 漏斗。本页的 cargo-nextest `profile` 是 runner 配置：它只拥有
retry、timeout、JUnit、test-group 和必要的 tool filter，不定义 gate、test 或 journey 的主要执行归属。
跨工具执行成员的唯一规范模型是 canonical `ExecutionProfile`（`check`、`test`、
`integration-critical`、`release-check`）；xtask 先从该模型选择 typed execution unit，再映射到合适的
`NextestProfile` 与 invocation 参数。

`ci-core`、`integration`、`production-artifact`、`fault-matrix` 四个 cargo-nextest profile 均为零重试；
任何 retry override、TOML 调度 selector 或直接 nextest 子进程都会使治理门失败。`production-artifact`
只由 typed `SettingsOnlyProductionArtifact` 所在 batch 路由，使用 900 秒 timeout 与独立 JUnit 路径；其它
integration batch 仍使用 300 秒 profile。#1883 使 component nextest 与 coverage 在类型上互斥；#1884 已将
关键旅程收敛到精确 selection；#1887 已把普通 PR 收敛为固定 Job。

## CI topology

- `preflight` 生成 package selection；component nextest 只由 `test-affected` 消费。critical nextest 由
  `postgres`、`transport`、`runtime`、`artifact` 四个闭合 carrier 消费各自拥有的稳定 integration unit ID；
  `integration-critical` 只聚合四组结果。
- shard 内部 partition 仍由 typed integration catalog 决定；carrier 只承载 shard 归组，不成为新的 proof owner。
  空投影 carrier 显式成功，固定图不随 selection 漂移。
- `postgres-domain`、`consistency-fault`、`cdc-projection-saga`、`object-storage` 不带 partition。fault matrix 当前只有
  一个顶层测试，使用独立 600 秒 `fault-matrix` profile，不伪装成可均衡拆分。

## Evidence 与重放

每次 invocation 先删除 profile 的 canonical JUnit 临时文件，再把本次结果保存到
`target/nextest-evidence/<invocation-id>.xml`，并原子写入同名 JSON sidecar。JSON 只包含闭合 lane、shard、
profile、outcome、JUnit 相对路径、钉定 nextest 版本、source revision 和闭合 `ReplaySpec`；其中 `profile`
是 cargo-nextest `NextestProfile`，不是 canonical owner。sidecar 不记录环境变量、服务 URL、
secret 或绝对路径。其中 `junitPath` 以下载后的 artifact 根为基准，固定解析到
`nextest/<invocation-id>.xml`。setup/编译失败只写 JSON，不伪造 XML；测试失败先保存证据，再传播原失败。

nextest evidence v4 的 XML/JSON 放入 `target/job-evidence/nextest/` 并作为纯诊断 artifact 上传。artifact 名含
固定 Job、shard、filesystem-safe partition label（`1-of-2` / `2-of-2`）、run ID 与 attempt；artifact 名不
直接使用含 `/` 的 partition。result-only gate 不下载或解释这些文件。下载 artifact 后先按 manifest 查看
失败证据；重放命令严格解析 v4 `ReplaySpec`，不执行 artifact
提供的 argv：

```bash
cd <repo-root>
cargo xtask nextest-evidence inspect <artifact-download-dir>
git fetch origin <artifact-run-head-sha>
git worktree add --detach <temporary-worktree> <artifact-run-head-sha>
cd <temporary-worktree>
cargo xtask nextest-evidence replay <artifact-download-dir>/nextest/<invocation-id>.json
```

v4 sidecar 的 Core replay 存储闭合 `CoreTestSelection`（Workspace 或私有非空 package set）；Integration
replay 存储 profile、shard、规范 selection、精确 batch unit IDs 与 partition，不再存易漂移 batch number。
Integration wire 由 committed golden `xtask/tests/golden/nextest-integration-evidence-v4.json` 独立冻结；v3、旧
`batch` / `batchNumber`、缺 selection、重复/乱序/未知 unit ID 及 selection/unitIds 矛盾均直接拒绝。wrapper 从 typed registry 恢复
命令并要求 `sourceRevision` 等于当前 HEAD。artifact 不记录环境名或值。integration 重放仍需相同
Docker/外部资源能力。输出日志可能来自被测程序，排障
时不得把 secret 或生产 endpoint 复制进 issue/PR。

受保护分支只应绑定稳定的固定 Job/result-only gate context，实际 app identity 与 context 仍需在合入窗口从
GitHub API 核对。shard 与 partition 只出现在 `integration-critical` 的日志和 artifact 名中，不形成动态
required context。代码不提供旧 aggregate 或 shard check 名的兼容 shim。
