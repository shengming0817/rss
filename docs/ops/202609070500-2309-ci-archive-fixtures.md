# CI 使用与故障排查

从仓库根目录通过 Make 运行验证。范围与深度遵循[验证规则](../rules/verification-scope.md#默认选择)，
Rust API 与 wire 兼容边界遵循[版本规则](../rules/api-versioning.md)。具体选择、阶段和工具版本分别由
[选择器](../../hack/ci-impact.py)、[执行器](../../hack/ci-pipeline.py)、[工具链](../../rust-toolchain.toml)
及 [workflow](../../.github/workflows/ci.yml) 持有。

## 运行

准备仓库工具链及所选阶段需要的 Cargo 工具；安装版本参照
[编译 workflow](../../.github/workflows/ci-compile.yml)。真实 provider 测试需要可用的 Docker；
Kafka 独立消费检查还需要宿主 OpenSSL SDK（Linux 的 pkg-config/libssl-dev，macOS 的 Homebrew openssl）。
先获取有效的比较基准；以下 `origin` 按实际 remote 替换。

```sh
make ci CI_BASE=origin/develop
make ci-full CI_BASE=origin/develop
# 定向诊断；不替代完整验证
make ci CI_PART=tests CI_FILTER='package(=amqp-integration) and test(=shared_amqp_subscriber_lifecycle_suite)'
```

普通运行选择受影响 package。已识别文档不贡献 package；混合提交仍选择代码的反向依赖闭包。
文档是否被识别以选择器为准，不能仅凭 Markdown 后缀判断。未知路径、rename/copy 或分析异常会
保守扩大范围。显式 `CI_FILTER` 独立于 affected 选择，零匹配失败。

按需使用 `CI_PART=checks` 运行静态检查、`tests` 构建归档并执行测试与适用覆盖率、`docs` 运行 doctest；
默认 `all` 包含这些阶段与适用的 SemVer 检查。纯文档空选择仍运行 CI 脚本检查，不表示所有验证都跳过。
分阶段消费归档时，先用 `CI_PART=select` 生成 plan，后续通过 `CI_PLAN` 指向同一产物；不要混用不同 SHA 的结果。

本地产物默认位于 `.local-ci-runs/current`，可通过 `CI_ARTIFACTS` 指定其它目录。
归档、正式结果和诊断报告属于该次运行；重新运行前将需要保留的证据保存到 PR 附件或已有持久制品。

## 结果与故障定位

以命令退出状态和正式结果判断成功。可执行阶段尽量继续收集失败，但编译失败或取消可能阻止后续
测试运行；不能把“已生成覆盖率报告”或“部分测试通过”当作完整成功。缺失、损坏或身份不匹配的
正式结果仍阻断验证；诊断统计不完整不会改写原测试结论。

失败后先查看产物中对应阶段的结果与日志，再使用定向命令复现。缺失或不兼容的 archive/plan 应重新
生成，不手工补字段或拼接旧结果。覆盖率适用范围与门槛按验证规则执行；这里不维护第二份测试清单。

provider 启动失败先检查 Docker、镜像拉取和资源权限。共享 fixture 缺失即失败，不以临时自起实例
掩盖接入错误；fixture 凭据不得进入日志或 artifact。排障与清理只处理本次运行的资源，不能删除其它
运行的容器、网络或活跃 target。保留原始失败与脱敏诊断，避免通过无限重试或放宽测试期限掩盖问题。
PostgreSQL 缺失端口映射的追踪见 [#2316](https://dev.azure.com/shengming0923/rss/_workitems/edit/2316)；
单次复验通过不证明根因已解决。

## 本地 target 与编译缓存

[本地启动器](../../hack/ci-run.py) 管理 target 租用和可选 sccache；直接 Cargo 命令不受它协调。
池只协调同用户、本地文件系统上的 CI，不提供跨权限用户隔离。

| 配置 | 使用方式 |
|---|---|
| `RSS_TARGET_POOL_N` | 正整数调整并发槽数；`off` 或 `0` 关闭池并使用 worktree target，仍可显式指定 `CARGO_TARGET_DIR` |
| `RSS_TARGET_POOL_ROOT` | 指定专用池目录；默认位置见启动器 |
| `CARGO_TARGET_DIR` | 显式指定 target 可绕过默认池；不能与显式正数槽配置同时设置，也不能指向活跃槽 |
| `RSS_COMPILER_CACHE` | `auto`（默认）在工具不可用时降级；`on` 要求可用；`off` 不自动接入 |

同 worktree 已有运行或全部槽忙时，等待原运行退出再重试。构建子进程可能在 wrapper 退出后仍持有锁，
不能仅凭 PID 元数据或 wrapper 退出就清理。不要删除活跃池的锁文件。检测到旧池或未标记非空目录时，
先停止并确认所有相关构建退出，再重置确认属于 RSS 的专用旧池，或改用新的空池目录；不要清空普通目录。

sccache 须预先安装启动器中 `SCCACHE_VERSION` 指定的版本，入口不自动下载安装。
已有自定义 rustc wrapper 时，auto 保留它，on 拒绝冲突。server 版本或缓存目录不匹配时，
等待所有使用该 RSS server 的 CI 退出后再停止 server；下次 CI 会重新启动。
下面命令使用默认 socket；若覆盖了 `SCCACHE_SERVER_UDS`，请使用实际配置的同一 socket。

```sh
SCCACHE_SERVER_UDS="$HOME/.cache/rss-sccache/server.sock" sccache --show-stats
# 确认没有使用该 server 的活跃 CI 后，才停止以应用新配置：
SCCACHE_SERVER_UDS="$HOME/.cache/rss-sccache/server.sock" sccache --stop-server
```

统计是共享 server 的累计值，不能视为当前任务独占命中数；缓存失败不代表编译成功。
容量配置等上游选项见 [sccache 配置](https://github.com/mozilla/sccache/blob/v0.15.0/docs/Configuration.md)。

## SemVer 检查

普通运行由选择结果决定受检包；无需检查时跳过。手工比较要求干净的 tracked checkout，且已 checkout 到
声明的 head。安装所需工具时从现有入口读取版本：

```sh
cargo install --locked --version "$(python3 hack/ci-semver.py --tool-version)" cargo-semver-checks
make ci CI_PART=semver CI_BASE=origin/develop CI_HEAD=HEAD
make ci CI_PART=semver CI_SEMVER_MODE=all CI_BASE=origin/develop
# 显式选择 package 比较；也可将 origin/develop 替换为实际基准 commit
make ci CI_PART=semver CI_SEMVER_MODE=compare CI_SEMVER_PACKAGES=rss-contract CI_BASE=origin/develop CI_HEAD=HEAD
```

`CI_SEMVER_PACKAGES` 仅用于 `compare`，不能与 `CI_SEMVER_FULL=1` 组合。工具缺失、版本不符、
不支持的检查目标或输入非法均需处理，不能当作通过。也可使用
[SemVer workflow](../../.github/workflows/ci-semver.yml) 的独立 dispatch，不重跑测试。

## GitHub 冷热缓存验证

仅在需要验证缓存行为时执行：冻结 SHA，在 CI workflow 中以明确的 `baseline` 和 `cold_cache=true`
dispatch。冷跑完整成功且缓存实际保存后，用同 SHA、同 baseline、`cold_cache=false` 和
`warm_run=<cold run ID>-<attempt>` 再次 dispatch。热跑必须精确命中指定缓存；修复后重新冻结 SHA，
从冷跑开始。PR 只恢复缓存，可信 develop/dispatch 才在成功后保存。

对比原始运行的 restore/save key、命中统计、阶段耗时和磁盘用量；完整 target 复用与编译对象命中是
不同证据，不预先承诺加速比例。运行记录留在 PR 或已有持久制品，不回填本文。

归档与覆盖率机制的来源：
[nextest archiving](https://nexte.st/docs/ci-features/archiving/)、
[cargo-llvm-cov report](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.8.7/src/report.rs)。
本地池历史来源为 RSS `hack/target-pool.py`、`hack/cargo.sh`，固定提交
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`；当前操作以现有启动器为准。
