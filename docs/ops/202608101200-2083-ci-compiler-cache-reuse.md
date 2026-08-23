# #2083 RSS CI 编译缓存复用

本页记录项目专属 RSS CI cache 生命周期；它不是通用 CI/cache 平台。正确性结果仍只由固定 Job 的仓库执行与
result-only gate 决定，restore、统计、stop、snapshot 和 save 均为 fail-open 性能路径。

## 命名空间与恢复顺序

cache key 只由 `.github/scripts/ci-cache-maintain.sh derive-keys` 派生：

- Cargo 下载 `v5`：OS、架构、stable toolchain、nightly、lane，以及 `Cargo.lock`、`.cargo/config.toml`、
  `rust-toolchain.toml` 的输入 hash、run id、attempt 组成唯一 primary；先恢复同输入的最新快照，再回退到去掉输入
  hash 的同 lane 环境前缀。每个 lane 独占 immutable namespace，每次运行在恢复快照上补齐依赖并保存新 key，
  避免并发 Job 或不同 affected 集合用不完整快照永久抢占相同 key。只缓存 runner 临时 Cargo home 内的
  registry cache/index 与 git db，不缓存 credentials。
- sealed 工具 `v4`：OS、架构、toolchain、nightly、lane 与工具策略 hash 组成 exact key。工具 cache 不包含
  Cargo/source 输入；restore 后必须验 seal，失效即安全重建。只有 develop push 能持久化工具 cache。
- sccache `v3`：OS、架构、toolchain、nightly、sccache 版本、lane、输入 hash、run id 与 attempt 组成唯一
  primary。恢复顺序为相同输入前缀，再到去掉输入 hash 的相同 invariant 前缀。输入变化只令不匹配的 sccache
  对象 miss，不再切断同 toolchain/lane 的历史对象；sccache 自身仍按 compiler、有效 rustc 参数/features、源码、
  extern、环境与工作目录校验对象。

显式 epoch 是格式不兼容或已知损坏时的整体熔断。旧 `rss-download-v4`、`rss-sccache-v2` 不做兼容读取或双写，
因此新 epoch 的首次运行预期冷启动，后续相邻提交和重跑才是复用验收对象。

## 失败保存与容量边界

`setup-rss-ci` 负责全部 restore，并仅在可信 develop push 保存已校验的 sealed tools；`finalize-rss-ci` 是
Cargo 下载与 compiler snapshot 的唯一 save owner。普通 success/failure
执行结束后先采集 JSON stats、停止 sccache server，再验证 cache root 是 runner temp 的安全、非空、最多 2 GiB
的 descendant，最后使用本次 run/attempt primary key 尝试保存。取消、timeout、setup 未完成、server 未停止、
stats/schema 失效、目录不安全/为空/超限时都跳过 compiler save；不保存完整 Cargo target、sccache error log 或凭据。

GitHub cache 为 immutable。日志中的 `attempted-success` 只表示 save action 成功返回，不宣称 backend 已新建条目；
下一次 restore 才是持久化证据。PR 写入仍沿用 GitHub merge-ref scope，不能被 base 或兄弟 PR 恢复；工具 cache
继续使用 trusted-writer 边界。

## 诊断与降级

每个 fixed/audit caller 都严格配对 setup/finalize。Job summary 同时显示 download/compiler restore 的
`exact|prefix|miss|unknown`、compile requests、hits、misses、not-cacheable、cache errors、timeouts、read/write
errors、`hits/(hits+misses)` 命中率、snapshot bytes 与 save attempt outcome。分母为零时命中率为 `n/a`。

restore 失败后只在已验证的 workspace/runner-temp descendant 上重建精确根目录；sccache 目录不可用时不设置
`RUSTC_WRAPPER`，转为普通 rustc。运行期 sccache I/O 继续由 `SCCACHE_IGNORE_SERVER_IO_ERROR=1` 降级。
这些诊断或缓存步骤失败不得覆盖仓库执行的原始结论。

缓存生命周期不新增第三个治理门：`CI-FIXED-WORKFLOW-01` 闭合两个 canonical workflow 的
`setup < execution < finalize` 顺序、outcome/eligibility 精确绑定、download/compiler cache funnel 与直接 cache
旁路；`CI-TOOL-ADAPTER-01` 继续唯一拥有 tool cache 的 restore/verify/reset/save 约束。key/path/stats shell
selftest 保留为行为证明。CI 调用顺序不属于类型或 schema 可表达的稳定产品不变式，因此不虚称 AI Hard。
