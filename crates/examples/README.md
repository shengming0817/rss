# RSS public consumers

本 package 不发布、不进入 Release Surface。它持有 #2286 的最小可运行场景，
#2266 回读这些场景及原组件 T1/T2 的运行证据完成原提取阶段验收。
源码在此维护；`rss-external-check/` 只保存可再生的独立 consumer、lock、构建和执行日志。

## 仓内运行

从仓库根目录执行；每个场景内部断言可观察结果，失败返回非零状态。

```sh
cargo run --locked -p rss-examples --features diagnostic,task-local,trace,redact,derive,protection,lifecycle
cargo run --locked -p rss-examples --features core
cargo run --locked -p rss-examples --features producer,consumer
cargo run --locked -p rss-examples --features managed-worker
```

| 场景 | 最低充分行为 | 包/边界 |
|---|---|---|
| diagnostic / task-local | 拒绝非法 correlation，两个任务隔离，spawn 不隐式继承 | rss-diag-context |
| trace | 非法输入拒绝，私有 subscriber 下 restore/capture 保留 trace ID、tracestate | rss-trace-context |
| redact / derive | Debug、Wire、ServerLog 与错误 source 不泄漏敏感值；显式启用 derive | rss-redact、rss-redact-derive |
| protection | consumer 自选 ring AES-GCM，正确 AAD 解密，跨租户/字段与篡改拒绝 | rss-data-protection；密钥只活在本次示例 |
| lifecycle | 注册、取消、有界关闭及完成观察 | rss-runtime |
| core / none | 公共值类型；无 producer/consumer 的 testkit 时钟 | messaging core/runtime/testkit |
| producer / consumer / both | 具体外部 Publisher、relay settlement；inbox 竞争/旧 claim 失效，自定义 ConsumerTx 无 commit 证据时 abandon、无 ACK | messaging core/runtime/testkit，各自独立解析 |
| managed-worker | 具体 relay worker 转为官方 registration，完成一次发布再取消、drain | messaging runtime → rss-runtime |
| self-host / managed | PG outbox → TLS AMQP → PG 业务效果/receipt → ACK，取消订阅并关闭资源 | PG/AMQP + 自有 host；同一源码启用官方桥 |

数据保护的身份表示 fixture 已认证输入，不实现认证或 KMS。消息 memory 场景明确不持久化；
持久化与 ACK 的组合由真实 PG/AMQP 场景证明。生产授权、业务表迁移、broker topology、配置装配、
进程入口与部署仍由消费方负责。示例不持有产品 readiness 或常驻产品 consumer。

真实后端沿用 `tests/postgres-integration/tests/suite.rs` 的受限 PG 角色、迁移和 fencing authority，
以及 testkit 的私有 CA / 分离 AMQP 角色 fixture。以下命令需要 Docker：

```sh
RSS_TEST_RUN_ID=extract-example cargo run --locked -p testkit --features containers --bin rss-test-launcher -- \
  -- cargo test --locked -p postgres-integration --test suite postgres_transactional_messaging_suite -- --exact --nocapture
```

加 `--features rss-runtime` 运行仓内托管桥。完整故障矩阵继续归原 PG/AMQP integration、runtime 和
testkit 测试；不在示例复制 commit-unknown、fencing、租户、ACK-after-commit 等所有组合。

## 独立源码和 artifact

```sh
python3 hack/extract-package-proof.py --source
python3 hack/extract-package-proof.py --source --scenario producer
python3 hack/extract-package-proof.py --artifacts /absolute/candidate-bundle --revision COMMIT_SHA
```

脚本为每个场景复制源码，生成显式依赖、独立 `[workspace]`、lock 与 `CARGO_TARGET_DIR`。
`none/producer/consumer/both` 不能由共享 workspace 的 `--all-features` 代替。
每个 consumer 先核验 metadata 来源与 feature 图，再实际 run；关闭的公共 API 必须被 rustc 拒绝。
真实后端 binary 由既有 fixture harness 启动，参数仅通过 stdin 传入；内部 testkit 不进入 consumer 图。
stdout/stderr 并发排空，各保留至多 16 KiB 尾部；失败时输出脱敏诊断，超时后显式终止并有界回收。
零测试、遗漏 consumer 或编译成功均不能冒充 provider 运行通过。
全部场景成功后删除各 consumer 的 target；保留复制的源码、manifest、lock、解析图和日志。
失败时保留该次构建现场，便于诊断。

artifact 模式要求 checkout 与候选为同一 clean revision，读取既有 `packages.tsv` 和 `SHA256SUMS`，
校验实际 `.crate` 字节、Cargo 内嵌 VCS revision、版本、安全成员路径和 normalized manifest。
每包限制为压缩输入 16 MiB、完整 TAR 流 64 MiB、4096 个成员、单成员 8 MiB、累计内容 32 MiB；
摘要流式计算，先限制解压流再解析 TAR（包含扩展 header 和 padding），超限立即失败。
RSS 依赖只允许指向该次解包的候选闭包，不能回到主仓源码或 internal package。
所需闭包从 examples 的 Cargo 声明和 workspace metadata 推导，不另建发布包注册表。

候选由 `.github/workflows/candidate-bundle.yml` 的既有 Release Surface 打包步骤生成。
该 workflow 依次执行源码及 artifact consumer，并保留 `commands.log`、`resolved.json`、独立 lock 和
`provider-integration.log`；精确 archive inventory/digest 随原 candidate artifact 保存。
PR/issue 的验收记录需指向实际 revision、环境和这些运行结果。此处使用说明本身不是通过证据。

rss-incubator 保留产品孵化、自有 pin/lock、产品 CI 和接入验收，不成为全部基础包的通用门禁；
它的 registry-only 消费约束不因本仓允许解包 path patch 而改变。

## 对标来源

- ref: Cargo `src/cargo/ops/cargo_package/vcs.rs` @ `30a34c6821b57de0aaec83a901aca39f88f6778c`
  （Cargo 0.97.0）：`sha1` 与仅 dirty 时出现的标志由 Cargo 实际打包实现持有。
- ref: ring `src/aead/less_safe_key.rs` @ 0.17.14：使用真实 seal/open 和 canonical AAD，
  消费方显式拥有短命密钥及随机 nonce；不实现密码原语。
