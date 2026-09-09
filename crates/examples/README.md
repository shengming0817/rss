# RSS public consumers

本 package 不发布、不进入 Release Surface。它持有 #2286 的基础场景和 #2318 的执行组件场景；
#2266 / #2294 分别回读对应场景及原组件 T1/T2 的运行证据完成阶段验收。
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

## 执行组件（#2318 / #2294）

四个 bin 分别由 `reconcile-pg`、`device-command-pg`、`projection-pg`、`saga-pg` 启用。
它们从 stdin 接收短命 fixture JSON（TLS host/port/database、受限 username/password、CA PEM、tenant）；
Device Command 额外要求独立提供 target/lineage/epoch。数据不写入 argv 或日志。
各组件 integration package 负责安装公开 migration、测试业务表和最小角色，运行结束清理临时后端。
需要可用 Docker；以下仓内命令直接运行进程内场景，验证业务行为。下方 package-proof 命令则构建并启动独立 bin，额外验证 stdin 合同和子进程边界。均从仓库根目录运行，不需要自行部署或配置生产数据库：

```sh
RSS_TEST_RUN_ID=execution-examples cargo run --locked -p testkit --features containers --bin rss-test-launcher -- \
  -- cargo test --locked -p reconcile-postgres-integration -p device-command-postgres-integration \
  -p projection-postgres-integration -p saga-postgres-integration --test suite \
  examples::example_consumer -- --exact --nocapture
```

| 场景 | 结果断言 |
|---|---|
| Reconcile | wake 后由真实 worker claim、执行业务写入、重新观察，reobserve/converged 各一次，持久结果为 converged |
| Device Command | command/outbox 原子落库，Queued/Published/Received/Applied 分开，旧 generation/epoch 不推进 |
| Projection | 同事务写读模型/checkpoint，持久位置到达 high-water；resume 无重复，v1/v2 均为 2 |
| Saga | exact definition、补偿失败持久化、销毁并重建 store/executor 后 resume；逆序补偿，journal/receipt 完整 |

Device Command 的 publisher 是显式模拟确认，只证明 PG 命令状态与 outbox 组合；不声称真实 broker 或设备执行。
Saga 使用短命独立 AEAD/HMAC 密钥和进程内 effect fixture，重建执行器时 effect 服务保持存活；
进程崩溃、Unknown/probe、完整租户/fencing/commit-unknown 矩阵仍由原 T1/T2 负责。
原 adapter 中的 compose/counter/setup 已迁移退出，此处是唯一场景来源。

```sh
python3 hack/reconcile-package-proof.py --source
python3 hack/device-command-package-proof.py --source
python3 hack/projection-package-proof.py --source
python3 hack/saga-package-proof.py --source
# 对以上任一入口，固定候选验收采用相同参数：
python3 hack/saga-package-proof.py --artifacts /absolute/candidate-bundle --revision COMMIT_SHA
```

四入口均拒绝无参数隐式打包。每项默认运行独立 core-only 和 PG consumer；Reconcile 另选消息 bridge，
Saga 另选 rss-runtime bridge，不用全 feature 编译替代独立选择。`--scenario core|pg` 可用于开发定位，
Reconcile 还支持 `messaging`，Saga 还支持 `runtime`；正式完整验收不缩小选择。
consumer 复制场景及 fixture，独立 manifest/lock/target；所有 PG 组合均实际执行 binary 并核对持久结果。
祖先和用户 Cargo source/patch/paths 覆盖拒绝，解析图继续验证精确来源及 feature。
纯工具由 `hack/package_proof.py` 单独持有；组件入口仅选择自己的场景，不新增 runner 或 receipt registry。
候选流水线复用既有 packages.tsv/SHA256SUMS，并上传 commands.log、resolved.json、Cargo.lock 与后端运行日志。
这些说明不是通过记录；精确最终 SHA、包/版本/digest、环境与运行结果在 issue/PR 签署。

### Independent Outbox writer and relay (#2362)

`outbox-writer` explicitly selects the PG writer and the dependencies needed for business SQL; it
does not enable the cancellation-oriented `execution-pg` feature or depend on `tokio-util`. The fixture
runs it after revoking Inbox and relay grants; it verifies commit and rollback of business + Outbox.
The `relay-only` probe implements delivery without an append method or transaction associated type.

```sh
python3 hack/extract-package-proof.py --source --scenario outbox-writer --scenario relay-only
python3 hack/extract-package-proof.py --artifacts "$RSS_PACKAGE_PROOF" --revision "$RSS_REVISION" --scenario outbox-writer --scenario relay-only
```

Both also run in the default scenario selection. The artifact command requires a clean exact
candidate revision and records archive digests; compilation alone is not writer behavior evidence.
The PG adapter still enables its existing core producer/consumer features; a narrow writer API does
not claim that delivery types have been removed from the adapter's dependency graph.
