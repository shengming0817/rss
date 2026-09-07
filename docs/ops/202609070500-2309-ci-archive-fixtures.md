# CI 分组、归档与共享 fixture

Make 是本地与 CI 的标准入口。`hack/ci-impact.py` 只选择 package 范围；`hack/ci-pipeline.py` 持有
一次选择、唯一测试分组 filter、构建身份与覆盖率判定。归档保留 Cargo fingerprint 元数据，让 trybuild 使用真实编译 feature。workflow 只编排 runner、缓存和产物。selection 从同一分组定义输出集成矩阵；unit/consumer 保留各自执行契约，最终门禁同时要求矩阵聚合成功。

普通 PR 为 affected；全局或未知影响回退全工作区测试及 80% 行覆盖率。deny 深度只由 develop/显式 `make ci-full` 开启；SemVer 按兼容承诺及影响独立选择，full 检查全部适用受保护包。取消人为 CI 总时限，不修改单项测试期限；GitHub 平台时限仍适用。

## 执行

```sh
make ci CI_BASE=origin/develop
make ci-full CI_BASE=<baseline>
# 同一启动器筛选单个真实测试；定向诊断不判定全工作区覆盖率
make ci CI_PART=tests CI_FILTER='package(=amqp-integration) and test(=shared_amqp_subscriber_lifecycle_suite)'
```

显式 `CI_FILTER` 独立于 affected 范围，零匹配即失败；筛选表达式同样写入 plan。
`CI_PART=select` 写出绑定 SHA 的 plan。GitHub 后续阶段通过 `CI_PLAN` 读取该产物，不能自行重新选择。
`CI_PART=build` 生成 nextest archive，验证所有非 ignored 测试恰好分到 unit、consumer、amqp、kafka、
providers 之一。consumer 先通过 `cargo fetch --locked` 准备冷 runner 的依赖下载，再运行 offline 证明；
保留独立 workspace/依赖解析/target，组内串行并使用独立编译缓存，不重新构建工作区。Kafka 独立 API/依赖图证明使用宿主 OpenSSL SDK（Linux 的 pkg-config/libssl-dev、
macOS 的 Homebrew openssl），避免为 cargo check 重编译 vendored OpenSSL；原工作区归档及真实 TLS 场景仍验证 vendored 构建。
三个 provider 组最多同时使用三个 runner，组内串行。doctest 使用独立 `cargo test --doc` 命令。

本地产物位于 `.local-ci-runs/current`，被 Git 忽略。普通和插桩构建使用不同 target 子目录与缓存身份。
执行 job 只运行原 archive；fixture 启动器作为 nextest non-test binary 一并构建、传递，不在执行 runner 重建。

所有 workflow 用 `python3 hack/ci-pipeline.py --install-toolchain` 从 `rust-toolchain.toml` 读取 channel/profile/components，统一安装并为独立消费目录设置默认工具链；不重复维护版本。

## fixture 所有权

`testkit` 的 `rss-test-launcher` 启动所选 provider，持有容器，向 nextest 子进程传递临时 0600 描述文件。
测试名中的 `shared_amqp_` / `shared_kafka_` / `shared_mqtt_` 声明所需共享 provider；
启动器只根据实际选中测试启动它们，纯脚本协议测试和独占测试不会额外启动共享 broker。
文件只包含客户端 TLS/连接信息和必要管理 endpoint，不传服务端私钥，不进入日志或 artifact。
共享 fixture 缺失即报错，不自行启动，也不切换独占路径。

普通 AMQP、Kafka、MQTT 使用共享实例。AMQP 用独立 vhost；Kafka 每个 fixture 用进程唯一 topic，
group/client ID 同时隔离；MQTT 的重连保留同一测试的 client ID，不同进程的公共配置添加 PID。
重启 broker、服务端 TLS 身份变化、PG 集群角色/ACL 与 archive 复合场景保持显式独占。
共享与独占复用同一构造和管理命令实现。MQTT 共享句柄不能重启 broker。

资源携带唯一 `rss.test-run` 标签。启动失败或取消时，启动器终止 nextest 进程组并清理本次标签的容器和网络；
容器 guard Drop 负责常规释放；网络 guard 在 5 秒期限内及时释放地址池容量，超时会终止并回收 Docker 子进程。
启动器保留最终兜底；标签扫描在单一 30 秒截止时间内
尝试所有可枚举资源，聚合失败而不因首项错误跳过后续删除。Docker 命令、启动与测试仍有界。清理失败或超时会与原 child exit code／启动或执行错误分类共同报告，不覆盖测试结果，不透传原始凭据。

## 覆盖率与失败

完整范围使用 `cargo llvm-cov show-env` 插桩后构建 archive。每组运行前清除自己的 profile 目录，
不同组写独立路径。构建期 proc-macro 对象和本轮 profile 也传递，避免漏掉原覆盖率口径。
覆盖率 job 校验 SHA、工具链、archive 和 launcher 摘要、分组身份以及逐个 profile 摘要，
解包原插桩对象后执行 `cargo llvm-cov report --nextest-archive-file ... --fail-under-lines 80`。
它不编译、不执行测试。缺组、损坏、身份不符、测试失败均失败；有效部分仍尽可能生成诊断报告。
最终 `cargo` 同时要求选择、静态检查、构建、所有执行组和应运行的 coverage 成功。

每阶段输出耗时；每个 fixture 输出镜像准备、容器启动至就绪和清理耗时、启动尝试次数及成功就绪数到不含凭据的
`fixture-metrics/<pid>.jsonl`，包括失败和取消 outcome。唯一入口为 `RSS_TEST_METRICS_DIR`；每进程独立写，进程内串行，无跨进程文件锁或轮询。写入失败留下同级 `fixture-metrics.incomplete` 标记并打印脱敏 warning。testcontainers 将启动和 readiness 纳入同一次有界调用，这一数值不冒充纯进程启动耗时。
正式 `result.json` 在诊断聚合前原子落盘。启动/等待失败用空退出码和独立错误字段表示；profile 元数据失败仍保留测试结论但阻断门禁。缺正式结果不容错。
聚合严格验证字段、范围和完整 JSONL；任一诊断故障或无记录标为 incomplete，保留原文件，不能将部分统计当完整数据。Summary/统计副本写入失败只告警。
旧环境变量和旧结果格式不再读取；旧运行不能复用作新执行输入。
GitHub step 时间保留 artifact 传输开销，缓存 summary 保留恢复 key、命中统计、保存结果和磁盘用量。

## 冷热验收

冻结 SHA 后 dispatch `cold_cache=true`。仅在完整运行成功且 checks/build/consumer 缓存实际保存后，
用同 SHA、同 baseline dispatch `warm_run=<cold run ID>-<attempt>`。精确缓存未命中则热跑失败，
不以相近缓存替代。失败修复后重新冻结 SHA 并从冷跑开始。实际结果和耗时写入既有 PR 验收记录，
首次完整数据前不承诺加速比例，不把历史问题当作已解决。

ref: [cargo-llvm-cov v0.8.7 report.rs](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.8.7/src/report.rs)
ref: [nextest archiving](https://nexte.st/docs/ci-features/archiving/)

PG 取消/期限证明在真实数据库到达 effect 或注入 commit 阶段后推进已有测试时钟，
保留 150ms 操作期限、连接回收与 durable rollback 断言；协调方同时观察操作提前完成，
并以真实 5 秒等待约束连接、阶段进入、期限响应及关闭，避免前置超时后永等通知。

## SemVer 独立检查与工具缓存

正常 PR/develop 由 plan 内的 semver 选择受影响受保护包，workflow 不重复维护清单。当前无承诺包明确跳过，
checks 不安装 SemVer；有受检项时独立 job 的失败、取消、缺正式结果均阻断最终 cargo。

```sh
make ci CI_PART=semver CI_BASE=<impact-base> CI_HEAD=HEAD
make ci CI_PART=semver CI_SEMVER_MODE=all CI_BASE=<impact-base>
# 显式比较可选择实验包；先 checkout 到声明 head，不隐式创建源码快照。
make ci CI_PART=semver CI_SEMVER_MODE=compare CI_SEMVER_PACKAGES=rss-contract CI_BASE=<baseline> CI_HEAD=HEAD
```

`CI_SEMVER_PACKAGES` 仅允许用于 `compare`，且不能与 `CI_SEMVER_FULL=1` 组合；冲突输入直接失败，不能缩小全量检查。
用户取消会先保存正式结果，再停止后续配置及流水线阶段。

受检源码必须是干净的 tracked checkout，base==head 保留相同比较，不偷偷改成父提交。
固定 cargo-semver-checks 0.49.0 与仓库 Rust 工具链联动验证。执行显式 default/all；仅两侧均证明 feature 集等价时去重。
过程宏不是该工具的受检通过项，rss-redact-derive 仍由现有消费者编译/trybuild 证明；显式要求工具检查不支持 target 时失败。
Rust 检查不替代 wire、持久化格式或行为证明。

GitHub 的 RSS SemVer workflow 支持独立 dispatch（baseline/head/packages），不重跑测试。
工具压缩包按版本/平台/架构/SHA256 缓存，恢复后复验；缺失、坏包或缓存服务失败回源，最多四次有界下载，
仅校验成功的包可安装和保存。工具安装、rustdoc/执行错误、兼容性失败分别保留实际阶段和退出码。
本地已选中检查需要同版 cargo-semver-checks；没有工具时严格失败，不影响未选中的普通检查。

工具冷热证据复用 cold_cache/warm_run：冷跑隔离 cache key 后缀为 run ID-attempt，热跑只接受对应精确命中、
再次验哈希且零回源，并核验相同 SemVer plan 与冷跑成功 result/cache facts。普通缓存失败可恢复，热跑不能以回源替代命中。
指标 complete 仅表示现存记录通过校验；性能验收还必须核对具体场景预期记录，缺写入证据不能宣称完整测量。
冷热事实及阶段耗时记入本次 PR 验收，不新增测量数据库或定时平台。

ref: cargo-semver-checks v0.49.0 src/main.rs
