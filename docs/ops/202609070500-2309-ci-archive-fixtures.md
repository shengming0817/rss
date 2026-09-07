# CI 分组、归档与共享 fixture

Make 是本地与 CI 的标准入口。`hack/ci-impact.py` 只选择 package 范围；`hack/ci-pipeline.py` 持有
一次选择、唯一测试分组 filter、构建身份与覆盖率判定。归档保留 Cargo fingerprint 元数据，让 trybuild 使用真实编译 feature。workflow 只编排 runner、缓存和产物。selection 从同一分组定义输出集成矩阵；unit/consumer 保留各自执行契约，最终门禁同时要求矩阵聚合成功。

普通 PR 为 affected；全局或未知影响回退全工作区测试及 80% 行覆盖率。deny/SemVer 深度独立，
只由 develop/显式 `make ci-full` 开启。取消人为 CI 总时限，不修改单项测试期限；GitHub 平台时限仍适用。

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
`fixtures.jsonl`，包括失败和取消 outcome。testcontainers 将启动和 readiness 纳入同一次有界调用，这一数值不冒充纯进程启动耗时。
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
