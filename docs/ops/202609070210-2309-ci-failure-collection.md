# CI 失败收集与 AMQP 关闭验证

关联 Azure 工作项 #2307、#2309。CI 清单仍由 Make 持有；两组各自使用独立 runner、target 和
sccache server，组内顺序执行，预算和失败退出码不变。

## 完整收集

`make ci` / `make ci-full` 的 checks/tests 每条可执行命令均运行并汇总非零结果；nextest 与
Cargo doctest 显式使用 `--no-fail-fast`。编译失败无法产生测试二进制、进程取消和总预算耗尽仍可能
阻止部分测试运行，不能据此宣称全部用例执行。coverage 即使生成，也不覆盖测试失败的最终结论。
SemVer 先验证 revision 和授权元数据，随后继续检查其余 package / feature；输入非法仍拒绝执行。

Kafka `consumer` 独立消费测试加入既有 compiler-proof 串行组，保留独立 workspace、target 与
120 秒预算。避免它与其它嵌套 Cargo 构建同时竞争 runner CPU，不改变依赖隔离证明。
Linux dev/test profile 仅保留行号调试信息，保持默认 debug assertions、overflow checks 与覆盖率插桩；
显式 `CC=sccache cc` / `CXX=sccache c++`，避免 llvm-cov 接管 Rust wrapper 后 native 构建失去缓存。

## 最近一天的已知失败

检查窗口：2026-09-06 至 2026-09-07 本次任务开始。

| 运行 | 观察 | 当前判断 |
| --- | --- | --- |
| 34041382103 | PG independent consumer 120 秒超时 | 主线已配置 compiler-proof 串行组；本轮复核 |
| 34042060884 | offline metadata 请求 android_system_properties | 主线已使用宿主平台过滤；本轮复核 |
| 34043790726 | SagaReceiptProtectionContext / Coordinates 公共 API 移除 | 历史 baseline 的 SemVer 失败，不能外推为新 baseline 失败 |
| 34046929820 | publisher close Operation；Saga receipt 用例失败 | 主线已共享 publisher close future、调整 Saga 夹具租约；本轮复核 |
| 34048025164 | 私有 CA subscriber shutdown Operation，569/588 执行 | #2307 剩余关闭问题与 #2309 fail-fast 缺口 |
| 34074163896 | Kafka independent compilation 120 秒超时，625/680 执行；checks 在 SemVer 达到 job 上限 | 本轮新增诊断；无完整 CI 通过证据 |

完整运行与冷/热缓存通过是不同证据。最终验收须绑定同一 SHA 和 baseline，回填 GitHub run、两组
结果、restore/save key、sccache 命中、耗时、目录大小和可用磁盘。`workflow_dispatch.cold_cache=true`
跳过两种恢复但保持可信分支保存；下一轮 false 使用同一候选及 baseline 验证恢复。PR 始终只恢复。

## 本次定位

本地首轮完整执行 680 项：678 通过、2 失败、4 跳过；doctest 与覆盖率报告继续执行，行覆盖率
90.63%。AMQP broker 回归在修复前观察 connection=0（预期 1）；改为先 join 取消任务再 close 后通过。
Device-command 夹具曾假设一次 claim 返回所有租户，DR fencing 的一次提交只返回一个租户批次；
夹具现在在同一 AbsoluteDeadline 下逐次投影剩余预算并排空批次。两项 coverage 定向回归均通过。
Linux 34075251697 同时复现上述两项；Kafka 仍超 120 秒，MQTT 事务消费 publication 失败，
两组最终达到 job 上限。MQTT 增加 closed failure/ambiguity 分类诊断，Kafka 超时保留编译日志。
这些历史失败不作为最终候选通过证据。

最终同 SHA 的可更新验收记录放在 [GitHub PR #4](https://github.com/shengming0817/rss/pull/4)
与 [Azure PR #943](https://dev.azure.com/shengming0923/rss/_git/rss/pullrequest/943) 的验证评论中，
避免为了提交运行结果而改变待验证 SHA。评论必须记录上节列出的全部指标。

## 回归载体

`hack/tests/test_ci_make.py` 用真实 Make recipe 和可失败的 Cargo stand-in，覆盖多条失败后全部
可执行命令仍被调用且整体非零；SemVer 用两个包、两组 feature 证明首包失败不短路。
AMQP 的 broker 回归将 subscription cancellation 暂停，检查 shutdown 不能提前关闭其 connection，
释放后确认连接退出；既有零预算、future drop、超时、私有 CA 拒绝及 split-role 权限断言继续保留。

ref: lapin src/connection.rs@71d01e2cc3e3221496d11ffcf1f4aaf41532fb9d
ref: lapin src/internal_rpc.rs@71d01e2cc3e3221496d11ffcf1f4aaf41532fb9d
ref: cargo-nextest https://nexte.st/docs/configuration/test-groups/

ref: sccache README.md@v0.15.0
ref: Cargo https://doc.rust-lang.org/cargo/reference/profiles.html#debug


## 第二轮 Linux 定位

Run [34076132335](https://github.com/shengming0817/rss/actions/runs/34076132335) 在 SHA `471fb6e34` 再次触及原 10 分钟预算：tests 初次编译 4m44s，591/680 项后取消；checks 尚未完成 Kafka SemVer。已修复新增回归的 Clippy 复杂度错误。Kafka 在编译 vendored OpenSSL/rdkafka 时超出 120 秒，现在独占 nextest 执行线程并在超时时终止整个编译进程组；保留独立 target、特性闭包和原期限。

用户通过飞书请求 `Q-24bf6a60ba2d48bd9f82a033404dc1d9` 明确选择：显式全量 dispatch/develop 的 job 上限改为 20 分钟，PR affected preflight 保持 10 分钟。该选择覆盖原 issue 的预算约束，不改变任何单项测试期限或失败判定。

本地第二轮 nextest 681/681 通过、doctest 通过，完整命令仍因上述 Clippy 错误返回非零，未将测试通过等同于全 CI 通过。远端仍复现 private CA subscriber Operation 和 delivery ACK shutdown transient，需继续修复 lapin Drop 自动关闭与连接关闭的竞态；冷热验收尚未完成。
