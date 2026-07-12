# Integration 分片服务生命周期（#1732）

> 真集成测试继续使用 per-test testcontainers；本机制只为 CI 中 self-provision 的
> Postgres、Redis、RabbitMQ、Mosquitto 统一所有权、失败日志和异常退出补偿清理，不把服务提升为
> job-global workflow service。分片与 partition 单源仍是 `xtask/src/integration_shards.rs`。

## 生命周期

脚本接口是闭合的 `bootstrap`、`prepare`、`snapshot`、`collect`、`cleanup` 五个 operation。Integration
reusable job 在执行 xtask 前先 `bootstrap` lifecycle evidence，再调用 `prepare` 建立当前 job 唯一的
scope 和权限为 `0700` 的日志目录。日志目录名包含完整 scope，必须是本次 prepare 新建的空目录；已存在目录
会 fail-closed 且不会被删除或复用。prepare 在目录权限或 baseline 测量失败时只回收本次新建的目录，并把闭合
失败原因原子写回 bootstrap evidence。scope 由 repository id、run id、run attempt、
shard 与 filesystem-safe partition label 组成；partition 的 canonical 值只允许 `unpartitioned`、`1/2`
或 `2/2`。

四类 fixture 仍由每个测试独立启动。CI context 完整存在时，testkit 的唯一启动 funnel 为容器附加：

- `io.rss.integration.managed=true`
- `io.rss.integration.scope`
- `io.rss.integration.shard`
- `io.rss.integration.partition`
- `io.rss.integration.service`

日志 consumer 从容器创建开始写入独立的 `service-pid-sequence.log`，标记 stdout/stderr，单文件最多
1 MiB；越界时保留一个截断标记。本地未设置任何 CI context 时继续使用纯 hermetic fixture；只设置
部分 context 会 fail-closed。external fixture 环境变量的空字符串视为未配置，显式非空但不完整的
Postgres 五元组仍直接报错。

xtask 结束后的顺序固定为：`collect` 先把 xtask 的四值终态写入 evidence，并仅在 `failure` 时生成日志归档；
随后独立 `snapshot` 记录 cleanup-before 可用空间，最后 `always()` 精确清理并记录 cleanup-after 可用空间，
再生成通用 after-build CI evidence。失败归档在两次磁盘测量前已经存在，因此其保留占用同时计入 before/after，
不会被误判为 cleanup 泄漏；after 测量失败时保留 `null` 和 `failure` status，不复制 before 值。正常 Rust
Drop 是快速路径，job-finally cleanup 是进程 abort、slow-timeout 或信号导致 Drop 未执行时的补偿路径。

## 失败日志与证据

`collection.outcome` 始终终结为 GitHub step 的 `success`、`failure`、`cancelled` 或 `skipped` 之一，不以
`null` 表示完成状态；artifact staging 在复制 lifecycle evidence 前以精确四值断言 fail-closed。成功、取消或跳过不创建服务日志压缩包；只有 `failure` 时，`collect` 才读取当前
私有日志目录，并为仍存在且重新校验为 exact scope 的容器补抓 `docker logs`。未压缩 payload 预算为 60 MiB，最终 tar.gz 上限为
64 MiB；Docker 日志在 producer 侧按剩余预算截断，control 输出固定限制为 1 MiB，达到预算会写入
`TRUNCATED.txt`。文件日志只接受四类服务的 canonical `service-pid-sequence.log` 普通文件，并要求同 basename
的 `.status` 普通文件精确为 `ok`；缺失、symlink、畸形或 `writer-error` 会将 collection 标记 degraded 并写入
闭合 writer I/O evidence，status 本身不进入归档。额外文件和畸形名称均不归档；机制不会扫描 runner 其它目录，
也不会归档容器 `inspect Env`。

`integration/lifecycle.json` 始终随现有 job evidence artifact 上传；字段闭集由 schema v1 golden 和
shell selftest 冻结。它记录 context、prepare 状态、baseline/cleanup-before/cleanup-after 可用字节数与测量状态、
日志归档 attempted/captured/degraded 状态、尝试与成功删除的容器 ID、闭合 Docker operation/reason/exit status
及镜像处置结论。Docker stderr 不写入 artifact；step 只输出不含原始 daemon 文本的有界诊断。prepare 失败时
bootstrap evidence 仍进入 artifact。大日志只在存在压缩包时进入同一 artifact，
retention 沿用 workflow 的 7 天。

## 清理安全边界

cleanup 必须同时以 `managed=true` 与 exact scope 查询候选，并在删除每个 ID 前重新 inspect 五个标签；
只有再次匹配的容器才执行 `docker rm -fv`。已经由 Drop 删除的容器使 cleanup 自然幂等。单个 inspect
或 remove 失败不会阻止继续处理其它候选，但 cleanup 最终返回非零并把闭合错误写入 evidence。reason 只允许
`unavailable`、`timeout`、`daemon-unreachable`、`permission-denied`、`not-found`、`conflict`、`io`、
`unknown`、`invalid-output`，不保留开放式 fallback。`ps`、
`inspect`、`logs`、`rm` 均有短 deadline，超时先 TERM、再 KILL，并以 `reason=timeout` 记录；单个 Docker
调用的 deadline 为 5 秒，随后 TERM，并在 2 秒 kill-after 后 KILL；阻塞不会吞掉后续候选或整个
job-finally 窗口。

workflow 另有独立 wall-clock 上限：全部 21 个 step 都有显式 timeout，闭合总和为 220 分钟，job ceiling 为
240 分钟，因而即使所有前置 step 用满预算也不会挤占 finally 的 26 分钟。xtask 命令在 90 分钟 TERM、30 秒后 KILL，step
硬上限为 92 分钟。job-finally 的 collect、snapshot、cleanup 命令上限依次为 10 分钟、30 秒、10 分钟，
kill-after 依次为 30 秒、5 秒、30 秒，对应 step 硬上限为 12、2、12 分钟。因三个 finally step 都使用
`always()` 且彼此不以先前 step success 为条件，collect 超时后 snapshot 与 cleanup 仍会执行；命令级
finally 总预算最多约 21 分 35 秒，step 级总硬上限为 26 分钟；job 另保留 20 分钟 ceiling 余量。

禁止 `docker system prune`、`docker image prune` 和 `docker volume prune`。匿名卷只随 owned container
的 `rm -v` 删除；容器标签不会传播到 image，且共享 daemon 存在并发拉取竞态，因此没有可证明的
job-owned 镜像层，固定记录 `imageCleanup=skipped-unprovable-ownership`，不删除镜像。

这些系统边界由 `CI-INTEGRATION-SERVICE-LIFECYCLE-01`（Medium）守住：xtask topology guard 锁定
integration-only 条件和步骤顺序，fake-Docker selftest 覆盖跨 scope canary、重新 inspect、幂等、部分
失败和禁止 prune。Rust 侧通过私有 `AsyncRunner` 导入和 typed context 形成编译期启动 funnel。

## 排障

1. `integration container context 不完整`：检查 prepare step 是否完整写入四个 `RSS_CI_*` 变量；不要补空值。
2. 测试失败：下载当前 shard/partition/run-attempt 的 artifact，先看 `integration/service-logs.tar.gz`，再看
   `integration/lifecycle.json` 的 `preparation`、`collection` 与 `cleanup.errors`；`degraded=true` 表示归档存在但
   至少一次 Docker 取证失败或 payload 被截断。
3. cleanup 失败：按 `containerId`、`operation`、`reason` 和 `exitStatus` 检查 Docker daemon 权限或资源状态；
   不要手工扩大 label filter。
4. 比较 `beforeCleanupAvailableBytes` 与 `afterCleanupAvailableBytes` 判断泄漏资源回收效果，并与通用
   `ci/ci-evidence.json` 的 after-build 快照交叉确认。

`always()` 不能保证 runner 被强制销毁后仍获得调度；这种执行边界与通用 CI evidence 相同。机制不会为此
扫描或删除其它 run 遗留的 testcontainers 资源。

ref: testcontainers/testcontainers-rs testcontainers/src/core/containers/async_container.rs@2c96733fd42aed77105f4003e0fe98f59c644848
