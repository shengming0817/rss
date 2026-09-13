# Saga 历史资源边界：验证与测量

关联：#2425 / PR #1014。以下为 2026-09-13 UTC 的实测，不建立生产性能 SLO。

## 被测身份与环境

```text
revision=2a5f103c942f4e8922c96cc3e21df66032f73415
binary_sha256=dedfaa52ee582a12205d93f505329d6e0ab85800720ce4528fa7f6eb757068e4
rustc=1.96.0 (ac68faa20 2026-05-25)
profile=debug
host=macOS 26.4 / arm64
postgres=16-alpine / verified TLS
postgres_image=sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
```

每个档位使用独立测试进程和一次性 PostgreSQL fixture。时间不是隔离机器上的统计分布；
首次查询的准备成本、缓存与主机负载会影响结果。本轮独立源码消费构建同时运行，因此不据提交时间的差异推导历史增长复杂度。

## 测量结果

| 档位 | 已存事件 | 计费字节 | journal DataRow 字节 | snapshot ms | run ms | 提交次数 / 总 ms | 峰值 RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| entries-100 | 100 | 25600 | 11750 | 8.996 | 21.068 | 2 / 7.991 | 27.25 |
| entries-1000 | 1000 | 256000 | 117500 | 27.587 | 42.313 | 2 / 9.585 | 27.19 |
| entries-10000 | 10000 | 2560000 | 1175000 | 250.049 | 243.915 | 2 / 10.049 | 27.38 |
| bytes-50 | 3 | 5246865 | 4793971 | 173.416 | 258.602 | 1 / 3.033 | 47.34 |
| bytes-95 | 3 | 5246865 | 4795474 | 189.762 | 275.316 | 1 / 3.707 | 47.39 |
| bytes-100 | 3 | 5246865 | 4795188 | 179.281 | 271.541 | 1 / 3.165 | 47.39 |

- `snapshot` 包含锁定元数据、读取、类型化解码和完整事件回放；随后 `run` 再执行一次正常恢复，
  包含完整回放、认证、测试 action/probe 与提交，两个时间不能直接相减解释为密码学成本。
- 提交耗时由委托到真实 PgStore 的计时 Store 记录；事件档位执行一个 intent 和一个 settlement，
  字节档位执行一个 pending probe settlement。当前提交访问固定进度及必要定点记录，完整恢复仍随历史增长。
- journal DataRow 字节按实际 SQL 投影的二进制字段宽度和实际 JSONB 文本长度统计：每行固定 100 字节，
  加 kind 长度及非空 receipt 的 JSONB 版本字节、文本长度；不含其它协议消息、definition 和元数据响应。
- RSS 来自 macOS `/usr/bin/time -l`，包含该 Rust 测试进程的 fixture 准备和整次运行，
  不包含 Docker/PostgreSQL 进程，不代表单个 Snapshot 的净 heap。
- 字节档位先通过真实 executor 产生一个 1 MiB 合法明文 receipt，再显式增加容量，记录第二步 pending。
  占用口径为 `(已用编码字节 + 必需预留)/容量`；95% 的整数向上取整误差小于一字节。
  三个档位均成功完成 pending 结算，100% 占用没有阻断已准入效果。

升级覆盖 416 条事件、pending、补偿暂停、成功和 400 条长历史四类实例。
本次升级耗时 **26.103 ms**，WAL 增量 **255,968 字节**，组件关系及索引占用由
**311,296** 变为 **352,256 字节**。关系占用差值不是迁移期间的临时磁盘峰值；
产品仍需为实际数据规模安排停写窗口、执行时限与临时磁盘空间。

## 复现

在仓库工作目录先编译 `saga-postgres-integration` 的 suite 和已有 fixture launcher。
使用 `cargo test --locked -p saga-postgres-integration --test suite --no-run --message-format=json`
返回的 executable 路径替换下面的 `SUITE_BINARY`；无需创建新的 CI gate。

```sh
cargo build --locked -p testkit --features containers --bin rss-test-launcher
RSS_TEST_RUN_ID=saga-history-local RSS_SAGA_HISTORY_PROFILE=entries-10000   target/debug/rss-test-launcher -- /usr/bin/time -l SUITE_BINARY   --exact history_measurements --ignored --nocapture
RSS_TEST_RUN_ID=saga-history-upgrade   target/debug/rss-test-launcher -- /usr/bin/time -l SUITE_BINARY   --exact history_upgrade --nocapture
```

其余 profile 为 `entries-100`、`entries-1000`、`bytes-50`、`bytes-95`、`bytes-100`。
每个并发运行使用不同 `RSS_TEST_RUN_ID`。Linux 可用 `/usr/bin/time -v` 并注明其 RSS 单位。

## 行为证明与边界

Core 用例覆盖跨 run 的 crash/负向 probe 累积、补偿 Resume、精确容量边界、最大 envelope、
认证预算逐次扣减（恢复认证与补偿共用）、未知正向/补偿 probe 保留 pending、错序拒绝和显式扩容 CAS。真实 PG 用例覆盖租户/lease、ACK 丢失、进程中断、
同一状态转换与计量的回放对照、约束漂移、巨大单行及计量篡改拒绝、同行 receipt 和单向升级。首审修复后额外覆盖 44 项独立权限/结构漂移，以及三个字节数组各 7 类非法值、字符串型 format/seq/attempt 共 24 个向量在 definer、同行 CHECK、升级三个入口的拒绝。
独立 source consumer 分别执行 core-only、PostgreSQL、runtime 组合。

F6 将 Report 收敛为单一只读 HistoryHead；新增三项编译失败测试证明消费者不能改写报告 revision、
改写 HistoryHead revision 或导入内部 Progress。完整本地 CI 的最终结果见 PR #1014 的交接记录。

这些结果证明受测 library 场景及资源边界；不证明任意规模恢复、无限重试、生产 T3 或实际发布。

<details>
<summary>绑定上述身份的测量输出</summary>

```text
SAGA_HISTORY_MEASURE profile=entries-100 entries=100 charged_bytes=25600 reserved_bytes=256 capacity_bytes=268435456 journal_data_row_bytes=11750 snapshot_ms=8.996 run_ms=21.068 receipt_opens=0 receipt_open_ms=0.000 commits=2 commit_ms=7.991
maximum_rss_bytes=28573696

SAGA_HISTORY_MEASURE profile=entries-1000 entries=1000 charged_bytes=256000 reserved_bytes=256 capacity_bytes=268435456 journal_data_row_bytes=117500 snapshot_ms=27.587 run_ms=42.313 receipt_opens=0 receipt_open_ms=0.000 commits=2 commit_ms=9.585
maximum_rss_bytes=28508160

SAGA_HISTORY_MEASURE profile=entries-10000 entries=10000 charged_bytes=2560000 reserved_bytes=256 capacity_bytes=268435456 journal_data_row_bytes=1175000 snapshot_ms=250.049 run_ms=243.915 receipt_opens=0 receipt_open_ms=0.000 commits=2 commit_ms=10.049
maximum_rss_bytes=28704768

SAGA_HISTORY_MEASURE profile=bytes-50 entries=3 charged_bytes=5246865 reserved_bytes=10515488 capacity_bytes=31524706 journal_data_row_bytes=4793971 snapshot_ms=173.416 run_ms=258.602 receipt_opens=1 receipt_open_ms=0.272 commits=1 commit_ms=3.033
maximum_rss_bytes=49643520

SAGA_HISTORY_MEASURE profile=bytes-95 entries=3 charged_bytes=5246865 reserved_bytes=10515488 capacity_bytes=16591951 journal_data_row_bytes=4795474 snapshot_ms=189.762 run_ms=275.316 receipt_opens=1 receipt_open_ms=0.346 commits=1 commit_ms=3.707
maximum_rss_bytes=49692672

SAGA_HISTORY_MEASURE profile=bytes-100 entries=3 charged_bytes=5246865 reserved_bytes=10515488 capacity_bytes=15762353 journal_data_row_bytes=4795188 snapshot_ms=179.281 run_ms=271.541 receipt_opens=1 receipt_open_ms=0.304 commits=1 commit_ms=3.165
maximum_rss_bytes=49692672

SAGA_HISTORY_UPGRADE entries=416 migration_ms=26.103 wal_bytes=255968 relation_bytes_before=311296 relation_bytes_after=352256
maximum_rss_bytes=28311552
```
</details>
