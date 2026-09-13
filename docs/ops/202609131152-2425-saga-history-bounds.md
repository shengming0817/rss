# Saga 历史资源边界：验证与测量

关联：#2425 / PR #1014。以下为 2026-09-13 UTC 的实测，不建立生产性能 SLO。

## 被测身份与环境

```text
revision=bc59fe9a88662e03e7c0bfef8206ab7b81864569
binary_sha256=c3cf4fb176d437929162a1d758b8b3835dfb6720818d4708cbce254616ea2e9b
rustc=1.96.0 (ac68faa20 2026-05-25)
profile=debug
host=macOS 26.4 / arm64
postgres=16-alpine / verified TLS
postgres_image=sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
```

每个档位使用独立测试进程和一次性 PostgreSQL fixture。时间不是隔离机器上的统计分布；
首次查询的准备成本、缓存与主机负载会影响结果。本轮独立源码消费构建与 CI 同时运行，因此不据提交时间的差异推导历史增长复杂度。

## 测量结果

| 档位 | 已存事件 | 计费字节 | journal DataRow 字节 | snapshot ms | run ms | 提交次数 / 总 ms | 峰值 RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| entries-100 | 100 | 25600 | 11750 | 29.413 | 17.644 | 2 / 7.149 | 26.67 |
| entries-1000 | 1000 | 256000 | 117500 | 55.900 | 84.919 | 2 / 29.930 | 27.55 |
| entries-10000 | 10000 | 2560000 | 1175000 | 250.617 | 279.360 | 2 / 10.992 | 26.81 |
| bytes-50 | 3 | 5246865 | 4794373 | 202.984 | 367.330 | 1 / 32.109 | 47.39 |
| bytes-95 | 3 | 5246865 | 4793855 | 216.383 | 314.078 | 1 / 4.022 | 47.33 |
| bytes-100 | 3 | 5246865 | 4794755 | 187.916 | 264.226 | 1 / 2.451 | 47.33 |

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
本次升级耗时 **21.776 ms**，WAL 增量 **255,856 字节**，组件关系及索引占用由
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

这些结果证明受测 library 场景及资源边界；不证明任意规模恢复、无限重试、生产 T3 或实际发布。

<details>
<summary>绑定上述身份的测量输出</summary>

```text
SAGA_HISTORY_MEASURE profile=entries-100 entries=100 charged_bytes=25600 reserved_bytes=256 capacity_bytes=268435456 journal_data_row_bytes=11750 snapshot_ms=29.413 run_ms=17.644 receipt_opens=0 receipt_open_ms=0.000 commits=2 commit_ms=7.149
maximum_rss_bytes=27967488

SAGA_HISTORY_MEASURE profile=entries-1000 entries=1000 charged_bytes=256000 reserved_bytes=256 capacity_bytes=268435456 journal_data_row_bytes=117500 snapshot_ms=55.900 run_ms=84.919 receipt_opens=0 receipt_open_ms=0.000 commits=2 commit_ms=29.930
maximum_rss_bytes=28884992

SAGA_HISTORY_MEASURE profile=entries-10000 entries=10000 charged_bytes=2560000 reserved_bytes=256 capacity_bytes=268435456 journal_data_row_bytes=1175000 snapshot_ms=250.617 run_ms=279.360 receipt_opens=0 receipt_open_ms=0.000 commits=2 commit_ms=10.992
maximum_rss_bytes=28114944

SAGA_HISTORY_MEASURE profile=bytes-50 entries=3 charged_bytes=5246865 reserved_bytes=10515488 capacity_bytes=31524706 journal_data_row_bytes=4794373 snapshot_ms=202.984 run_ms=367.330 receipt_opens=1 receipt_open_ms=0.355 commits=1 commit_ms=32.109
maximum_rss_bytes=49692672

SAGA_HISTORY_MEASURE profile=bytes-95 entries=3 charged_bytes=5246865 reserved_bytes=10515488 capacity_bytes=16591951 journal_data_row_bytes=4793855 snapshot_ms=216.383 run_ms=314.078 receipt_opens=1 receipt_open_ms=0.326 commits=1 commit_ms=4.022
maximum_rss_bytes=49627136

SAGA_HISTORY_MEASURE profile=bytes-100 entries=3 charged_bytes=5246865 reserved_bytes=10515488 capacity_bytes=15762353 journal_data_row_bytes=4794755 snapshot_ms=187.916 run_ms=264.226 receipt_opens=1 receipt_open_ms=0.295 commits=1 commit_ms=2.451
maximum_rss_bytes=49627136

SAGA_HISTORY_UPGRADE entries=416 migration_ms=21.776 wal_bytes=255856 relation_bytes_before=311296 relation_bytes_after=352256
maximum_rss_bytes=27901952
```
</details>
