# Phase 1 Data Model: eventexec 数据持久化与事件处理

durable 拓扑的 postgres 表 + 引擎类型 + 状态机。demo 拓扑以 `adapters/memory` in-mem 等价替身（同语义，不落表）。所有表遵 migration 只增不改、新字段默认值/NULL、pre-GA 普通 `CREATE INDEX`、命名 `{序号}_{动词}_{对象}.sql`。

## 引擎类型（consistency，P1/P2 兑现 body）

| 类型 | 模块 | 形态 | 校验/funnel |
|------|------|------|------------|
| `IdemKey` | idempotency(L0) | newtype(String) | parse 拒空 |
| `SeenState` | idempotency | enum {Fresh,Duplicate} | 穷尽 |
| `Topic` | outbox(L1) | newtype(String) | parse 拒空/非 canonical dotted |
| `Disposition` | outbox | enum {Ack,Requeue,Reject} | as_label 闭映射 |
| `PermanentError`/`Kind` | outbox | struct/enum {Permanent,Invariant} | 排除 Transient |
| `HandleResult` | outbox | struct(私有) | ack/requeue/reject funnel |
| `Entry` | outbox | struct(私有: topic,idem_key,payload) | new funnel + envelope 注入 |
| `EngineError`/`Kind` | error | struct/enum {Transient,Permanent,Invariant} | message &'static const |
| `StepName` | saga(L3) | newtype | parse 合法 Rust 标识符 |
| `SagaOutcome`/`CompensationOutcome` | saga | enum | 穷尽 |
| `EntityId` | reconcile(L4) | newtype | parse 拒空 |
| `Request`/`Outcome`/`Context` | reconcile | struct(私有) | default=resync；Context opaque sealed |
| `ReconcileError` | reconcile | struct | is_transient/is_permanent |
| `Lsn` | projection(L3) | newtype(u64) | 单调 |
| `ProjectionEvent` | projection | sync trait | topic/lsn/payload |

## Postgres 表

### outbox（P4）
| 列 | 类型 | 说明 |
|----|------|------|
| id | uuid PK | entry id |
| event_id | uuid UNIQUE | 幂等 key（EventId，消费侧去重锚） |
| domain | text | 归属域（per-domain relay 读） |
| topic | text | dotted topic |
| contract_id | text | 契约 id |
| payload | bytea | 已编码 payload |
| metadata | jsonb | envelope: trace/correlation/principal/occurred_at；`principal` 仅 opaque subject id（UUID），不序列化完整 Principal 或含 PII（refs: FR-020） |
| status | text | pending/publishing/published/dlx（值集冻结） |
| retry_count | int default 0 | |
| retry_after | timestamptz NULL | 瞬态失败延后 |
| lease_token | uuid NULL | relay CAS fencing |
| created_at/updated_at | timestamptz | |

- Index: `(domain, status, retry_after)`（relay 扫未发）；`(created_at)`（清理）。
- 状态机：`pending → publishing → published`；`publishing →(永久/预算耗尽)→ dlx`；`publishing →(瞬态)→ pending(+retry_after)`。
- CAS：status 转移以 `lease_token` 比对（防并发双发）。

### inbox_dedup（P5）
| 列 | 类型 | 说明 |
|----|------|------|
| event_id | text | 去重 key |
| consumer_group | text | 消费者组（稳定，漂移则去重失效） |
| status | text | claimed/done |
| lease_token | uuid NULL | claim fencing |
| claimed_at | timestamptz | |

- PK: `(event_id, consumer_group)`。claim = INSERT ON CONFLICT DO NOTHING → 首见 Fresh，冲突 Duplicate。
- Redis 等价：按 observability.md §Redis Namespace 当前登记的 outbox 消费幂等 claimer key `_runtime:{eventID}:lease|done` 扩 consumer-group 维度为 `_runtime:{eventID}:{group}:lease|done`。**该扩展格式须由 T005 在 observability.md §Redis Namespace 登记**（与既有 `_runtime:{eventID}` 形态结构性互斥），否则违反「新增 `_runtime` shared-infra 原语必须登记」规则。EventId 全局唯一（UUID）保证跨租户不冲突；key 不加 tenant 段属显式决策（见 spec.md §Assumptions 租户隔离立场）。

### dead_letter（P7）
| 列 | 类型 | 说明 |
|----|------|------|
| id | uuid PK | |
| domain/contract_id/topic | text | |
| original_entry | jsonb | 原始 entry 引用 |
| error_summary | text | 安全摘要（经 `secure` redaction + 长度截断约 512 chars，不直接写 handler 的 Display/Debug 原文、不含原始 payload 片段；runtime 数据只经 `with_internal` 进服务端 tracing） |
| num_attempts | int | |
| first_attempt_at/last_attempt_at | timestamptz | |

### saga_journal（P9）
| 列 | 类型 | 说明 |
|----|------|------|
| saga_id | uuid | |
| seq | bigint | append 序（journal 顺序） |
| step_name | text | |
| status | text | executing/completed/compensating/compensated/failed |
| output | bytea NULL | step 输出 |
| error_summary | text NULL | |
| occurred_at | timestamptz | |

- PK: `(saga_id, seq)`。append-only。resume = 读 max(seq) 重建栈。
- 补偿：失败时按 seq 逆序对 completed step 调 compensate。

### checkpoint（P9，saga+projection 共享）
| 列 | 类型 | 说明 |
|----|------|------|
| owner | text | 消费者 owner |
| checkpoint_id | text | 投影/saga 标识 |
| offset_lsn | bigint | 已处理位点(Lsn) |
| version | bigint | CAS 版本 |
| updated_at | timestamptz | |

- PK: `(owner, checkpoint_id)`。save = CAS by version（旧版本拒）。

### projection_events（P10）
| 列 | 类型 | 说明 |
|----|------|------|
| id | bigint PK（单调=Lsn 源） | |
| domain/aggregate_id/event_type | text | |
| payload | bytea | |
| occurred_at/correlation_id/created_at | | |

- **append-only**：migration 内 `REVOKE UPDATE, DELETE`；代码侧 dylint `rss_projection_append_only` 拒 DELETE/TRUNCATE 字面量（PROJECTION-APPEND-ONLY-01）。
- Index: `(domain, aggregate_id)`。

### command 表（P12）
- 复用 outbox 表（topic = `<domain>.commands.<name>`，event_id=DispatchId，payload=Request JSON）；不另建表。

## DI port 数据契约（diport）

| port | 方法（async dyn） | 落地 PR |
|------|------------------|---------|
| `OwnerCheckpointStore` | get_checkpoint / save_checkpoint(CAS) | P9 |
| `LeaderElector` | acquire_lease / renew_lease(LostLease) | P11 |
| `FencedWriter` | write_fenced(key,val,epoch)→bool | P11 |
| `DeadLetterStore` | write_dead_letter | P7 |
| `TxRunner` | run_in_transaction | P3(基座)/P10(projection 用) |

> 既有 `Publisher`/`Subscriber`/`AuditSink`/`Clock`/`Signer`/`ManagedResource`/`SubscribeInitializer` 已在 diport（已实现/已冻结）。`IdempotencyStore`/`OutboxRelay` 是 consistency 引擎 trait（native AFIT，非 diport）。

## 状态机汇总

- **outbox entry**：pending→publishing→{published | dlx | pending(retry)}。
- **inbox claim**：absent→claimed→done（重投见 claimed/done 即 Duplicate）。
- **saga**：running→{succeeded | compensating→{compensated(failed 终态) | dead-letter}}。
- **reconcile entity**：observe→{settled | requeue_after | transient-backoff}；leader 丢 lease→cancel。
- **projection checkpoint**：offset N→N+1（CAS version++）；replay 从 0。
