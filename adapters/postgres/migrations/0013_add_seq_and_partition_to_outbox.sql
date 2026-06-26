-- 0013_add_seq_and_partition_to_outbox.sql — outbox 分区有序投递支持（#1211）。
--
-- seq：表级单调序（GENERATED ALWAYS ⇒ 应用不可写/伪造、隐式 NOT NULL、允许 gap）= partition 内投递顺序锚。
-- partition_key：NULL = 无序并行（与现有行为兼容）；NOT NULL = 同 (domain, partition_key) 串行有序。
--   head-of-partition gating 在 poll_pending 收口：NOT NULL 行仅在同 partition 所有 seq < o.seq 的行已
--   published 时才被捞出，保证同 partition 内严格按 seq 顺序投递。
-- 只增不改（pre-GA 普通 ALTER，migration README §索引形态）。
-- idx_outbox_partition_head：加速 poll_pending NOT EXISTS 子查询的 (domain, partition_key, seq) 范围扫
-- （partial：仅非 published 行，加速 happy-path NOT EXISTS——happy-path 下同 partition 前驱全 published，
-- partial 索引排除 published 行后该 partition 索引项为 0 → NOT EXISTS O(1) 无 heap-fetch）。

-- 注意：GENERATED ALWAYS AS IDENTITY 的 volatile default（nextval()）非 PG fast-path；非空表
-- ADD COLUMN 需 ACCESS EXCLUSIVE + 逐行回填，故仅 pre-GA 空表安全（与 CONCURRENTLY 索引禁用理由对称）。
ALTER TABLE outbox ADD COLUMN seq           bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE outbox ADD COLUMN partition_key text;
CREATE INDEX idx_outbox_partition_head
    ON outbox (domain, partition_key, seq) WHERE partition_key IS NOT NULL AND status <> 'published';
