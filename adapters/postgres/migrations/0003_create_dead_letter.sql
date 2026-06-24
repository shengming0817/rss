-- 0003_create_dead_letter.sql — 死信持久化表（DLX，eventexec ConsumerBase，#1120）。
--
-- 仅 INSERT（immutable append）；不执行 UPDATE / DELETE——死信记录是不可变审计物料，
-- 运维巡检 / 重放通过 SELECT 读取，不修改原记录。
--
-- original_entry jsonb 存原始 payload 字节的 JSON 数组表示（{"bytes": [u8, ...]}），
-- 往返完整保留原始字节；调用方（PgDeadLetterStore）负责序列化/反序列化（仅用 serde_json）。
-- error_summary 是调用方传入的已脱敏 + 截断安全摘要，不含原始错误串或 PII。
--
-- first_attempt_at / last_attempt_at 均用 DB DEFAULT now()（不注入 Clock，
-- 与 outbox/inbox 同范式：时间源保持 DB 端单一，无跨进程偏移）。
--
-- 语义澄清：immutable append 设计下 last_attempt_at == first_attempt_at == 写入时刻
-- （每条 INSERT 仅执行一次，不更新已有行）。重试次数由 num_attempts 字段表达；
-- 勿误以为 last_attempt_at 可用于筛选「最近一次失败」——该语义在 immutable 模式下无意义。

CREATE TABLE dead_letter (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain           text        NOT NULL,
    contract_id      text        NOT NULL,
    topic            text        NOT NULL,
    original_entry   jsonb       NOT NULL,
    error_summary    text        NOT NULL,
    num_attempts     int         NOT NULL,
    first_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at  timestamptz NOT NULL DEFAULT now()
);

-- 运维巡检扫描索引：按 domain + last_attempt_at 范围扫（「最近失败记录」主路径）。
CREATE INDEX idx_dead_letter_scan ON dead_letter (domain, last_attempt_at);
