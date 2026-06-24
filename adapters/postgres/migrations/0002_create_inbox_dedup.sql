-- 0002_create_inbox_dedup.sql — inbox_dedup：消费幂等去重表（claim-or-skip，PK (event_id, consumer_group)）。
-- #1118 / data-model §inbox_dedup。
--
-- claim = INSERT ON CONFLICT DO NOTHING → 首见（插入成功, rows_affected=1）= Fresh；
-- 冲突（0 行）= Duplicate。status / claimed_at 用表 DEFAULT，INSERT 不显式传。
-- lease_token 已删除（YAGNI：claim-or-skip 只需 PK；T007 consumer 阶段再按需扩展）。
CREATE TABLE inbox_dedup (
    event_id       text        NOT NULL,
    consumer_group text        NOT NULL,
    status         text        NOT NULL DEFAULT 'claimed',
    claimed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, consumer_group)
);
