-- 0020_add_inbox_dedup_sweep_index.sql — inbox_dedup 保留期清理索引（#1210）。
--
-- 覆盖 PgInboxSweeper 的 sweep 谓词 `status='done' AND claimed_at <= now()-interval`（删除超保留期去重记录，
-- 防表无界膨胀）。镜 outbox 的 idx_outbox_sweep (status, created_at) 复合非偏索引范式。
-- pre-GA 空表，普通 CREATE INDEX（留事务型迁移内，rust-standards.md §数据库迁移 / migrations README §索引形态）。
CREATE INDEX idx_inbox_dedup_sweep ON inbox_dedup (status, claimed_at);
