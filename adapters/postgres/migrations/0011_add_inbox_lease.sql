-- 0011_add_inbox_lease.sql — inbox_dedup 租约 token（CAS 围栏 + TTL 重捞，#1213）。
-- pre-GA 空表，普通 ALTER ADD COLUMN nullable（无事务内 CONCURRENTLY，遵 rust-standards.md §数据库迁移）。
ALTER TABLE inbox_dedup ADD COLUMN lease_token uuid;
