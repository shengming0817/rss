-- Exact operation retries use the existing receipt; different operations cannot claim one replay ID.
DROP INDEX rss_transactional_messaging.recovery_replay_source;
ALTER TABLE rss_transactional_messaging.recovery_operations ADD CONSTRAINT recovery_replay_identity UNIQUE (tenant_id,replay_message_id);
