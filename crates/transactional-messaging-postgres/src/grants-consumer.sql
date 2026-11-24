GRANT USAGE ON SCHEMA rss_transactional_messaging TO {role};
GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO {role};
GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO {role};
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.local_projection_dr_status(uuid,bigint,uuid) TO {role};
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.next_outbox_wakeup(uuid,text),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid),rss_transactional_messaging.check_execution() TO {role};
