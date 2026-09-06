-- Keep caller-created temporary relations/types behind the trusted component schema.
-- ref: PostgreSQL src/backend/catalog/namespace.c; CREATE FUNCTION, Writing SECURITY DEFINER Functions Safely.
ALTER FUNCTION rss_transactional_messaging.archive_claim(uuid,uuid,bigint,bytea,bigint,bigint,boolean,bigint)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
ALTER FUNCTION rss_transactional_messaging.archive_prepare(uuid,uuid,bytea,jsonb,bytea)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
ALTER FUNCTION rss_transactional_messaging.archive_record(uuid,uuid,bytea,uuid,jsonb)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
ALTER FUNCTION rss_transactional_messaging.archive_purge(uuid,uuid,bytea,jsonb)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
ALTER FUNCTION rss_transactional_messaging.archive_missing(uuid,uuid,bytea,uuid,jsonb)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
ALTER FUNCTION rss_transactional_messaging.archive_fault(uuid,uuid,bytea,text)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
ALTER FUNCTION rss_transactional_messaging.archive_fence(uuid,uuid,bytea)
 SET search_path=pg_catalog,rss_transactional_messaging,pg_temp;
