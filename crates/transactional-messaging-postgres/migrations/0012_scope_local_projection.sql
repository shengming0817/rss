-- A projection login has one immutable domain/group binding, owned by the external migrator.
-- session_user survives SECURITY DEFINER and SET ROLE; inherited grants cannot widen this scope.
-- ref: PostgreSQL REL_17_6 src/backend/commands/policy.c (restrictive policy conjunction).
CREATE TABLE rss_transactional_messaging.consumer_scope (
 login_role name PRIMARY KEY,
 domain text NOT NULL CHECK (length(domain)>0),
 consumer_group text NOT NULL CHECK (length(consumer_group)>0)
);
REVOKE ALL ON rss_transactional_messaging.consumer_scope FROM PUBLIC;
GRANT SELECT ON rss_transactional_messaging.consumer_scope TO rss_tmsg_relay;
GRANT CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.consumer_domain_allowed(p_domain text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT NOT EXISTS(SELECT FROM consumer_scope s WHERE s.login_role=session_user AND s.domain IS DISTINCT FROM p_domain)
$f$;
ALTER FUNCTION rss_transactional_messaging.consumer_domain_allowed(text) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.consumer_inbox_allowed(p_tenant uuid,p_message text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT NOT EXISTS(SELECT FROM consumer_scope s WHERE s.login_role=session_user)
 OR EXISTS(SELECT FROM consumer_scope s JOIN outbox o ON o.domain=s.domain
  WHERE s.login_role=session_user AND s.consumer_group=p_group AND o.tenant_id=p_tenant AND o.message_id=p_message)
$f$;
ALTER FUNCTION rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text) OWNER TO rss_tmsg_relay;
CREATE FUNCTION rss_transactional_messaging.projection_scope_matches(p_domain text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT EXISTS(SELECT FROM consumer_scope WHERE login_role=session_user AND domain=p_domain AND consumer_group=p_group)
$f$;
ALTER FUNCTION rss_transactional_messaging.projection_scope_matches(text,text) OWNER TO rss_tmsg_relay;
-- These predicates disclose only the caller's own scope and are used by mandatory RLS policies.
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.consumer_domain_allowed(text),
 rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text),
 rss_transactional_messaging.projection_scope_matches(text,text) TO PUBLIC;
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;

CREATE POLICY outbox_consumer_scope ON rss_transactional_messaging.outbox AS RESTRICTIVE
 USING(rss_transactional_messaging.consumer_domain_allowed(domain))
 WITH CHECK(rss_transactional_messaging.consumer_domain_allowed(domain));
CREATE POLICY inbox_consumer_scope ON rss_transactional_messaging.inbox AS RESTRICTIVE
 USING(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group))
 WITH CHECK(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group));
CREATE POLICY dead_letter_consumer_scope ON rss_transactional_messaging.consumer_dead_letter AS RESTRICTIVE
 USING(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group))
 WITH CHECK(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group));
