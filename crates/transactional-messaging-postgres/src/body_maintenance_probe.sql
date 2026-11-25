SELECT EXISTS(SELECT FROM pg_proc p WHERE p.oid=to_regprocedure('rss_transactional_messaging.reclaim_published_bodies(bigint,bigint,integer)')
 AND p.prosrc=$1 AND p.prosecdef AND p.provolatile='v' AND p.proowner='rss_tmsg_relay'::regrole
 AND p.proconfig=ARRAY['search_path=pg_catalog, rss_transactional_messaging, pg_temp']
 AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
 AND has_function_privilege(current_user,p.oid,'EXECUTE')
 AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) WHERE grantee=0 AND privilege_type='EXECUTE'))
 AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN pg_roles r
  WHERE n.nspname='rss_transactional_messaging' AND c.relkind IN ('r','p')
   AND (pg_has_role(current_user,r.oid,'USAGE') OR pg_has_role(current_user,r.oid,'SET'))
   AND (has_schema_privilege(r.oid,n.oid,'CREATE') OR pg_has_role(r.oid,c.relowner,'MEMBER') OR has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN pg_roles r
  WHERE p.pronamespace='rss_transactional_messaging'::regnamespace
   AND (pg_has_role(current_user,r.oid,'USAGE') OR pg_has_role(current_user,r.oid,'SET'))
   AND has_function_privilege(r.oid,p.oid,'EXECUTE')
   AND p.oid NOT IN ('rss_transactional_messaging.check_execution()'::regprocedure,
    'rss_transactional_messaging.reclaim_published_bodies(bigint,bigint,integer)'::regprocedure,
    'rss_transactional_messaging.consumer_scope_domain()'::regprocedure,
    'rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text)'::regprocedure,
    'rss_transactional_messaging.projection_scope_matches(text,text)'::regprocedure))
 AND EXISTS(SELECT FROM pg_constraint WHERE conrelid='rss_transactional_messaging.outbox'::regclass
  AND conname='outbox_body_shape' AND convalidated AND NOT condeferrable
  AND pg_get_constraintdef(oid)='CHECK ((((payload IS NULL) = body_retired) AND ((NOT body_retired) OR ((status = ''published''::text) AND (body_digest IS NOT NULL) AND (authored_evidence IS NOT NULL)))))')
 AND EXISTS(SELECT FROM pg_attribute WHERE attrelid='rss_transactional_messaging.outbox'::regclass
  AND attname='payload' AND atttypid='bytea'::regtype AND NOT attnotnull AND NOT attisdropped)

 AND EXISTS(SELECT FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  WHERE i.indexrelid=to_regclass('rss_transactional_messaging.outbox_published_body')
   AND i.indrelid='rss_transactional_messaging.outbox'::regclass AND i.indisvalid AND i.indisready
   AND NOT i.indisunique AND c.relam=(SELECT oid FROM pg_am WHERE amname='btree')
   AND ARRAY(SELECT lower(pg_get_indexdef(i.indexrelid,k,true)) FROM generate_series(1,i.indnatts) k)=ARRAY['tenant_id','seq']
   AND pg_get_expr(i.indpred,i.indrelid)='((status = ''published''::text) AND (payload IS NOT NULL))')
