-- Installed only on the fixture administrator's session. Each invocation is a fresh window.
CREATE OR REPLACE FUNCTION pg_temp.seed_hot_scan(layout text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE tenant uuid:=current_setting('rss.tenant_id')::uuid;
BEGIN
 TRUNCATE rss_reconcile.target_resources,rss_reconcile.resources,rss_reconcile.targets,rss_reconcile.scans;
 INSERT INTO rss_reconcile.scans(tenant_id,reconciler) VALUES(tenant,'profile');
 INSERT INTO rss_reconcile.targets(tenant_id,reconciler,entity,queue_ticket,binding_revision,next_run)
 SELECT tenant,'profile',n::text,n,1,
  CASE WHEN layout='future' AND n<=10000 THEN now()+interval '1 hour'
       WHEN layout='miss' THEN now()-interval '1 day'+n*interval '1 millisecond'
       ELSE now()-n*interval '1 millisecond' END
 FROM generate_series(1,10001) n;
 IF layout<>'future' THEN
  PERFORM setval('rss_reconcile.queue_tickets',10001);
  PERFORM rss_reconcile.wake(tenant,'holder','holder',ARRAY['hot']);
  PERFORM FROM rss_reconcile.claim_due(tenant,'holder',1,128,600000);
  INSERT INTO rss_reconcile.target_resources(tenant_id,reconciler,entity,resource)
   SELECT tenant,'profile',n::text,'hot' FROM generate_series(1,10000) n;
 END IF;
 ANALYZE rss_reconcile.targets;
 ANALYZE rss_reconcile.target_resources;
END $$;
