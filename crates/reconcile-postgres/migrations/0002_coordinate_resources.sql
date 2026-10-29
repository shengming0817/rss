-- One-way v1 -> v2. Stop/drain old workers before running as the dedicated owner.
-- ref: tokio-rs/tokio tokio/src/sync/batch_semaphore.rs@tokio-1.48.0 (old waiter first).
BEGIN;
LOCK TABLE rss_reconcile.targets IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_reconcile') IS DISTINCT FROM 'rss-reconcile-postgres:1' THEN
  RAISE EXCEPTION 'expected reconcile storage revision 1';
 END IF;
END $$;
ALTER TABLE rss_reconcile.targets NO FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
 IF EXISTS(SELECT FROM rss_reconcile.targets WHERE lease_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'stop and drain reconcile claims before upgrade';
 END IF;
END $$;
CREATE SEQUENCE rss_reconcile.queue_tickets AS bigint MINVALUE 1 NO CYCLE;
ALTER TABLE rss_reconcile.targets ADD COLUMN binding_revision bigint NOT NULL DEFAULT 0 CHECK(binding_revision>=0);
ALTER TABLE rss_reconcile.targets ADD COLUMN queue_ticket bigint;
WITH ordered AS (
 SELECT tenant_id,reconciler,entity,row_number() OVER(ORDER BY next_run,tenant_id,reconciler COLLATE "C",entity COLLATE "C") AS ticket
 FROM rss_reconcile.targets WHERE next_run IS NOT NULL
) UPDATE rss_reconcile.targets t SET queue_ticket=o.ticket FROM ordered o
 WHERE (t.tenant_id,t.reconciler,t.entity)=(o.tenant_id,o.reconciler,o.entity);
SELECT setval('rss_reconcile.queue_tickets',greatest(coalesce(max(queue_ticket),0),1),coalesce(max(queue_ticket),0)>0) FROM rss_reconcile.targets;
ALTER TABLE rss_reconcile.targets ADD CONSTRAINT target_queue CHECK((next_run IS NULL)=(queue_ticket IS NULL) AND (queue_ticket IS NULL OR queue_ticket>0));
ALTER TABLE rss_reconcile.targets FORCE ROW LEVEL SECURITY;
CREATE INDEX targets_queue ON rss_reconcile.targets(tenant_id,reconciler,queue_ticket) WHERE next_run IS NOT NULL;
CREATE INDEX targets_unbound ON rss_reconcile.targets(tenant_id,reconciler) WHERE binding_revision=0 AND next_run IS NOT NULL;
CREATE TABLE rss_reconcile.resources (
 tenant_id uuid NOT NULL,
 resource text NOT NULL CHECK(resource ~ '^[A-Za-z0-9_.:-]{1,128}$'),
 owner_reconciler text,
 owner_entity text,
 owner_token uuid,
 owner_epoch bigint,
 PRIMARY KEY(tenant_id,resource),
 FOREIGN KEY(tenant_id,owner_reconciler,owner_entity) REFERENCES rss_reconcile.targets(tenant_id,reconciler,entity),
 CHECK((owner_token IS NULL)=(owner_reconciler IS NULL) AND (owner_token IS NULL)=(owner_entity IS NULL) AND (owner_token IS NULL)=(owner_epoch IS NULL)),
 CHECK(owner_epoch IS NULL OR owner_epoch>0)
);
CREATE INDEX resources_owner ON rss_reconcile.resources(tenant_id,owner_reconciler,owner_entity,owner_token,owner_epoch) WHERE owner_token IS NOT NULL;
CREATE TABLE rss_reconcile.target_resources (
 tenant_id uuid NOT NULL,
 reconciler text NOT NULL,
 entity text NOT NULL,
 resource text NOT NULL,
 waiting_ticket bigint CHECK(waiting_ticket IS NULL OR waiting_ticket>0),
 PRIMARY KEY(tenant_id,reconciler,entity,resource),
 FOREIGN KEY(tenant_id,reconciler,entity) REFERENCES rss_reconcile.targets(tenant_id,reconciler,entity),
 FOREIGN KEY(tenant_id,resource) REFERENCES rss_reconcile.resources(tenant_id,resource)
);
CREATE INDEX resource_waiters ON rss_reconcile.target_resources(tenant_id,resource,waiting_ticket) WHERE waiting_ticket IS NOT NULL;
CREATE TABLE rss_reconcile.scans (
 tenant_id uuid NOT NULL,
 reconciler text NOT NULL CHECK(reconciler ~ '^[A-Za-z0-9_.:-]{1,128}$'),
 cursor_ticket bigint NOT NULL DEFAULT 0 CHECK(cursor_ticket>=0),
 high_watermark bigint NOT NULL DEFAULT 0 CHECK(high_watermark>=cursor_ticket),
 PRIMARY KEY(tenant_id,reconciler)
);
ALTER TABLE rss_reconcile.targets NO FORCE ROW LEVEL SECURITY;
INSERT INTO rss_reconcile.scans(tenant_id,reconciler) SELECT DISTINCT tenant_id,reconciler FROM rss_reconcile.targets;
ALTER TABLE rss_reconcile.targets FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_reconcile.resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_reconcile.resources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_reconcile.resources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE rss_reconcile.target_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_reconcile.target_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_reconcile.target_resources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE rss_reconcile.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_reconcile.scans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_reconcile.scans USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
DROP FUNCTION rss_reconcile.wake(uuid,text,text),rss_reconcile.claim_due(uuid,text,integer,bigint),rss_reconcile.lock_claim(uuid,text,text,uuid,bigint),rss_reconcile.renew(uuid,text,text,uuid,bigint,bigint),rss_reconcile.finish(uuid,text,text,uuid,bigint,bigint,text,bigint,bigint),rss_reconcile.release(uuid,text,text,uuid,bigint),rss_reconcile.mark_applied(uuid,text,text,uuid,bigint),rss_reconcile.assert_tenant(uuid);

CREATE FUNCTION rss_reconcile.assert_tenant(t uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 IF t IS NULL OR t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'reconcile scope mismatch' USING ERRCODE='P1001';
 END IF;
END $$;
-- Lock only this target's declaration and acquired resources; never another target row.
CREATE FUNCTION rss_reconcile.lock_resources(t uuid,r text,e text,extra text[],nonblocking boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE key text;
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 FOR key IN SELECT resource FROM rss_reconcile.target_resources WHERE tenant_id=t AND reconciler=r AND entity=e
  UNION SELECT resource FROM rss_reconcile.resources WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=e
  UNION SELECT unnest(extra) ORDER BY 1
 LOOP
  IF nonblocking THEN
   PERFORM FROM rss_reconcile.resources WHERE tenant_id=t AND resource=key FOR UPDATE NOWAIT;
  ELSE
   PERFORM FROM rss_reconcile.resources WHERE tenant_id=t AND resource=key FOR UPDATE;
  END IF;
  IF NOT FOUND THEN RAISE EXCEPTION 'missing reconcile resource' USING ERRCODE='P1005'; END IF;
 END LOOP;
END $$;
CREATE FUNCTION rss_reconcile.bind_resources(t uuid,r text,e text,keys text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets; canonical text[]; previous text[]; was_waiting boolean;
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 IF keys IS NULL OR cardinality(keys)>1000 OR EXISTS(SELECT FROM unnest(keys) k WHERE k IS NULL OR k !~ '^[A-Za-z0-9_.:-]{1,128}$') THEN
  RAISE EXCEPTION 'invalid resources' USING ERRCODE='P1003';
 END IF;
 SELECT coalesce(array_agg(DISTINCT k ORDER BY k),'{}'::text[]) INTO canonical FROM unnest(keys) k;
 SELECT * INTO row FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND entity=e FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'missing target' USING ERRCODE='P1003'; END IF;
 SELECT coalesce(array_agg(resource ORDER BY resource),'{}'::text[]) INTO previous FROM rss_reconcile.target_resources WHERE tenant_id=t AND reconciler=r AND entity=e;
 IF row.binding_revision>0 AND previous=canonical THEN RETURN; END IF;
 INSERT INTO rss_reconcile.resources(tenant_id,resource) SELECT t,k FROM unnest(canonical) k ON CONFLICT DO NOTHING;
 PERFORM rss_reconcile.lock_resources(t,r,e,canonical,false);
 was_waiting:=EXISTS(SELECT FROM rss_reconcile.target_resources WHERE tenant_id=t AND reconciler=r AND entity=e AND waiting_ticket IS NOT NULL);
 DELETE FROM rss_reconcile.target_resources WHERE tenant_id=t AND reconciler=r AND entity=e;
 INSERT INTO rss_reconcile.target_resources(tenant_id,reconciler,entity,resource,waiting_ticket)
 SELECT t,r,e,k,CASE WHEN was_waiting AND row.next_run<=clock_timestamp() AND (row.lease_until IS NULL OR row.lease_until<=clock_timestamp()) THEN row.queue_ticket END FROM unnest(canonical) k;
 UPDATE rss_reconcile.targets SET binding_revision=binding_revision+1 WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.wake(t uuid,r text,e text,keys text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 INSERT INTO rss_reconcile.scans(tenant_id,reconciler) VALUES(t,r) ON CONFLICT DO NOTHING;
 INSERT INTO rss_reconcile.targets(tenant_id,reconciler,entity,queue_ticket) VALUES(t,r,e,nextval('rss_reconcile.queue_tickets'))
 ON CONFLICT(tenant_id,reconciler,entity) DO UPDATE SET wake_version=targets.wake_version+1,
  next_run=clock_timestamp(),failures=0,result='pending',queue_ticket=coalesce(targets.queue_ticket,excluded.queue_ticket);
 PERFORM rss_reconcile.bind_resources(t,r,e,keys);
END $$;
CREATE FUNCTION rss_reconcile.lock_authority(t uuid,r text,e text,k uuid,g bigint) RETURNS rss_reconcile.targets
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets;
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 SELECT * INTO row FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND entity=e FOR UPDATE;
 IF NOT FOUND OR k IS NULL OR row.token IS DISTINCT FROM k OR row.epoch IS DISTINCT FROM g OR row.lease_until IS NULL OR row.lease_until<=clock_timestamp() THEN
  RAISE EXCEPTION 'reconcile claim lost' USING ERRCODE='P1002';
 END IF;
 PERFORM rss_reconcile.lock_resources(t,r,e,'{}'::text[],false);
 IF row.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'reconcile claim expired' USING ERRCODE='P1002'; END IF;
 RETURN row;
END $$;
CREATE FUNCTION rss_reconcile.lock_execution(t uuid,r text,e text,k uuid,g bigint,b bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets;
BEGIN
 row:=rss_reconcile.lock_authority(t,r,e,k,g);
 IF b IS NULL OR b=0 OR row.binding_revision<>b THEN RETURN false; END IF;
 IF EXISTS(SELECT FROM rss_reconcile.target_resources d JOIN rss_reconcile.resources o USING(tenant_id,resource)
  WHERE d.tenant_id=t AND d.reconciler=r AND d.entity=e AND
   (o.owner_reconciler IS DISTINCT FROM r OR o.owner_entity IS DISTINCT FROM e OR o.owner_token IS DISTINCT FROM k OR o.owner_epoch IS DISTINCT FROM g)) THEN
  RAISE EXCEPTION 'reconcile resource lost' USING ERRCODE='P1002';
 END IF;
 RETURN true;
END $$;
CREATE FUNCTION rss_reconcile.claim_due(t uuid,r text,n integer,ttl bigint)
RETURNS TABLE(claims rss_reconcile.targets[],more boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE scan rss_reconcile.scans; candidate record; row rss_reconcile.targets; at_time timestamptz; key text; head bigint; blocked boolean;
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 IF n IS NULL OR n NOT BETWEEN 1 AND 64 OR ttl IS NULL OR ttl NOT BETWEEN 1 AND 86400000 THEN RAISE EXCEPTION 'invalid claim limits' USING ERRCODE='P1003'; END IF;
 IF EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND binding_revision=0 AND next_run IS NOT NULL) THEN
  RAISE EXCEPTION 'pending targets require explicit resource binding' USING ERRCODE='P1005';
 END IF;
 claims:='{}'::rss_reconcile.targets[]; more:=false;
 SELECT * INTO scan FROM rss_reconcile.scans WHERE tenant_id=t AND reconciler=r FOR UPDATE SKIP LOCKED;
 IF NOT FOUND THEN RETURN NEXT; RETURN; END IF;
 IF scan.cursor_ticket>=scan.high_watermark THEN
  SELECT coalesce(max(queue_ticket),0) INTO scan.high_watermark FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND next_run IS NOT NULL;
  scan.cursor_ticket:=0;
 END IF;
 FOR candidate IN SELECT entity,queue_ticket FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND next_run IS NOT NULL
   AND queue_ticket>scan.cursor_ticket AND queue_ticket<=scan.high_watermark ORDER BY queue_ticket LIMIT 64
 LOOP
  scan.cursor_ticket:=candidate.queue_ticket;
  BEGIN
   SELECT * INTO row FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND entity=candidate.entity FOR UPDATE NOWAIT;
   at_time:=clock_timestamp();
   IF row.queue_ticket IS DISTINCT FROM candidate.queue_ticket OR row.next_run>at_time OR row.next_run IS NULL OR row.lease_until>at_time THEN CONTINUE; END IF;
   PERFORM rss_reconcile.lock_resources(t,r,row.entity,'{}'::text[],true);
   UPDATE rss_reconcile.target_resources SET waiting_ticket=row.queue_ticket WHERE tenant_id=t AND reconciler=r AND entity=row.entity;
   blocked:=false;
   FOR key IN SELECT resource FROM rss_reconcile.target_resources WHERE tenant_id=t AND reconciler=r AND entity=row.entity ORDER BY resource LOOP
    SELECT waiting_ticket INTO head FROM rss_reconcile.target_resources WHERE tenant_id=t AND resource=key AND waiting_ticket IS NOT NULL ORDER BY waiting_ticket LIMIT 1;
    IF head<>row.queue_ticket OR EXISTS(
     SELECT FROM rss_reconcile.resources o JOIN rss_reconcile.targets holder ON (holder.tenant_id,holder.reconciler,holder.entity)=(o.tenant_id,o.owner_reconciler,o.owner_entity)
     WHERE o.tenant_id=t AND o.resource=key AND holder.token=o.owner_token AND holder.epoch=o.owner_epoch AND holder.lease_until>clock_timestamp()
    ) THEN blocked:=true; EXIT; END IF;
   END LOOP;
   IF blocked THEN CONTINUE; END IF;
   UPDATE rss_reconcile.resources SET owner_reconciler=NULL,owner_entity=NULL,owner_token=NULL,owner_epoch=NULL
    WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=row.entity AND owner_token=row.token AND owner_epoch=row.epoch;
   UPDATE rss_reconcile.targets SET token=gen_random_uuid(),epoch=epoch+1,lease_until=clock_timestamp()+ttl*interval '1 millisecond',result='running'
    WHERE tenant_id=t AND reconciler=r AND entity=row.entity RETURNING * INTO row;
   UPDATE rss_reconcile.resources o SET owner_reconciler=r,owner_entity=row.entity,owner_token=row.token,owner_epoch=row.epoch
    FROM rss_reconcile.target_resources d WHERE d.tenant_id=t AND d.reconciler=r AND d.entity=row.entity AND (o.tenant_id,o.resource)=(d.tenant_id,d.resource);
   UPDATE rss_reconcile.target_resources SET waiting_ticket=NULL WHERE tenant_id=t AND reconciler=r AND entity=row.entity;
   claims:=array_append(claims,row);
  EXCEPTION WHEN lock_not_available THEN NULL; -- An unacquired candidate consumes no execution slot.
  END;
  IF cardinality(claims)=n THEN EXIT; END IF;
 END LOOP;
 more:=EXISTS(SELECT FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND next_run IS NOT NULL AND queue_ticket>scan.cursor_ticket AND queue_ticket<=scan.high_watermark);
 IF NOT more THEN scan.cursor_ticket:=scan.high_watermark; END IF;
 UPDATE rss_reconcile.scans SET cursor_ticket=scan.cursor_ticket,high_watermark=scan.high_watermark WHERE tenant_id=t AND reconciler=r;
 RETURN NEXT;
END $$;
CREATE FUNCTION rss_reconcile.renew(t uuid,r text,e text,k uuid,g bigint,b bigint,ttl bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 IF NOT rss_reconcile.lock_execution(t,r,e,k,g,b) THEN RAISE EXCEPTION 'reconcile binding changed' USING ERRCODE='P1004'; END IF;
 IF ttl IS NULL OR ttl NOT BETWEEN 1 AND 86400000 THEN RAISE EXCEPTION 'invalid lease' USING ERRCODE='P1003'; END IF;
 UPDATE rss_reconcile.targets SET lease_until=clock_timestamp()+ttl*interval '1 millisecond' WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.finish(t uuid,r text,e text,k uuid,g bigint,b bigint,w bigint,outcome text,delay bigint,f bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets; at_time timestamptz; newer boolean; next_time timestamptz;
BEGIN
 row:=rss_reconcile.lock_authority(t,r,e,k,g);
 IF outcome IS DISTINCT FROM 'deferred' AND NOT rss_reconcile.lock_execution(t,r,e,k,g,b) THEN RAISE EXCEPTION 'reconcile binding changed' USING ERRCODE='P1004'; END IF;
 at_time:=clock_timestamp();
 IF outcome IS NULL OR outcome NOT IN ('converged','pending','retry','suspended','deferred') OR f IS NULL OR f NOT BETWEEN 0 AND 4294967295 OR
  (outcome IN ('pending','retry','deferred') AND (delay IS NULL OR delay NOT BETWEEN 1 AND 86400000)) THEN RAISE EXCEPTION 'invalid completion' USING ERRCODE='P1003'; END IF;
 IF w IS NULL OR w>row.wake_version THEN RAISE EXCEPTION 'invalid wake version' USING ERRCODE='P1003'; END IF;
 newer:=row.wake_version<>w;
 next_time:=CASE WHEN newer THEN least(row.next_run,at_time) WHEN outcome IN ('converged','suspended') THEN NULL ELSE at_time+delay*interval '1 millisecond' END;
 UPDATE rss_reconcile.resources SET owner_reconciler=NULL,owner_entity=NULL,owner_token=NULL,owner_epoch=NULL
  WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=e AND owner_token=k AND owner_epoch=g;
 UPDATE rss_reconcile.target_resources SET waiting_ticket=NULL WHERE tenant_id=t AND reconciler=r AND entity=e;
 UPDATE rss_reconcile.targets SET token=NULL,lease_until=NULL,next_run=next_time,
  failures=CASE WHEN newer OR outcome='deferred' THEN row.failures ELSE f END,
  result=CASE WHEN newer OR outcome='deferred' THEN 'pending' ELSE outcome END,
  queue_ticket=CASE WHEN next_time IS NULL THEN NULL WHEN newer OR outcome='deferred' THEN row.queue_ticket ELSE nextval('rss_reconcile.queue_tickets') END
 WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.release(t uuid,r text,e text,k uuid,g bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 PERFORM rss_reconcile.lock_authority(t,r,e,k,g);
 UPDATE rss_reconcile.resources SET owner_reconciler=NULL,owner_entity=NULL,owner_token=NULL,owner_epoch=NULL
  WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=e AND owner_token=k AND owner_epoch=g;
 UPDATE rss_reconcile.targets SET token=NULL,lease_until=NULL WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
CREATE FUNCTION rss_reconcile.mark_applied(t uuid,r text,e text,k uuid,g bigint,b bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 IF NOT rss_reconcile.lock_execution(t,r,e,k,g,b) THEN RAISE EXCEPTION 'reconcile binding changed' USING ERRCODE='P1004'; END IF;
 UPDATE rss_reconcile.targets SET next_run=least(next_run,clock_timestamp()),result='applied' WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_reconcile FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA rss_reconcile FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_reconcile FROM PUBLIC;
COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:2';
COMMIT;
