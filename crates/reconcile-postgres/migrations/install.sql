-- Fresh installation by a dedicated NOSUPERUSER NOBYPASSRLS owner.
-- ref: tokio-rs/tokio tokio/src/sync/batch_semaphore.rs@tokio-1.48.0 (old waiter first).
CREATE SCHEMA rss_reconcile;
COMMENT ON SCHEMA rss_reconcile IS 'rss-reconcile-postgres:3';

CREATE TABLE rss_reconcile.targets (
    tenant_id uuid NOT NULL,
    reconciler text NOT NULL CHECK (reconciler ~ '^[A-Za-z0-9_.:-]{1,255}$'),
    entity text NOT NULL CHECK (entity ~ '^[A-Za-z0-9_.:-]{1,255}$'),
    wake_version bigint NOT NULL DEFAULT 1 CHECK (wake_version > 0),
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    token uuid,
    lease_until timestamptz,
    next_run timestamptz DEFAULT clock_timestamp(),
    failures bigint NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 4294967295),
    result text NOT NULL DEFAULT 'pending' CHECK (result IN ('pending','running','applied','converged','retry','suspended')),
    PRIMARY KEY (tenant_id,reconciler,entity),
    CHECK ((token IS NULL) = (lease_until IS NULL)),
    CHECK (token IS NULL OR next_run IS NOT NULL),
 binding_revision bigint NOT NULL DEFAULT 0 CHECK(binding_revision>=0),
 queue_ticket bigint,
 CONSTRAINT target_queue CHECK((next_run IS NULL)=(queue_ticket IS NULL) AND (queue_ticket IS NULL OR queue_ticket>0))
);

CREATE INDEX targets_due ON rss_reconcile.targets(tenant_id,reconciler,(GREATEST(next_run,lease_until))) WHERE next_run IS NOT NULL;

ALTER TABLE rss_reconcile.targets ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_reconcile.targets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_scope ON rss_reconcile.targets
USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid)
WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE SEQUENCE rss_reconcile.queue_tickets AS bigint MINVALUE 1 NO CYCLE;

CREATE INDEX targets_queue ON rss_reconcile.targets(tenant_id,reconciler,queue_ticket) WHERE next_run IS NOT NULL;

CREATE INDEX targets_unbound ON rss_reconcile.targets(tenant_id,reconciler) WHERE binding_revision=0 AND next_run IS NOT NULL;

CREATE TABLE rss_reconcile.resources (
 tenant_id uuid NOT NULL,
 resource text NOT NULL CHECK(resource ~ '^[A-Za-z0-9_.:-]{1,255}$'),
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
 reconciler text NOT NULL CHECK(reconciler ~ '^[A-Za-z0-9_.:-]{1,255}$'),
 cursor_ticket bigint NOT NULL DEFAULT 0 CHECK(cursor_ticket>=0),
 high_watermark bigint NOT NULL DEFAULT 0 CHECK(high_watermark>=cursor_ticket),
 PRIMARY KEY(tenant_id,reconciler)
);

ALTER TABLE rss_reconcile.resources ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_reconcile.resources FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_scope ON rss_reconcile.resources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

ALTER TABLE rss_reconcile.target_resources ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_reconcile.target_resources FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_scope ON rss_reconcile.target_resources USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

ALTER TABLE rss_reconcile.scans ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_reconcile.scans FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_scope ON rss_reconcile.scans USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE FUNCTION rss_reconcile.assert_tenant(t uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 IF t IS NULL OR t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'reconcile scope mismatch' USING ERRCODE='P1001';
 END IF;
END $$;

CREATE FUNCTION rss_reconcile.lock_resources(t uuid,r text,e text,extra text[],nonblocking boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE required_keys text[]; locked_count bigint;
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 required_keys:=ARRAY(
  SELECT resource FROM rss_reconcile.target_resources WHERE tenant_id=t AND reconciler=r AND entity=e
  UNION SELECT resource FROM rss_reconcile.resources WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=e AND owner_token IS NOT NULL
  UNION SELECT unnest(extra)
 );
 IF cardinality(required_keys)=0 THEN RETURN; END IF;
 IF nonblocking THEN
  PERFORM FROM rss_reconcile.resources WHERE tenant_id=t AND resource=ANY(required_keys) ORDER BY resource FOR UPDATE NOWAIT;
 ELSE
  PERFORM FROM rss_reconcile.resources WHERE tenant_id=t AND resource=ANY(required_keys) ORDER BY resource FOR UPDATE;
 END IF;
 GET DIAGNOSTICS locked_count = ROW_COUNT;
 IF locked_count<>cardinality(required_keys) THEN RAISE EXCEPTION 'missing reconcile resource' USING ERRCODE='P1005'; END IF;
END $$;

CREATE FUNCTION rss_reconcile.bind_resources(t uuid,r text,e text,keys text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets; canonical text[]; previous text[]; was_waiting boolean;
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 IF keys IS NULL OR cardinality(keys)>1024 OR EXISTS(SELECT FROM unnest(keys) k WHERE k IS NULL OR k !~ '^[A-Za-z0-9_.:-]{1,255}$') THEN
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

CREATE FUNCTION rss_reconcile.claim_due(t uuid,r text,n integer,scan_budget integer,ttl bigint)
RETURNS TABLE(claims rss_reconcile.targets[],more boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE scan rss_reconcile.scans; page refcursor; candidate record; row rss_reconcile.targets; at_time timestamptz; desired_ticket bigint;
 cutoff timestamptz; page_limit bigint; examined integer:=0;
 probe_limit integer; sampled_entities text[]; sampled_tickets bigint[];
BEGIN
 PERFORM rss_reconcile.assert_tenant(t);
 IF n IS NULL OR n NOT BETWEEN 1 AND 1024 OR scan_budget IS NULL OR scan_budget<1 OR ttl IS NULL OR ttl NOT BETWEEN 1 AND 9223372036854775 THEN RAISE EXCEPTION 'invalid claim limits' USING ERRCODE='P1003'; END IF;
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
 -- Only a complete scope sample can skip ticket ranges. Reserve a lookahead
 -- for more and a sentinel to distinguish a complete sample from a truncated one.
 cutoff:=clock_timestamp();
 page_limit:=scan_budget::bigint+1;
 probe_limit:=least(n,scan_budget)+2;
 SELECT array_agg(entity),array_agg(queue_ticket) INTO sampled_entities,sampled_tickets
 FROM (SELECT entity,queue_ticket FROM rss_reconcile.targets
       WHERE tenant_id=t AND reconciler=r AND next_run IS NOT NULL AND GREATEST(next_run,lease_until)<=cutoff
       ORDER BY GREATEST(next_run,lease_until) LIMIT probe_limit) AS due_sample;
 IF cardinality(sampled_tickets)=probe_limit THEN
  -- Seek directly from the persisted cursor. Filtering after the ticket LIMIT
  -- bounds both future prefixes and already-passed hot waiters on every page.
  OPEN page NO SCROLL FOR SELECT entity,queue_ticket,GREATEST(next_run,lease_until)<=cutoff AS eligible
   FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND next_run IS NOT NULL
    AND queue_ticket>scan.cursor_ticket AND queue_ticket<=scan.high_watermark
   ORDER BY queue_ticket LIMIT page_limit;
 ELSE
  OPEN page NO SCROLL FOR SELECT entity,queue_ticket,true AS eligible
   FROM unnest(sampled_entities,sampled_tickets) AS sample(entity,queue_ticket)
   WHERE queue_ticket>scan.cursor_ticket AND queue_ticket<=scan.high_watermark ORDER BY queue_ticket;
 END IF;
 LOOP
  FETCH page INTO candidate;
  EXIT WHEN NOT FOUND;
  -- Leave the lookahead for the next page; its eligibility may change before then.
  IF examined=scan_budget OR cardinality(claims)=n THEN more:=true; EXIT; END IF;
  examined:=examined+1;
  scan.cursor_ticket:=candidate.queue_ticket;
  IF NOT candidate.eligible THEN CONTINUE; END IF;
  BEGIN
   SELECT * INTO row FROM rss_reconcile.targets WHERE tenant_id=t AND reconciler=r AND entity=candidate.entity FOR UPDATE NOWAIT;
   at_time:=clock_timestamp();
   IF row.queue_ticket IS DISTINCT FROM candidate.queue_ticket OR row.next_run>at_time OR row.next_run IS NULL OR row.lease_until>at_time THEN CONTINUE; END IF;
   PERFORM rss_reconcile.lock_resources(t,r,row.entity,'{}'::text[],true);
   -- With all resource rows locked, only another older waiter or a live owner can block us.
   SELECT CASE WHEN EXISTS(
    SELECT FROM rss_reconcile.target_resources d
    WHERE d.tenant_id=t AND d.reconciler=r AND d.entity=row.entity AND (
     EXISTS(SELECT FROM rss_reconcile.target_resources w WHERE w.tenant_id=d.tenant_id AND w.resource=d.resource
      AND w.waiting_ticket<row.queue_ticket AND (w.reconciler,w.entity)<>(d.reconciler,d.entity))
     OR EXISTS(SELECT FROM rss_reconcile.resources o JOIN rss_reconcile.targets holder
      ON (holder.tenant_id,holder.reconciler,holder.entity)=(o.tenant_id,o.owner_reconciler,o.owner_entity)
      WHERE o.tenant_id=d.tenant_id AND o.resource=d.resource AND holder.token=o.owner_token
       AND holder.epoch=o.owner_epoch AND holder.lease_until>clock_timestamp())
    )
   ) THEN row.queue_ticket END INTO desired_ticket;
   UPDATE rss_reconcile.target_resources SET waiting_ticket=desired_ticket
    WHERE tenant_id=t AND reconciler=r AND entity=row.entity AND waiting_ticket IS DISTINCT FROM desired_ticket;
   IF desired_ticket IS NOT NULL THEN CONTINUE; END IF;
   UPDATE rss_reconcile.resources SET owner_reconciler=NULL,owner_entity=NULL,owner_token=NULL,owner_epoch=NULL
    WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=row.entity AND owner_token=row.token AND owner_epoch=row.epoch;
   UPDATE rss_reconcile.targets SET token=gen_random_uuid(),epoch=epoch+1,lease_until=clock_timestamp()+(ttl::text||' milliseconds')::interval,result='running'
    WHERE tenant_id=t AND reconciler=r AND entity=row.entity RETURNING * INTO row;
   UPDATE rss_reconcile.resources o SET owner_reconciler=r,owner_entity=row.entity,owner_token=row.token,owner_epoch=row.epoch
    FROM rss_reconcile.target_resources d WHERE d.tenant_id=t AND d.reconciler=r AND d.entity=row.entity AND (o.tenant_id,o.resource)=(d.tenant_id,d.resource);
   claims:=array_append(claims,row);
  EXCEPTION WHEN lock_not_available THEN NULL; -- An unacquired candidate consumes no execution slot.
  END;
 END LOOP;
 CLOSE page;
 IF NOT more THEN scan.cursor_ticket:=scan.high_watermark; END IF;
 -- Locks remain necessary; only a changed durable scan position needs a new tuple version.
 UPDATE rss_reconcile.scans AS persisted SET cursor_ticket=scan.cursor_ticket,high_watermark=scan.high_watermark
 WHERE persisted.tenant_id=t AND persisted.reconciler=r
  AND (persisted.cursor_ticket,persisted.high_watermark) IS DISTINCT FROM (scan.cursor_ticket,scan.high_watermark);
 RETURN NEXT;
END $$;

CREATE FUNCTION rss_reconcile.renew(t uuid,r text,e text,k uuid,g bigint,b bigint,ttl bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
BEGIN
 IF NOT rss_reconcile.lock_execution(t,r,e,k,g,b) THEN RAISE EXCEPTION 'reconcile binding changed' USING ERRCODE='P1004'; END IF;
 IF ttl IS NULL OR ttl NOT BETWEEN 1 AND 9223372036854775 THEN RAISE EXCEPTION 'invalid lease' USING ERRCODE='P1003'; END IF;
 UPDATE rss_reconcile.targets SET lease_until=clock_timestamp()+(ttl::text||' milliseconds')::interval WHERE tenant_id=t AND reconciler=r AND entity=e;
END $$;

CREATE FUNCTION rss_reconcile.finish(t uuid,r text,e text,k uuid,g bigint,b bigint,w bigint,outcome text,delay bigint,f bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog,rss_reconcile AS $$
DECLARE row rss_reconcile.targets; at_time timestamptz; newer boolean; next_time timestamptz;
BEGIN
 row:=rss_reconcile.lock_authority(t,r,e,k,g);
 IF outcome IS DISTINCT FROM 'deferred' AND NOT rss_reconcile.lock_execution(t,r,e,k,g,b) THEN RAISE EXCEPTION 'reconcile binding changed' USING ERRCODE='P1004'; END IF;
 at_time:=clock_timestamp();
 IF outcome IS NULL OR outcome NOT IN ('converged','pending','retry','suspended','deferred') OR f IS NULL OR f NOT BETWEEN 0 AND 4294967295 OR
  (outcome IN ('pending','retry','deferred') AND (delay IS NULL OR delay NOT BETWEEN 1 AND 9223372036854775)) THEN RAISE EXCEPTION 'invalid completion' USING ERRCODE='P1003'; END IF;
 IF w IS NULL OR w>row.wake_version THEN RAISE EXCEPTION 'invalid wake version' USING ERRCODE='P1003'; END IF;
 newer:=row.wake_version<>w;
 next_time:=CASE WHEN newer THEN least(row.next_run,at_time) WHEN outcome IN ('converged','suspended') THEN NULL ELSE at_time+(delay::text||' milliseconds')::interval END;
 UPDATE rss_reconcile.resources SET owner_reconciler=NULL,owner_entity=NULL,owner_token=NULL,owner_epoch=NULL
  WHERE tenant_id=t AND owner_reconciler=r AND owner_entity=e AND owner_token=k AND owner_epoch=g;
 UPDATE rss_reconcile.target_resources SET waiting_ticket=NULL WHERE tenant_id=t AND reconciler=r AND entity=e AND waiting_ticket IS NOT NULL;
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
