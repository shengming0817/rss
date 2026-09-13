-- One-way V1 -> V2. External schema owner stops writers before executing this transaction.
-- ref: restatedev/restate crates/worker-api/src/invoker/invocation_reader.rs@7fcc614c75fac74d051b68b118e87421e90467cc
BEGIN;
LOCK TABLE rss_saga.instances, rss_saga.journal, rss_saga.step_receipts IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF (SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_saga') IS DISTINCT FROM 'rss-saga-postgres:1' THEN RAISE EXCEPTION 'expected saga schema 1'; END IF;
END $$;
ALTER TABLE rss_saga.instances NO FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.journal NO FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.step_receipts NO FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
 IF EXISTS (SELECT FROM rss_saga.journal j LEFT JOIN rss_saga.step_receipts r ON (r.tenant_id,r.saga_id,r.completed_seq)=(j.tenant_id,j.saga_id,j.seq)
 WHERE (j.kind='ForwardApplied') IS DISTINCT FROM (r.step IS NOT NULL) OR (r.step IS NOT NULL AND (r.step<>j.step OR r.effect_key<>j.effect_key OR (r.protected->>'attempt')::bigint IS DISTINCT FROM j.attempt)))
 OR EXISTS (SELECT FROM rss_saga.step_receipts r LEFT JOIN rss_saga.journal j ON (j.tenant_id,j.saga_id,j.seq)=(r.tenant_id,r.saga_id,r.completed_seq) WHERE j.kind IS DISTINCT FROM 'ForwardApplied')
 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga upgrade receipt integrity'; END IF;
END $$;
DROP TRIGGER receipt_pair ON rss_saga.journal;
DROP TRIGGER journal_pair ON rss_saga.step_receipts;
DROP FUNCTION rss_saga.assert_receipt_pair();
ALTER TABLE rss_saga.journal ADD COLUMN protected jsonb;
UPDATE rss_saga.journal j SET protected=r.protected FROM rss_saga.step_receipts r WHERE (j.tenant_id,j.saga_id,j.seq)=(r.tenant_id,r.saga_id,r.completed_seq);
DROP TABLE rss_saga.step_receipts;
ALTER TABLE rss_saga.instances ADD COLUMN progress jsonb NOT NULL DEFAULT '{"status":"Ready","forward":0,"forwardAttempt":0,"forwardFailures":0,"compensation":null,"compensationAttempt":0,"pending":null,"lastKind":null}';
ALTER TABLE rss_saga.instances ADD COLUMN history_encoded_bytes bigint NOT NULL DEFAULT 0 CHECK(history_encoded_bytes>=0);
ALTER TABLE rss_saga.instances ADD COLUMN history_entry_limit bigint NOT NULL DEFAULT 1 CHECK(history_entry_limit>0);
ALTER TABLE rss_saga.instances ADD COLUMN history_byte_limit bigint NOT NULL DEFAULT 1 CHECK(history_byte_limit>0);

CREATE FUNCTION rss_saga.history_charge(r jsonb) RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
DECLARE n bigint;
BEGIN
 IF r IS NULL OR r='null'::jsonb THEN RETURN 256; END IF;
 IF (jsonb_typeof(r)='object' AND jsonb_typeof(r->'ciphertext')='object' AND jsonb_typeof(r->'ciphertext'->'bytes')='array' AND jsonb_typeof(r->'aad')='array' AND jsonb_typeof(r->'digest')='array' AND jsonb_typeof(r->'ciphertext'->'key_ref')='string' AND jsonb_typeof(r->'key_id')='string' AND (r->>'format')::integer=1) IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt shape'; END IF;
 IF jsonb_array_length(r->'ciphertext'->'bytes') NOT BETWEEN 1 AND 2097152 OR jsonb_array_length(r->'aad')>4096 OR jsonb_array_length(r->'digest')<>32 OR octet_length(r->'ciphertext'->>'key_ref') NOT BETWEEN 1 AND 1024 OR octet_length(r->>'key_id') NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt bound'; END IF;
 n:=256+1024+6*(octet_length(r->'ciphertext'->>'key_ref')+octet_length(r->>'key_id'))::bigint+5*(jsonb_array_length(r->'ciphertext'->'bytes')+jsonb_array_length(r->'aad')+jsonb_array_length(r->'digest'))::bigint;
 IF octet_length(r::text)>n-256 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt encoding'; END IF;
 -- Validate the u8 domain before any typed Rust reader can receive this envelope.
 IF EXISTS(SELECT FROM (
    SELECT value FROM jsonb_array_elements(r->'ciphertext'->'bytes')
    UNION ALL SELECT value FROM jsonb_array_elements(r->'aad')
    UNION ALL SELECT value FROM jsonb_array_elements(r->'digest')
 ) b WHERE jsonb_typeof(value)<>'number' OR value::text !~ '^(0|[1-9][0-9]{0,2})$' OR value>'255'::jsonb)
 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt byte domain'; END IF;
 RETURN n;
END $$;
CREATE FUNCTION rss_saga.history_reserve(p jsonb) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
DECLARE n bigint:=0; receipt boolean:=false; state_ text:=p->>'status';
BEGIN
 IF state_ IN ('Ready','Running') THEN
  receipt:=p->'pending'<>'null'::jsonb;
  n:=2*(p->>'forward')::bigint+1+CASE WHEN receipt THEN 3 ELSE 0 END;
 ELSIF state_ IN ('Compensating','CompensationFailed') THEN
  n:=2*coalesce((p->>'compensation')::bigint,0)+CASE WHEN p->'pending'<>'null'::jsonb THEN 1 WHEN (p->>'compensationAttempt')::bigint=0 OR p->>'lastKind'='Resume' THEN 2 ELSE 0 END;
 ELSIF state_ NOT IN ('Succeeded','Compensated') THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga reserve state'; END IF;
 RETURN jsonb_build_object('entries',n,'bytes',n*256+CASE WHEN receipt THEN 1024+6*(1024+64)+5*(2097152+4096+32) ELSE 0 END);
END $$;
CREATE FUNCTION rss_saga.next_progress(p jsonb,d jsonb,e jsonb) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
DECLARE state_ text:=p->>'status'; f bigint:=(p->>'forward')::bigint; fa bigint:=(p->>'forwardAttempt')::bigint; ff bigint:=(p->>'forwardFailures')::bigint;
 c bigint:=(p->>'compensation')::bigint; ca bigint:=(p->>'compensationAttempt')::bigint; pending jsonb:=p->'pending';
 k text:=e->>'kind'; s bigint:=(e->>'step')::bigint; a bigint:=(e->>'attempt')::bigint; valid boolean:=false;
BEGIN
 IF s IS NULL OR s<0 OR s>=jsonb_array_length(d->'steps') OR a IS NULL OR a NOT BETWEEN 1 AND 4294967295 OR state_ IN ('Succeeded','Compensated') THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga event invalid'; END IF;
 IF (k='ForwardApplied') IS DISTINCT FROM (e->'receipt' IS NOT NULL AND e->'receipt'<>'null'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt pairing'; END IF;
 IF k='ForwardIntent' THEN
  valid:=state_ IN ('Ready','Running') AND pending='null'::jsonb AND s=f AND a=fa+1 AND ff<(d->'steps'->s::integer->>'max_failures')::bigint;
  fa:=a; state_:='Running'; pending:=jsonb_build_object('step',s,'attempt',a,'kind',k);
 ELSIF k IN ('ForwardApplied','ForwardNotApplied','ForwardProbeNotApplied') THEN
  valid:=pending=jsonb_build_object('step',s,'attempt',a,'kind','ForwardIntent'); pending:='null'::jsonb;
  IF k='ForwardApplied' THEN
   valid:=valid AND (e->'receipt'->>'seq')::bigint=(e->>'seq')::bigint AND (e->'receipt'->>'attempt')::bigint=a;
   f:=f+1; fa:=0; ff:=0; state_:=CASE WHEN f=jsonb_array_length(d->'steps') THEN 'Succeeded' ELSE 'Running' END;
  ELSE state_:='Ready'; IF k='ForwardNotApplied' THEN ff:=ff+1; END IF; END IF;
 ELSIF k='Abort' THEN
  valid:=state_='Ready' AND pending='null'::jsonb AND s=f AND a=fa AND p->>'lastKind'='ForwardNotApplied' AND ff>=(d->'steps'->s::integer->>'max_failures')::bigint;
  c:=CASE WHEN f=0 THEN NULL ELSE f-1 END; ca:=0; state_:=CASE WHEN c IS NULL THEN 'Compensated' ELSE 'Compensating' END;
 ELSIF k='CompensationIntent' THEN
  valid:=state_='Compensating' AND pending='null'::jsonb AND s=c AND a=ca+1;
  ca:=a; pending:=jsonb_build_object('step',s,'attempt',a,'kind',k);
 ELSIF k IN ('CompensationApplied','CompensationNotApplied','CompensationFailed') THEN
  valid:=state_='Compensating' AND pending=jsonb_build_object('step',s,'attempt',a,'kind','CompensationIntent'); pending:='null'::jsonb;
  IF k='CompensationApplied' THEN c:=CASE WHEN s=0 THEN NULL ELSE s-1 END; ca:=0; state_:=CASE WHEN c IS NULL THEN 'Compensated' ELSE 'Compensating' END;
  ELSIF k='CompensationFailed' THEN state_:='CompensationFailed'; END IF;
 ELSIF k='Resume' THEN
  valid:=state_='CompensationFailed' AND pending='null'::jsonb AND s=c AND a=ca; state_:='Compensating';
 END IF;
 IF valid IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga transition invalid'; END IF;
 RETURN jsonb_build_object('status',state_,'forward',f,'forwardAttempt',fa,'forwardFailures',ff,'compensation',c,'compensationAttempt',ca,'pending',pending,'lastKind',k);
END $$;
-- One bounded row at a time; the caller's migration deadline also bounds this replay.
DO $$
DECLARE i record; j record; p jsonb; q bigint; bytes_ bigint; reserve_ jsonb; e jsonb;
BEGIN
 FOR i IN SELECT * FROM rss_saga.instances ORDER BY tenant_id,saga_id LOOP
  p:='{"status":"Ready","forward":0,"forwardAttempt":0,"forwardFailures":0,"compensation":null,"compensationAttempt":0,"pending":null,"lastKind":null}'; q:=0; bytes_:=0;
  FOR j IN SELECT * FROM rss_saga.journal WHERE tenant_id=i.tenant_id AND saga_id=i.saga_id ORDER BY seq LOOP
   IF j.seq<>q THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga upgrade sequence'; END IF;
   e:=jsonb_build_object('seq',j.seq,'step',j.step,'attempt',j.attempt,'kind',j.kind,'receipt',j.protected);
   p:=rss_saga.next_progress(p,i.definition,e); bytes_:=bytes_+rss_saga.history_charge(j.protected); q:=q+1;
  END LOOP;
  IF q<>i.revision OR p->>'status'<>i.status OR (p->>'forward')::integer<>i.next_step THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga upgrade projection'; END IF;
  reserve_:=rss_saga.history_reserve(p);
  UPDATE rss_saga.instances SET progress=p,history_encoded_bytes=bytes_,history_entry_limit=greatest(1,q+(reserve_->>'entries')::bigint),history_byte_limit=greatest(1,bytes_+(reserve_->>'bytes')::bigint) WHERE tenant_id=i.tenant_id AND saga_id=i.saga_id;
 END LOOP;
END $$;
DROP INDEX rss_saga.candidates;
ALTER TABLE rss_saga.instances DROP COLUMN status, DROP COLUMN next_step;
CREATE FUNCTION rss_saga.valid_instance(d jsonb,p jsonb,q bigint,bytes_ bigint,entries bigint,limit_bytes bigint) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
BEGIN
 RETURN (octet_length(d::text)<=2097152 AND octet_length(p::text)<=2048 AND q>=0 AND bytes_>=0 AND entries>0 AND limit_bytes>0 AND q<=entries AND bytes_<=limit_bytes
 AND jsonb_typeof(p)='object' AND p->>'status' IN ('Ready','Running','Compensating','CompensationFailed','Succeeded','Compensated')
 AND (p->>'forward')::bigint BETWEEN 0 AND 1024 AND (p->>'forwardAttempt')::bigint BETWEEN 0 AND 4294967295 AND (p->>'forwardFailures')::bigint BETWEEN 0 AND 4294967295
 AND (p->>'compensationAttempt')::bigint BETWEEN 0 AND 4294967295 AND (p->'compensation'='null'::jsonb OR (p->>'compensation')::bigint BETWEEN 0 AND 1023)
 AND (p->'pending'='null'::jsonb OR (p->'pending'->>'kind' IN ('ForwardIntent','CompensationIntent') AND (p->'pending'->>'step')::bigint BETWEEN 0 AND 1023 AND (p->'pending'->>'attempt')::bigint BETWEEN 1 AND 4294967295))) IS TRUE;
END $$;
CREATE FUNCTION rss_saga.valid_journal(k text,q bigint,a bigint,p_key bytea,r jsonb,bytes_ bigint) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
BEGIN
 RETURN (k IN ('ForwardIntent','ForwardApplied','ForwardNotApplied','ForwardProbeNotApplied','Abort','CompensationIntent','CompensationApplied','CompensationNotApplied','CompensationFailed','Resume') AND octet_length(p_key)=32 AND q>=0 AND a BETWEEN 1 AND 4294967295 AND bytes_=rss_saga.history_charge(r) AND (k='ForwardApplied')=(r IS NOT NULL) AND (r IS NULL OR ((r->>'seq')::bigint=q AND (r->>'attempt')::bigint=a))) IS TRUE;
END $$;
ALTER TABLE rss_saga.instances ADD CONSTRAINT saga_history_instance CHECK(rss_saga.valid_instance(definition,progress,revision,history_encoded_bytes,history_entry_limit,history_byte_limit));
ALTER TABLE rss_saga.journal ADD COLUMN encoded_bytes bigint NOT NULL DEFAULT 256;
UPDATE rss_saga.journal SET encoded_bytes=rss_saga.history_charge(protected);
ALTER TABLE rss_saga.journal ADD CONSTRAINT saga_history_journal CHECK(rss_saga.valid_journal(kind,seq,attempt,effect_key,protected,encoded_bytes));
CREATE UNIQUE INDEX saga_forward_step ON rss_saga.journal(tenant_id,saga_id,step) WHERE kind='ForwardApplied';
CREATE UNIQUE INDEX saga_forward_effect ON rss_saga.journal(tenant_id,effect_key) WHERE kind='ForwardApplied';
CREATE INDEX candidates ON rss_saga.instances(tenant_id,(progress->>'status'),expires_at,saga_id);
DROP FUNCTION rss_saga.register(uuid,jsonb);
DROP FUNCTION rss_saga.commit_event(uuid,uuid,bigint,jsonb,bytea);
CREATE FUNCTION rss_saga.register(p_id uuid,p_definition jsonb,p_capacity jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE existing rss_saga.instances; t uuid:=current_setting('rss.tenant_id')::uuid; entries bigint:=(p_capacity->>'maxEntries')::bigint; bytes_ bigint:=(p_capacity->>'maxEncodedBytes')::bigint;
BEGIN
 IF entries IS NULL OR bytes_ IS NULL OR entries<=0 OR bytes_<=0 THEN RAISE EXCEPTION USING ERRCODE='RS004',MESSAGE='saga capacity invalid'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(t::text||':'||(p_definition->'identity'->>'contract')||':'||(p_definition->'identity'->>'version'),0));
 IF EXISTS(SELECT FROM rss_saga.instances WHERE tenant_id=t AND definition->'identity'->>'contract'=p_definition->'identity'->>'contract' AND definition->'identity'->>'version'=p_definition->'identity'->>'version' AND definition<>p_definition) THEN RAISE EXCEPTION USING ERRCODE='RS002',MESSAGE='saga version conflict'; END IF;
 INSERT INTO rss_saga.instances(tenant_id,saga_id,definition,history_entry_limit,history_byte_limit) VALUES(t,p_id,p_definition,entries,bytes_) ON CONFLICT DO NOTHING;
 SELECT * INTO existing FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
 IF existing.definition IS DISTINCT FROM p_definition OR existing.history_entry_limit IS DISTINCT FROM entries OR existing.history_byte_limit IS DISTINCT FROM bytes_ THEN RAISE EXCEPTION USING ERRCODE='RS002',MESSAGE='saga registration conflict'; END IF;
END $$;
CREATE OR REPLACE FUNCTION rss_saga.lock_instance(p_id uuid,p_token uuid,p_epoch bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row_ rss_saga.instances; t uuid:=current_setting('rss.tenant_id')::uuid;
BEGIN
 SELECT * INTO row_ FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
 IF NOT FOUND OR p_token IS NULL OR p_epoch IS NULL OR p_epoch<=0 OR row_.expires_at IS NULL OR row_.lease_token IS DISTINCT FROM p_token OR row_.epoch<>p_epoch OR row_.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='RS001',MESSAGE='saga lease lost'; END IF;
 RETURN jsonb_build_object('revision',row_.revision,'encodedBytes',row_.history_encoded_bytes,'capacity',jsonb_build_object('maxEntries',row_.history_entry_limit,'maxEncodedBytes',row_.history_byte_limit),'progress',row_.progress);
END $$;
CREATE FUNCTION rss_saga.extend_history(p_id uuid,p_token uuid,p_epoch bigint,p_revision bigint,p_expected jsonb,p_capacity jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE h jsonb; t uuid:=current_setting('rss.tenant_id')::uuid; entries bigint:=(p_capacity->>'maxEntries')::bigint; bytes_ bigint:=(p_capacity->>'maxEncodedBytes')::bigint;
BEGIN
 h:=rss_saga.lock_instance(p_id,p_token,p_epoch);
 IF (h->>'revision')::bigint IS DISTINCT FROM p_revision OR h->'capacity' IS DISTINCT FROM p_expected OR entries IS NULL OR bytes_ IS NULL OR entries<(h->'capacity'->>'maxEntries')::bigint OR bytes_<(h->'capacity'->>'maxEncodedBytes')::bigint OR p_capacity=p_expected THEN RAISE EXCEPTION USING ERRCODE='RS002',MESSAGE='saga capacity conflict'; END IF;
 UPDATE rss_saga.instances SET history_entry_limit=entries,history_byte_limit=bytes_ WHERE tenant_id=t AND saga_id=p_id;
END $$;
CREATE FUNCTION rss_saga.commit_event(p_id uuid,p_token uuid,p_epoch bigint,e jsonb,p_key bytea,p_before jsonb,p_after jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE h jsonb; d jsonb; p jsonb; actual jsonb; reserve_ jsonb; n bigint; q bigint; t uuid:=current_setting('rss.tenant_id')::uuid; previous_key bytea;
BEGIN
 h:=rss_saga.lock_instance(p_id,p_token,p_epoch);
 q:=(h->>'revision')::bigint;
 IF h IS DISTINCT FROM p_before OR (e->>'seq')::bigint IS DISTINCT FROM q THEN RAISE EXCEPTION USING ERRCODE='RS002',MESSAGE='saga revision conflict'; END IF;
 IF octet_length(p_key) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga effect key invalid'; END IF;
 IF h->'progress'->'pending'<>'null'::jsonb THEN
  SELECT effect_key INTO previous_key FROM rss_saga.journal WHERE tenant_id=t AND saga_id=p_id AND seq=q-1;
  IF previous_key IS DISTINCT FROM p_key THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga pending key mismatch'; END IF;
 END IF;
 SELECT definition INTO d FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id;
 p:=rss_saga.next_progress(h->'progress',d,e); n:=(h->>'encodedBytes')::bigint+rss_saga.history_charge(e->'receipt');
 actual:=jsonb_build_object('revision',q+1,'encodedBytes',n,'capacity',h->'capacity','progress',p);
 IF actual IS DISTINCT FROM p_after THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga projection mismatch'; END IF;
 reserve_:=rss_saga.history_reserve(p);
 IF q+1+(reserve_->>'entries')::bigint>(h->'capacity'->>'maxEntries')::bigint OR n+(reserve_->>'bytes')::bigint>(h->'capacity'->>'maxEncodedBytes')::bigint THEN RAISE EXCEPTION USING ERRCODE='RS004',MESSAGE='saga history capacity'; END IF;
 INSERT INTO rss_saga.journal(tenant_id,saga_id,seq,step,attempt,effect_key,kind,protected,encoded_bytes) VALUES(t,p_id,q,(e->>'step')::integer,(e->>'attempt')::bigint,p_key,e->>'kind',nullif(e->'receipt','null'::jsonb),rss_saga.history_charge(e->'receipt'));
 UPDATE rss_saga.instances SET revision=q+1,progress=p,history_encoded_bytes=n WHERE tenant_id=t AND saga_id=p_id;
END $$;
CREATE FUNCTION rss_saga.runnable(p jsonb,d jsonb,q bigint,bytes_ bigint,entries bigint,capacity_bytes bigint) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
DECLARE e jsonb; next_ jsonb; reserve_ jsonb; step_ bigint; attempt_ bigint; kind_ text;
BEGIN
 IF p->>'status' NOT IN ('Ready','Running','Compensating') THEN RETURN false; END IF;
 IF p->'pending'<>'null'::jsonb THEN RETURN true; END IF;
 IF p->>'status'='Compensating' THEN step_:=(p->>'compensation')::bigint; attempt_:=(p->>'compensationAttempt')::bigint+1; kind_:='CompensationIntent';
 ELSE step_:=(p->>'forward')::bigint; attempt_:=(p->>'forwardAttempt')::bigint+1; kind_:='ForwardIntent';
  IF (p->>'forwardFailures')::bigint>=(d->'steps'->step_::integer->>'max_failures')::bigint THEN RETURN true; END IF;
 END IF;
 IF attempt_>4294967295 THEN RETURN false; END IF;
 e:=jsonb_build_object('seq',q,'step',step_,'attempt',attempt_,'kind',kind_,'receipt',null);
 next_:=rss_saga.next_progress(p,d,e); reserve_:=rss_saga.history_reserve(next_);
 RETURN q::numeric+1+(reserve_->>'entries')::numeric<=entries AND bytes_::numeric+256+(reserve_->>'bytes')::numeric<=capacity_bytes;
END $$;

CREATE OR REPLACE FUNCTION rss_saga.claim(p_id uuid,p_token uuid,p_ttl bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row rss_saga.instances; t uuid := current_setting('rss.tenant_id')::uuid; now_ timestamptz;
BEGIN
    IF p_ttl IS NULL OR p_token IS NULL OR p_ttl<=0 OR p_ttl>86400000 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
    SELECT * INTO row FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    now_ := clock_timestamp();
    IF NOT FOUND OR (row.expires_at IS NOT NULL AND row.expires_at>now_) THEN RAISE EXCEPTION USING ERRCODE='RS001',MESSAGE='saga lease unavailable'; END IF;
    UPDATE rss_saga.instances SET lease_token=p_token,epoch=epoch+1,expires_at=now_+p_ttl*interval '1 millisecond' WHERE tenant_id=t AND saga_id=p_id RETURNING epoch INTO row.epoch;
    RETURN row.epoch;
END $$;

CREATE OR REPLACE FUNCTION rss_saga.lease(p_id uuid,p_token uuid,p_epoch bigint,p_ttl bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE ignored jsonb; t uuid := current_setting('rss.tenant_id')::uuid;
BEGIN
    ignored := rss_saga.lock_instance(p_id,p_token,p_epoch);
    IF p_ttl=0 THEN UPDATE rss_saga.instances SET lease_token=NULL,expires_at=NULL WHERE tenant_id=t AND saga_id=p_id;
    ELSIF p_ttl>0 AND p_ttl<=86400000 THEN UPDATE rss_saga.instances SET expires_at=clock_timestamp()+p_ttl*interval '1 millisecond' WHERE tenant_id=t AND saga_id=p_id;
    ELSE RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
END $$;

ALTER TABLE rss_saga.instances FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.journal FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_saga FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_saga FROM PUBLIC;
COMMENT ON SCHEMA rss_saga IS 'rss-saga-postgres:2';
COMMIT;
