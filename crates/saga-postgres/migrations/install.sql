-- Fresh component installation by a dedicated NOSUPERUSER NOBYPASSRLS owner.
BEGIN;
CREATE SCHEMA rss_saga;
REVOKE ALL ON SCHEMA rss_saga FROM PUBLIC;
-- ref: PostgreSQL REL_16_0 src/backend/executor/execIndexing.c (unique conflict wait and recheck).
CREATE TABLE rss_saga.definitions (
    tenant_id uuid NOT NULL,
    definition jsonb NOT NULL,
    contract text COLLATE "C" GENERATED ALWAYS AS (definition #>> '{identity,contract}') STORED,
    version text COLLATE "C" GENERATED ALWAYS AS (definition #>> '{identity,version}') STORED,
    PRIMARY KEY (tenant_id, contract, version)
);

CREATE TABLE rss_saga.instances (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    contract text COLLATE "C" NOT NULL,
    version text COLLATE "C" NOT NULL,
    progress jsonb NOT NULL DEFAULT '{"status":"Ready","forward":0,"forwardAttempt":0,"forwardFailures":0,"compensation":null,"compensationAttempt":0,"pending":null,"lastKind":null}',
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    history_encoded_bytes bigint NOT NULL DEFAULT 0,
    history_entry_limit bigint NOT NULL,
    history_byte_limit bigint NOT NULL,
    lease_token uuid,
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    expires_at timestamptz,
    PRIMARY KEY (tenant_id,saga_id),
    CHECK ((lease_token IS NULL) = (expires_at IS NULL)),
    CONSTRAINT instance_definition FOREIGN KEY (tenant_id, contract, version)
        REFERENCES rss_saga.definitions (tenant_id, contract, version)
);
CREATE TABLE rss_saga.journal (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    seq bigint NOT NULL CHECK (seq >= 0),
    step integer NOT NULL CHECK (step >= 0),
    attempt bigint NOT NULL CHECK (attempt BETWEEN 1 AND 4294967295),
    effect_key bytea NOT NULL CHECK (octet_length(effect_key)=32),
    kind text NOT NULL CHECK (kind IN ('ForwardIntent','ForwardApplied','ForwardNotApplied','ForwardProbeNotApplied','Abort','CompensationIntent','CompensationApplied','CompensationNotApplied','CompensationFailed','Resume')),
    protected jsonb,
    encoded_bytes bigint NOT NULL DEFAULT 256,
    PRIMARY KEY (tenant_id,saga_id,seq),
    FOREIGN KEY (tenant_id,saga_id) REFERENCES rss_saga.instances
);

ALTER TABLE rss_saga.definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_saga.definitions USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE rss_saga.instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.instances FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.journal FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_saga.instances USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_saga.journal USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE FUNCTION rss_saga.history_charge(r jsonb) RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
DECLARE n bigint;
BEGIN
 IF r IS NULL OR r='null'::jsonb THEN RETURN 256; END IF;
 IF (jsonb_typeof(r)='object' AND jsonb_typeof(r->'ciphertext')='object' AND jsonb_typeof(r->'ciphertext'->'bytes')='array' AND jsonb_typeof(r->'aad')='array' AND jsonb_typeof(r->'digest')='array' AND jsonb_typeof(r->'ciphertext'->'key_ref')='string' AND jsonb_typeof(r->'key_id')='string' AND jsonb_typeof(r->'format')='number' AND r->>'format'='1' AND jsonb_typeof(r->'attempt')='number' AND jsonb_typeof(r->'seq')='number') IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt shape'; END IF;
 IF r->>'attempt' !~ '^[1-9][0-9]{0,9}$' OR r->'attempt'>'4294967295'::jsonb OR r->>'seq' !~ '^(0|[1-9][0-9]{0,18})$' OR r->'seq'>'9223372036854775807'::jsonb THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga receipt coordinates'; END IF;
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

CREATE FUNCTION rss_saga.valid_definition(d jsonb) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
BEGIN
    RETURN (octet_length(d::text) <= 2097152
        AND jsonb_typeof(d #> '{identity,contract}') = 'string'
        AND octet_length(d #>> '{identity,contract}') BETWEEN 1 AND 255
        AND jsonb_typeof(d #> '{identity,version}') = 'string'
        AND octet_length(d #>> '{identity,version}') BETWEEN 2 AND 11
        AND jsonb_array_length(d->'steps') BETWEEN 1 AND 1024) IS TRUE;
END $$;

CREATE FUNCTION rss_saga.valid_instance(p jsonb,q bigint,bytes_ bigint,entries bigint,limit_bytes bigint) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
BEGIN
 RETURN (octet_length(p::text)<=2048 AND q>=0 AND bytes_>=0 AND entries>0 AND limit_bytes>0 AND q<=entries AND bytes_<=limit_bytes
 AND jsonb_typeof(p)='object' AND p->>'status' IN ('Ready','Running','Compensating','CompensationFailed','Succeeded','Compensated')
 AND (p->>'forward')::bigint BETWEEN 0 AND 1024 AND (p->>'forwardAttempt')::bigint BETWEEN 0 AND 4294967295 AND (p->>'forwardFailures')::bigint BETWEEN 0 AND 4294967295
 AND (p->>'compensationAttempt')::bigint BETWEEN 0 AND 4294967295 AND (p->'compensation'='null'::jsonb OR (p->>'compensation')::bigint BETWEEN 0 AND 1023)
 AND (p->'pending'='null'::jsonb OR (p->'pending'->>'kind' IN ('ForwardIntent','CompensationIntent') AND (p->'pending'->>'step')::bigint BETWEEN 0 AND 1023 AND (p->'pending'->>'attempt')::bigint BETWEEN 1 AND 4294967295))) IS TRUE;
END $$;

CREATE FUNCTION rss_saga.valid_journal(k text,q bigint,a bigint,p_key bytea,r jsonb,bytes_ bigint) RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
DECLARE charged bigint;
BEGIN
 charged:=rss_saga.history_charge(r);
 RETURN (k IN ('ForwardIntent','ForwardApplied','ForwardNotApplied','ForwardProbeNotApplied','Abort','CompensationIntent','CompensationApplied','CompensationNotApplied','CompensationFailed','Resume') AND octet_length(p_key)=32 AND q>=0 AND a BETWEEN 1 AND 4294967295 AND bytes_=charged AND (k='ForwardApplied')=(r IS NOT NULL) AND (r IS NULL OR ((r->>'seq')::bigint=q AND (r->>'attempt')::bigint=a))) IS TRUE;
END $$;

CREATE FUNCTION rss_saga.register(p_id uuid,p_definition jsonb,p_capacity jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE
    t uuid := current_setting('rss.tenant_id')::uuid;
    contract_ text := p_definition #>> '{identity,contract}';
    version_ text := p_definition #>> '{identity,version}';
    entries bigint := (p_capacity->>'maxEntries')::bigint;
    bytes_ bigint := (p_capacity->>'maxEncodedBytes')::bigint;
    matches boolean;
    existing rss_saga.instances;
BEGIN
    IF entries IS NULL OR bytes_ IS NULL OR entries <= 0 OR bytes_ <= 0 THEN
        RAISE EXCEPTION USING ERRCODE='RS004', MESSAGE='saga capacity invalid';
    END IF;
    SELECT definition = p_definition INTO matches FROM rss_saga.definitions
        WHERE tenant_id=t AND contract=contract_ AND version=version_;
    IF NOT FOUND THEN
        INSERT INTO rss_saga.definitions(tenant_id,definition) VALUES(t,p_definition)
            ON CONFLICT (tenant_id,contract,version) DO NOTHING;
        matches := FOUND;
        IF NOT matches THEN
            -- A concurrent winner can be invisible to the INSERT snapshot. Read its committed row.
            SELECT definition = p_definition INTO STRICT matches FROM rss_saga.definitions
                WHERE tenant_id=t AND contract=contract_ AND version=version_;
        END IF;
    END IF;
    IF matches IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING ERRCODE='RS002', MESSAGE='saga version conflict';
    END IF;

    INSERT INTO rss_saga.instances(tenant_id,saga_id,contract,version,history_entry_limit,history_byte_limit)
        VALUES(t,p_id,contract_,version_,entries,bytes_) ON CONFLICT (tenant_id,saga_id) DO NOTHING;
    IF FOUND THEN RETURN; END IF;
    SELECT * INTO STRICT existing FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    IF existing.contract IS DISTINCT FROM contract_ OR existing.version IS DISTINCT FROM version_
        OR existing.history_entry_limit IS DISTINCT FROM entries OR existing.history_byte_limit IS DISTINCT FROM bytes_ THEN
        RAISE EXCEPTION USING ERRCODE='RS002', MESSAGE='saga registration conflict';
    END IF;
END $$;

CREATE FUNCTION rss_saga.lock_instance(p_id uuid,p_token uuid,p_epoch bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
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
 SELECT definition INTO STRICT d FROM rss_saga.instances JOIN rss_saga.definitions USING (tenant_id,contract,version)
 WHERE tenant_id=t AND saga_id=p_id;
 n:=(h->>'encodedBytes')::bigint+rss_saga.history_charge(e->'receipt'); p:=rss_saga.next_progress(h->'progress',d,e);
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
 -- Exhausted attempt ordinals cannot be resolved by capacity growth; exclude both discovery sets.
 IF attempt_>4294967295 THEN RETURN NULL; END IF;
 e:=jsonb_build_object('seq',q,'step',step_,'attempt',attempt_,'kind',kind_,'receipt',null);
 next_:=rss_saga.next_progress(p,d,e); reserve_:=rss_saga.history_reserve(next_);
 RETURN q::numeric+1+(reserve_->>'entries')::numeric<=entries AND bytes_::numeric+256+(reserve_->>'bytes')::numeric<=capacity_bytes;
END $$;

CREATE FUNCTION rss_saga.claim(p_id uuid,p_token uuid,p_ttl bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row rss_saga.instances; t uuid := current_setting('rss.tenant_id')::uuid; now_ timestamptz;
BEGIN
    IF p_ttl IS NULL OR p_token IS NULL OR p_ttl<=0 OR p_ttl>9223372036854775 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
    SELECT * INTO row FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    now_ := clock_timestamp();
    IF NOT FOUND OR (row.expires_at IS NOT NULL AND row.expires_at>now_) THEN RAISE EXCEPTION USING ERRCODE='RS001',MESSAGE='saga lease unavailable'; END IF;
    UPDATE rss_saga.instances SET lease_token=p_token,epoch=epoch+1,expires_at=now_+(p_ttl::text || ' milliseconds')::interval WHERE tenant_id=t AND saga_id=p_id RETURNING epoch INTO row.epoch;
    RETURN row.epoch;
END $$;

CREATE FUNCTION rss_saga.lease(p_id uuid,p_token uuid,p_epoch bigint,p_ttl bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE ignored jsonb; t uuid := current_setting('rss.tenant_id')::uuid;
BEGIN
    ignored := rss_saga.lock_instance(p_id,p_token,p_epoch);
    IF p_ttl=0 THEN UPDATE rss_saga.instances SET lease_token=NULL,expires_at=NULL WHERE tenant_id=t AND saga_id=p_id;
    ELSIF p_ttl>0 AND p_ttl<=9223372036854775 THEN UPDATE rss_saga.instances SET expires_at=clock_timestamp()+(p_ttl::text || ' milliseconds')::interval WHERE tenant_id=t AND saga_id=p_id;
    ELSE RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
END $$;

ALTER TABLE rss_saga.definitions ADD CONSTRAINT saga_definition CHECK(rss_saga.valid_definition(definition));
ALTER TABLE rss_saga.instances ADD CONSTRAINT saga_history_instance CHECK(rss_saga.valid_instance(progress,revision,history_encoded_bytes,history_entry_limit,history_byte_limit));
ALTER TABLE rss_saga.journal ADD CONSTRAINT saga_history_journal CHECK(rss_saga.valid_journal(kind,seq,attempt,effect_key,protected,encoded_bytes));
CREATE UNIQUE INDEX saga_forward_step ON rss_saga.journal(tenant_id,saga_id,step) WHERE kind='ForwardApplied';
CREATE UNIQUE INDEX saga_forward_effect ON rss_saga.journal(tenant_id,effect_key) WHERE kind='ForwardApplied';
CREATE INDEX candidates ON rss_saga.instances(tenant_id,(progress->>'status'),expires_at,saga_id);
REVOKE ALL ON ALL TABLES IN SCHEMA rss_saga FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_saga FROM PUBLIC;
COMMENT ON SCHEMA rss_saga IS 'rss-saga-postgres:4';
COMMIT;
