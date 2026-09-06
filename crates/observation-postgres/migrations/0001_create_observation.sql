-- Fresh installation by an external, dedicated NOSUPERUSER NOBYPASSRLS owner.
-- Runtime role provisioning and grants are consumer-owned. No historical data is imported.
CREATE SCHEMA rss_observation;
COMMENT ON SCHEMA rss_observation IS 'rss-observation-postgres:1';
CREATE TABLE rss_observation.objects (
 tenant_id uuid NOT NULL, object_id text NOT NULL,
 registration_id text, revision numeric(20,0) NOT NULL CHECK (revision BETWEEN 0 AND 18446744073709551615),
 PRIMARY KEY (tenant_id, object_id)
);
CREATE TABLE rss_observation.streams (
 tenant_id uuid NOT NULL, scope text NOT NULL,
 object_id text GENERATED ALWAYS AS (scope::jsonb->>'object') STORED,
 registration_id text GENERATED ALWAYS AS (scope::jsonb->>'registration') STORED,
 source_id text GENERATED ALWAYS AS (scope::jsonb->>'source') STORED,
 dataset_id text GENERATED ALWAYS AS (scope::jsonb->>'dataset') STORED,
 epoch_id text GENERATED ALWAYS AS (scope::jsonb->>'epoch') STORED,
 activation_previous numeric(20,0), activation_revision numeric(20,0) NOT NULL,
 policy text NOT NULL, state text NOT NULL,
 revision numeric(20,0) GENERATED ALWAYS AS ((state::jsonb->>'revision')::numeric) STORED,
 PRIMARY KEY (tenant_id,scope),
 UNIQUE (tenant_id,object_id,registration_id,source_id,dataset_id,epoch_id),
 CHECK ((scope::jsonb->>'tenant')::uuid=tenant_id),
 CHECK (revision BETWEEN 0 AND 18446744073709551615),
 CHECK (activation_revision BETWEEN 1 AND 18446744073709551615),
 FOREIGN KEY (tenant_id,object_id) REFERENCES rss_observation.objects
);
CREATE TABLE rss_observation.batches (
 tenant_id uuid NOT NULL, scope text NOT NULL, batch_id text NOT NULL,
 sequence numeric(20,0) NOT NULL CHECK (sequence BETWEEN 0 AND 18446744073709551615),
 raw bytea NOT NULL CHECK (octet_length(raw) BETWEEN 1 AND 4194304),
 fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
 received_at bigint NOT NULL CHECK (received_at>=0),
 policy text NOT NULL, decision text NOT NULL,
 applicable boolean NOT NULL,
 PRIMARY KEY (tenant_id,scope,batch_id),
 UNIQUE (tenant_id,scope,sequence),
 FOREIGN KEY (tenant_id,scope) REFERENCES rss_observation.streams
);
CREATE INDEX observation_ready ON rss_observation.batches (tenant_id,scope,sequence) WHERE applicable;
CREATE INDEX observation_active_stream ON rss_observation.streams (tenant_id,object_id,registration_id,source_id,dataset_id,activation_revision DESC);
ALTER TABLE rss_observation.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.objects FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.streams FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.batches FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_observation.objects USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_observation.streams USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_observation.batches USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

-- Object registration and observation epochs share one durable lifecycle CAS coordinate.
-- Historical activation retries return their original revision without reactivating anything.
CREATE FUNCTION rss_observation.activate(p_scope text,p_expected numeric,p_policy text,p_initial text)
RETURNS numeric LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_observation AS $$
DECLARE t uuid := (p_scope::jsonb->>'tenant')::uuid;
 o text := p_scope::jsonb->>'object'; r text := p_scope::jsonb->>'registration';
 current_object rss_observation.objects; prior rss_observation.streams; next_revision numeric;
BEGIN
 INSERT INTO rss_observation.objects(tenant_id,object_id,revision) VALUES(t,o,0) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT current_object FROM rss_observation.objects WHERE tenant_id=t AND object_id=o FOR UPDATE;
 SELECT * INTO prior FROM rss_observation.streams WHERE tenant_id=t AND scope=p_scope;
 IF FOUND THEN
  IF prior.activation_previous IS NOT DISTINCT FROM p_expected AND prior.policy::jsonb=p_policy::jsonb THEN RETURN prior.activation_revision; END IF;
  RAISE EXCEPTION USING ERRCODE='OB003',MESSAGE='lifecycle conflict';
 END IF;
 IF ((p_expected IS NULL AND current_object.revision=0) OR p_expected=current_object.revision) IS NOT TRUE THEN
  RAISE EXCEPTION USING ERRCODE='OB003',MESSAGE='lifecycle conflict';
 END IF;
 IF current_object.registration_id IS DISTINCT FROM r AND EXISTS(SELECT FROM rss_observation.streams WHERE tenant_id=t AND object_id=o AND registration_id=r) THEN
  RAISE EXCEPTION USING ERRCODE='OB003',MESSAGE='retired registration';
 END IF;
 next_revision:=current_object.revision+1;
 INSERT INTO rss_observation.streams(tenant_id,scope,activation_previous,activation_revision,policy,state)
 VALUES(t,p_scope,p_expected,next_revision,p_policy,p_initial);
 UPDATE rss_observation.objects SET registration_id=r,revision=next_revision WHERE tenant_id=t AND object_id=o;
 RETURN next_revision;
END $$;

-- Lock ordering: object SHARE, then stream UPDATE. Registration switches exclude all its streams.
CREATE FUNCTION rss_observation.lock_stream(p_scope text)
RETURNS SETOF rss_observation.streams LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_observation AS $$
DECLARE t uuid := (p_scope::jsonb->>'tenant')::uuid; current_registration text; selected rss_observation.streams;
BEGIN
 SELECT registration_id INTO current_registration FROM rss_observation.objects WHERE tenant_id=t AND object_id=p_scope::jsonb->>'object' FOR SHARE;
 IF current_registration IS NULL OR current_registration<>p_scope::jsonb->>'registration' THEN
  RAISE EXCEPTION USING ERRCODE='OB002',MESSAGE='inactive registration';
 END IF;
 SELECT * INTO selected FROM rss_observation.streams WHERE tenant_id=t AND scope=p_scope FOR UPDATE;
 IF NOT FOUND OR selected.activation_revision<>(SELECT max(activation_revision) FROM rss_observation.streams WHERE tenant_id=t AND object_id=selected.object_id AND registration_id=selected.registration_id AND source_id=selected.source_id AND dataset_id=selected.dataset_id) THEN
  RAISE EXCEPTION USING ERRCODE='OB002',MESSAGE='inactive epoch';
 END IF;
 RETURN NEXT selected;
END $$;

-- Rust computes the decision. SQL owns CAS, immutable identity and the atomic write boundary.
CREATE FUNCTION rss_observation.commit_batch(p_scope text,p_id text,p_sequence numeric,p_raw bytea,p_fingerprint bytea,p_received bigint,p_policy text,p_decision text,p_expected numeric,p_applicable boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_observation AS $$
DECLARE current_stream rss_observation.streams; t uuid := (p_scope::jsonb->>'tenant')::uuid;
BEGIN
 SELECT * INTO STRICT current_stream FROM rss_observation.lock_stream(p_scope);
 IF current_stream.revision<>p_expected OR current_stream.state::jsonb<>p_decision::jsonb->'before'
 OR (p_decision::jsonb->'after'->>'revision')::numeric<>p_expected+1 OR current_stream.policy::jsonb<>p_policy::jsonb THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='transition contract';
 END IF;
 INSERT INTO rss_observation.batches(tenant_id,scope,batch_id,sequence,raw,fingerprint,received_at,policy,decision,applicable)
 VALUES(t,p_scope,p_id,p_sequence,p_raw,p_fingerprint,p_received,p_policy,p_decision,p_applicable);
 UPDATE rss_observation.streams SET state=(p_decision::jsonb->'after')::text WHERE tenant_id=t AND scope=p_scope;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_observation FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_observation FROM PUBLIC;
-- Runtime: schema USAGE, table SELECT, function EXECUTE only. No DELETE/UPDATE/INSERT grants.
