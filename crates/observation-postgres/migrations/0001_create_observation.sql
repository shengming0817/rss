-- Fresh installation by an external, dedicated NOSUPERUSER NOBYPASSRLS owner.
-- Runtime role provisioning and grants are consumer-owned.
-- ref: postgres/postgres doc/src/sgml/mvcc.sgml@c13dd7d50f21268dc64b4b3edbce31993985ab12
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
CREATE TABLE rss_observation.admissions (
 tenant_id uuid PRIMARY KEY,
 is_open boolean NOT NULL DEFAULT true
);
CREATE TABLE rss_observation.journals (
 tenant_id uuid PRIMARY KEY,
 last_position bigint NOT NULL CHECK(last_position>0),
 expired_through bigint NOT NULL DEFAULT 0 CHECK (expired_through BETWEEN 0 AND last_position)
);
CREATE TABLE rss_observation.batches (
 tenant_id uuid NOT NULL, scope text NOT NULL, batch_id text NOT NULL,
 sequence numeric(20,0) NOT NULL CHECK (sequence BETWEEN 0 AND 18446744073709551615),
 -- PG16 can push bigint range predicates through forced RLS. Bias the full u64 domain
 -- monotonically so the maintenance cursor seeks directly to its first candidate.
 sequence_key bigint GENERATED ALWAYS AS ((sequence-9223372036854775808)::bigint) STORED,
 raw bytea CHECK (octet_length(raw) BETWEEN 1 AND 4194304),
 fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
 received_at bigint NOT NULL CHECK (received_at>=0),
 policy text, decision text,
 CHECK ((raw IS NULL)=(policy IS NULL) AND (raw IS NULL)=(decision IS NULL)),
 applicable boolean NOT NULL,
 log_position bigint,
 CONSTRAINT observation_position CHECK (
  applicable=(log_position IS NOT NULL) AND (log_position IS NULL OR log_position>0)
 ),
 PRIMARY KEY (tenant_id,scope,batch_id),
 UNIQUE (tenant_id,scope,sequence_key),
 FOREIGN KEY (tenant_id,scope) REFERENCES rss_observation.streams
);
CREATE UNIQUE INDEX observation_log ON rss_observation.batches (tenant_id,log_position) WHERE applicable;
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
ALTER TABLE rss_observation.journals ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.journals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_observation.journals USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE rss_observation.admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_observation.admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_observation.admissions USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

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
 INSERT INTO rss_observation.admissions(tenant_id) VALUES(t) ON CONFLICT DO NOTHING;
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
 position bigint; max_position CONSTANT bigint := 9223372036854775807;
BEGIN
 SELECT * INTO STRICT current_stream FROM rss_observation.lock_stream(p_scope);
 IF p_raw IS NULL OR p_policy IS NULL OR p_decision IS NULL
 OR current_stream.revision<>p_expected OR current_stream.state::jsonb<>p_decision::jsonb->'before'
 OR (p_decision::jsonb->'after'->>'revision')::numeric<>p_expected+1 OR current_stream.policy::jsonb<>p_policy::jsonb THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='transition contract';
 END IF;
 IF p_applicable THEN
  INSERT INTO rss_observation.journals AS j(tenant_id,last_position) VALUES(t,1)
  ON CONFLICT (tenant_id) DO UPDATE SET last_position=j.last_position+1
  WHERE j.last_position<max_position RETURNING last_position INTO position;
  IF NOT FOUND THEN
   RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='journal exhausted';
  END IF;
  IF position=max_position THEN
   -- Drain admitted reports before the last position becomes visible.
   UPDATE rss_observation.admissions SET is_open=false WHERE tenant_id=t AND is_open;
   IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='journal admission invariant';
   END IF;
  END IF;
 ELSE
  PERFORM 1 FROM rss_observation.admissions WHERE tenant_id=t AND is_open FOR SHARE;
  IF NOT FOUND THEN
   RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='journal admission closed';
  END IF;
 END IF;
 INSERT INTO rss_observation.batches(tenant_id,scope,batch_id,sequence,raw,fingerprint,received_at,policy,decision,applicable,log_position)
 VALUES(t,p_scope,p_id,p_sequence,p_raw,p_fingerprint,p_received,current_stream.policy,p_decision,p_applicable,position);
 UPDATE rss_observation.streams SET state=(p_decision::jsonb->'after')::text WHERE tenant_id=t AND scope=p_scope;
END $$;
-- ref: etcd-io/etcd server/storage/mvcc/kvstore_compaction.go@f5d605a93abe2fdfa13880aab0f1f3a4203628dd
-- Candidate window includes released and ineligible identities. Its boundaries survive retries.
CREATE FUNCTION rss_observation.reclaim(p_scope text,p_cutoff bigint,p_through bigint,p_after numeric,p_limit integer)
RETURNS TABLE(last_examined numeric,scanned integer,reclaimed integer,released_bytes bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_observation AS $$
DECLARE t uuid := (p_scope::jsonb->>'tenant')::uuid;
 s rss_observation.streams; candidate record; first_key bigint; latest_revision numeric; policy_json json; duration_key text; minimum_age numeric; floor_position bigint := 0;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION USING ERRCODE='OB007',MESSAGE='maintenance scope mismatch';
 END IF;
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1024 OR p_cutoff IS NULL OR p_cutoff NOT BETWEEN 0 AND floor(extract(epoch FROM clock_timestamp()))
    OR p_through IS NULL OR p_through<0 OR p_after NOT BETWEEN 0 AND 18446744073709551615 OR p_after<>trunc(p_after) THEN
  RAISE EXCEPTION USING ERRCODE='OB005',MESSAGE='invalid maintenance window';
 END IF;
 SELECT * INTO s FROM rss_observation.streams WHERE tenant_id=t AND scope=p_scope FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='OB006',MESSAGE='unknown stream'; END IF;
 IF EXISTS (SELECT FROM rss_observation.objects WHERE tenant_id=t AND object_id=s.object_id AND registration_id=s.registration_id) THEN
  SELECT activation_revision INTO STRICT latest_revision FROM rss_observation.streams
   WHERE tenant_id=t AND object_id=s.object_id AND registration_id=s.registration_id
    AND source_id=s.source_id AND dataset_id=s.dataset_id
   ORDER BY activation_revision DESC LIMIT 1;
  IF latest_revision=s.activation_revision THEN
   RAISE EXCEPTION USING ERRCODE='OB003',MESSAGE='stream is active';
  END IF;
 END IF;
 IF p_through>coalesce((SELECT last_position FROM rss_observation.journals WHERE tenant_id=t),0) THEN
  RAISE EXCEPTION USING ERRCODE='OB005',MESSAGE='uncommitted release position';
 END IF;
 -- Validate the durable V1 policy before using it to authorize irreversible release.
 IF NOT (s.policy IS JSON OBJECT WITH UNIQUE KEYS) THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='invalid retention policy';
 END IF;
 -- json preserves numeric tokens; jsonb would normalize exponent forms rejected by PolicyWire.
 policy_json:=s.policy::json;
 IF (policy_json->'version')::text IS DISTINCT FROM '1'
    OR (SELECT count(*) FROM json_object_keys(policy_json))<>4 THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='invalid retention policy';
 END IF;
 FOREACH duration_key IN ARRAY ARRAY['retrySeconds','safetySeconds','baselineSeconds'] LOOP
  IF coalesce((policy_json->duration_key)::text,'') !~ '^[1-9][0-9]{0,18}$' THEN
   RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='invalid retention duration';
  END IF;
  IF (policy_json->>duration_key)::numeric>9223372036854775807 THEN
   RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='invalid retention duration';
  END IF;
 END LOOP;
 minimum_age:=(policy_json->>'retrySeconds')::numeric+(policy_json->>'safetySeconds')::numeric;
 IF minimum_age>9223372036854775807 THEN
  RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='invalid retention horizon';
 END IF;
 -- Keep numeric conversion outside the RLS scan, including in a cached generic plan.
 IF p_after IS DISTINCT FROM 18446744073709551615 THEN
  first_key:=(coalesce(p_after,-1)+1-9223372036854775808)::bigint;
 END IF;
 scanned:=0; reclaimed:=0; released_bytes:=0;
 FOR candidate IN SELECT sequence,batch_id,received_at,log_position,policy,octet_length(raw) AS bytes
  FROM rss_observation.batches WHERE tenant_id=t AND scope=p_scope AND sequence_key >= first_key
  ORDER BY sequence_key LIMIT p_limit
 LOOP
  scanned:=scanned+1; last_examined:=candidate.sequence;
  IF candidate.bytes IS NOT NULL AND candidate.policy IS DISTINCT FROM s.policy THEN
   RAISE EXCEPTION USING ERRCODE='OB004',MESSAGE='batch policy differs from stream';
  END IF;
  IF candidate.bytes IS NOT NULL AND candidate.received_at+minimum_age<=p_cutoff
     AND (candidate.log_position IS NULL OR candidate.log_position<=p_through) THEN
   UPDATE rss_observation.batches SET raw=NULL,policy=NULL,decision=NULL
    WHERE tenant_id=t AND scope=p_scope AND batch_id=candidate.batch_id;
   reclaimed:=reclaimed+1; released_bytes:=released_bytes+candidate.bytes;
   floor_position:=greatest(floor_position,candidate.log_position);
  END IF;
 END LOOP;
 IF floor_position>0 THEN
  UPDATE rss_observation.journals SET expired_through=greatest(expired_through,floor_position)
   WHERE tenant_id=t AND expired_through<floor_position;
 END IF;
 RETURN NEXT;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_observation FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_observation FROM PUBLIC;
-- Runtime: schema USAGE, table SELECT, function EXECUTE only. No DELETE/UPDATE/INSERT grants.
