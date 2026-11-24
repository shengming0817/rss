-- Fresh installation only; the external owner provisions roles and executes this artifact.
-- Each object has one current definition. No historical schema is upgraded or adopted.
-- ref: PostgreSQL REL_17_6 src/backend/executor/nodeLockRows.c; src/pl/plpgsql/src/pl_exec.c.
CREATE SCHEMA rss_transactional_messaging;

CREATE TABLE rss_transactional_messaging.policy (
  revision integer PRIMARY KEY CHECK (revision = 1),
  automatic_window_seconds bigint NOT NULL CHECK (automatic_window_seconds = 86400),
  safety_seconds bigint NOT NULL CHECK (safety_seconds = 86400),
  receipt_retention_seconds bigint NOT NULL CHECK
    (receipt_retention_seconds > automatic_window_seconds + safety_seconds)
);

CREATE TABLE rss_transactional_messaging.inbox (
  tenant_id uuid NOT NULL,
  message_id text NOT NULL,
  consumer_group text NOT NULL,
  contract text NOT NULL,
  lease_token uuid NOT NULL,
  lease_until timestamptz NOT NULL,
  receive_count bigint NOT NULL DEFAULT 1 CHECK (receive_count > 0),
  fingerprint bytea,
  disposition text,
  PRIMARY KEY (tenant_id, message_id, consumer_group),
  CONSTRAINT inbox_receipt_shape CHECK (
    (fingerprint IS NULL AND disposition IS NULL) OR
    (fingerprint IS NOT NULL AND octet_length(fingerprint) = 32
      AND disposition IS NOT NULL AND disposition IN ('succeeded','rejected_permanent','rejected_invariant'))
  ),
 claim_epoch bigint NOT NULL DEFAULT 0, claim_lineage bytea
);

CREATE TABLE rss_transactional_messaging.outbox (
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL,
  message_id text NOT NULL,
  domain text COLLATE "C" NOT NULL,
  partition_key text COLLATE "C",
  partition_head boolean NOT NULL DEFAULT false CHECK (NOT partition_head OR partition_key IS NOT NULL),
  envelope jsonb NOT NULL,
  fingerprint bytea NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','publishing','published','dead_letter','resolved')),
  retry_count integer NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
  retry_after timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token uuid,
  lease_until timestamptz,
  automatic_retry_deadline timestamptz,
  UNIQUE (tenant_id, message_id),
  CONSTRAINT outbox_fingerprint_length CHECK (octet_length(fingerprint) = 32),
  CONSTRAINT outbox_lease_shape CHECK ((status = 'publishing') = (lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 recovery_version bigint NOT NULL DEFAULT 1 CHECK (recovery_version > 0),
 claim_epoch bigint NOT NULL DEFAULT 0, claim_lineage bytea,
 partition_seq bigint,
 CONSTRAINT outbox_partition_sequence_shape CHECK((partition_key IS NULL)=(partition_seq IS NULL) AND (partition_seq IS NULL OR partition_seq > 0))
);

CREATE TABLE rss_transactional_messaging.consumer_dead_letter (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 message_id text NOT NULL,
 consumer_group text NOT NULL,
 contract text NOT NULL,
 contract_version text NOT NULL,
 schema_digest text NOT NULL,
 fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
 capsule bytea CHECK (octet_length(capsule) BETWEEN 1 AND 16777216),
 reason text NOT NULL CHECK (reason IN ('rejected_permanent','rejected_invariant')),
 recovery_version bigint NOT NULL DEFAULT 1 CHECK (recovery_version > 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,id),
 UNIQUE (tenant_id,message_id,consumer_group)
);

CREATE TABLE rss_transactional_messaging.recovery_operations (
 tenant_id uuid NOT NULL,
 operation_id uuid NOT NULL,
 request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
 target_kind text NOT NULL CHECK (target_kind IN ('consumer','outbox')),
 target_key text NOT NULL,
 outcome text NOT NULL CHECK (outcome IN ('replayed','redriven','resolved')),
 result_version bigint NOT NULL CHECK (result_version > 0),
 replay_message_id text,
 resolution text CHECK (resolution IN ('accepted_gap','compensated')),
 evidence_message_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,operation_id),
 CONSTRAINT operation_shape CHECK (
   (outcome = 'replayed' AND target_kind = 'consumer' AND replay_message_id IS NOT NULL AND resolution IS NULL AND evidence_message_id IS NULL)
   OR (outcome = 'redriven' AND target_kind = 'outbox' AND replay_message_id IS NULL AND resolution IS NULL AND evidence_message_id IS NULL)
   OR (outcome = 'resolved' AND target_kind = 'outbox' AND replay_message_id IS NULL AND resolution IS NOT NULL AND
     ((resolution = 'accepted_gap' AND evidence_message_id IS NULL) OR (resolution = 'compensated' AND evidence_message_id IS NOT NULL)))),
 CONSTRAINT recovery_replay_identity UNIQUE (tenant_id,replay_message_id)
);

CREATE TABLE rss_transactional_messaging.archive_jobs (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, dead_letter_id uuid NOT NULL,
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32), source_version bigint NOT NULL,
 hot_seconds bigint NOT NULL CHECK(hot_seconds>0), cold_seconds bigint NOT NULL CHECK(cold_seconds>0),
 held boolean NOT NULL, generation uuid NOT NULL, lease_token uuid, lease_until timestamptz,
 purged boolean NOT NULL DEFAULT false, fault text CHECK(fault IN ('missing','evidence')),
 PRIMARY KEY(tenant_id,operation_id),
 FOREIGN KEY(tenant_id,dead_letter_id) REFERENCES rss_transactional_messaging.consumer_dead_letter(tenant_id,id),
 claim_epoch bigint NOT NULL DEFAULT 0, claim_lineage bytea
);

CREATE TABLE rss_transactional_messaging.archive_objects (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, generation uuid NOT NULL,
 object jsonb NOT NULL, prepared bytea, verified boolean NOT NULL DEFAULT false,
 reconciled boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,generation),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES rss_transactional_messaging.archive_jobs(tenant_id,operation_id),
 CHECK(prepared IS NULL OR octet_length(prepared) BETWEEN 1 AND 67108864),
 last_checked timestamptz, verified_epoch bigint NOT NULL DEFAULT 0, verified_lineage bytea
);

CREATE TABLE rss_transactional_messaging.storage_lineage (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 target bytea NOT NULL CHECK(octet_length(target)=16),
 lineage bytea NOT NULL CHECK(octet_length(lineage)=16)
);

CREATE TABLE rss_transactional_messaging.tenant_epoch (
 tenant_id uuid PRIMARY KEY, epoch bigint NOT NULL CHECK(epoch>0)
);

CREATE TABLE rss_transactional_messaging.dr_plans (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 lineage bytea NOT NULL CHECK(octet_length(lineage)=16), epoch bigint NOT NULL CHECK(epoch>0),
 kind text NOT NULL CHECK(kind IN ('database','broker','terminate')), evidence jsonb,
 target_operation uuid, target_digest bytea,
 CONSTRAINT dr_plan_action CHECK((kind<>'terminate' AND evidence IS NOT NULL AND target_operation IS NULL AND target_digest IS NULL) OR (kind='terminate' AND evidence IS NULL AND target_operation IS NOT NULL AND target_digest IS NOT NULL AND octet_length(target_digest)=32)),
 FOREIGN KEY(tenant_id,target_operation) REFERENCES rss_transactional_messaging.dr_plans(tenant_id,operation_id),
 UNIQUE(tenant_id,target_operation),
 PRIMARY KEY(tenant_id,operation_id), UNIQUE(tenant_id,lineage,epoch)
);

CREATE TABLE rss_transactional_messaging.dr_members (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 1023),
 message_id text NOT NULL, consumer_group text NOT NULL, contract text,
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), outbox_seq bigint REFERENCES rss_transactional_messaging.outbox(seq),
 status text NOT NULL CHECK(status IN ('pending','publishing','completed','blocked')),
 block_reason text CONSTRAINT dr_member_reason CHECK(block_reason IN ('deadline_expired','permanent_publish_failure')),
 CONSTRAINT dr_member_block_shape CHECK((status='blocked')=(block_reason IS NOT NULL)),
 lease_token uuid, lease_until timestamptz, retry_after timestamptz NOT NULL DEFAULT clock_timestamp(),
 retry_count integer NOT NULL DEFAULT 0 CHECK(retry_count>=0),
 PRIMARY KEY(tenant_id,operation_id,ordinal), UNIQUE(tenant_id,operation_id,message_id,consumer_group),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES rss_transactional_messaging.dr_plans(tenant_id,operation_id),
 CHECK((status='publishing')=(lease_token IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK((outbox_seq IS NOT NULL AND consumer_group='' AND contract IS NULL) OR (outbox_seq IS NULL AND consumer_group<>'' AND contract IS NOT NULL))
);

CREATE TABLE rss_transactional_messaging.outbox_partitions (
 tenant_id uuid NOT NULL,
 domain text COLLATE "C" NOT NULL,
 partition_key text COLLATE "C" NOT NULL,
 last_sequence bigint NOT NULL DEFAULT 0 CHECK(last_sequence >= 0),
 prepared_by xid8 NOT NULL,
 PRIMARY KEY(tenant_id, domain, partition_key)
);

CREATE TABLE rss_transactional_messaging.consumer_scope (
 login_role name PRIMARY KEY,
 domain text NOT NULL CHECK (length(domain)>0),
 consumer_group text NOT NULL CHECK (length(consumer_group)>0)
);

INSERT INTO rss_transactional_messaging.policy VALUES (1,86400,86400,604800);

CREATE UNIQUE INDEX outbox_partition ON rss_transactional_messaging.outbox(tenant_id,domain,partition_key,partition_seq)
 WHERE partition_key IS NOT NULL;

CREATE INDEX archive_source ON rss_transactional_messaging.archive_jobs(tenant_id,dead_letter_id);

CREATE INDEX dr_member_outbox ON rss_transactional_messaging.dr_members(outbox_seq);

CREATE INDEX outbox_partition_preparation ON rss_transactional_messaging.outbox_partitions(tenant_id, prepared_by);

CREATE INDEX outbox_unfinished_partition ON rss_transactional_messaging.outbox(tenant_id,domain,partition_key,partition_seq)
 WHERE partition_key IS NOT NULL AND status NOT IN ('published','resolved');

CREATE UNIQUE INDEX outbox_one_head ON rss_transactional_messaging.outbox(tenant_id,domain,partition_key)
 WHERE partition_head;

CREATE INDEX outbox_pending_due ON rss_transactional_messaging.outbox(tenant_id,domain,retry_after)
 WHERE (partition_head OR partition_key IS NULL) AND status='pending';

CREATE INDEX outbox_lease_due ON rss_transactional_messaging.outbox(tenant_id,domain,claim_epoch,claim_lineage,greatest(retry_after,lease_until))
 WHERE (partition_head OR partition_key IS NULL) AND status='publishing';

CREATE INDEX outbox_stale_retry ON rss_transactional_messaging.outbox(tenant_id,domain,claim_epoch,claim_lineage,retry_after)
 WHERE (partition_head OR partition_key IS NULL) AND status='publishing';

ALTER TABLE rss_transactional_messaging.inbox ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.inbox FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.outbox ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.outbox FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.consumer_dead_letter ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.consumer_dead_letter FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.recovery_operations ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.recovery_operations FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.archive_jobs ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.archive_jobs FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.archive_objects ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.archive_objects FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.tenant_epoch ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.tenant_epoch FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.dr_plans ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.dr_plans FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.dr_members ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.dr_members FORCE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.outbox_partitions ENABLE ROW LEVEL SECURITY;

ALTER TABLE rss_transactional_messaging.outbox_partitions FORCE ROW LEVEL SECURITY;

GRANT USAGE,CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;

GRANT SELECT, UPDATE ON rss_transactional_messaging.outbox TO rss_tmsg_relay;

GRANT SELECT,UPDATE(singleton) ON rss_transactional_messaging.storage_lineage TO rss_tmsg_relay;

GRANT SELECT,UPDATE ON rss_transactional_messaging.tenant_epoch TO rss_tmsg_relay;

GRANT SELECT,INSERT,UPDATE ON rss_transactional_messaging.dr_plans,rss_transactional_messaging.dr_members TO rss_tmsg_relay;

GRANT SELECT ON rss_transactional_messaging.inbox TO rss_tmsg_relay;

GRANT SELECT,INSERT,UPDATE ON rss_transactional_messaging.outbox_partitions TO rss_tmsg_relay;

GRANT INSERT ON rss_transactional_messaging.outbox TO rss_tmsg_relay;

GRANT USAGE ON SEQUENCE rss_transactional_messaging.outbox_seq_seq TO rss_tmsg_relay;

GRANT SELECT ON rss_transactional_messaging.consumer_scope TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.check_execution() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE s storage_lineage; e bigint;
BEGIN
 SELECT * INTO s FROM storage_lineage WHERE singleton FOR SHARE;
 IF NOT FOUND OR s.target IS DISTINCT FROM decode(current_setting('rss.storage_target',true),'hex') OR s.lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage',true),'hex') THEN
  RAISE EXCEPTION 'storage lineage fenced' USING ERRCODE='PZ001'; END IF;
 SELECT epoch INTO e FROM tenant_epoch WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid FOR SHARE;
 IF NOT FOUND OR e IS DISTINCT FROM nullif(current_setting('rss.execution_epoch',true),'')::bigint THEN RAISE EXCEPTION 'tenant epoch fenced' USING ERRCODE='PZ001'; END IF;
END $f$;

ALTER FUNCTION rss_transactional_messaging.check_execution() OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.guard_execution() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
BEGIN
 PERFORM check_execution();
 IF TG_OP='DELETE' THEN
  IF OLD.tenant_id IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION 'tenant scope denied' USING ERRCODE='42501'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.tenant_id IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION 'tenant scope denied' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME IN ('inbox','outbox','archive_jobs') THEN
 IF TG_OP='INSERT' OR NEW.lease_token IS DISTINCT FROM OLD.lease_token THEN
  NEW.claim_epoch:=current_setting('rss.execution_epoch')::bigint;
  NEW.claim_lineage:=decode(current_setting('rss.storage_lineage'),'hex');
 END IF;
 END IF;
 RETURN NEW;
END $f$;

ALTER FUNCTION rss_transactional_messaging.guard_execution() OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.read_outbox_frame(data bytea, pos integer, tag integer)
RETURNS TABLE(value bytea, next_pos integer)
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE size bigint;
BEGIN
 IF pos<0 OR octet_length(data)-pos<9 OR get_byte(data,pos)<>tag THEN
  RAISE EXCEPTION 'invalid message frame' USING ERRCODE='22023';
 END IF;
 size:=('x'||encode(substring(data FROM pos+2 FOR 8),'hex'))::bit(64)::bigint;
 IF size<0 OR size>octet_length(data)-pos-9 THEN
  RAISE EXCEPTION 'invalid message frame length' USING ERRCODE='22023';
 END IF;
 RETURN QUERY SELECT substring(data FROM pos+10 FOR size::integer),pos+9+size::integer;
END $f$;

ALTER FUNCTION rss_transactional_messaging.read_outbox_frame(bytea,integer,integer) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.decode_outbox_message(data bytea)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE pos integer:=0; v bytea; result jsonb:='{}'; flag bytea; key text; prior_key text;
 attrs jsonb:='{}'; count bigint; number bigint; tag integer; name text; value text;
BEGIN
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,0);
 IF v<>convert_to('rss-transactional-message-v1','UTF8') THEN RAISE EXCEPTION 'unsupported message contract' USING ERRCODE='22023'; END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,1);
 result:=jsonb_build_object('id',convert_from(v,'UTF8'));
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,2);
 IF octet_length(v)<>16 THEN RAISE EXCEPTION 'invalid tenant' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('tenant',encode(v,'hex')::uuid::text);
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,3);
 IF octet_length(v)<>8 THEN RAISE EXCEPTION 'invalid time' USING ERRCODE='22023'; END IF;
 number:=('x'||encode(v,'hex'))::bit(64)::bigint;
 IF number<0 THEN RAISE EXCEPTION 'invalid time' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('occurred_at',number);
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,4);
 flag:=v;
 IF flag NOT IN (decode('00','hex'),decode('01','hex')) THEN RAISE EXCEPTION 'invalid optional presence' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('correlation',NULL);
 IF flag=decode('01','hex') THEN
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,4);
 result:=result||jsonb_build_object('correlation',convert_from(v,'UTF8'));
 END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,5);
 result:=result||jsonb_build_object('domain',convert_from(v,'UTF8'));
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,6);
 result:=result||jsonb_build_object('route',convert_from(v,'UTF8'));
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,7);
 result:=result||jsonb_build_object('contract',convert_from(v,'UTF8'));
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,8);
 IF octet_length(v)<>4 THEN RAISE EXCEPTION 'invalid contract version' USING ERRCODE='22023'; END IF;
 number:=('x'||encode(v,'hex'))::bit(32)::bigint;
 IF number=0 THEN RAISE EXCEPTION 'invalid contract version' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('version','v'||number::text);
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,9);
 result:=result||jsonb_build_object('schema',convert_from(v,'UTF8'));
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,10);
 flag:=v;
 IF flag NOT IN (decode('00','hex'),decode('01','hex')) THEN RAISE EXCEPTION 'invalid partition presence' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('partition',NULL);
 IF flag=decode('01','hex') THEN
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,11);
 IF octet_length(v)<>16 OR encode(v,'hex')::uuid::text<>result->>'tenant' THEN RAISE EXCEPTION 'partition tenant mismatch' USING ERRCODE='22023'; END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,12);
 IF convert_from(v,'UTF8')<>result->>'domain' THEN RAISE EXCEPTION 'partition domain mismatch' USING ERRCODE='22023'; END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,13);
 result:=result||jsonb_build_object('partition',convert_from(v,'UTF8'));
 END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,14);
 flag:=v;
 IF flag NOT IN (decode('00','hex'),decode('01','hex')) THEN RAISE EXCEPTION 'invalid optional presence' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('causation',NULL);
 IF flag=decode('01','hex') THEN
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,14);
 result:=result||jsonb_build_object('causation',convert_from(v,'UTF8'));
 END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,15);
 IF octet_length(v)<>8 THEN RAISE EXCEPTION 'invalid attribute count' USING ERRCODE='22023'; END IF;
 count:=('x'||encode(v,'hex'))::bit(64)::bigint;
 IF count<0 OR count>(octet_length(data)-pos)/18 THEN RAISE EXCEPTION 'invalid attribute count' USING ERRCODE='22023'; END IF;
 WHILE count>0 LOOP
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,16);
 key:=convert_from(v,'UTF8');
 IF prior_key IS NOT NULL AND (key COLLATE "C")<=(prior_key COLLATE "C") THEN RAISE EXCEPTION 'attributes must be unique and byte sorted' USING ERRCODE='22023'; END IF;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,17);
 attrs:=attrs||jsonb_build_object(key,convert_from(v,'UTF8'));
 prior_key:=key; count:=count-1;
 END LOOP;
 SELECT * INTO v,pos FROM read_outbox_frame(data,pos,18);
 IF pos<>octet_length(data) THEN RAISE EXCEPTION 'trailing message frames' USING ERRCODE='22023'; END IF;
 result:=result||jsonb_build_object('attributes',attrs,'payload',COALESCE((SELECT jsonb_agg(get_byte(v,i) ORDER BY i) FROM generate_series(0,octet_length(v)-1) i),'[]'::jsonb));
 -- Apply the same primitive shapes as the core before creating the private durable projection.
 FOREACH name IN ARRAY ARRAY['id','domain','route','causation'] LOOP
  value:=result->>name;
  IF value IS NOT NULL AND (octet_length(value) NOT BETWEEN 1 AND 255 OR (value COLLATE "C") ~ '[^A-Za-z0-9_.:-]') THEN
   RAISE EXCEPTION 'invalid message identity' USING ERRCODE='22023';
  END IF;
 END LOOP;
 value:=result->>'correlation';
 IF value IS NOT NULL AND (octet_length(value) NOT BETWEEN 1 AND 255 OR (value COLLATE "C") ~ '[^A-Za-z0-9_.-]') THEN
  RAISE EXCEPTION 'invalid correlation' USING ERRCODE='22023';
 END IF;
 value:=result->>'partition';
 IF value IS NOT NULL AND (octet_length(value) NOT BETWEEN 1 AND 255 OR (value COLLATE "C") ~ '[[:cntrl:]]') THEN
  RAISE EXCEPTION 'invalid partition' USING ERRCODE='22023';
 END IF;
 value:=result->>'contract';
 IF octet_length(value)>255 OR (value COLLATE "C") !~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*(\.[a-z][a-z0-9]*(-[a-z0-9]+)*)+$' THEN
  RAISE EXCEPTION 'invalid contract id' USING ERRCODE='22023';
 END IF;
 IF (result->>'schema' COLLATE "C") !~ '^sha256:[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'invalid schema digest' USING ERRCODE='22023';
 END IF;
 RETURN result;
EXCEPTION WHEN character_not_in_repertoire OR untranslatable_character THEN
 RAISE EXCEPTION 'message text is not PostgreSQL UTF8 text' USING ERRCODE='22023';
END $f$;

ALTER FUNCTION rss_transactional_messaging.decode_outbox_message(bytea) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.consumer_scope_domain()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT domain FROM consumer_scope WHERE login_role=session_user
$f$;

ALTER FUNCTION rss_transactional_messaging.consumer_scope_domain() OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.consumer_inbox_allowed(p_tenant uuid,p_message text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT CASE WHEN p_tenant=nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
  NOT EXISTS(SELECT FROM consumer_scope s WHERE s.login_role=session_user)
  OR EXISTS(SELECT FROM consumer_scope s JOIN outbox o ON o.domain=s.domain
   WHERE s.login_role=session_user AND s.consumer_group=p_group AND o.tenant_id=p_tenant AND o.message_id=p_message)
 ELSE false END
$f$;

ALTER FUNCTION rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.projection_scope_matches(p_domain text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT EXISTS(SELECT FROM consumer_scope WHERE login_role=session_user AND domain=p_domain AND consumer_group=p_group)
$f$;

ALTER FUNCTION rss_transactional_messaging.projection_scope_matches(text,text) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.local_projection_dr_status(p_tenant uuid,p_seq bigint,p_operation uuid)
RETURNS TABLE(status text,fingerprint bytea) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
 SELECT d.status,d.fingerprint FROM dr_members d JOIN outbox o ON o.tenant_id=d.tenant_id AND o.seq=d.outbox_seq
 WHERE p_tenant=nullif(current_setting('rss.tenant_id',true),'')::uuid
 AND d.tenant_id=p_tenant AND d.outbox_seq=p_seq AND d.operation_id=p_operation
$f$;

ALTER FUNCTION rss_transactional_messaging.local_projection_dr_status(uuid,bigint,uuid) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.prepare_outbox_partitions(p_partitions jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 x xid8:=pg_current_xact_id(); item jsonb; r record;
BEGIN
 PERFORM check_execution();
 IF p_partitions IS NULL OR jsonb_typeof(p_partitions)<>'array' THEN
  RAISE EXCEPTION 'invalid partition declaration' USING ERRCODE='22023';
 END IF;
 -- An empty set acquires nothing and does not establish an ordered admission.
 IF jsonb_array_length(p_partitions)=0 THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM outbox_partitions WHERE tenant_id=t AND prepared_by=x) THEN
  RAISE EXCEPTION 'partition set already declared' USING ERRCODE='PZ002';
 END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(p_partitions) LOOP
  IF jsonb_typeof(item)<>'array' THEN
   RAISE EXCEPTION 'invalid partition declaration' USING ERRCODE='22023';
  END IF;
  IF jsonb_array_length(item)<>2 OR jsonb_typeof(item->0) IS DISTINCT FROM 'string' OR jsonb_typeof(item->1) IS DISTINCT FROM 'string'
   OR octet_length(item->>0) NOT BETWEEN 1 AND 255 OR octet_length(item->>1) NOT BETWEEN 1 AND 255
   OR ((item->>0) COLLATE "C") ~ '[^A-Za-z0-9_.:-]' OR ((item->>1) COLLATE "C") ~ '[[:cntrl:]]' THEN
   RAISE EXCEPTION 'invalid partition declaration' USING ERRCODE='22023';
  END IF;
 END LOOP;
 FOR r IN SELECT DISTINCT (value->>0) COLLATE "C" AS domain, (value->>1) COLLATE "C" AS partition_key
  FROM jsonb_array_elements(p_partitions) ORDER BY domain,partition_key LOOP
  INSERT INTO outbox_partitions(tenant_id,domain,partition_key,prepared_by)
   VALUES(t,r.domain,r.partition_key,x)
   ON CONFLICT(tenant_id,domain,partition_key) DO UPDATE SET prepared_by=EXCLUDED.prepared_by;
 END LOOP;
END $f$;

ALTER FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.append_outbox(p_message bytea,p_transport jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 first_in_partition boolean:=false; ordinal bigint; persisted bytea; digest bytea; envelope jsonb; id text; domain_name text; partition_name text;
BEGIN
 PERFORM check_execution();
 IF p_message IS NULL OR jsonb_typeof(p_transport) IS DISTINCT FROM 'object'
  OR p_transport-ARRAY['trace','tenant_authority']<>'{}'::jsonb
  OR NOT (p_transport ?& ARRAY['trace','tenant_authority'])
  OR jsonb_typeof(p_transport->'trace') NOT IN ('string','null')
  OR jsonb_typeof(p_transport->'tenant_authority') NOT IN ('string','null') THEN
  RAISE EXCEPTION 'invalid message input' USING ERRCODE='22023';
 END IF;
 envelope:=decode_outbox_message(p_message)||p_transport;
 IF (envelope->>'tenant')::uuid IS DISTINCT FROM t THEN
  RAISE EXCEPTION 'message tenant mismatch' USING ERRCODE='22023';
 END IF;
 id:=envelope->>'id'; domain_name:=envelope->>'domain'; partition_name:=envelope->>'partition';
 digest:=sha256(p_message);
 IF partition_name IS NOT NULL AND NOT EXISTS(SELECT 1 FROM outbox_partitions
  WHERE tenant_id=t AND domain=domain_name AND partition_key=partition_name AND prepared_by=pg_current_xact_id()) THEN
  RAISE EXCEPTION 'partition was not declared by this transaction' USING ERRCODE='PZ002';
 END IF;
 SELECT o.fingerprint INTO persisted FROM outbox o WHERE o.tenant_id=t AND o.message_id=id;
 IF FOUND THEN RETURN CASE WHEN persisted=digest THEN 'already_present' ELSE 'conflict' END; END IF;
 IF partition_name IS NOT NULL THEN
  UPDATE outbox_partitions SET last_sequence=last_sequence+1
   WHERE tenant_id=t AND domain=domain_name AND partition_key=partition_name AND prepared_by=pg_current_xact_id()
   RETURNING last_sequence INTO ordinal;
  SELECT NOT EXISTS(SELECT FROM outbox o WHERE o.tenant_id=t AND o.domain=domain_name
   AND o.partition_key=partition_name AND o.partition_head) INTO first_in_partition;
 END IF;
 INSERT INTO outbox(tenant_id,message_id,domain,partition_key,partition_seq,partition_head,envelope,fingerprint)
  VALUES(t,id,domain_name,partition_name,ordinal,first_in_partition,envelope,digest)
  ON CONFLICT(tenant_id,message_id) DO NOTHING RETURNING outbox.fingerprint INTO persisted;
 IF FOUND THEN RETURN 'inserted'; END IF;
 SELECT o.fingerprint INTO STRICT persisted FROM outbox o WHERE o.tenant_id=t AND o.message_id=id;
 RETURN CASE WHEN persisted=digest THEN 'already_present' ELSE 'conflict' END;
END $f$;

ALTER FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) OWNER TO rss_tmsg_relay;

-- Both ordinary settlement and explicit recovery can release a partition. Serialize
-- promotion against append, including an append racing the last head's completion.
CREATE FUNCTION rss_transactional_messaging.refresh_outbox_head() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE next_seq bigint;
BEGIN
 PERFORM 1 FROM outbox_partitions WHERE tenant_id=NEW.tenant_id AND domain=NEW.domain
  AND partition_key=NEW.partition_key FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'partition allocator missing'; END IF;
 SELECT seq INTO next_seq FROM outbox WHERE tenant_id=NEW.tenant_id AND domain=NEW.domain
  AND partition_key=NEW.partition_key AND status NOT IN ('published','resolved')
  ORDER BY partition_seq LIMIT 1;
 UPDATE outbox SET partition_head=false WHERE tenant_id=NEW.tenant_id AND domain=NEW.domain
  AND partition_key=NEW.partition_key AND partition_head AND seq IS DISTINCT FROM next_seq;
 UPDATE outbox SET partition_head=true WHERE seq=next_seq AND NOT partition_head;
 RETURN NULL;
END $f$;

ALTER FUNCTION rss_transactional_messaging.refresh_outbox_head() OWNER TO rss_tmsg_relay;

CREATE TRIGGER refresh_outbox_head AFTER UPDATE OF status ON rss_transactional_messaging.outbox
 FOR EACH ROW WHEN (NEW.partition_key IS NOT NULL AND
  ((OLD.partition_head AND NEW.status IN ('published','resolved') AND OLD.status NOT IN ('published','resolved'))
   OR (OLD.status IN ('published','resolved') AND NEW.status NOT IN ('published','resolved'))))
 EXECUTE FUNCTION rss_transactional_messaging.refresh_outbox_head();

CREATE FUNCTION rss_transactional_messaging.outbox_candidates(p_tenant uuid,p_domain text)
RETURNS TABLE(source_seq bigint,dr_operation uuid,eligible_at timestamptz)
LANGUAGE sql STABLE AS $f$
 WITH current_dr AS MATERIALIZED (
  SELECT d.*,src.partition_key,src.partition_seq FROM rss_transactional_messaging.dr_plans p
  JOIN rss_transactional_messaging.dr_members d USING(tenant_id,operation_id)
  JOIN rss_transactional_messaging.outbox src ON src.seq=d.outbox_seq AND src.tenant_id=d.tenant_id
  WHERE p.tenant_id=p_tenant AND src.domain=p_domain AND d.status<>'completed'
   AND p.epoch=nullif(current_setting('rss.execution_epoch',true),'')::bigint
   AND p.lineage=decode(current_setting('rss.storage_lineage',true),'hex')
 ), ordinary AS NOT MATERIALIZED (
  SELECT src.* FROM rss_transactional_messaging.outbox src
  WHERE src.tenant_id=p_tenant AND src.domain=p_domain AND (src.partition_head OR src.partition_key IS NULL)
   AND NOT EXISTS(SELECT FROM current_dr d WHERE d.outbox_seq=src.seq
    OR (d.partition_key=src.partition_key AND d.partition_seq<src.partition_seq))
 ), publishing AS NOT MATERIALIZED (
  SELECT src.*,nullif(current_setting('rss.execution_epoch',true),'')::bigint AS epoch,
   decode(current_setting('rss.storage_lineage',true),'hex') AS lineage
  FROM ordinary src WHERE src.status='publishing'
 )
 SELECT seq,NULL::uuid,retry_after FROM ordinary WHERE status='pending'
 UNION ALL
 SELECT seq,NULL::uuid,greatest(retry_after,lease_until) FROM publishing
 WHERE claim_epoch=epoch AND claim_lineage=lineage
 UNION ALL
 SELECT seq,NULL::uuid,retry_after FROM publishing
 WHERE claim_epoch<>epoch OR claim_lineage IS DISTINCT FROM lineage
 UNION ALL
 SELECT d.outbox_seq,d.operation_id AS dr_operation,
  greatest(d.retry_after,CASE WHEN d.status='publishing' THEN d.lease_until END)
 FROM current_dr d WHERE d.status IN ('pending','publishing')
 AND NOT EXISTS(SELECT FROM current_dr earlier WHERE earlier.partition_key=d.partition_key
  AND earlier.partition_seq<d.partition_seq)
 AND NOT EXISTS(SELECT FROM rss_transactional_messaging.outbox earlier WHERE earlier.tenant_id=p_tenant
  AND earlier.domain=p_domain AND earlier.partition_key=d.partition_key AND earlier.partition_head
  AND earlier.partition_seq<d.partition_seq)
$f$;

ALTER FUNCTION rss_transactional_messaging.outbox_candidates(uuid,text) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.claim_outbox(p_tenant uuid,p_domain text,p_limit integer,p_ttl_ms bigint)
RETURNS TABLE(seq bigint,tenant_id uuid,message_id text,domain text,partition_key text,lease_token uuid,lease_until timestamptz,envelope jsonb,fingerprint bytea,dr_operation uuid,remaining_us bigint,delivery_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE r record; o outbox; m dr_members; n timestamptz; e bigint:=nullif(current_setting('rss.execution_epoch',true),'')::bigint; l bytea:=decode(current_setting('rss.storage_lineage',true),'hex'); used integer:=0;
 observed timestamptz;
 candidates NO SCROLL CURSOR FOR
  SELECT src AS source,c.dr_operation AS op
  FROM outbox_candidates(p_tenant,p_domain) c JOIN outbox src ON src.seq=c.source_seq
  WHERE c.eligible_at<=observed ORDER BY src.seq FOR UPDATE OF src SKIP LOCKED;
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_limit IS NULL OR p_limit < 1 OR p_ttl_ms NOT BETWEEN 1 AND 9223372036854775 THEN RAISE EXCEPTION 'invalid claim' USING ERRCODE='22023'; END IF;
 -- FETCH NEXT avoids PL/pgSQL FOR's prefetch locks and never reopens an exhausted scan.
 -- ref: PostgreSQL REL_17_6 src/pl/plpgsql/src/pl_exec.c exec_stmt_fetch/exec_for_query.
 observed:=clock_timestamp();
 OPEN candidates;
 LOOP
  EXIT WHEN used>=p_limit;
  FETCH NEXT FROM candidates INTO r;
  EXIT WHEN NOT FOUND;
  o:=r.source;
  n:=clock_timestamp();
  IF r.op IS NULL THEN
   IF NOT (o.status='pending' OR (o.status='publishing' AND (o.lease_until<=n OR o.claim_epoch<>e OR o.claim_lineage IS DISTINCT FROM l))) OR o.retry_after>n THEN CONTINUE; END IF;
   UPDATE outbox src SET status='publishing',lease_token=gen_random_uuid(),lease_until=n+(p_ttl_ms::text || ' milliseconds')::interval,automatic_retry_deadline=COALESCE(src.automatic_retry_deadline,n+interval '24 hours') WHERE src.seq=o.seq RETURNING * INTO o;
  ELSE
   SELECT * INTO m FROM dr_members x WHERE x.tenant_id=p_tenant AND x.operation_id=r.op AND x.outbox_seq=o.seq FOR UPDATE;
   IF NOT FOUND OR NOT (m.status='pending' OR (m.status='publishing' AND m.lease_until<=n)) OR m.retry_after>n THEN CONTINUE; END IF;
   IF o.automatic_retry_deadline IS NULL OR o.automatic_retry_deadline<=n THEN
    UPDATE dr_members x SET status='blocked',block_reason='deadline_expired',lease_token=NULL,lease_until=NULL WHERE x.tenant_id=p_tenant AND x.operation_id=r.op AND x.outbox_seq=o.seq; CONTINUE;
   END IF;
   UPDATE dr_members x SET status='publishing',lease_token=gen_random_uuid(),lease_until=n+(p_ttl_ms::text || ' milliseconds')::interval WHERE x.tenant_id=p_tenant AND x.operation_id=r.op AND x.outbox_seq=o.seq RETURNING * INTO m;
   o.lease_token:=m.lease_token; o.lease_until:=m.lease_until;
  END IF;
  used:=used+1;
  n:=clock_timestamp();
  RETURN QUERY SELECT o.seq,o.tenant_id,o.message_id,o.domain,o.partition_key,o.lease_token,o.lease_until,o.envelope,o.fingerprint,r.op,
   greatest(0,(extract(epoch FROM o.lease_until-n)*1000000)::bigint),
   greatest(0,(extract(epoch FROM o.automatic_retry_deadline-n)*1000000)::bigint);
 END LOOP;
 CLOSE candidates;
END $f$;

ALTER FUNCTION rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.next_outbox_wakeup(p_tenant uuid,p_domain text)
RETURNS TABLE(due_now boolean,next_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE observed timestamptz;
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_domain IS NULL THEN
  RAISE EXCEPTION 'invalid wakeup scope' USING ERRCODE='22023';
 END IF;
 observed:=clock_timestamp();
 RETURN QUERY SELECT EXISTS(SELECT FROM outbox_candidates(p_tenant,p_domain) c WHERE c.eligible_at<=observed),
  (SELECT floor(extract(epoch FROM (c.eligible_at-observed))*1000000)::bigint
   FROM outbox_candidates(p_tenant,p_domain) c WHERE c.eligible_at>observed ORDER BY c.eligible_at LIMIT 1);
END $f$;

ALTER FUNCTION rss_transactional_messaging.next_outbox_wakeup(uuid,text) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.outbox_lease(p_tenant uuid,p_seq bigint,p_token uuid,p_lease_us bigint,p_extend_ms bigint,p_dr uuid)
RETURNS TABLE(lease_us bigint,remaining_us bigint,delivery_us bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE o outbox; m dr_members; n timestamptz; deadline timestamptz; e bigint:=current_setting('rss.execution_epoch')::bigint; l bytea:=decode(current_setting('rss.storage_lineage'),'hex');
BEGIN
 PERFORM check_execution();
 IF p_tenant IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid OR p_extend_ms NOT BETWEEN 0 AND 9223372036854775 THEN RETURN; END IF;
 SELECT * INTO o FROM outbox src WHERE src.seq=p_seq AND src.tenant_id=p_tenant FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 IF p_dr IS NULL THEN
  IF o.status<>'publishing' OR o.lease_token IS DISTINCT FROM p_token OR o.claim_epoch<>e OR o.claim_lineage IS DISTINCT FROM l THEN RETURN; END IF;
  deadline:=o.lease_until;
 ELSE
  SELECT x.* INTO m FROM dr_members x JOIN dr_plans p ON p.tenant_id=x.tenant_id AND p.operation_id=x.operation_id WHERE x.tenant_id=p_tenant AND x.operation_id=p_dr AND x.outbox_seq=p_seq AND p.epoch=e AND p.lineage=l FOR UPDATE OF x;
  IF NOT FOUND OR m.status<>'publishing' OR m.lease_token IS DISTINCT FROM p_token THEN RETURN; END IF;
  deadline:=m.lease_until;
 END IF;
 n:=clock_timestamp();
 IF deadline<=n OR (extract(epoch FROM deadline)*1000000)::bigint<>p_lease_us THEN RETURN; END IF;
 IF p_extend_ms>0 THEN
  deadline:=n+(p_extend_ms::text || ' milliseconds')::interval;
  IF p_dr IS NULL THEN UPDATE outbox SET lease_until=deadline WHERE outbox.seq=p_seq;
  ELSE UPDATE dr_members SET lease_until=deadline WHERE dr_members.tenant_id=p_tenant AND operation_id=p_dr AND outbox_seq=p_seq; END IF;
 END IF;
 RETURN QUERY SELECT (extract(epoch FROM deadline)*1000000)::bigint,GREATEST(0,(extract(epoch FROM deadline-n)*1000000)::bigint),GREATEST(0,(extract(epoch FROM o.automatic_retry_deadline-n)*1000000)::bigint);
END $f$;

ALTER FUNCTION rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.settle_outbox(p_tenant uuid,p_seq bigint,p_token uuid,p_lease_us bigint,p_disposition text,p_dr uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE n timestamptz; remaining bigint;
BEGIN
 SELECT delivery_us INTO remaining FROM outbox_lease(p_tenant,p_seq,p_token,p_lease_us,0,p_dr);
 IF NOT FOUND THEN RETURN 'lost_lease'; END IF;
 IF p_disposition NOT IN ('published','retry','dead_letter') THEN RAISE EXCEPTION 'invalid settlement' USING ERRCODE='22023'; END IF;
 n:=clock_timestamp();
 IF p_dr IS NULL THEN
  UPDATE outbox SET recovery_version=recovery_version+CASE WHEN p_disposition='dead_letter' THEN 1 ELSE 0 END,
   status=CASE WHEN p_disposition='retry' THEN 'pending' ELSE p_disposition END,
   retry_count=retry_count+CASE WHEN p_disposition='retry' THEN 1 ELSE 0 END,
   retry_after=CASE WHEN p_disposition='retry' THEN n+LEAST(3600,1::bigint<<LEAST(retry_count,12))*interval '1 second' ELSE retry_after END,
   lease_token=NULL,lease_until=NULL WHERE seq=p_seq AND tenant_id=p_tenant;
 ELSE
  UPDATE dr_members SET block_reason=CASE WHEN p_disposition='published' OR (p_disposition='retry' AND remaining>0) THEN NULL WHEN remaining<=0 THEN 'deadline_expired' ELSE 'permanent_publish_failure' END,
   status=CASE WHEN p_disposition='published' THEN 'completed' WHEN p_disposition='retry' AND remaining>0 THEN 'pending' ELSE 'blocked' END,
   retry_after=n+LEAST(3600,1::bigint<<LEAST(retry_count,12))*interval '1 second',retry_count=retry_count+1,
   lease_token=NULL,lease_until=NULL WHERE tenant_id=p_tenant AND operation_id=p_dr AND outbox_seq=p_seq;
 END IF;
 RETURN 'settled';
END $f$;

ALTER FUNCTION rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.archive_fence(p_op uuid,p_token uuid,p_digest bytea)
RETURNS rss_transactional_messaging.archive_jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; j archive_jobs; v bigint;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op;
 SELECT recovery_version INTO v FROM consumer_dead_letter WHERE tenant_id=t AND id=j.dead_letter_id FOR UPDATE;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 IF NOT FOUND OR j.claim_epoch<>current_setting('rss.execution_epoch')::bigint OR j.claim_lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage'),'hex') OR j.source_version<>v OR j.lease_token IS DISTINCT FROM p_token OR j.lease_until<=clock_timestamp() OR j.request_digest<>p_digest THEN RAISE EXCEPTION 'archive fenced' USING ERRCODE='PZ001'; END IF;
 RETURN j;
END $f$;

CREATE FUNCTION rss_transactional_messaging.archive_claim(p_op uuid,p_id uuid,p_version bigint,p_digest bytea,p_hot bigint,p_cold bigint,p_hold boolean,p_ttl bigint,p_scan integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; d consumer_dead_letter; j archive_jobs; p policy; a archive_objects; n timestamptz; retired jsonb;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 SELECT * INTO d FROM consumer_dead_letter WHERE tenant_id=t AND id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'archive not found' USING ERRCODE='P0002'; END IF;
 SELECT * INTO p FROM policy WHERE revision=1;
 IF p_hot<p.automatic_window_seconds+p.safety_seconds OR p_cold<=0 OR p_ttl NOT BETWEEN 1 AND 9223372036854775 OR p_scan IS NULL OR p_scan NOT BETWEEN 1 AND 1024 THEN RAISE EXCEPTION 'archive retention' USING ERRCODE='22023'; END IF;
 SELECT * INTO j FROM archive_jobs WHERE tenant_id=t AND operation_id=p_op FOR UPDATE;
 n:=clock_timestamp();
 IF FOUND THEN
  IF j.request_digest<>p_digest OR j.dead_letter_id<>p_id THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='40001'; END IF;
  IF j.source_version<>d.recovery_version THEN RAISE EXCEPTION 'archive fenced' USING ERRCODE='PZ001'; END IF;
  IF j.fault='missing' THEN RAISE EXCEPTION 'archive fault' USING ERRCODE='PZ002'; END IF;
  IF j.fault='evidence' THEN RAISE EXCEPTION 'archive fault' USING ERRCODE='PZ003'; END IF;
  IF j.lease_until>n AND j.claim_epoch=current_setting('rss.execution_epoch')::bigint AND j.claim_lineage=decode(current_setting('rss.storage_lineage'),'hex') THEN RAISE EXCEPTION 'archive leased' USING ERRCODE='55P03'; END IF;
 ELSE
  IF d.recovery_version<>p_version THEN RAISE EXCEPTION 'archive revision' USING ERRCODE='40001'; END IF;
  UPDATE consumer_dead_letter SET recovery_version=recovery_version+1 WHERE tenant_id=t AND id=p_id RETURNING * INTO d;
  UPDATE archive_jobs SET lease_until=NULL,lease_token=NULL WHERE tenant_id=t AND dead_letter_id=p_id;
  INSERT INTO archive_jobs(tenant_id,operation_id,dead_letter_id,request_digest,source_version,hot_seconds,cold_seconds,held,generation,purged)
  VALUES(t,p_op,p_id,p_digest,d.recovery_version,p_hot,p_cold,p_hold,gen_random_uuid(),d.capsule IS NULL) RETURNING * INTO j;
  -- A new operation after purge must reuse the existing durable object, never fabricate a HOT source.
  IF d.capsule IS NULL THEN
   SELECT o.* INTO a FROM archive_objects o JOIN archive_jobs old ON old.tenant_id=o.tenant_id AND old.operation_id=o.operation_id WHERE old.tenant_id=t AND old.dead_letter_id=p_id AND o.verified ORDER BY old.source_version DESC LIMIT 1;
   IF NOT FOUND THEN RAISE EXCEPTION 'archive receipt absent' USING ERRCODE='23514'; END IF;
   UPDATE archive_jobs SET generation=a.generation WHERE tenant_id=t AND operation_id=p_op RETURNING * INTO j;
  END IF;
 END IF;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=t AND generation=j.generation;
 IF d.capsule IS NOT NULL AND FOUND AND (a.object->>'retainUntil')::bigint <= extract(epoch FROM n)::bigint+greatest(p_cold,p.receipt_retention_seconds) THEN
  -- Retain coordinates but discard redundant ciphertext of expired generations.
  UPDATE archive_objects SET prepared=NULL WHERE tenant_id=t AND generation=j.generation;
  UPDATE archive_jobs SET generation=gen_random_uuid() WHERE tenant_id=t AND operation_id=p_op RETURNING * INTO j;
 END IF;
 UPDATE archive_jobs SET lease_token=gen_random_uuid(),lease_until=n+(p_ttl::text || ' milliseconds')::interval WHERE tenant_id=t AND operation_id=p_op RETURNING * INTO j;
 -- Persist rotation even when an unknown PUT remains unresolved. Every eligible row gets a turn.
 WITH batch AS (
  SELECT o.generation FROM archive_objects o JOIN archive_jobs old ON old.tenant_id=o.tenant_id AND old.operation_id=o.operation_id
  WHERE old.tenant_id=t AND old.dead_letter_id=p_id AND o.generation<>j.generation AND NOT o.reconciled
   AND (o.object->>'retainUntil')::bigint <= floor(extract(epoch FROM n))
  ORDER BY o.last_checked NULLS FIRST,o.generation LIMIT p_scan
 ), scanned AS (
  UPDATE archive_objects o SET last_checked=n FROM batch b WHERE o.tenant_id=t AND o.generation=b.generation RETURNING o.object
 ) SELECT coalesce(jsonb_agg(object),'[]'::jsonb) INTO retired FROM scanned;
 RETURN jsonb_build_object('retired',retired,'job',to_jsonb(j),'source',to_jsonb(d)-'capsule','capsule',encode(d.capsule,'hex'),'now',floor(extract(epoch FROM n))::bigint,'receipt',p.receipt_retention_seconds,'captured',floor(extract(epoch FROM d.created_at)*1000000)::bigint);
END $f$;

CREATE FUNCTION rss_transactional_messaging.archive_prepare(p_op uuid,p_token uuid,p_digest bytea,p_object jsonb,p_bytes bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 IF j.held OR j.purged OR p_object->>'key'<>'consumer/'||j.tenant_id::text||'/'||j.dead_letter_id::text||'/'||j.generation::text||'.v1.enc' OR (p_object->>'length')::bigint<>octet_length(p_bytes) THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='23514'; END IF;
 INSERT INTO archive_objects(tenant_id,operation_id,generation,object,prepared) VALUES(j.tenant_id,p_op,j.generation,p_object,p_bytes) ON CONFLICT DO NOTHING;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=j.generation;
 IF a.object<>p_object OR a.prepared IS DISTINCT FROM p_bytes THEN RAISE EXCEPTION 'archive conflict' USING ERRCODE='40001'; END IF;
END $f$;

CREATE FUNCTION rss_transactional_messaging.archive_record(p_op uuid,p_token uuid,p_digest bytea,p_generation uuid,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=p_generation FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM archive_jobs old WHERE old.tenant_id=j.tenant_id AND old.operation_id=a.operation_id AND old.dead_letter_id=j.dead_letter_id) OR j.held OR a.object-'version'-'retainUntil'<>p_object-'version'-'retainUntil' OR nullif(p_object->>'version','') IS NULL OR p_object->>'version'='null' OR (p_object->>'retainUntil')::bigint<(a.object->>'retainUntil')::bigint OR (a.verified AND a.object->>'version'<>p_object->>'version') THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='23514'; END IF;
 UPDATE archive_objects SET object=p_object,verified=true,prepared=NULL WHERE tenant_id=j.tenant_id AND generation=p_generation;
END $f$;

CREATE FUNCTION rss_transactional_messaging.archive_purge(p_op uuid,p_token uuid,p_digest bytea,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects; d consumer_dead_letter; p policy; n timestamptz;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO d FROM consumer_dead_letter WHERE tenant_id=j.tenant_id AND id=j.dead_letter_id;
 SELECT * INTO p FROM policy WHERE revision=1;
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=j.generation;
 n:=clock_timestamp();
 IF j.held OR j.fault IS NOT NULL OR NOT a.verified OR a.object IS DISTINCT FROM p_object OR j.hot_seconds<p.automatic_window_seconds+p.safety_seconds OR d.created_at+j.hot_seconds*interval '1 second'>n OR (p_object->>'retainUntil')::bigint<=extract(epoch FROM n)+greatest(j.cold_seconds,p.receipt_retention_seconds) THEN RAISE EXCEPTION 'archive unsafe purge' USING ERRCODE='23514'; END IF;
 UPDATE consumer_dead_letter SET capsule=NULL WHERE tenant_id=j.tenant_id AND id=j.dead_letter_id;
 UPDATE archive_jobs SET purged=true WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;

CREATE FUNCTION rss_transactional_messaging.archive_missing(p_op uuid,p_token uuid,p_digest bytea,p_generation uuid,p_object jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs; a archive_objects;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 SELECT * INTO a FROM archive_objects WHERE tenant_id=j.tenant_id AND generation=p_generation FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM archive_jobs old WHERE old.tenant_id=j.tenant_id AND old.operation_id=a.operation_id AND old.dead_letter_id=j.dead_letter_id) OR a.object<>p_object OR (a.object->>'retainUntil')::bigint>extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'archive unsafe reconcile' USING ERRCODE='23514'; END IF;
 UPDATE archive_objects SET reconciled=true,prepared=NULL WHERE tenant_id=j.tenant_id AND generation=p_generation;
END $f$;

CREATE FUNCTION rss_transactional_messaging.archive_fault(p_op uuid,p_token uuid,p_digest bytea,p_fault text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE j archive_jobs;
BEGIN
 PERFORM rss_transactional_messaging.check_execution();
 j:=archive_fence(p_op,p_token,p_digest);
 IF p_fault IS NULL OR p_fault NOT IN ('missing','evidence') THEN RAISE EXCEPTION 'archive invalid fault' USING ERRCODE='23514'; END IF;
 UPDATE archive_jobs SET fault=coalesce(fault,p_fault) WHERE tenant_id=j.tenant_id AND operation_id=p_op;
END $f$;

CREATE FUNCTION rss_transactional_messaging.guard_archive_generation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
BEGIN
 IF TG_TABLE_NAME='archive_jobs' THEN
  IF NEW.purged AND NOT OLD.purged AND NOT EXISTS(SELECT 1 FROM archive_objects o WHERE o.tenant_id=NEW.tenant_id AND o.generation=NEW.generation AND o.verified_epoch=current_setting('rss.execution_epoch')::bigint AND o.verified_lineage=decode(current_setting('rss.storage_lineage'),'hex')) THEN RAISE EXCEPTION 'archive evidence' USING ERRCODE='PZ003'; END IF;
 ELSE
  NEW.verified_epoch:=current_setting('rss.execution_epoch')::bigint;
  NEW.verified_lineage:=decode(current_setting('rss.storage_lineage'),'hex');
 END IF;
 RETURN NEW;
END $f$;

CREATE FUNCTION rss_transactional_messaging.apply_dr(p_operation uuid,p_digest bytea,p_kind text,p_evidence jsonb,p_members jsonb,p_expected bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; old_epoch bigint:=nullif(current_setting('rss.execution_epoch',true),'')::bigint; current_epoch bigint; s storage_lineage; prior dr_plans; target dr_plans; item jsonb; idx integer:=0; src outbox; terminal inbox; next_epoch bigint;
BEGIN
 SELECT * INTO s FROM storage_lineage WHERE singleton FOR SHARE;
 IF NOT FOUND OR s.target IS DISTINCT FROM decode(current_setting('rss.storage_target',true),'hex') OR s.lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage',true),'hex') THEN RAISE EXCEPTION 'execution fenced' USING ERRCODE='PZ001'; END IF;
 SELECT epoch INTO current_epoch FROM tenant_epoch WHERE tenant_id=t FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'execution fenced' USING ERRCODE='PZ001'; END IF;
 SELECT * INTO prior FROM dr_plans WHERE tenant_id=t AND operation_id=p_operation;
 IF FOUND THEN
  IF prior.request_digest IS DISTINCT FROM p_digest OR prior.lineage IS DISTINCT FROM s.lineage THEN RAISE EXCEPTION 'plan conflict' USING ERRCODE='23505'; END IF;
  RETURN prior.epoch;
 END IF;
 IF current_epoch IS DISTINCT FROM old_epoch OR current_epoch IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'execution fenced' USING ERRCODE='PZ001'; END IF;
 IF p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000'::uuid OR p_digest IS NULL OR octet_length(p_digest)<>32 OR p_kind IS NULL OR p_kind NOT IN ('database','broker','terminate') OR p_members IS NULL OR jsonb_typeof(p_members)<>'array' THEN RAISE EXCEPTION 'invalid plan' USING ERRCODE='22023'; END IF;
 IF p_kind='terminate' THEN
  IF jsonb_array_length(p_members)<>0 THEN RAISE EXCEPTION 'termination has members' USING ERRCODE='22023'; END IF;
  SELECT * INTO target FROM dr_plans WHERE tenant_id=t AND operation_id=(p_evidence->>'operation')::uuid;
  IF NOT FOUND THEN RAISE EXCEPTION 'target absent' USING ERRCODE='P0002'; END IF;
  IF target.kind='terminate' OR target.request_digest IS DISTINCT FROM decode(p_evidence->>'digest','hex') OR target.lineage IS DISTINCT FROM s.lineage OR target.epoch<>current_epoch THEN RAISE EXCEPTION 'termination conflict' USING ERRCODE='23505'; END IF;
 ELSIF jsonb_array_length(p_members) NOT BETWEEN 1 AND 1024 THEN
  RAISE EXCEPTION 'invalid members' USING ERRCODE='22023';
 END IF;
 next_epoch:=old_epoch+1;
 -- All ordinary workers are excluded by the tenant lock. No progress becomes visible early.
 UPDATE tenant_epoch SET epoch=next_epoch WHERE tenant_id=t;
 PERFORM set_config('rss.execution_epoch',next_epoch::text,true);
 IF p_kind='terminate' THEN
  INSERT INTO dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,target_operation,target_digest)
   VALUES(t,p_operation,p_digest,s.lineage,next_epoch,p_kind,target.operation_id,target.request_digest);
  RETURN next_epoch;
 END IF;
 INSERT INTO dr_plans(tenant_id,operation_id,request_digest,lineage,epoch,kind,evidence) VALUES(t,p_operation,p_digest,s.lineage,next_epoch,p_kind,p_evidence);
 FOR item IN SELECT value FROM jsonb_array_elements(p_members) LOOP
  IF p_kind='database' THEN
   SELECT * INTO src FROM outbox WHERE tenant_id=t AND message_id=item->>'message' FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'member absent' USING ERRCODE='P0002'; END IF;
   IF src.status<>'published' OR src.fingerprint<>decode(item->>'fingerprint','hex') OR src.recovery_version<>(item->>'version')::bigint THEN RAISE EXCEPTION 'member conflict' USING ERRCODE='23505'; END IF;
   IF src.automatic_retry_deadline IS NULL OR src.automatic_retry_deadline<=clock_timestamp() THEN RAISE EXCEPTION 'redrive expired' USING ERRCODE='PZ004'; END IF;
   INSERT INTO dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,fingerprint,outbox_seq,status) VALUES(t,p_operation,idx,src.message_id,'',src.fingerprint,src.seq,'pending');
  ELSE
   SELECT * INTO terminal FROM inbox WHERE tenant_id=t AND message_id=item->>'message' AND consumer_group=item->>'group';
   IF FOUND AND (terminal.contract<>item->>'contract' OR (terminal.fingerprint IS NOT NULL AND terminal.fingerprint<>decode(item->>'fingerprint','hex'))) THEN RAISE EXCEPTION 'consumer conflict' USING ERRCODE='23505'; END IF;
   INSERT INTO dr_members(tenant_id,operation_id,ordinal,message_id,consumer_group,contract,fingerprint,status)
    VALUES(t,p_operation,idx,item->>'message',item->>'group',item->>'contract',decode(item->>'fingerprint','hex'),CASE WHEN terminal.disposition IS NOT NULL THEN 'completed' ELSE 'pending' END);
  END IF;
  idx:=idx+1;
 END LOOP;
 RETURN next_epoch;
END $f$;

ALTER FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.read_dr(p_operation uuid,p_digest bytea)
RETURNS TABLE(epoch bigint,statuses text[],reasons text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid; prior dr_plans; s storage_lineage; e bigint;
BEGIN
 SELECT * INTO s FROM storage_lineage WHERE singleton FOR SHARE;
 IF NOT FOUND OR s.target IS DISTINCT FROM decode(current_setting('rss.storage_target',true),'hex') OR s.lineage IS DISTINCT FROM decode(current_setting('rss.storage_lineage',true),'hex') THEN RAISE EXCEPTION 'execution fenced' USING ERRCODE='PZ001'; END IF;
 SELECT x.epoch INTO e FROM tenant_epoch x WHERE x.tenant_id=t FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'execution fenced' USING ERRCODE='PZ001'; END IF;
 SELECT * INTO prior FROM dr_plans WHERE tenant_id=t AND operation_id=p_operation;
 IF NOT FOUND THEN RETURN; END IF;
 IF prior.request_digest IS DISTINCT FROM p_digest OR prior.lineage IS DISTINCT FROM s.lineage THEN RAISE EXCEPTION 'plan conflict' USING ERRCODE='23505'; END IF;
 RETURN QUERY SELECT prior.epoch,
 coalesce(array_agg(CASE WHEN m.status='completed' THEN 'completed'
  WHEN EXISTS(SELECT 1 FROM dr_plans ended WHERE ended.tenant_id=t AND ended.target_operation=prior.operation_id AND ended.target_digest=prior.request_digest AND ended.lineage=prior.lineage) THEN 'terminated'
  WHEN prior.epoch<>e THEN 'superseded' ELSE m.status END ORDER BY m.ordinal),ARRAY[]::text[]),
 coalesce(array_agg(m.block_reason ORDER BY m.ordinal),ARRAY[]::text[])
 FROM dr_members m WHERE m.tenant_id=t AND m.operation_id=p_operation;
END $f$;

ALTER FUNCTION rss_transactional_messaging.read_dr(uuid,bytea) OWNER TO rss_tmsg_relay;

CREATE FUNCTION rss_transactional_messaging.guard_dr_consumer() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE member dr_members;
BEGIN
 PERFORM check_execution();
 FOR member IN SELECT m.* FROM dr_members m JOIN dr_plans p ON p.tenant_id=m.tenant_id AND p.operation_id=m.operation_id WHERE m.tenant_id=NEW.tenant_id AND m.message_id=NEW.message_id AND m.consumer_group=NEW.consumer_group AND p.epoch=current_setting('rss.execution_epoch')::bigint AND p.lineage=decode(current_setting('rss.storage_lineage'),'hex') FOR UPDATE OF m LOOP
  IF member.contract<>NEW.contract OR (NEW.fingerprint IS NOT NULL AND member.fingerprint<>NEW.fingerprint) THEN RAISE EXCEPTION 'consumer recovery evidence' USING ERRCODE='23505'; END IF;
  IF NEW.disposition IS NOT NULL THEN UPDATE dr_members SET status='completed' WHERE tenant_id=member.tenant_id AND operation_id=member.operation_id AND ordinal=member.ordinal; END IF;
 END LOOP;
 RETURN NEW;
END $f$;

ALTER FUNCTION rss_transactional_messaging.guard_dr_consumer() OWNER TO rss_tmsg_relay;

CREATE POLICY inbox_tenant ON rss_transactional_messaging.inbox
  USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);

CREATE POLICY outbox_tenant ON rss_transactional_messaging.outbox
  USING (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid);

CREATE POLICY outbox_relay ON rss_transactional_messaging.outbox TO rss_tmsg_relay
  USING (true) WITH CHECK (true);

CREATE POLICY recovery_tenant ON rss_transactional_messaging.consumer_dead_letter USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY recovery_tenant ON rss_transactional_messaging.recovery_operations USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY archive_tenant ON rss_transactional_messaging.archive_jobs USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY archive_tenant ON rss_transactional_messaging.archive_objects USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY tenant_fence ON rss_transactional_messaging.tenant_epoch USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY dr_tenant ON rss_transactional_messaging.dr_plans USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY dr_tenant ON rss_transactional_messaging.dr_members USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY outbox_partition_tenant ON rss_transactional_messaging.outbox_partitions
 USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE POLICY inbox_consumer_scope ON rss_transactional_messaging.inbox AS RESTRICTIVE
 USING(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group))
 WITH CHECK(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group));

CREATE POLICY dead_letter_consumer_scope ON rss_transactional_messaging.consumer_dead_letter AS RESTRICTIVE
 USING(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group))
 WITH CHECK(rss_transactional_messaging.consumer_inbox_allowed(tenant_id,message_id,consumer_group));

CREATE POLICY outbox_consumer_scope ON rss_transactional_messaging.outbox AS RESTRICTIVE
 USING((domain=(SELECT rss_transactional_messaging.consumer_scope_domain())) IS NOT FALSE)
 WITH CHECK((domain=(SELECT rss_transactional_messaging.consumer_scope_domain())) IS NOT FALSE);

DO $f$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['inbox','outbox','consumer_dead_letter','recovery_operations','archive_jobs','archive_objects','dr_members'] LOOP
 EXECUTE format('CREATE TRIGGER execution_fence BEFORE INSERT OR UPDATE OR DELETE ON rss_transactional_messaging.%I FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_execution()',tab);
 END LOOP;
END $f$;

CREATE TRIGGER archive_generation BEFORE UPDATE ON rss_transactional_messaging.archive_jobs FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_archive_generation();

CREATE TRIGGER archive_generation BEFORE UPDATE OF verified ON rss_transactional_messaging.archive_objects FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_archive_generation();

CREATE TRIGGER dr_consumer AFTER INSERT OR UPDATE ON rss_transactional_messaging.inbox FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_dr_consumer();

REVOKE ALL ON ALL TABLES IN SCHEMA rss_transactional_messaging FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_transactional_messaging FROM PUBLIC;
-- Caller-scope predicates are the only public entrypoints, including inside restrictive RLS.
GRANT EXECUTE ON FUNCTION rss_transactional_messaging.consumer_scope_domain(),rss_transactional_messaging.consumer_inbox_allowed(uuid,text,text),rss_transactional_messaging.projection_scope_matches(text,text) TO PUBLIC;
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
