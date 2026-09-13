-- Unverified historical messages have no trustworthy canonical input to validate or backfill.
-- Constraint validation scans all rows regardless of tenant RLS visibility.
ALTER TABLE rss_transactional_messaging.outbox ADD CONSTRAINT outbox_empty_message_upgrade CHECK(false);
ALTER TABLE rss_transactional_messaging.outbox DROP CONSTRAINT outbox_empty_message_upgrade;
GRANT CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
-- Core-owned message-wire-v1.md is the public contract. Decode authored facts first,
-- then hash the exact canonical input with PostgreSQL SHA-256. No caller digest is trusted.
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
 IF value IS NOT NULL AND (octet_length(value) NOT BETWEEN 1 AND 128 OR (value COLLATE "C") ~ '[^A-Za-z0-9_.-]') THEN
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

-- Replace the insecure signature, including all old EXECUTE grants. Provisioning must grant
-- the new signature explicitly. Transport inputs are separate and never alter authored identity.
DROP FUNCTION rss_transactional_messaging.append_outbox(text,text,text,jsonb,bytea);
CREATE FUNCTION rss_transactional_messaging.append_outbox(p_message bytea,p_transport jsonb)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_transactional_messaging,pg_temp AS $f$
DECLARE t uuid:=nullif(current_setting('rss.tenant_id',true),'')::uuid;
 ordinal bigint; persisted bytea; digest bytea; envelope jsonb; id text; domain_name text; partition_name text;
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
 END IF;
 INSERT INTO outbox(tenant_id,message_id,domain,partition_key,partition_seq,envelope,fingerprint)
  VALUES(t,id,domain_name,partition_name,ordinal,envelope,digest)
  ON CONFLICT(tenant_id,message_id) DO NOTHING RETURNING outbox.fingerprint INTO persisted;
 IF FOUND THEN RETURN 'inserted'; END IF;
 SELECT o.fingerprint INTO STRICT persisted FROM outbox o WHERE o.tenant_id=t AND o.message_id=id;
 RETURN CASE WHEN persisted=digest THEN 'already_present' ELSE 'conflict' END;
END $f$;
ALTER FUNCTION rss_transactional_messaging.read_outbox_frame(bytea,integer,integer) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.decode_outbox_message(bytea) OWNER TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.append_outbox(bytea,jsonb) OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.read_outbox_frame(bytea,integer,integer),
 rss_transactional_messaging.decode_outbox_message(bytea),rss_transactional_messaging.append_outbox(bytea,jsonb) FROM PUBLIC;

REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
