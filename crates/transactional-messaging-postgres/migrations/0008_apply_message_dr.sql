-- Dedicated DR operator entrypoints. External migrator grants these only to the DR operator.
GRANT USAGE,CREATE ON SCHEMA rss_transactional_messaging TO rss_tmsg_relay;
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
 ELSIF jsonb_array_length(p_members) NOT BETWEEN 1 AND 500 THEN
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
-- Narrow definer must only see the requested tenant, including Inbox terminal evidence.
GRANT SELECT ON rss_transactional_messaging.inbox TO rss_tmsg_relay;
ALTER FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) OWNER TO rss_tmsg_relay;
REVOKE ALL ON FUNCTION rss_transactional_messaging.apply_dr(uuid,bytea,text,jsonb,jsonb,bigint) FROM PUBLIC;

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
REVOKE ALL ON FUNCTION rss_transactional_messaging.read_dr(uuid,bytea) FROM PUBLIC;

-- Consumer completion and evidence checking are part of the encompassing effect transaction.
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
REVOKE ALL ON FUNCTION rss_transactional_messaging.guard_dr_consumer() FROM PUBLIC;
CREATE TRIGGER dr_consumer AFTER INSERT OR UPDATE ON rss_transactional_messaging.inbox FOR EACH ROW EXECUTE FUNCTION rss_transactional_messaging.guard_dr_consumer();
REVOKE CREATE ON SCHEMA rss_transactional_messaging FROM rss_tmsg_relay;
