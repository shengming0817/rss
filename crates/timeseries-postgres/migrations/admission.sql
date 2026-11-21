-- A single stream lock protects the receipt and all sample identity classifications.
CREATE FUNCTION rss_timeseries.admit_batch(
 t uuid, n text, s text, g text, batch_key text, batch_digest bytea,
 payloads bytea[], sample_digests bytea[], series_digests bytea[], definition_digests bytea[], horizon bigint
) RETURNS TABLE(replay boolean, received_at bigint, new_samples integer, replayed_samples integer, replay_until bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
DECLARE
 receipt rss_timeseries.batches;
 total integer := cardinality(payloads);
 added integer;
 failure text;
 received bigint;
BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 SELECT b.* INTO receipt FROM rss_timeseries.batches b
 WHERE (b.tenant_id,b.namespace,b.source,b.generation,b.batch_id)=(t,n,s,g,batch_key);
 IF FOUND THEN
  IF receipt.digest IS DISTINCT FROM batch_digest THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='batch conflict'; END IF;
  IF receipt.expired THEN RAISE EXCEPTION USING ERRCODE='TS004',MESSAGE='receipt expired'; END IF;
  replay := true;
 ELSE
  IF EXISTS(SELECT FROM rss_timeseries.streams WHERE (tenant_id,namespace,source,generation)=(t,n,s,g) AND closed)
  THEN RAISE EXCEPTION USING ERRCODE='TS004',MESSAGE='stream closed'; END IF;
  IF total IS NULL OR total NOT BETWEEN 1 AND 4096 OR cardinality(sample_digests) IS DISTINCT FROM total
     OR cardinality(series_digests) IS DISTINCT FROM total OR cardinality(definition_digests) IS DISTINCT FROM total
  THEN RAISE EXCEPTION USING ERRCODE='TS002',MESSAGE='invalid batch arrays'; END IF;
  received := floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;

  WITH decoded AS MATERIALIZED (
   SELECT u.*, convert_from(raw,'UTF8')::jsonb AS j
   FROM unnest(payloads,sample_digests,series_digests,definition_digests) WITH ORDINALITY AS u(raw,digest,series_hash,def_hash,ord)
  ), input AS MATERIALIZED (
   SELECT x.*, j->>'id' AS id, (j->>'observedAt')::bigint AS at_time,
          j#>>'{series,definition,key}' AS key, (j#>>'{series,definition,version}')::numeric AS version
   FROM decoded x
  ), locked AS MATERIALIZED (
   SELECT d.key,d.version,d.digest,convert_from(d.raw,'UTF8')::jsonb AS definition,d.retired
   FROM rss_timeseries.definitions d JOIN (SELECT DISTINCT key,version FROM input) wanted USING(key,version)
   WHERE d.tenant_id=t AND d.namespace=n ORDER BY d.key,d.version FOR SHARE OF d
  ), classified AS MATERIALIZED (
   SELECT x.*, old.sample_id IS NULL AS fresh,
    CASE
     WHEN (j#>>'{stream,scope,tenant}')::uuid IS DISTINCT FROM t
       OR j#>>'{stream,scope,namespace}' IS DISTINCT FROM n OR j#>>'{stream,source}' IS DISTINCT FROM s
       OR j#>>'{stream,generation}' IS DISTINCT FROM g THEN '42501'
     WHEN d.key IS NULL THEN 'TS002'
     WHEN d.definition=j#>'{series,definition}' AND d.digest IS DISTINCT FROM x.def_hash THEN 'TS005'
     WHEN d.digest IS DISTINCT FROM x.def_hash THEN 'TS001'
     WHEN d.definition IS DISTINCT FROM j#>'{series,definition}' THEN 'TS005'
     WHEN old.sample_id IS NOT NULL THEN CASE WHEN old.digest IS DISTINCT FROM x.digest THEN 'TS001' END
     WHEN EXISTS(SELECT FROM rss_timeseries.fences f WHERE f.tenant_id=t AND f.namespace=n
                 AND f.lo<=at_time AND f.hi>at_time AND rss_timeseries.matches(f.selection,j)) THEN 'TS004'
     WHEN d.retired THEN 'TS003'
    END AS error_code
   FROM input x LEFT JOIN locked d USING(key,version)
   LEFT JOIN rss_timeseries.sample_identities old
    ON (old.tenant_id,old.namespace,old.source,old.generation,old.sample_id)=(t,n,s,g,x.id)
  ), rejected AS MATERIALIZED (
   SELECT error_code FROM classified WHERE error_code IS NOT NULL ORDER BY ord LIMIT 1
  ), admitted AS MATERIALIZED (
   SELECT * FROM classified WHERE fresh AND NOT EXISTS(SELECT FROM rejected)
  ), identities AS (
   INSERT INTO rss_timeseries.sample_identities(tenant_id,namespace,source,generation,sample_id,digest,observed_at,received_at)
   SELECT t,n,s,g,id,digest,at_time,received FROM admitted RETURNING sample_id
  ), samples AS (
   INSERT INTO rss_timeseries.samples(tenant_id,namespace,source,generation,sample_id,observed_at,sequence,series_digest,key,version,subject,resource,raw,received_at)
   SELECT t,n,s,g,id,at_time,(j->>'sequence')::numeric,series_hash,key,version,j#>>'{series,subject}',j#>>'{series,resource}',raw,received
   FROM admitted JOIN identities ON sample_id=id RETURNING sample_id
  ), affected AS MATERIALIZED (
   SELECT DISTINCT j->'stream' AS stream,j->'series' AS series,at_time FROM admitted
  ), dirtied AS (
   UPDATE rss_timeseries.summaries m SET dirty=true WHERE m.tenant_id=t AND m.namespace=n AND NOT m.dirty
   AND EXISTS(SELECT FROM affected a WHERE m.hi>a.at_time
     AND a.stream=convert_from(m.spec,'UTF8')::jsonb->'stream' AND a.series=convert_from(m.spec,'UTF8')::jsonb->'series'
     AND rss_timeseries.affects_summary(convert_from(m.spec,'UTF8')::jsonb,m.lo,a.at_time+1))
  )
  SELECT (SELECT error_code FROM rejected),(SELECT count(*) FROM samples) INTO failure,added;
  IF failure IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE=failure,MESSAGE='batch admission failed'; END IF;
  IF added>0 THEN UPDATE rss_timeseries.streams SET revision=revision+1 WHERE (tenant_id,namespace,source,generation)=(t,n,s,g); END IF;
  INSERT INTO rss_timeseries.batches VALUES(t,n,s,g,batch_key,batch_digest,received,added,total-added,received+horizon,false)
  RETURNING * INTO receipt;
  replay := false;
 END IF;
 RETURN QUERY SELECT replay,receipt.received_at,receipt.new_samples,receipt.replayed_samples,receipt.replay_until;
END $$;
