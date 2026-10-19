-- ref: timescale/timescaledb tsl/src/continuous_aggs/refresh.c@2.30.2
CREATE FUNCTION rss_timeseries.project_gauge() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
DECLARE j jsonb:=convert_from(NEW.raw,'UTF8')::jsonb;
BEGIN
 IF j#>>'{series,definition,metric,kind}'='gauge' THEN
  NEW.gauge_kind:=j#>>'{series,definition,metric,number}';
  IF NEW.gauge_kind IN ('i64','u64') AND j#>>'{reading,quality}'='valid' THEN
   NEW.gauge_value:=(j#>>'{reading,value,value,value}')::numeric;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER project_gauge BEFORE INSERT ON rss_timeseries.samples FOR EACH ROW EXECUTE FUNCTION rss_timeseries.project_gauge();
CREATE FUNCTION rss_timeseries.sync_gauge(t uuid,n text,s text,g text,d bytea,l bigint,h bigint,at_time bigint,seq numeric,ident text,cap integer)
RETURNS TABLE(observed_at bigint,sequence numeric,sample_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 RETURN QUERY UPDATE rss_timeseries.samples r SET aggregate_visible=rss_timeseries.visible(convert_from(r.raw,'UTF8')::jsonb,r.observed_at)
 WHERE (r.tenant_id,r.namespace,r.source,r.generation,r.sample_id,r.observed_at) IN
 (SELECT x.tenant_id,x.namespace,x.source,x.generation,x.sample_id,x.observed_at FROM rss_timeseries.samples x
 WHERE x.tenant_id=t AND x.namespace=n AND x.source=s AND x.generation=g AND x.series_digest=d AND x.observed_at>=l AND x.observed_at<h
 AND (at_time IS NULL OR (x.observed_at,x.sequence,x.sample_id)>(at_time,seq,ident COLLATE "C"))
 ORDER BY x.observed_at,x.sequence,x.sample_id LIMIT cap)
 RETURNING r.observed_at,r.sequence,r.sample_id;
END $$;
