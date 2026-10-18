CREATE FUNCTION rss_timeseries.create_partition(lo bigint,hi bigint) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE name text:='samples_'||lo::text||'_'||hi::text; BEGIN
 IF lo<0 OR hi<=lo THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='partition bounds'; END IF;
 EXECUTE format('CREATE TABLE rss_timeseries.%I PARTITION OF rss_timeseries.samples FOR VALUES FROM (%s) TO (%s)',name,lo,hi);
 EXECUTE format('ALTER TABLE rss_timeseries.%I ENABLE ROW LEVEL SECURITY',name);
 EXECUTE format('ALTER TABLE rss_timeseries.%I FORCE ROW LEVEL SECURITY',name);
 EXECUTE format('CREATE POLICY tenant ON rss_timeseries.%I USING (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',name);
 EXECUTE format('REVOKE ALL ON rss_timeseries.%I FROM PUBLIC',name);
END $$;
