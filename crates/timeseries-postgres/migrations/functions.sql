CREATE INDEX batches_expiry ON rss_timeseries.batches
 (tenant_id,namespace,source,generation,received_at,batch_id) WHERE NOT expired;
CREATE INDEX batches_replay ON rss_timeseries.batches
 (tenant_id,namespace,source,generation,replay_until) INCLUDE (received_at) WHERE NOT expired;
CREATE INDEX samples_history ON rss_timeseries.samples(tenant_id,namespace,series_digest,source,generation,observed_at,sequence,sample_id);
CREATE INDEX samples_resource ON rss_timeseries.samples(tenant_id,namespace,subject,resource,key,observed_at);
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['definition_heads','definitions','streams','batches','sample_identities','samples'] LOOP
  EXECUTE format('ALTER TABLE rss_timeseries.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE rss_timeseries.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY tenant ON rss_timeseries.%I USING (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n);
 END LOOP;
END $$;
CREATE FUNCTION rss_timeseries.lock_key(t uuid,n text,k text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='tenant'; END IF;
 INSERT INTO rss_timeseries.definition_heads(tenant_id,namespace,key) VALUES(t,n,k) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM rss_timeseries.definition_heads WHERE tenant_id=t AND namespace=n AND key=k FOR UPDATE;
END $$;
CREATE FUNCTION rss_timeseries.put_definition(t uuid,n text,k text,v numeric,b bytea,d bytea,retire boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE prior rss_timeseries.definitions; BEGIN
 PERFORM rss_timeseries.lock_key(t,n,k);
 SELECT * INTO prior FROM rss_timeseries.definitions WHERE tenant_id=t AND namespace=n AND key=k AND version=v FOR UPDATE;
 IF FOUND THEN
  IF prior.digest<>d OR prior.raw<>b THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='definition conflict'; END IF;
  IF retire THEN UPDATE rss_timeseries.definitions SET retired=true WHERE tenant_id=t AND namespace=n AND key=k AND version=v; END IF;
 ELSE
  IF retire THEN RAISE EXCEPTION USING ERRCODE='TS002',MESSAGE='definition missing'; END IF;
  INSERT INTO rss_timeseries.namespaces(tenant_id,namespace) VALUES(t,n) ON CONFLICT DO NOTHING;
  INSERT INTO rss_timeseries.definitions VALUES(t,n,k,v,b,d,false);
  UPDATE rss_timeseries.definition_heads SET version=v WHERE tenant_id=t AND namespace=n AND key=k;
 END IF;
END $$;
-- Semantic validation is the trusted Rust provider's responsibility. SQL owns immutable identities,
-- RLS, exact-definition references and the transaction. No client receives these credentials.
-- Owner-only explicit bounded partition provisioning. No data-moving fallback/default partition.
CREATE TABLE rss_timeseries.namespaces (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 PRIMARY KEY(tenant_id,namespace)
);
CREATE TABLE rss_timeseries.fences (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, id text COLLATE "C" NOT NULL,
 kind text NOT NULL CHECK(kind IN ('cutoff','delete','pruned')), selection jsonb NOT NULL,
 series_digest bytea, CHECK ((selection->>'selection'='exact') = (series_digest IS NOT NULL)),
 CHECK (octet_length(series_digest)=32),
 lo bigint NOT NULL CHECK(lo>=0), hi bigint NOT NULL CHECK(hi>=lo), restore_until bigint,
 restored boolean NOT NULL DEFAULT false, PRIMARY KEY(tenant_id,namespace,id)
);
CREATE INDEX fences_range ON rss_timeseries.fences(tenant_id,namespace,lo,hi);
CREATE TABLE rss_timeseries.plans (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, id text COLLATE "C" NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding)=32), state bytea NOT NULL,
 done boolean NOT NULL DEFAULT false, PRIMARY KEY(tenant_id,namespace,id)
);
CREATE TABLE rss_timeseries.summary_ranges (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 spec_digest bytea NOT NULL CHECK(octet_length(spec_digest)=32), spec bytea NOT NULL,
 lo bigint NOT NULL, hi bigint NOT NULL CHECK(hi>lo AND lo>=0),
 PRIMARY KEY(tenant_id,namespace,spec_digest,lo,hi)
);
CREATE TABLE rss_timeseries.summaries (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 spec_digest bytea NOT NULL CHECK(octet_length(spec_digest)=32), semantics bytea NOT NULL CHECK(octet_length(semantics)=32),
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL,
 series_digest bytea NOT NULL CHECK(octet_length(series_digest)=32),
 subject text COLLATE "C" NOT NULL, resource text COLLATE "C" NOT NULL, key text COLLATE "C" NOT NULL,
 lo bigint NOT NULL, hi bigint NOT NULL CHECK(hi>lo AND lo>=0),
 impact int8range NOT NULL CHECK(NOT isempty(impact) AND NOT lower_inf(impact) AND NOT upper_inf(impact)
                                AND lower(impact) BETWEEN 0 AND lo AND upper(impact)=hi),
 dirty boolean NOT NULL DEFAULT false, data bytea NOT NULL,
 PRIMARY KEY(tenant_id,namespace,spec_digest,lo)
);
CREATE INDEX summaries_semantics ON rss_timeseries.summaries(tenant_id,namespace,semantics,lo,hi DESC) WHERE NOT dirty;
CREATE INDEX summaries_stream ON rss_timeseries.summaries
 (tenant_id,namespace,source,generation,series_digest) WHERE NOT dirty;
CREATE INDEX summaries_impact ON rss_timeseries.summaries USING gist (impact) WHERE NOT dirty;
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['namespaces','fences','plans','summary_ranges','summaries'] LOOP
  EXECUTE format('ALTER TABLE rss_timeseries.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE rss_timeseries.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY tenant ON rss_timeseries.%I USING (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',n);
 END LOOP;
END $$;
CREATE FUNCTION rss_timeseries.lock_namespace(t uuid,n text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE r bigint; BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='tenant'; END IF;
 INSERT INTO rss_timeseries.namespaces(tenant_id,namespace) VALUES(t,n) ON CONFLICT DO NOTHING;
 SELECT revision INTO r FROM rss_timeseries.namespaces WHERE tenant_id=t AND namespace=n FOR UPDATE;
 RETURN r;
END $$;
CREATE FUNCTION rss_timeseries.lock_stream(t uuid,n text,s text,g text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='tenant'; END IF;
 INSERT INTO rss_timeseries.namespaces(tenant_id,namespace) VALUES(t,n) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM rss_timeseries.namespaces WHERE tenant_id=t AND namespace=n FOR SHARE;
 INSERT INTO rss_timeseries.streams(tenant_id,namespace,source,generation) VALUES(t,n,s,g) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM rss_timeseries.streams WHERE tenant_id=t AND namespace=n AND source=s AND generation=g FOR UPDATE;
END $$;
CREATE FUNCTION rss_timeseries.matches(sel jsonb,j jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
 SELECT CASE sel->>'selection'
 WHEN 'exact' THEN sel->'stream'=j->'stream' AND sel->'series'=j->'series'
 WHEN 'resource' THEN sel->'scope'=j#>'{stream,scope}' AND sel->>'subject'=j#>>'{series,subject}' AND sel->>'resource'=j#>>'{series,resource}'
 AND (jsonb_array_length(sel->'keys')=0 OR (sel->'keys') ? (j#>>'{series,definition,key}'))
 ELSE false END
$$;
CREATE FUNCTION rss_timeseries.overlaps(a jsonb,b jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
 SELECT CASE WHEN a->>'selection'='exact' THEN rss_timeseries.matches(b,a)
 WHEN b->>'selection'='exact' THEN rss_timeseries.matches(a,b)
 ELSE a->'scope'=b->'scope' AND a->>'subject'=b->>'subject' AND a->>'resource'=b->>'resource'
 AND (jsonb_array_length(a->'keys')=0 OR jsonb_array_length(b->'keys')=0 OR (a->'keys') ?| ARRAY(SELECT jsonb_array_elements_text(b->'keys'))) END
$$;
-- Compare a trusted selector to the same structured columns on samples and summaries.
CREATE FUNCTION rss_timeseries.matches_row(sel jsonb,wanted bytea,t uuid,n text,s text,g text,d bytea,sub text,res text,k text)
RETURNS boolean LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
 SELECT CASE sel->>'selection'
 WHEN 'exact' THEN (s,g,d)=(sel#>>'{stream,source}',sel#>>'{stream,generation}',wanted)
   AND (t::text,n)=(sel#>>'{stream,scope,tenant}',sel#>>'{stream,scope,namespace}')
 WHEN 'resource' THEN (t::text,n,sub,res)=(sel#>>'{scope,tenant}',sel#>>'{scope,namespace}',sel->>'subject',sel->>'resource')
   AND (jsonb_array_length(sel->'keys')=0 OR (sel->'keys') ? k)
 ELSE false END
$$;
CREATE FUNCTION rss_timeseries.visible(t uuid,n text,s text,g text,d bytea,sub text,res text,k text,at_time bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
 SELECT NOT EXISTS(SELECT FROM rss_timeseries.fences f WHERE f.tenant_id=t AND f.namespace=n
 AND (f.kind='pruned' OR (f.kind='delete' AND NOT f.restored)) AND f.lo<=at_time AND f.hi>at_time
 AND rss_timeseries.matches_row(f.selection,f.series_digest,t,n,s,g,d,sub,res,k))
$$;
CREATE FUNCTION rss_timeseries.invalidate(t uuid,n text,sel jsonb,wanted bytea,lo_time bigint,hi_time bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 UPDATE rss_timeseries.namespaces SET revision=revision+1 WHERE tenant_id=t AND namespace=n;
 IF sel->>'selection'='exact' AND (t::text,n)=(sel#>>'{stream,scope,tenant}',sel#>>'{stream,scope,namespace}') THEN
  UPDATE rss_timeseries.summaries SET dirty=true WHERE tenant_id=t AND namespace=n AND NOT dirty
   AND impact && int8range(lo_time,hi_time,'[)') AND (source,generation,series_digest)=(sel#>>'{stream,source}',sel#>>'{stream,generation}',wanted);
 ELSIF sel->>'selection'='resource' AND (t::text,n)=(sel#>>'{scope,tenant}',sel#>>'{scope,namespace}') THEN
  UPDATE rss_timeseries.summaries SET dirty=true WHERE tenant_id=t AND namespace=n AND NOT dirty
   AND impact && int8range(lo_time,hi_time,'[)') AND (subject,resource)=(sel->>'subject',sel->>'resource')
     AND (jsonb_array_length(sel->'keys')=0 OR (sel->'keys') ? key);
 END IF;
END $$;
CREATE FUNCTION rss_timeseries.put_plan(t uuid,n text,i text,b bytea,s bytea,d boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 IF EXISTS(SELECT FROM rss_timeseries.plans WHERE tenant_id=t AND namespace=n AND id=i AND binding<>b) THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='plan conflict'; END IF;
 INSERT INTO rss_timeseries.plans VALUES(t,n,i,b,s,d) ON CONFLICT(tenant_id,namespace,id) DO UPDATE SET state=excluded.state,done=excluded.done;
END $$;
CREATE FUNCTION rss_timeseries.put_fence(t uuid,n text,i text,k text,sel jsonb,l bigint,h bigint,u bigint,wanted bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 IF EXISTS(SELECT FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND id=i) THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='fence conflict'; END IF;
 IF k IN ('cutoff','pruned') THEN
  SELECT greatest(h,coalesce(max(hi),h)) INTO h FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND kind=k AND selection=sel;
  DELETE FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND kind=k AND selection=sel;
 END IF;
 INSERT INTO rss_timeseries.fences VALUES(t,n,i,k,sel,wanted,l,h,u,false);
 IF k='delete' THEN
  PERFORM rss_timeseries.invalidate(t,n,sel,wanted,l,h);
 ELSIF k='pruned' THEN
  -- In-flight folds must recheck raw availability; retained materialized summaries stay valid.
  UPDATE rss_timeseries.namespaces SET revision=revision+1 WHERE tenant_id=t AND namespace=n;
 END IF;
END $$;
CREATE FUNCTION rss_timeseries.restore_fence(t uuid,n text,i text,sel jsonb,l bigint,h bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE wanted bytea; BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 UPDATE rss_timeseries.fences SET restored=true WHERE tenant_id=t AND namespace=n AND id=i AND kind='delete' AND selection=sel AND lo=l AND hi=h AND NOT restored AND restore_until>floor(extract(epoch FROM clock_timestamp())*1000000)::bigint RETURNING series_digest INTO wanted;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='TS004',MESSAGE='restore unavailable'; END IF;
 PERFORM rss_timeseries.invalidate(t,n,sel,wanted,l,h);
END $$;
CREATE FUNCTION rss_timeseries.put_summary(t uuid,n text,d bytea,m bytea,s text,g text,series bytea,sub text,res text,k text,l bigint,h bigint,impact_lo bigint,b bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 INSERT INTO rss_timeseries.summaries VALUES(t,n,d,m,s,g,series,sub,res,k,l,h,int8range(impact_lo,h,'[)'),false,b) ON CONFLICT(tenant_id,namespace,spec_digest,lo) DO UPDATE SET hi=excluded.hi,impact=excluded.impact,data=excluded.data,dirty=false;
END $$;
CREATE FUNCTION rss_timeseries.register_summary(t uuid,n text,d bytea,s bytea,l bigint,h bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 INSERT INTO rss_timeseries.summary_ranges VALUES(t,n,d,s,l,h) ON CONFLICT DO NOTHING;
END $$;
CREATE FUNCTION rss_timeseries.close_stream(t uuid,n text,s text,g text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 UPDATE rss_timeseries.streams SET closed=true WHERE tenant_id=t AND namespace=n AND source=s AND generation=g;
END $$;
CREATE FUNCTION rss_timeseries.prune_rows(t uuid,n text,sel jsonb,r bigint,s bigint,cap integer,wanted bytea) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE total integer:=0; changed integer; BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 WITH scoped AS NOT MATERIALIZED (
  SELECT * FROM rss_timeseries.samples WHERE tenant_id=t AND namespace=n AND observed_at<r
 ), victims AS (
  SELECT tenant_id,namespace,source,generation,sample_id,observed_at FROM scoped WHERE sel->>'selection'='exact' AND (t::text,n)=(sel#>>'{stream,scope,tenant}',sel#>>'{stream,scope,namespace}')
   AND (source,generation,series_digest)=(sel#>>'{stream,source}',sel#>>'{stream,generation}',wanted)
  UNION ALL
  SELECT tenant_id,namespace,source,generation,sample_id,observed_at FROM scoped WHERE sel->>'selection'='resource' AND (t::text,n)=(sel#>>'{scope,tenant}',sel#>>'{scope,namespace}')
   AND (subject,resource)=(sel->>'subject',sel->>'resource')
     AND (jsonb_array_length(sel->'keys')=0 OR (sel->'keys') ? key)
  ORDER BY observed_at,source,generation,sample_id LIMIT cap
 )
 DELETE FROM rss_timeseries.samples WHERE (tenant_id,namespace,source,generation,sample_id,observed_at) IN (SELECT * FROM victims);
 GET DIAGNOSTICS changed=ROW_COUNT; total:=total+changed;
 WITH scoped AS NOT MATERIALIZED (
  SELECT * FROM rss_timeseries.summaries WHERE tenant_id=t AND namespace=n AND hi<=s
 ), victims AS (
  SELECT tenant_id,namespace,spec_digest,lo FROM scoped WHERE sel->>'selection'='exact' AND (t::text,n)=(sel#>>'{stream,scope,tenant}',sel#>>'{stream,scope,namespace}')
   AND (source,generation,series_digest)=(sel#>>'{stream,source}',sel#>>'{stream,generation}',wanted)
  UNION ALL
  SELECT tenant_id,namespace,spec_digest,lo FROM scoped WHERE sel->>'selection'='resource' AND (t::text,n)=(sel#>>'{scope,tenant}',sel#>>'{scope,namespace}')
   AND (subject,resource)=(sel->>'subject',sel->>'resource')
     AND (jsonb_array_length(sel->'keys')=0 OR (sel->'keys') ? key)
  ORDER BY lo,spec_digest LIMIT greatest(cap-total,0)
 )
 DELETE FROM rss_timeseries.summaries WHERE (tenant_id,namespace,spec_digest,lo) IN (SELECT * FROM victims);
 GET DIAGNOSTICS changed=ROW_COUNT; total:=total+changed;
 DELETE FROM rss_timeseries.fences WHERE (tenant_id,namespace,id) IN
 (SELECT tenant_id,namespace,id FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND kind='delete' AND selection=sel AND hi<=r AND (restored OR restore_until<=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint) ORDER BY id LIMIT greatest(cap-total,0));
 GET DIAGNOSTICS changed=ROW_COUNT; total:=total+changed;
 RETURN total;
END $$;
CREATE FUNCTION rss_timeseries.expire_receipts(t uuid,n text,s text,g text,b bigint,cap integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE changed integer; BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 UPDATE rss_timeseries.batches SET expired=true WHERE (tenant_id,namespace,source,generation,batch_id) IN
 (SELECT tenant_id,namespace,source,generation,batch_id FROM rss_timeseries.batches WHERE tenant_id=t AND namespace=n AND source=s AND generation=g AND received_at<b AND replay_until<=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint AND NOT expired ORDER BY received_at,batch_id LIMIT cap);
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed;
END $$;
CREATE FUNCTION rss_timeseries.reclaim_rows(t uuid,n text,s text,g text,cap integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE total integer:=0; changed integer; BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 IF NOT EXISTS(SELECT FROM rss_timeseries.streams WHERE tenant_id=t AND namespace=n AND source=s AND generation=g AND closed) THEN RAISE EXCEPTION USING ERRCODE='TS004',MESSAGE='stream open'; END IF;
 DELETE FROM rss_timeseries.batches WHERE (tenant_id,namespace,source,generation,batch_id) IN
 (SELECT tenant_id,namespace,source,generation,batch_id FROM rss_timeseries.batches WHERE tenant_id=t AND namespace=n AND source=s AND generation=g ORDER BY batch_id LIMIT cap);
 GET DIAGNOSTICS changed=ROW_COUNT; total:=total+changed;
 DELETE FROM rss_timeseries.sample_identities WHERE (tenant_id,namespace,source,generation,sample_id) IN
 (SELECT tenant_id,namespace,source,generation,sample_id FROM rss_timeseries.sample_identities WHERE tenant_id=t AND namespace=n AND source=s AND generation=g ORDER BY sample_id LIMIT greatest(cap-total,0));
 GET DIAGNOSTICS changed=ROW_COUNT; total:=total+changed;
 UPDATE rss_timeseries.streams SET reclaimed=true WHERE tenant_id=t AND namespace=n AND source=s AND generation=g;
 RETURN total;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_timeseries FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_timeseries FROM PUBLIC;
