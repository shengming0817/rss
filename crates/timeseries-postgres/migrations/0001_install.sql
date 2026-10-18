-- External dedicated NOLOGIN NOSUPERUSER NOBYPASSRLS owner executes this once.
CREATE SCHEMA rss_timeseries;
DO $$ BEGIN EXECUTE format('COMMENT ON SCHEMA rss_timeseries IS %L', 'rss-timeseries-postgres:3:' || gen_random_uuid()::text); END $$;
CREATE TABLE rss_timeseries.definition_heads (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, key text COLLATE "C" NOT NULL,
 version numeric(20,0), PRIMARY KEY (tenant_id,namespace,key),
 CHECK (version BETWEEN 1 AND 18446744073709551615)
);
CREATE TABLE rss_timeseries.definitions (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, key text COLLATE "C" NOT NULL,
 version numeric(20,0) NOT NULL CHECK (version BETWEEN 1 AND 18446744073709551615),
 raw bytea NOT NULL, digest bytea NOT NULL CHECK (octet_length(digest)=32), retired boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id,namespace,key,version),
 FOREIGN KEY (tenant_id,namespace,key) REFERENCES rss_timeseries.definition_heads
);
CREATE TABLE rss_timeseries.streams (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL,
 closed boolean NOT NULL DEFAULT false, reclaimed boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id,namespace,source,generation)
);
CREATE TABLE rss_timeseries.batches (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, batch_id text COLLATE "C" NOT NULL,
 digest bytea NOT NULL CHECK (octet_length(digest)=32), received_at bigint NOT NULL CHECK (received_at>=0),
 new_samples integer NOT NULL CHECK (new_samples>=0), replayed_samples integer NOT NULL CHECK (replayed_samples>=0),
 replay_until bigint NOT NULL CHECK (replay_until>received_at),
 expired boolean NOT NULL DEFAULT false,
 CHECK (new_samples+replayed_samples BETWEEN 1 AND 4096),
 PRIMARY KEY (tenant_id,namespace,source,generation,batch_id),
 FOREIGN KEY (tenant_id,namespace,source,generation) REFERENCES rss_timeseries.streams
);
CREATE TABLE rss_timeseries.sample_identities (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, sample_id text COLLATE "C" NOT NULL,
 digest bytea NOT NULL CHECK (octet_length(digest)=32), observed_at bigint NOT NULL CHECK (observed_at BETWEEN 0 AND 9223372036854775806),
 received_at bigint NOT NULL CHECK (received_at>=0),
 PRIMARY KEY (tenant_id,namespace,source,generation,sample_id),
 UNIQUE (tenant_id,namespace,source,generation,sample_id,observed_at),
 FOREIGN KEY (tenant_id,namespace,source,generation) REFERENCES rss_timeseries.streams
);
CREATE TABLE rss_timeseries.samples (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, sample_id text COLLATE "C" NOT NULL,
 observed_at bigint NOT NULL, sequence numeric(20,0) NOT NULL CHECK (sequence BETWEEN 0 AND 18446744073709551615),
 series_digest bytea NOT NULL CHECK (octet_length(series_digest)=32),
 key text COLLATE "C" NOT NULL, version numeric(20,0) NOT NULL,
 subject text COLLATE "C" NOT NULL, resource text COLLATE "C" NOT NULL,
 raw bytea NOT NULL CHECK (octet_length(raw) BETWEEN 1 AND 4194304), received_at bigint NOT NULL CHECK (received_at>=0),
 PRIMARY KEY (tenant_id,namespace,source,generation,sample_id,observed_at),
 FOREIGN KEY (tenant_id,namespace,source,generation,sample_id,observed_at) REFERENCES rss_timeseries.sample_identities(tenant_id,namespace,source,generation,sample_id,observed_at),
 FOREIGN KEY (tenant_id,namespace,key,version) REFERENCES rss_timeseries.definitions
) PARTITION BY RANGE (observed_at);
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
CREATE FUNCTION rss_timeseries.lock_definition(t uuid,n text,k text,v numeric) RETURNS SETOF rss_timeseries.definitions
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='tenant'; END IF;
 RETURN QUERY SELECT * FROM rss_timeseries.definitions WHERE tenant_id=t AND namespace=n AND key=k AND version=v FOR SHARE;
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
  INSERT INTO rss_timeseries.definitions VALUES(t,n,k,v,b,d,false);
  UPDATE rss_timeseries.definition_heads SET version=v WHERE tenant_id=t AND namespace=n AND key=k;
 END IF;
END $$;
-- Semantic validation is the trusted Rust provider's responsibility. SQL owns immutable identities,
-- RLS, exact-definition references and the transaction. No client receives these credentials.
-- Owner-only explicit bounded partition provisioning. No data-moving fallback/default partition.
CREATE FUNCTION rss_timeseries.create_partition(lo bigint,hi bigint) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE name text:='samples_'||lo::text||'_'||hi::text; BEGIN
 IF lo<0 OR hi<=lo THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='partition bounds'; END IF;
 EXECUTE format('CREATE TABLE rss_timeseries.%I PARTITION OF rss_timeseries.samples FOR VALUES FROM (%s) TO (%s)',name,lo,hi);
 EXECUTE format('ALTER TABLE rss_timeseries.%I ENABLE ROW LEVEL SECURITY',name);
 EXECUTE format('ALTER TABLE rss_timeseries.%I FORCE ROW LEVEL SECURITY',name);
 EXECUTE format('CREATE POLICY tenant ON rss_timeseries.%I USING (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',name);
 EXECUTE format('REVOKE ALL ON rss_timeseries.%I FROM PUBLIC',name);
END $$;
CREATE TABLE rss_timeseries.namespaces (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 PRIMARY KEY(tenant_id,namespace)
);
CREATE TABLE rss_timeseries.fences (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, id text COLLATE "C" NOT NULL,
 kind text NOT NULL CHECK(kind IN ('cutoff','delete','pruned')), selection jsonb NOT NULL,
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
 spec bytea NOT NULL, lo bigint NOT NULL, hi bigint NOT NULL CHECK(hi>lo AND lo>=0),
 dirty boolean NOT NULL DEFAULT false, data bytea NOT NULL,
 PRIMARY KEY(tenant_id,namespace,spec_digest,lo)
);
CREATE INDEX summaries_semantics ON rss_timeseries.summaries(tenant_id,namespace,semantics,lo,hi);
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
CREATE FUNCTION rss_timeseries.read_namespace(t uuid,n text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='tenant'; END IF;
 PERFORM 1 FROM rss_timeseries.namespaces WHERE tenant_id=t AND namespace=n FOR SHARE;
END $$;
CREATE FUNCTION rss_timeseries.lock_stream(t uuid,n text,s text,g text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
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
CREATE FUNCTION rss_timeseries.visible(j jsonb,at_time bigint) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
 SELECT NOT EXISTS(SELECT FROM rss_timeseries.fences f WHERE f.tenant_id=(j#>>'{stream,scope,tenant}')::uuid AND f.namespace=j#>>'{stream,scope,namespace}'
 AND (f.kind='pruned' OR (f.kind='delete' AND NOT f.restored)) AND f.lo<=at_time AND f.hi>at_time AND rss_timeseries.matches(f.selection,j))
$$;
CREATE FUNCTION rss_timeseries.invalidate(t uuid,n text,sel jsonb,lo_time bigint,hi_time bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 UPDATE rss_timeseries.namespaces SET revision=revision+1 WHERE tenant_id=t AND namespace=n;
 UPDATE rss_timeseries.summaries SET dirty=true WHERE tenant_id=t AND namespace=n AND hi>lo_time
 AND ((convert_from(spec,'UTF8')::jsonb#>>'{series,definition,metric,kind}' IN ('bool','state') AND convert_from(spec,'UTF8')::jsonb#>>'{coverage,coverage}'='observedOnly') OR lo::numeric < hi_time::numeric + coalesce((convert_from(spec,'UTF8')::jsonb->>'maxGap')::numeric,(convert_from(spec,'UTF8')::jsonb#>>'{coverage,maxHoldMicros}')::numeric,0))
 AND rss_timeseries.matches(sel,convert_from(spec,'UTF8')::jsonb);
END $$;
CREATE FUNCTION rss_timeseries.put_plan(t uuid,n text,i text,b bytea,s bytea,d boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 IF EXISTS(SELECT FROM rss_timeseries.plans WHERE tenant_id=t AND namespace=n AND id=i AND binding<>b) THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='plan conflict'; END IF;
 INSERT INTO rss_timeseries.plans VALUES(t,n,i,b,s,d) ON CONFLICT(tenant_id,namespace,id) DO UPDATE SET state=excluded.state,done=excluded.done;
END $$;
CREATE FUNCTION rss_timeseries.put_fence(t uuid,n text,i text,k text,sel jsonb,l bigint,h bigint,u bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 IF EXISTS(SELECT FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND id=i) THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='fence conflict'; END IF;
 IF k IN ('cutoff','pruned') THEN
  SELECT greatest(h,coalesce(max(hi),h)) INTO h FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND kind=k AND selection=sel;
  DELETE FROM rss_timeseries.fences WHERE tenant_id=t AND namespace=n AND kind=k AND selection=sel;
 END IF;
 INSERT INTO rss_timeseries.fences VALUES(t,n,i,k,sel,l,h,u,false);
 IF k='delete' THEN PERFORM rss_timeseries.invalidate(t,n,sel,l,h); END IF;
END $$;
CREATE FUNCTION rss_timeseries.restore_fence(t uuid,n text,i text,sel jsonb,l bigint,h bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 UPDATE rss_timeseries.fences SET restored=true WHERE tenant_id=t AND namespace=n AND id=i AND kind='delete' AND selection=sel AND lo=l AND hi=h AND NOT restored AND restore_until>floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='TS004',MESSAGE='restore unavailable'; END IF;
 PERFORM rss_timeseries.invalidate(t,n,sel,l,h);
END $$;
CREATE FUNCTION rss_timeseries.put_summary(t uuid,n text,d bytea,m bytea,s bytea,l bigint,h bigint,b bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 INSERT INTO rss_timeseries.summaries VALUES(t,n,d,m,s,l,h,false,b) ON CONFLICT(tenant_id,namespace,spec_digest,lo) DO UPDATE SET hi=excluded.hi,data=excluded.data,dirty=false;
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
CREATE FUNCTION rss_timeseries.put_sample(b bytea,d bytea,sd bytea,received bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$
DECLARE j jsonb:=convert_from(b,'UTF8')::jsonb; t uuid:=(j#>>'{stream,scope,tenant}')::uuid;
 n text:=j#>>'{stream,scope,namespace}'; s text:=j#>>'{stream,source}'; g text:=j#>>'{stream,generation}';
 i text:=j->>'id'; old rss_timeseries.sample_identities; def rss_timeseries.definitions;
BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 SELECT * INTO old FROM rss_timeseries.sample_identities WHERE tenant_id=t AND namespace=n AND source=s AND generation=g AND sample_id=i;
 IF FOUND THEN
  IF old.digest<>d THEN RAISE EXCEPTION USING ERRCODE='TS001',MESSAGE='sample conflict'; END IF;
  RETURN false;
 END IF;
 IF EXISTS(SELECT FROM rss_timeseries.streams WHERE tenant_id=t AND namespace=n AND source=s AND generation=g AND closed)
 OR EXISTS(SELECT FROM rss_timeseries.fences f WHERE f.tenant_id=t AND f.namespace=n AND f.lo<=(j->>'observedAt')::bigint AND f.hi>(j->>'observedAt')::bigint AND rss_timeseries.matches(f.selection,j))
 THEN RAISE EXCEPTION USING ERRCODE='TS004',MESSAGE='input fenced'; END IF;
 SELECT * INTO def FROM rss_timeseries.lock_definition(t,n,j#>>'{series,definition,key}',(j#>>'{series,definition,version}')::numeric);
 IF NOT FOUND OR convert_from(def.raw,'UTF8')::jsonb<>j#>'{series,definition}' THEN RAISE EXCEPTION USING ERRCODE='TS002',MESSAGE='definition missing'; END IF;
 IF def.retired THEN RAISE EXCEPTION USING ERRCODE='TS003',MESSAGE='definition retired'; END IF;
 INSERT INTO rss_timeseries.sample_identities VALUES(t,n,s,g,i,d,(j->>'observedAt')::bigint,received);
 INSERT INTO rss_timeseries.samples VALUES(t,n,s,g,i,(j->>'observedAt')::bigint,(j->>'sequence')::numeric,sd,
 j#>>'{series,definition,key}',(j#>>'{series,definition,version}')::numeric,j#>>'{series,subject}',j#>>'{series,resource}',b,received);
 PERFORM rss_timeseries.invalidate(t,n,jsonb_build_object('selection','exact','stream',j->'stream','series',j->'series'),(j->>'observedAt')::bigint,(j->>'observedAt')::bigint+1);
 RETURN true;
END $$;
CREATE FUNCTION rss_timeseries.put_batch(t uuid,n text,s text,g text,i text,d bytea,received bigint,added integer,replayed integer,until_time bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 INSERT INTO rss_timeseries.batches VALUES(t,n,s,g,i,d,received,added,replayed,until_time,false);
END $$;
CREATE FUNCTION rss_timeseries.prune_rows(t uuid,n text,sel jsonb,r bigint,s bigint,cap integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ DECLARE total integer:=0; changed integer; BEGIN
 PERFORM rss_timeseries.lock_namespace(t,n);
 DELETE FROM rss_timeseries.samples WHERE (tenant_id,namespace,source,generation,sample_id,observed_at) IN
 (SELECT tenant_id,namespace,source,generation,sample_id,observed_at FROM rss_timeseries.samples WHERE tenant_id=t AND namespace=n AND observed_at<r AND rss_timeseries.matches(sel,convert_from(raw,'UTF8')::jsonb) ORDER BY observed_at,source,generation,sample_id LIMIT cap);
 GET DIAGNOSTICS changed=ROW_COUNT; total:=total+changed;
 DELETE FROM rss_timeseries.summaries WHERE (tenant_id,namespace,spec_digest,lo) IN
 (SELECT tenant_id,namespace,spec_digest,lo FROM rss_timeseries.summaries WHERE tenant_id=t AND namespace=n AND hi<=s AND rss_timeseries.matches(sel,convert_from(spec,'UTF8')::jsonb) ORDER BY lo,spec_digest LIMIT greatest(cap-total,0));
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
