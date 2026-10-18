-- External dedicated NOLOGIN NOSUPERUSER NOBYPASSRLS owner executes this once.
CREATE SCHEMA rss_timeseries;
DO $$ BEGIN EXECUTE format('COMMENT ON SCHEMA rss_timeseries IS %L', 'rss-timeseries-postgres:1:' || gen_random_uuid()::text); END $$;
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
 PRIMARY KEY (tenant_id,namespace,source,generation)
);
CREATE TABLE rss_timeseries.batches (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, batch_id text COLLATE "C" NOT NULL,
 digest bytea NOT NULL CHECK (octet_length(digest)=32), received_at bigint NOT NULL CHECK (received_at>=0),
 new_samples integer NOT NULL CHECK (new_samples>=0), replayed_samples integer NOT NULL CHECK (replayed_samples>=0),
 replay_until bigint NOT NULL CHECK (replay_until>received_at),
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
CREATE FUNCTION rss_timeseries.lock_stream(t uuid,n text,s text,g text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='tenant'; END IF;
 INSERT INTO rss_timeseries.streams VALUES(t,n,s,g) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM rss_timeseries.streams WHERE tenant_id=t AND namespace=n AND source=s AND generation=g FOR UPDATE;
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
 SELECT * INTO def FROM rss_timeseries.lock_definition(t,n,j#>>'{series,definition,key}',(j#>>'{series,definition,version}')::numeric);
 IF NOT FOUND OR convert_from(def.raw,'UTF8')::jsonb<>j#>'{series,definition}' THEN RAISE EXCEPTION USING ERRCODE='TS002',MESSAGE='definition missing'; END IF;
 IF def.retired THEN RAISE EXCEPTION USING ERRCODE='TS003',MESSAGE='definition retired'; END IF;
 INSERT INTO rss_timeseries.sample_identities VALUES(t,n,s,g,i,d,(j->>'observedAt')::bigint,received);
 INSERT INTO rss_timeseries.samples VALUES(t,n,s,g,i,(j->>'observedAt')::bigint,(j->>'sequence')::numeric,sd,
 j#>>'{series,definition,key}',(j#>>'{series,definition,version}')::numeric,j#>>'{series,subject}',j#>>'{series,resource}',b,received);
 RETURN true;
END $$;
CREATE FUNCTION rss_timeseries.put_batch(t uuid,n text,s text,g text,i text,d bytea,received bigint,added integer,replayed integer,until_time bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_timeseries AS $$ BEGIN
 PERFORM rss_timeseries.lock_stream(t,n,s,g);
 INSERT INTO rss_timeseries.batches VALUES(t,n,s,g,i,d,received,added,replayed,until_time);
END $$;
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
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_timeseries FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_timeseries FROM PUBLIC;
