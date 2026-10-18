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
