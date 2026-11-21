-- Fresh-only installation by a dedicated NOLOGIN NOSUPERUSER NOBYPASSRLS owner.
-- ref: PostgreSQL 17 row security; ClickHouse PostgreSQLSource.cpp@v25.8.12.129-lts.
CREATE SCHEMA rss_ts_ch;
CREATE TABLE rss_ts_ch.installation (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 id uuid NOT NULL DEFAULT gen_random_uuid(), version integer NOT NULL DEFAULT 2 CHECK(version=2),
 max_pending_batches integer NOT NULL DEFAULT 1 CHECK(max_pending_batches BETWEEN 1 AND 16)
);
INSERT INTO rss_ts_ch.installation DEFAULT VALUES;
CREATE TABLE rss_ts_ch.namespaces (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 allocated bigint NOT NULL DEFAULT 0 CHECK(allocated>=published),
 published bigint NOT NULL DEFAULT 0 CHECK(published>=0),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0),
 PRIMARY KEY(tenant_id,namespace)
);
CREATE TABLE rss_ts_ch.definitions (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, key text COLLATE "C" NOT NULL,
 version numeric(20,0) NOT NULL CHECK(version BETWEEN 1 AND 18446744073709551615),
 raw bytea NOT NULL, digest bytea NOT NULL CHECK(octet_length(digest)=32),
 retired boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,namespace,key,version),
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces
);
CREATE TABLE rss_ts_ch.streams (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL,
 closed boolean NOT NULL DEFAULT false, reclaimed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,namespace,source,generation),
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces
);
CREATE TABLE rss_ts_ch.batches (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, batch_id text COLLATE "C" NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), revision bigint NOT NULL CHECK(revision>0),
 received_at bigint NOT NULL CHECK(received_at>=0), replay_until bigint NOT NULL CHECK(replay_until>received_at),
 new_samples integer NOT NULL CHECK(new_samples>=0), replayed_samples integer NOT NULL CHECK(replayed_samples>=0),
 payload bytea, projection bytea, attempt uuid,
 phase text NOT NULL DEFAULT 'prepared' CHECK(phase IN ('prepared','verified','published','expired')),
 CHECK(phase='prepared' OR attempt IS NULL),
 CHECK(new_samples+replayed_samples BETWEEN 1 AND 4096),
 CHECK((phase='prepared' AND payload IS NOT NULL AND projection IS NOT NULL)
    OR (phase<>'prepared' AND payload IS NULL AND projection IS NULL)),
 UNIQUE(tenant_id,namespace,revision),
 PRIMARY KEY(tenant_id,namespace,source,generation,batch_id),
 FOREIGN KEY(tenant_id,namespace,source,generation) REFERENCES rss_ts_ch.streams
);
CREATE UNIQUE INDEX one_pending_stream ON rss_ts_ch.batches(tenant_id,namespace,source,generation)
 WHERE phase IN ('prepared','verified');
CREATE TABLE rss_ts_ch.identities (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, sample_id text COLLATE "C" NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), received_at bigint NOT NULL CHECK(received_at>=0),
 PRIMARY KEY(tenant_id,namespace,source,generation,sample_id),
 FOREIGN KEY(tenant_id,namespace,source,generation) REFERENCES rss_ts_ch.streams
);
CREATE TABLE rss_ts_ch.attempts (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), query_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 target text NOT NULL CHECK(target IN ('raw','summaries')),
 digest text NOT NULL CHECK(length(digest)=64), revision bigint NOT NULL CHECK(revision>=0),
 allowed boolean NOT NULL DEFAULT true, drained boolean NOT NULL DEFAULT false,
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces,
 CHECK(NOT allowed OR NOT drained)
);
CREATE UNIQUE INDEX raw_batch_attempt ON rss_ts_ch.attempts(tenant_id,namespace,revision) WHERE target='raw';
CREATE TABLE rss_ts_ch.fences (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, id text COLLATE "C" NOT NULL,
 kind text NOT NULL CHECK(kind IN ('cutoff','delete','pruned')),
 selection jsonb NOT NULL, lo bigint NOT NULL CHECK(lo>=0), hi bigint NOT NULL CHECK(hi>lo),
 restore_until bigint, restored boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,namespace,id),
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces
);
CREATE TABLE rss_ts_ch.plans (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, id text COLLATE "C" NOT NULL,
 binding bytea NOT NULL CHECK(octet_length(binding)=32), state bytea NOT NULL,
 complete boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,namespace,id),
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces
);
-- Only references/checkpoints are in PG; summary values live exclusively in ClickHouse.
CREATE TABLE rss_ts_ch.summaries (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, spec_digest bytea NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL,
 series text COLLATE "C" NOT NULL CHECK(length(series)=64),
 semantics bytea NOT NULL, spec bytea NOT NULL, lo bigint NOT NULL, hi bigint NOT NULL CHECK(hi>lo),
 object_id uuid NOT NULL, dirty_from bigint CHECK(dirty_from>=0),
 PRIMARY KEY(tenant_id,namespace,spec_digest,lo),
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces
);
CREATE INDEX clean_series_summaries ON rss_ts_ch.summaries(tenant_id,namespace,source,generation,series,hi) WHERE dirty_from IS NULL;
CREATE TABLE rss_ts_ch.ranges (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL, spec_digest bytea NOT NULL,
 spec bytea NOT NULL, lo bigint NOT NULL, hi bigint NOT NULL CHECK(hi>lo),
 PRIMARY KEY(tenant_id,namespace,spec_digest,lo,hi),
 FOREIGN KEY(tenant_id,namespace) REFERENCES rss_ts_ch.namespaces
);
DO $$ DECLARE t text; BEGIN
 FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='rss_ts_ch' AND tablename<>'installation' LOOP
  EXECUTE format('ALTER TABLE rss_ts_ch.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE rss_ts_ch.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant ON rss_ts_ch.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
 -- The NOLOGIN owner is the sole definer of the payload-free guard view.
 EXECUTE format('CREATE POLICY guard_owner ON rss_ts_ch.attempts TO %I USING (true)',current_user);
END $$;
CREATE VIEW rss_ts_ch.active_attempts WITH (security_barrier=true) AS
 SELECT a.tenant_id::text AS tenant,a.namespace,a.id::text AS attempt,a.query_id::text AS query_id,
 a.target,a.digest,a.revision,i.id::text AS installation
 FROM rss_ts_ch.attempts a CROSS JOIN rss_ts_ch.installation i WHERE a.allowed AND NOT pg_is_in_recovery() AND (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid());
REVOKE ALL ON SCHEMA rss_ts_ch FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_ts_ch FROM PUBLIC;
-- The guard checks installation lineage and live TLS/primary posture independently
-- of whether there are any active attempts. It exposes no producer payload.
CREATE VIEW rss_ts_ch.guard_identity WITH (security_barrier=true) AS
 SELECT id::text AS installation,NOT pg_is_in_recovery() AS primary_server,
 (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS tls,
 session_user::text AS guard_user FROM rss_ts_ch.installation;
REVOKE ALL ON rss_ts_ch.guard_identity FROM PUBLIC;
