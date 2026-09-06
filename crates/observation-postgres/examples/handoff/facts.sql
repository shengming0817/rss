-- Consumer-owned example table; deliberately outside component migrations.
CREATE TABLE public.observation_facts (
 tenant_id uuid NOT NULL, journal text NOT NULL, projection text NOT NULL, generation text NOT NULL,
 scope text NOT NULL, coverage text NOT NULL, fact_key text NOT NULL, value bytea NOT NULL,
 PRIMARY KEY(tenant_id,journal,projection,generation,scope,coverage,fact_key)
);
ALTER TABLE public.observation_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.observation_facts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON public.observation_facts USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
