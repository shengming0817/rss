CREATE TABLE public.projection_demo_facts(tenant_id uuid NOT NULL,event_id text NOT NULL,PRIMARY KEY(tenant_id,event_id));
CREATE TABLE public.projection_demo_counts(tenant_id uuid NOT NULL,generation text NOT NULL,total bigint NOT NULL,PRIMARY KEY(tenant_id,generation));
ALTER TABLE public.projection_demo_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projection_demo_facts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.projection_demo_counts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.projection_demo_counts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.projection_demo_facts
    USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant_scope ON public.projection_demo_counts
    USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON public.projection_demo_facts TO projection_runtime;
GRANT SELECT,INSERT,UPDATE ON public.projection_demo_counts TO projection_runtime;
