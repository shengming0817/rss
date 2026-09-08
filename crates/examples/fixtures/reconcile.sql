CREATE TABLE public.reconcile_demo(tenant_id uuid PRIMARY KEY, n bigint NOT NULL);
ALTER TABLE public.reconcile_demo ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reconcile_demo FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON public.reconcile_demo
USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON public.reconcile_demo TO reconcile_runtime;
