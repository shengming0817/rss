-- Fresh schema only; execute in one transaction as the separate NOLOGIN NOSUPERUSER NOBYPASSRLS owner.
-- Product owns installation and runtime grants. Existing schemas are not upgraded or repaired.
CREATE SCHEMA rss_audit;
REVOKE ALL ON SCHEMA rss_audit FROM PUBLIC;
CREATE SEQUENCE rss_audit.positions AS bigint MINVALUE 0 START 0 NO CYCLE;
CREATE TABLE rss_audit.records (
    tenant_id uuid NOT NULL,
    source_id text COLLATE "C" NOT NULL CHECK (octet_length(source_id) BETWEEN 1 AND 255),
    event_id text COLLATE "C" NOT NULL CHECK (octet_length(event_id) BETWEEN 1 AND 255),
    position bigint NOT NULL CHECK (position >= 0),
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0),
    canonical bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 1 AND 131072),
    ledger_sequence bigint CHECK (ledger_sequence >= 0),
    PRIMARY KEY (tenant_id, source_id, event_id),
    UNIQUE (tenant_id, position)
);
CREATE UNIQUE INDEX records_tenant_ledger_sequence_uidx ON rss_audit.records (tenant_id, ledger_sequence)
    WHERE ledger_sequence IS NOT NULL;
ALTER TABLE rss_audit.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_audit.records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_audit.records
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
REVOKE ALL ON ALL TABLES IN SCHEMA rss_audit FROM PUBLIC;

CREATE FUNCTION rss_audit.append_batch(p_tenant uuid,p_sources text[],p_events text[],
 p_recorded bigint[],p_canonical bytea[],p_ledger bigint[])
RETURNS TABLE(source_id text,event_id text,"position" bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_audit AS $append$
BEGIN
 IF p_tenant IS DISTINCT FROM NULLIF(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'audit tenant mismatch' USING ERRCODE='PA001';
 END IF;
 IF cardinality(p_sources) IS NULL OR cardinality(p_events) IS DISTINCT FROM cardinality(p_sources)
 OR cardinality(p_recorded) IS DISTINCT FROM cardinality(p_sources)
 OR cardinality(p_canonical) IS DISTINCT FROM cardinality(p_sources)
 OR cardinality(p_ledger) IS DISTINCT FROM cardinality(p_sources) THEN
  RAISE EXCEPTION 'invalid audit batch' USING ERRCODE='PA002';
 END IF;
 RETURN QUERY
 INSERT INTO rss_audit.records AS r(tenant_id,source_id,event_id,position,recorded_at,canonical,ledger_sequence)
 SELECT p_tenant,i.source_id,i.event_id,nextval('rss_audit.positions'),i.recorded,i.canonical,i.ledger
 FROM unnest(p_sources,p_events,p_recorded,p_canonical,p_ledger)
 AS i(source_id,event_id,recorded,canonical,ledger)
 ORDER BY i.source_id COLLATE "C",i.event_id COLLATE "C"
 ON CONFLICT ON CONSTRAINT records_pkey DO NOTHING
 RETURNING r.source_id,r.event_id,r.position;
END $append$;
REVOKE ALL ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM PUBLIC;
REVOKE ALL ON SEQUENCE rss_audit.positions FROM PUBLIC;
