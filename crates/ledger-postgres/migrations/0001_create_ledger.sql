-- Fresh component schema, executed by a dedicated NOSUPERUSER NOBYPASSRLS migrator.
-- ref: baseline 5b63e10 adapters/postgres/src/audit_repo.rs (transactional chain append).
-- Keys never enter SQL. Product owns migration execution and runtime grants.
CREATE SCHEMA rss_ledger;
COMMENT ON SCHEMA rss_ledger IS 'rss-ledger-postgres:1';
CREATE TABLE rss_ledger.heads (
    tenant_id uuid NOT NULL,
    chain_id text NOT NULL CHECK (octet_length(chain_id) BETWEEN 1 AND 255),
    key_id text NOT NULL CHECK (octet_length(key_id) BETWEEN 1 AND 255),
    encoding_version smallint NOT NULL CHECK (encoding_version=1),
    seq bigint CHECK (seq>=0),
    tag bytea NOT NULL CHECK (octet_length(tag)=32),
    PRIMARY KEY(tenant_id,chain_id),
    CHECK(seq IS NOT NULL OR tag=decode(repeat('00',32),'hex'))
);
CREATE TABLE rss_ledger.entries (
    tenant_id uuid NOT NULL,
    chain_id text NOT NULL,
    record_id text NOT NULL CHECK(octet_length(record_id) BETWEEN 1 AND 255),
    seq bigint NOT NULL CHECK(seq>=0),
    previous_tag bytea NOT NULL CHECK(octet_length(previous_tag)=32),
    tag bytea NOT NULL CHECK(octet_length(tag)=32),
    payload bytea NOT NULL CHECK(octet_length(payload)<=1048576),
    encoding_version smallint NOT NULL CHECK(encoding_version=1),
    key_id text NOT NULL CHECK(octet_length(key_id) BETWEEN 1 AND 255),
    PRIMARY KEY(tenant_id,chain_id,seq),
    UNIQUE(tenant_id,chain_id,record_id),
    FOREIGN KEY(tenant_id,chain_id) REFERENCES rss_ledger.heads,
    CHECK(seq<>0 OR previous_tag=decode(repeat('00',32),'hex'))
);
ALTER TABLE rss_ledger.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_ledger.heads FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_ledger.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_ledger.entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_ledger.heads
USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant_scope ON rss_ledger.entries
USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);

CREATE FUNCTION rss_ledger.prepare_append(t uuid,c text,k text,v smallint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_ledger AS $$
DECLARE h rss_ledger.heads;
BEGIN
    IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
        RAISE EXCEPTION 'ledger scope mismatch' USING ERRCODE='PL001';
    END IF;
    INSERT INTO rss_ledger.heads VALUES(t,c,k,v,NULL,decode(repeat('00',32),'hex')) ON CONFLICT DO NOTHING;
    SELECT * INTO STRICT h FROM rss_ledger.heads WHERE tenant_id=t AND chain_id=c FOR UPDATE;
    IF h.key_id<>k THEN RAISE EXCEPTION 'ledger key mismatch' USING ERRCODE='PL002'; END IF;
    IF h.encoding_version<>v THEN RAISE EXCEPTION 'ledger version mismatch' USING ERRCODE='PL003'; END IF;
END $$;

CREATE FUNCTION rss_ledger.insert_entry(t uuid,c text,r text,s bigint,p bytea,a bytea,b bytea,k text,v smallint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_ledger AS $$
DECLARE h rss_ledger.heads;
BEGIN
    PERFORM rss_ledger.prepare_append(t,c,k,v);
    SELECT * INTO STRICT h FROM rss_ledger.heads WHERE tenant_id=t AND chain_id=c FOR UPDATE;
    IF h.seq=9223372036854775807 THEN RAISE EXCEPTION 'ledger exhausted' USING ERRCODE='PL004'; END IF;
    IF s IS DISTINCT FROM coalesce(h.seq+1,0) OR p IS DISTINCT FROM h.tag THEN
        RAISE EXCEPTION 'ledger predecessor mismatch' USING ERRCODE='PL005';
    END IF;
    INSERT INTO rss_ledger.entries VALUES(t,c,r,s,p,a,b,v,k);
    UPDATE rss_ledger.heads SET seq=s,tag=a WHERE tenant_id=t AND chain_id=c;
END $$;
REVOKE ALL ON SCHEMA rss_ledger FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_ledger FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_ledger FROM PUBLIC;
