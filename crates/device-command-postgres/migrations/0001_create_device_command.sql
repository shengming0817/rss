-- Fresh install only, by a dedicated NOSUPERUSER NOBYPASSRLS owner.
-- Extraction: baseline 5b63e10 migrations 0082, 0087, 0103; no product identity schema.
CREATE SCHEMA rss_device_command;
COMMENT ON SCHEMA rss_device_command IS 'rss-device-command-postgres:1';
CREATE TABLE rss_device_command.authorities (
    tenant_id uuid NOT NULL, device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0),
    authority_epoch bigint NOT NULL CHECK(authority_epoch>0),
    PRIMARY KEY(tenant_id,device_id)
);
CREATE TABLE rss_device_command.commands (
    tenant_id uuid NOT NULL, command_id text NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_.:-]{1,255}$'),
    device_id uuid NOT NULL, generation bigint NOT NULL CHECK(generation>0),
    authority_epoch bigint NOT NULL CHECK(authority_epoch>0),
    expected_digest bytea NOT NULL CHECK(octet_length(expected_digest)=32),
    deadline bigint NOT NULL, queued_at bigint NOT NULL,
    outbox_domain text NOT NULL CHECK(outbox_domain ~ '^[A-Za-z0-9_.:-]{1,255}$'),
    outbox_message_id text NOT NULL, outbox_fingerprint bytea NOT NULL CHECK(octet_length(outbox_fingerprint)=32),
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','published','received','applied','rejected','timed_out','superseded','cancelled')),
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    published_at bigint, received_at bigint, terminal_at bigint,
    PRIMARY KEY(tenant_id,command_id), UNIQUE(tenant_id,outbox_message_id),
    FOREIGN KEY(tenant_id,device_id) REFERENCES rss_device_command.authorities,
    CHECK(deadline>queued_at),
    CHECK(published_at IS NULL OR (published_at>=queued_at AND published_at<deadline)),
    CHECK(received_at IS NULL OR (published_at IS NOT NULL AND received_at>=published_at AND received_at<deadline)),
    CHECK(terminal_at IS NULL OR terminal_at>=coalesce(received_at,published_at,queued_at)),
    CHECK((status IN ('applied','rejected','timed_out','superseded','cancelled'))=(terminal_at IS NOT NULL)),
    CHECK(status<>'queued' OR (published_at IS NULL AND received_at IS NULL)),
    CHECK(status<>'published' OR (published_at IS NOT NULL AND received_at IS NULL)),
    CHECK(status NOT IN ('received','applied') OR received_at IS NOT NULL),
    CHECK(status<>'rejected' OR published_at IS NOT NULL),
    CHECK(status<>'timed_out' OR terminal_at>=deadline),
    CHECK(status<>'applied' OR terminal_at<deadline)
);
CREATE INDEX command_scope ON rss_device_command.commands(tenant_id,device_id,command_id);
ALTER TABLE rss_device_command.authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_device_command.authorities FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_device_command.authorities
    USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
ALTER TABLE rss_device_command.commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_device_command.commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_device_command.commands
    USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)
    WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE FUNCTION rss_device_command.initialize(t uuid,d uuid,g bigint,e bigint) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS $$
    INSERT INTO rss_device_command.authorities VALUES(t,d,g,e) ON CONFLICT DO NOTHING;
$$;
CREATE FUNCTION rss_device_command.lock_authority(t uuid,d uuid) RETURNS SETOF rss_device_command.authorities
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS $$
    SELECT * FROM rss_device_command.authorities WHERE tenant_id=t AND device_id=d FOR UPDATE;
$$;
CREATE FUNCTION rss_device_command.advance(t uuid,d uuid,g bigint,e bigint,ng bigint,ne bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS $$
    WITH changed AS (UPDATE rss_device_command.authorities SET generation=ng,authority_epoch=ne
    WHERE tenant_id=t AND device_id=d AND generation=g AND authority_epoch=e AND ng>=g AND ne>e RETURNING 1)
    SELECT EXISTS(SELECT FROM changed);
$$;
CREATE FUNCTION rss_device_command.enqueue(t uuid,d uuid,c text,g bigint,e bigint,digest bytea,expires bigint,at_time bigint,m text,f bytea,domain_name text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS $$
    INSERT INTO rss_device_command.commands(tenant_id,device_id,command_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_message_id,outbox_fingerprint,outbox_domain)
    SELECT t,d,c,g,e,digest,expires,at_time,m,f,domain_name FROM rss_device_command.authorities
    WHERE tenant_id=t AND device_id=d AND generation=g AND authority_epoch=e;
$$;
-- Typed Rust owns transition semantics; SQL preserves immutable fields and compare-and-set.
CREATE FUNCTION rss_device_command.save(t uuid,d uuid,c text,v bigint,s text,p bigint,r bigint,done bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,rss_device_command AS $$
    WITH changed AS (UPDATE rss_device_command.commands SET status=s,version=v+1,published_at=p,received_at=r,terminal_at=done
    WHERE tenant_id=t AND device_id=d AND command_id=c AND version=v AND terminal_at IS NULL RETURNING 1)
    SELECT EXISTS(SELECT FROM changed);
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_device_command FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_device_command FROM PUBLIC;
-- External runtime grants: schema USAGE, tables SELECT, functions EXECUTE. No direct DML.
