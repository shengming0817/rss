-- Fresh component installation by a dedicated NOSUPERUSER NOBYPASSRLS owner.
-- ref: baseline/pre-community-core-20260902 adapters/postgres/migrations/0083_create_saga_step_receipts.sql
CREATE SCHEMA rss_saga;
REVOKE ALL ON SCHEMA rss_saga FROM PUBLIC;
CREATE TABLE rss_saga.instances (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    definition jsonb NOT NULL,
    status text NOT NULL DEFAULT 'Ready' CHECK (status IN ('Ready','Running','Compensating','CompensationFailed','Succeeded','Compensated')),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    next_step integer NOT NULL DEFAULT 0 CHECK (next_step >= 0),
    lease_token uuid,
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    expires_at timestamptz,
    PRIMARY KEY (tenant_id,saga_id),
    CHECK ((lease_token IS NULL) = (expires_at IS NULL)),
    CHECK (jsonb_array_length(definition->'steps') BETWEEN 1 AND 1024)
);
CREATE TABLE rss_saga.journal (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    seq bigint NOT NULL CHECK (seq >= 0),
    step integer NOT NULL CHECK (step >= 0),
    attempt bigint NOT NULL CHECK (attempt BETWEEN 1 AND 4294967295),
    effect_key bytea NOT NULL CHECK (octet_length(effect_key)=32),
    kind text NOT NULL CHECK (kind IN ('ForwardIntent','ForwardApplied','ForwardNotApplied','ForwardProbeNotApplied','Abort','CompensationIntent','CompensationApplied','CompensationNotApplied','CompensationFailed','Resume')),
    PRIMARY KEY (tenant_id,saga_id,seq),
    FOREIGN KEY (tenant_id,saga_id) REFERENCES rss_saga.instances
);
CREATE TABLE rss_saga.step_receipts (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    step integer NOT NULL,
    completed_seq bigint NOT NULL,
    effect_key bytea NOT NULL CHECK (octet_length(effect_key)=32),
    protected jsonb NOT NULL,
    PRIMARY KEY (tenant_id,saga_id,step),
    UNIQUE (tenant_id,saga_id,completed_seq),
    UNIQUE (tenant_id,effect_key),
    FOREIGN KEY (tenant_id,saga_id,completed_seq) REFERENCES rss_saga.journal DEFERRABLE INITIALLY DEFERRED,
    CHECK ((protected->>'format')::integer=1),
    CHECK ((protected->>'seq')::bigint=completed_seq),
    CHECK (jsonb_typeof(protected->'ciphertext')='object')
);
ALTER TABLE rss_saga.instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.instances FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.journal FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.step_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_saga.step_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON rss_saga.instances USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_saga.journal USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE POLICY tenant ON rss_saga.step_receipts USING (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('rss.tenant_id',true),'')::uuid);
CREATE INDEX candidates ON rss_saga.instances (tenant_id,status,expires_at,saga_id);

CREATE FUNCTION rss_saga.assert_receipt_pair() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,rss_saga AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM rss_saga.journal j LEFT JOIN rss_saga.step_receipts r ON (r.tenant_id,r.saga_id,r.completed_seq)=(j.tenant_id,j.saga_id,j.seq)
        WHERE j.tenant_id=NEW.tenant_id AND j.saga_id=NEW.saga_id AND j.kind='ForwardApplied' AND (r.step IS NULL OR r.step<>j.step OR r.effect_key<>j.effect_key OR (r.protected->>'attempt')::bigint<>j.attempt))
       OR EXISTS (SELECT 1 FROM rss_saga.step_receipts r LEFT JOIN rss_saga.journal j ON (j.tenant_id,j.saga_id,j.seq)=(r.tenant_id,r.saga_id,r.completed_seq)
        WHERE r.tenant_id=NEW.tenant_id AND r.saga_id=NEW.saga_id AND (j.kind IS DISTINCT FROM 'ForwardApplied' OR j.step<>r.step OR j.effect_key<>r.effect_key OR j.attempt<>(r.protected->>'attempt')::bigint)) THEN
        RAISE EXCEPTION USING ERRCODE='RS003', MESSAGE='saga receipt integrity';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER receipt_pair AFTER INSERT ON rss_saga.journal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.assert_receipt_pair();
CREATE CONSTRAINT TRIGGER journal_pair AFTER INSERT ON rss_saga.step_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.assert_receipt_pair();

CREATE FUNCTION rss_saga.register(p_id uuid,p_definition jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE existing jsonb; t uuid := current_setting('rss.tenant_id')::uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(t::text || ':' || (p_definition->'identity'->>'contract') || ':' || (p_definition->'identity'->>'version'),0));
    IF EXISTS (SELECT 1 FROM rss_saga.instances WHERE tenant_id=t AND definition->'identity'->>'contract'=p_definition->'identity'->>'contract' AND definition->'identity'->>'version'=p_definition->'identity'->>'version' AND definition<>p_definition) THEN RAISE EXCEPTION USING ERRCODE='RS002',MESSAGE='saga version conflict'; END IF;
    INSERT INTO rss_saga.instances(tenant_id,saga_id,definition) VALUES(t,p_id,p_definition) ON CONFLICT DO NOTHING;
    SELECT definition INTO existing FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    IF existing IS DISTINCT FROM p_definition THEN RAISE EXCEPTION USING ERRCODE='RS002', MESSAGE='saga definition conflict'; END IF;
END $$;

CREATE FUNCTION rss_saga.claim(p_id uuid,p_token uuid,p_ttl bigint) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row rss_saga.instances; t uuid := current_setting('rss.tenant_id')::uuid; now_ timestamptz;
BEGIN
    IF p_ttl IS NULL OR p_token IS NULL OR p_ttl<=0 OR p_ttl>86400000 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
    SELECT * INTO row FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    now_ := clock_timestamp();
    IF NOT FOUND OR (row.expires_at IS NOT NULL AND row.expires_at>now_) THEN RAISE EXCEPTION USING ERRCODE='RS001',MESSAGE='saga lease unavailable'; END IF;
    UPDATE rss_saga.instances SET lease_token=p_token,epoch=epoch+1,expires_at=now_+p_ttl*interval '1 millisecond' WHERE tenant_id=t AND saga_id=p_id RETURNING epoch INTO row.epoch;
    RETURN row.epoch;
END $$;
CREATE FUNCTION rss_saga.lock_instance(p_id uuid,p_token uuid,p_epoch bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row rss_saga.instances; t uuid := current_setting('rss.tenant_id')::uuid;
BEGIN
    SELECT * INTO row FROM rss_saga.instances WHERE tenant_id=t AND saga_id=p_id FOR UPDATE;
    IF NOT FOUND OR p_token IS NULL OR p_epoch IS NULL OR p_epoch<=0 OR row.expires_at IS NULL OR row.lease_token IS DISTINCT FROM p_token OR row.epoch<>p_epoch OR row.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='RS001',MESSAGE='saga lease lost'; END IF;
    RETURN to_jsonb(row);
END $$;
CREATE FUNCTION rss_saga.lease(p_id uuid,p_token uuid,p_epoch bigint,p_ttl bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE ignored jsonb; t uuid := current_setting('rss.tenant_id')::uuid;
BEGIN
    ignored := rss_saga.lock_instance(p_id,p_token,p_epoch);
    IF p_ttl=0 THEN UPDATE rss_saga.instances SET lease_token=NULL,expires_at=NULL WHERE tenant_id=t AND saga_id=p_id;
    ELSIF p_ttl>0 AND p_ttl<=86400000 THEN UPDATE rss_saga.instances SET expires_at=clock_timestamp()+p_ttl*interval '1 millisecond' WHERE tenant_id=t AND saga_id=p_id;
    ELSE RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga lease ttl'; END IF;
END $$;

CREATE FUNCTION rss_saga.commit_event(p_id uuid,p_token uuid,p_epoch bigint,e jsonb,p_key bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_saga AS $$
DECLARE row_ jsonb; t uuid := current_setting('rss.tenant_id')::uuid; k text:=e->>'kind'; s integer:=(e->>'step')::integer; a bigint:=(e->>'attempt')::bigint; q bigint:=(e->>'seq')::bigint;
    prev rss_saga.journal; highest integer; attempts bigint; failures bigint; state_ text; valid boolean:=false;
BEGIN
    row_:=rss_saga.lock_instance(p_id,p_token,p_epoch);
    IF q IS DISTINCT FROM (row_->>'revision')::bigint THEN RAISE EXCEPTION USING ERRCODE='RS002',MESSAGE='saga revision conflict'; END IF;
    state_:=row_->>'status';
    IF s IS NULL OR s<0 OR s>=jsonb_array_length(row_->'definition'->'steps') OR a IS NULL OR a<1 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga event invalid'; END IF;
    SELECT * INTO prev FROM rss_saga.journal WHERE tenant_id=t AND saga_id=p_id ORDER BY seq DESC LIMIT 1;
    SELECT max(r.step) INTO highest FROM rss_saga.step_receipts r WHERE r.tenant_id=t AND r.saga_id=p_id AND NOT EXISTS (SELECT 1 FROM rss_saga.journal j WHERE j.tenant_id=t AND j.saga_id=p_id AND j.step=r.step AND j.kind='CompensationApplied');
    SELECT count(*) INTO failures FROM rss_saga.journal WHERE tenant_id=t AND saga_id=p_id AND step=s AND kind='ForwardNotApplied';
    IF k='ForwardIntent' THEN
        SELECT coalesce(max(attempt),0) INTO attempts FROM rss_saga.journal WHERE tenant_id=t AND saga_id=p_id AND step=s AND kind='ForwardIntent';
        valid:=state_ IN ('Ready','Running') AND s=(row_->>'next_step')::integer AND (prev.kind IS NULL OR prev.kind NOT IN ('ForwardIntent','CompensationIntent')) AND a=attempts+1 AND failures<(row_->'definition'->'steps'->s->>'max_failures')::bigint;
        state_:='Running';
    ELSIF k IN ('ForwardApplied','ForwardNotApplied','ForwardProbeNotApplied') THEN
        valid:=prev.kind='ForwardIntent' AND prev.step=s AND prev.attempt=a AND prev.effect_key=p_key;
        IF k='ForwardApplied' THEN state_:=CASE WHEN s+1=jsonb_array_length(row_->'definition'->'steps') THEN 'Succeeded' ELSE 'Running' END;
        ELSE state_:='Ready'; END IF;
    ELSIF k='Abort' THEN
        valid:=state_='Ready' AND prev.kind='ForwardNotApplied' AND prev.step=s AND prev.attempt=a AND failures>=(row_->'definition'->'steps'->s->>'max_failures')::bigint;
        state_:=CASE WHEN highest IS NULL THEN 'Compensated' ELSE 'Compensating' END;
    ELSIF k='CompensationIntent' THEN
        SELECT coalesce(max(attempt),0) INTO attempts FROM rss_saga.journal WHERE tenant_id=t AND saga_id=p_id AND step=s AND kind='CompensationIntent';
        valid:=state_='Compensating' AND s=highest AND prev.kind IS DISTINCT FROM 'CompensationIntent' AND a=attempts+1;
    ELSIF k IN ('CompensationApplied','CompensationNotApplied','CompensationFailed') THEN
        valid:=state_='Compensating' AND prev.kind='CompensationIntent' AND prev.step=s AND prev.attempt=a AND prev.effect_key=p_key;
        state_:=CASE WHEN k='CompensationFailed' THEN 'CompensationFailed' WHEN k='CompensationApplied' AND s=0 THEN 'Compensated' ELSE 'Compensating' END;
    ELSIF k='Resume' THEN
        valid:=state_='CompensationFailed' AND prev.kind='CompensationFailed' AND prev.step=s AND prev.attempt=a AND prev.effect_key=p_key;
        state_:='Compensating';
    END IF;
    IF valid IS DISTINCT FROM true OR ((k='ForwardApplied') IS DISTINCT FROM (e->'receipt' IS NOT NULL AND e->'receipt'<>'null'::jsonb)) THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga transition invalid'; END IF;
    IF octet_length(p_key) IS DISTINCT FROM 32 THEN RAISE EXCEPTION USING ERRCODE='RS003',MESSAGE='saga effect key invalid'; END IF;
    INSERT INTO rss_saga.journal VALUES(t,p_id,q,s,a,p_key,k);
    IF k='ForwardApplied' THEN INSERT INTO rss_saga.step_receipts VALUES(t,p_id,s,q,p_key,e->'receipt'); END IF;
    UPDATE rss_saga.instances SET revision=revision+1,status=state_,next_step=CASE WHEN k='ForwardApplied' THEN s+1 ELSE next_step END WHERE tenant_id=t AND saga_id=p_id;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA rss_saga FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_saga FROM PUBLIC;
COMMENT ON SCHEMA rss_saga IS 'rss-saga-postgres:1';
