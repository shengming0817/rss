-- Fresh schema v24 only. The host installs RSS messaging and admits its tenants separately.
CREATE SCHEMA identity_authority;
CREATE TABLE identity_authority.schema_version(version integer PRIMARY KEY CHECK(version=24));
INSERT INTO identity_authority.schema_version VALUES(24);
CREATE TABLE identity_authority.deployment (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 authority_id uuid NOT NULL CHECK(authority_id <> '00000000-0000-0000-0000-000000000000'),
 account_cursor_key bytea NOT NULL CHECK(octet_length(account_cursor_key)=32)
);
CREATE FUNCTION identity_authority.protect_deployment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'immutable authentication instance';
END $$;
CREATE TRIGGER protect_deployment BEFORE UPDATE OR DELETE ON identity_authority.deployment FOR EACH ROW EXECUTE FUNCTION identity_authority.protect_deployment();
CREATE TABLE identity_authority.tenants(tenant_id uuid PRIMARY KEY);
CREATE TABLE identity_authority.tenant_state (
 tenant_id uuid NOT NULL REFERENCES identity_authority.tenants,
 kind text NOT NULL CHECK(kind IN ('profile_sequence','receipt_clock','attempt_capacity')),
 value bigint NOT NULL DEFAULT 0 CHECK(value>=0),
 PRIMARY KEY(tenant_id,kind)
);
-- Source counters live as long as the tenant so a replaced source never reuses its old generation.
CREATE TABLE identity_authority.directory_revisions (
 tenant_id uuid NOT NULL REFERENCES identity_authority.tenants,
 kind text NOT NULL CHECK(kind IN ('rows','enabled','member','epoch','login','password','origin','profile','department','groups','reference')),
 source text NOT NULL,
 value bigint NOT NULL CHECK(value>0),
 PRIMARY KEY(tenant_id,kind,source)
);
CREATE FUNCTION identity_authority.initialize_tenant_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO identity_authority.tenant_state(tenant_id,kind) VALUES
  (NEW.tenant_id,'profile_sequence'),(NEW.tenant_id,'receipt_clock'),(NEW.tenant_id,'attempt_capacity');
 RETURN NEW;
END $$;
CREATE TRIGGER initialize_state AFTER INSERT ON identity_authority.tenants
 FOR EACH ROW EXECUTE FUNCTION identity_authority.initialize_tenant_state();
CREATE TABLE identity_authority.accounts (
 tenant_id uuid NOT NULL,
 principal_id uuid NOT NULL CHECK(principal_id <> '00000000-0000-0000-0000-000000000000'),
 enabled boolean NOT NULL DEFAULT true,
 auth_epoch bigint NOT NULL DEFAULT 1 CHECK(auth_epoch>0),
 PRIMARY KEY(tenant_id,principal_id)
);
-- Keep composite bounds flat: pg_dump/reparse must preserve structural attestation.
CREATE TABLE identity_authority.local_credentials (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 login_key text NOT NULL CHECK(octet_length(login_key)>=1 AND octet_length(login_key)<=255 AND login_key=lower(login_key COLLATE "C") AND login_key !~ '[^\x20-\x7e]' AND login_key=btrim(login_key)),
 password_hash text NOT NULL CHECK(octet_length(password_hash)>=80 AND octet_length(password_hash)<=256 AND password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'),
 PRIMARY KEY(tenant_id,principal_id), UNIQUE(tenant_id,login_key),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.memberships (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, active boolean NOT NULL DEFAULT true,
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts
);
CREATE TABLE identity_authority.attempts (
 tenant_id uuid NOT NULL, key text NOT NULL CHECK(octet_length(key) BETWEEN 1 AND 300),
 count integer NOT NULL CHECK(count>0), expires_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,key)
);
CREATE INDEX attempts_expiry ON identity_authority.attempts(tenant_id,expires_at);
CREATE TABLE identity_authority.password_attempts (
 tenant_id uuid NOT NULL,
 login_digest bytea NOT NULL CHECK(octet_length(login_digest)=32),
 failures integer NOT NULL DEFAULT 0 CHECK(failures>=0),
 window_until timestamptz,
 claim_token uuid CHECK(claim_token <> '00000000-0000-0000-0000-000000000000'),
 claim_until timestamptz,
 PRIMARY KEY(tenant_id,login_digest),
 CHECK((failures=0) = (window_until IS NULL)),
 CHECK((claim_token IS NULL) = (claim_until IS NULL))
);
CREATE INDEX password_attempts_expiry ON identity_authority.password_attempts(tenant_id,window_until,claim_until);
CREATE TABLE identity_authority.providers (
 tenant_id uuid NOT NULL REFERENCES identity_authority.tenants,
 provider_id uuid NOT NULL CHECK(provider_id <> '00000000-0000-0000-0000-000000000000'),
 config_version bigint NOT NULL CHECK(config_version>0),
 revocation_epoch bigint NOT NULL CHECK(revocation_epoch>0),
 enabled boolean NOT NULL,
 settings jsonb NOT NULL CHECK(jsonb_typeof(settings)='object' AND octet_length(settings::text)<=16384),
 PRIMARY KEY(tenant_id,provider_id),
 assurance_profile bytea NOT NULL CHECK(octet_length(assurance_profile)=32),
 credential_version bigint NOT NULL CHECK(credential_version>0)
);
CREATE TABLE identity_authority.provider_credentials (
 tenant_id uuid NOT NULL, provider_id uuid NOT NULL, credential_version bigint NOT NULL CHECK(credential_version>0),
 sealed jsonb NOT NULL CHECK(jsonb_typeof(sealed)='object' AND octet_length(sealed::text)<=131072),
 PRIMARY KEY(tenant_id,provider_id), FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers
);
CREATE TABLE identity_authority.external_identities (
 tenant_id uuid NOT NULL, identity_id uuid NOT NULL, principal_id uuid NOT NULL, provider_id uuid NOT NULL,
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 2048),
 subject text NOT NULL CHECK(octet_length(subject)>=6 AND octet_length(subject)<=260 AND (subject LIKE 'oidc:%' OR subject ~ '^entra:[0-9a-f-]{36}:[0-9a-f-]{36}$')),
 PRIMARY KEY(tenant_id,identity_id), UNIQUE(tenant_id,principal_id,provider_id,identity_id), UNIQUE(tenant_id,provider_id,issuer,subject),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers
);
CREATE TABLE identity_authority.sessions (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
 facts_sequence bigint CHECK(facts_sequence>0),
 session_id uuid NOT NULL CHECK(session_id <> '00000000-0000-0000-0000-000000000000'),
 authentication_source text NOT NULL CHECK(authentication_source IN ('local_password','oidc','platform')),
 local_authenticated_at bigint,
 platform_authentication jsonb,
 credential_kind text NOT NULL CHECK(credential_kind IN ('cookie','bearer')),
 token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0),
 membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 issued_at bigint NOT NULL CHECK(issued_at>0),
 idle_timeout bigint NOT NULL CHECK(idle_timeout>0),
 absolute_timeout bigint NOT NULL CHECK(absolute_timeout>=idle_timeout),
 idle_expires_at bigint NOT NULL,
 absolute_expires_at bigint NOT NULL,
 revoked_at bigint,
 profile_source text,
 profile_snapshot uuid,
 CHECK ((profile_source IS NULL) = (profile_snapshot IS NULL)),
 external_identity_id uuid,
 source_provider_id uuid,
 CHECK ((external_identity_id IS NULL) = (source_provider_id IS NULL)),
 provider_epoch bigint,
 auth_facts jsonb,
 provider_config_version bigint GENERATED ALWAYS AS (
   CASE WHEN jsonb_typeof(auth_facts->'provider_config_version')='number'
     THEN (auth_facts->>'provider_config_version')::bigint END
 ) STORED,
 CONSTRAINT session_presentation CHECK(credential_kind='cookie' OR authentication_source='local_password'),
 CONSTRAINT authentication_kind CHECK (((authentication_source='local_password' AND local_authenticated_at>0 AND local_authenticated_at<=issued_at AND platform_authentication IS NULL AND external_identity_id IS NULL)
 OR (authentication_source='oidc' AND local_authenticated_at IS NULL AND platform_authentication IS NULL AND external_identity_id IS NOT NULL)
 OR (authentication_source='platform' AND local_authenticated_at IS NULL AND external_identity_id IS NULL AND jsonb_typeof(platform_authentication)='object' AND octet_length(platform_authentication::text)<=4096)) IS TRUE),
 CONSTRAINT session_source CHECK((external_identity_id IS NULL AND provider_epoch IS NULL AND auth_facts IS NULL AND facts_sequence IS NULL) OR (external_identity_id IS NOT NULL AND provider_config_version IS NOT NULL AND provider_config_version>0 AND facts_sequence IS NOT NULL AND provider_epoch IS NOT NULL AND provider_epoch>0 AND auth_facts IS NOT NULL AND jsonb_typeof(auth_facts)='object' AND (auth_facts->'format_version'='3'::jsonb AND jsonb_typeof(auth_facts->'department_snapshot')='object') IS TRUE)),
 FOREIGN KEY(tenant_id,principal_id,source_provider_id,external_identity_id) REFERENCES identity_authority.external_identities(tenant_id,principal_id,provider_id,identity_id),
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,token_hash), UNIQUE(tenant_id,principal_id,session_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 CONSTRAINT session_lifetime CHECK(issued_at < idle_expires_at AND idle_expires_at <= absolute_expires_at),
 CONSTRAINT session_duration CHECK(absolute_expires_at::numeric-issued_at::numeric=absolute_timeout),
 CONSTRAINT session_revocation CHECK(revoked_at IS NULL OR revoked_at >= issued_at)
);
CREATE INDEX sessions_accepted_facts ON identity_authority.sessions(tenant_id,principal_id,facts_sequence DESC) WHERE external_identity_id IS NOT NULL;
CREATE TABLE identity_authority.link_intents (
 tenant_id uuid NOT NULL, intent_id uuid NOT NULL, principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 source_identity uuid, source_epoch bigint, source_facts jsonb, source_facts_sequence bigint CHECK(source_facts_sequence>0), local_authenticated_at bigint,
 CHECK (((source_identity IS NULL AND local_authenticated_at>0) OR (source_identity IS NOT NULL AND local_authenticated_at IS NULL)) IS TRUE),
 target_provider uuid NOT NULL, target_version bigint NOT NULL CHECK(target_version>0),
 browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 stage smallint NOT NULL CHECK(stage BETWEEN 0 AND 2),
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(tenant_id,intent_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts,
 FOREIGN KEY(tenant_id,session_id) REFERENCES identity_authority.sessions,
 FOREIGN KEY(tenant_id,target_provider) REFERENCES identity_authority.providers,
 FOREIGN KEY(tenant_id,source_identity) REFERENCES identity_authority.external_identities,
 CHECK((source_identity IS NULL AND source_epoch IS NULL AND source_facts IS NULL AND source_facts_sequence IS NULL) OR (source_identity IS NOT NULL AND source_facts_sequence IS NOT NULL AND source_epoch IS NOT NULL AND source_epoch>0 AND source_facts IS NOT NULL AND jsonb_typeof(source_facts)='object' AND (source_facts->'format_version'='3'::jsonb AND jsonb_typeof(source_facts->'department_snapshot')='object') IS TRUE))
);
CREATE TABLE identity_authority.oidc_transactions (
 operation_context jsonb,
 tenant_id uuid NOT NULL, attempt_id bytea NOT NULL CHECK(octet_length(attempt_id)=32),
 provider_id uuid NOT NULL, config_version bigint NOT NULL CHECK(config_version>0),
 state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32), browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 profile_sequence bigint NOT NULL CHECK(profile_sequence>0),
 purpose smallint NOT NULL CHECK(purpose BETWEEN 0 AND 2),
 authentication_mode smallint NOT NULL CHECK(authentication_mode BETWEEN 0 AND 2),
 nonce text, verifier text, claimed boolean NOT NULL DEFAULT false,
 created_at bigint NOT NULL, expires_at bigint NOT NULL CHECK(expires_at>created_at),
 return_url text NOT NULL CHECK(octet_length(return_url) BETWEEN 1 AND 2048),
 link_intent uuid, replacement_session uuid,
 PRIMARY KEY(tenant_id,attempt_id), UNIQUE(tenant_id,state_hash),
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers,
 FOREIGN KEY(tenant_id,link_intent) REFERENCES identity_authority.link_intents,
 FOREIGN KEY(tenant_id,replacement_session) REFERENCES identity_authority.sessions,
 CHECK((purpose=1 AND authentication_mode=1) OR (purpose=2 AND authentication_mode=0) OR (purpose=0 AND (authentication_mode=0 OR (authentication_mode=2 AND replacement_session IS NOT NULL)))),
 CHECK((purpose=0 AND link_intent IS NULL) OR (purpose IN(1,2) AND link_intent IS NOT NULL)),
 CHECK((claimed AND nonce IS NULL AND verifier IS NULL) OR (NOT claimed AND octet_length(nonce)=43 AND octet_length(verifier)=43))
);
CREATE INDEX oidc_expiry ON identity_authority.oidc_transactions(tenant_id,expires_at);
CREATE INDEX link_expiry ON identity_authority.link_intents(tenant_id,expires_at);
CREATE TABLE identity_authority.platform_challenges (
 purpose jsonb NOT NULL CHECK(jsonb_typeof(purpose)='object' AND octet_length(purpose::text)<=512),
 target jsonb CHECK(target IS NULL OR (jsonb_typeof(target)='object' AND octet_length(target::text)<=8192)),
 tenant_id uuid NOT NULL, challenge_id uuid NOT NULL, principal_id uuid NOT NULL,
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=4096),
 audience text NOT NULL CHECK(octet_length(audience) BETWEEN 1 AND 256),
 nonce_hash bytea NOT NULL CHECK(octet_length(nonce_hash)=32), browser_hash bytea NOT NULL CHECK(octet_length(browser_hash)=32),
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 created_at bigint NOT NULL CHECK(created_at>0), expires_at bigint NOT NULL CHECK(expires_at>created_at),
 profile_sequence bigint NOT NULL CHECK(profile_sequence>0),
 PRIMARY KEY(tenant_id,challenge_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE INDEX platform_challenge_expiry ON identity_authority.platform_challenges(tenant_id,expires_at);
CREATE TABLE identity_authority.local_profiles (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 reclaimed_through bigint NOT NULL DEFAULT 0 CHECK(reclaimed_through>=0 AND reclaimed_through<=revision),
 value jsonb CHECK(value IS NULL OR (jsonb_typeof(value)='object')),
 PRIMARY KEY(tenant_id,principal_id),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.profile_observations (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, source text NOT NULL,
 provider_id uuid, config_version bigint, source_epoch bigint, source_revision bigint,
 snapshot_id uuid NOT NULL, sequence bigint NOT NULL CHECK(sequence>0),
 observed_at bigint NOT NULL CHECK(observed_at>0), collected_at bigint NOT NULL CHECK(collected_at>0),
 expires_at bigint NOT NULL CHECK(expires_at>observed_at),
 value jsonb NOT NULL CHECK(jsonb_typeof(value)='object'),
 CHECK (((source='local' AND provider_id IS NULL AND config_version IS NULL AND source_epoch IS NULL)
 OR (provider_id IS NOT NULL AND source=provider_id::text AND config_version>0 AND source_epoch>0 AND source_revision IS NULL)) IS TRUE),
 PRIMARY KEY(tenant_id,principal_id,source),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,provider_id) REFERENCES identity_authority.providers ON DELETE CASCADE
);
CREATE TABLE identity_authority.profile_operations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL CHECK((get_byte(uuid_send(operation_id),6) >> 4)=7 AND (get_byte(uuid_send(operation_id),8) >> 6)=2), principal_id uuid NOT NULL, actor uuid NOT NULL,
 digest bytea NOT NULL CHECK(octet_length(digest)=32), revision bigint NOT NULL CHECK(revision>0),
 accepted_at_ms bigint NOT NULL CHECK(accepted_at_ms>=0),
 PRIMARY KEY(tenant_id,operation_id), UNIQUE(tenant_id,principal_id,revision),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.webauthn_rp (
 tenant_id uuid NOT NULL, rp text NOT NULL CHECK(octet_length(rp) BETWEEN 1 AND 253),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32), generation bigint NOT NULL CHECK(generation>0),
 PRIMARY KEY(tenant_id,rp)
);
CREATE TABLE identity_authority.webauthn_accounts (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, user_handle uuid NOT NULL DEFAULT gen_random_uuid(),
 enrolled boolean NOT NULL DEFAULT false, epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0),
 PRIMARY KEY(tenant_id,principal_id), UNIQUE(user_handle),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.webauthn_credentials (
 tenant_id uuid NOT NULL, principal_id uuid NOT NULL, id uuid NOT NULL,
 rp text NOT NULL CHECK(octet_length(rp)<=253), rp_config bytea NOT NULL CHECK(octet_length(rp_config)=32),
 credential_hash bytea NOT NULL CHECK(octet_length(credential_hash)=32),
 value jsonb NOT NULL CHECK(jsonb_typeof(value)='object' AND octet_length(value::text)<=16384),
 label text NOT NULL CHECK(octet_length(label) BETWEEN 1 AND 255),
 epoch bigint NOT NULL DEFAULT 1 CHECK(epoch>0), version bigint NOT NULL DEFAULT 1 CHECK(version>0), revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,id), UNIQUE(rp,credential_hash),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.webauthn_ceremonies (
 tenant_id uuid NOT NULL, id uuid NOT NULL, principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0), credential_epoch bigint NOT NULL CHECK(credential_epoch>0),
 rp_config bytea NOT NULL CHECK(octet_length(rp_config)=32), state jsonb NOT NULL CHECK(jsonb_typeof(state)='object' AND octet_length(state::text)<=131072),
 created_at bigint NOT NULL CHECK(created_at>0), expires_at bigint NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=120),
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE TABLE identity_authority.step_up_grants (
 tenant_id uuid NOT NULL, token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32), principal_id uuid NOT NULL, session_id uuid NOT NULL,
 auth_epoch bigint NOT NULL CHECK(auth_epoch>0), membership_epoch bigint NOT NULL CHECK(membership_epoch>0),
 context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=2048),
 source jsonb NOT NULL CHECK(jsonb_typeof(source)='object' AND octet_length(source::text)<=2048),
 authenticated_at bigint NOT NULL CHECK(authenticated_at>0), expires_at bigint NOT NULL CHECK(expires_at>authenticated_at),
 PRIMARY KEY(tenant_id,token_hash), FOREIGN KEY(tenant_id,principal_id) REFERENCES identity_authority.accounts ON DELETE CASCADE
);
CREATE INDEX webauthn_ceremony_expiry ON identity_authority.webauthn_ceremonies(tenant_id,expires_at);
CREATE INDEX step_up_subject ON identity_authority.step_up_grants(tenant_id,principal_id);
CREATE INDEX webauthn_ceremony_subject ON identity_authority.webauthn_ceremonies(tenant_id,principal_id);
CREATE INDEX step_up_expiry ON identity_authority.step_up_grants(tenant_id,expires_at);
CREATE INDEX webauthn_account_credentials ON identity_authority.webauthn_credentials(tenant_id,principal_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['webauthn_rp','webauthn_accounts','webauthn_credentials','webauthn_ceremonies','step_up_grants','platform_challenges','local_profiles','profile_observations','profile_operations','provider_credentials','tenants','tenant_state','directory_revisions','local_credentials','accounts','memberships','password_attempts','attempts','sessions','providers','external_identities','link_intents','oidc_transactions'] LOOP
 EXECUTE format('ALTER TABLE identity_authority.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE identity_authority.%I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant ON identity_authority.%I USING (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''rss.tenant_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA identity_authority FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA identity_authority FROM PUBLIC;

-- Narrow lock-only ports for the host admission roles. Tenant comes from the fenced transaction.
CREATE FUNCTION identity_authority.share_host_tenant() RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT FROM identity_authority.tenants
  WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid FOR SHARE)
$$;
CREATE FUNCTION identity_authority.share_provider(id uuid) RETURNS boolean
LANGUAGE sql VOLATILE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT FROM identity_authority.providers
  WHERE tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid AND provider_id=id FOR SHARE)
$$;
CREATE FUNCTION identity_authority.share_subject(id uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid;
BEGIN
 PERFORM FROM identity_authority.accounts WHERE tenant_id=tenant AND principal_id=id FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM FROM identity_authority.memberships WHERE tenant_id=tenant AND principal_id=id FOR SHARE;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION identity_authority.share_host_tenant(),identity_authority.share_provider(uuid),identity_authority.share_subject(uuid) FROM PUBLIC;

-- REF: PostgreSQL REL_17_6 src/backend/access/heap/heapam.c, tupleLockExtraInfo.
-- Credentials only locate rows. After waiting, lock the exact original credential/source
-- and let the caller restore the facts in a fresh READ COMMITTED statement.
CREATE FUNCTION identity_authority.lock_session(
 digest bytea, reference_id uuid, presentation text, intent text, target uuid
) RETURNS boolean LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 tenant uuid := nullif(current_setting('rss.tenant_id',true),'')::uuid;
 candidate record;
 source_id uuid;
 write_provider uuid;
 write_account uuid;
 other_account uuid;
 id uuid;
BEGIN
 IF num_nonnulls(digest,reference_id)<>1 OR intent NOT IN
  ('inspect','activity','rotate','revoke','all','host','account','provider','profile_write') THEN
  RETURN false;
 END IF;
 SELECT s.session_id,s.principal_id,s.source_provider_id,s.authentication_source,s.platform_authentication
 INTO candidate FROM identity_authority.sessions s
 WHERE s.tenant_id=tenant AND s.credential_kind=presentation
 AND (s.token_hash=digest OR s.session_id=reference_id);
 IF NOT FOUND THEN RETURN false; END IF;

 IF intent IN ('account','provider') OR
    (intent='all' AND candidate.authentication_source='platform') THEN
  PERFORM FROM identity_authority.tenants WHERE tenant_id=tenant FOR NO KEY UPDATE;
 ELSIF intent='host' OR candidate.authentication_source='platform' THEN
  PERFORM FROM identity_authority.tenants WHERE tenant_id=tenant FOR SHARE;
 ELSE
  PERFORM FROM identity_authority.tenants WHERE tenant_id=tenant FOR KEY SHARE;
 END IF;
 IF NOT FOUND THEN RETURN false; END IF;

 source_id := coalesce(candidate.source_provider_id,
  (candidate.platform_authentication #>> '{binding,externalIdentity,provider}')::uuid);
 IF intent='provider' THEN write_provider:=target; END IF;
 FOR id IN SELECT DISTINCT k FROM unnest(ARRAY[source_id,write_provider]) k WHERE k IS NOT NULL ORDER BY k LOOP
  IF id=write_provider THEN
   PERFORM FROM identity_authority.providers WHERE tenant_id=tenant AND provider_id=id FOR UPDATE;
  ELSE
   PERFORM FROM identity_authority.providers WHERE tenant_id=tenant AND provider_id=id FOR SHARE;
  END IF;
  IF NOT FOUND AND id=source_id THEN RETURN false; END IF;
 END LOOP;

 IF intent IN ('account','profile_write') THEN other_account:=target; END IF;
 IF intent='account' THEN write_account:=target;
 ELSIF intent='all' THEN write_account:=candidate.principal_id; END IF;
 FOR id IN SELECT DISTINCT k FROM unnest(ARRAY[candidate.principal_id,other_account]) k WHERE k IS NOT NULL ORDER BY k LOOP
  IF id=write_account THEN
   PERFORM FROM identity_authority.accounts WHERE tenant_id=tenant AND principal_id=id FOR UPDATE;
  ELSE
   PERFORM FROM identity_authority.accounts WHERE tenant_id=tenant AND principal_id=id FOR SHARE;
  END IF;
  IF NOT FOUND THEN
   IF id=candidate.principal_id THEN RETURN false; END IF;
   CONTINUE; -- Host policy determines visibility of a missing management target.
  END IF;
  -- All component membership mutations acquire the account first.
  IF intent='account' AND id=target THEN
   PERFORM FROM identity_authority.memberships WHERE tenant_id=tenant AND principal_id=id FOR UPDATE;
  ELSE
   PERFORM FROM identity_authority.memberships WHERE tenant_id=tenant AND principal_id=id FOR SHARE;
  END IF;
  IF NOT FOUND AND id=candidate.principal_id THEN RETURN false; END IF;
 END LOOP;

 IF intent='rotate' THEN
  PERFORM FROM identity_authority.sessions WHERE tenant_id=tenant AND session_id=candidate.session_id FOR UPDATE;
 ELSIF intent IN ('activity','revoke') THEN
  PERFORM FROM identity_authority.sessions WHERE tenant_id=tenant AND session_id=candidate.session_id FOR NO KEY UPDATE;
 ELSE
  PERFORM FROM identity_authority.sessions WHERE tenant_id=tenant AND session_id=candidate.session_id FOR SHARE;
 END IF;
 IF NOT FOUND THEN RETURN false; END IF;
 RETURN EXISTS(SELECT FROM identity_authority.sessions s WHERE s.tenant_id=tenant AND s.session_id=candidate.session_id
  AND s.credential_kind=presentation AND (digest IS NULL OR s.token_hash=digest)
  AND s.principal_id=candidate.principal_id AND s.authentication_source=candidate.authentication_source
  AND s.source_provider_id IS NOT DISTINCT FROM candidate.source_provider_id
  AND s.platform_authentication IS NOT DISTINCT FROM candidate.platform_authentication);
END $$;
REVOKE ALL ON FUNCTION identity_authority.lock_session(bytea,uuid,text,text,uuid) FROM PUBLIC;

-- Maintenance, cascades and ON CONFLICT use the same transactional write path.
-- PostgreSQL fires same-event triggers in name order. Moves take both keys in order.
-- ref: PostgreSQL REL_17_6 src/backend/commands/trigger.c
CREATE FUNCTION identity_authority.advance_directory_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE prior_source text := ''; next_source text := '';
BEGIN
 CASE TG_ARGV[1]
  WHEN 'provider' THEN prior_source := OLD.provider_id::text; next_source := NEW.provider_id::text;
  WHEN 'profile' THEN prior_source := OLD.source; next_source := NEW.source;
  WHEN 'fact' THEN prior_source := OLD.source_provider_id::text; next_source := NEW.source_provider_id::text;
  WHEN 'reference' THEN
   prior_source := coalesce(OLD.source_provider_id::text,OLD.authentication_source);
   next_source := coalesce(NEW.source_provider_id::text,NEW.authentication_source);
  WHEN 'global' THEN NULL;
  ELSE RAISE EXCEPTION 'unknown directory source';
 END CASE;
 INSERT INTO identity_authority.directory_revisions AS r(tenant_id,kind,source,value)
 SELECT DISTINCT tenant,TG_ARGV[0],source,1 FROM
  (VALUES (OLD.tenant_id,prior_source),(NEW.tenant_id,next_source)) affected(tenant,source)
 WHERE tenant IS NOT NULL AND source IS NOT NULL ORDER BY 1,2,3
 ON CONFLICT(tenant_id,kind,source) DO UPDATE SET value=r.value+1;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION identity_authority.advance_directory_revision() FROM PUBLIC;

-- Each entry declares the facts observed by one revision family. UPDATE OF skips unrelated
-- writes and WHEN skips assignments which preserve the value. INSERT/DELETE also track presence.
DO $$ DECLARE item record; cols text; pred text; trg text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('accounts','rows','global','principal_id'),
  ('accounts','enabled','global','principal_id,enabled'),
  ('accounts','epoch','global','principal_id,auth_epoch'),
  ('memberships','rows','global','principal_id'),
  ('memberships','member','global','principal_id,active'),
  ('memberships','epoch','global','principal_id,epoch'),
  ('local_credentials','password','global','principal_id'),
  ('local_credentials','login','global','principal_id,login_key'),
  ('providers','origin','provider','provider_id,enabled,config_version,revocation_epoch'),
  ('external_identities','origin','provider','provider_id,principal_id,identity_id'),
  ('profile_observations','profile','profile','source,principal_id,provider_id,config_version,source_epoch,snapshot_id,sequence,source_revision,collected_at,observed_at,expires_at,value'),
  ('sessions','department','fact','source_provider_id,principal_id,session_id,auth_epoch,membership_epoch,provider_epoch,facts_sequence,auth_facts->''provider_config_version'',auth_facts->''department_snapshot'''),
  ('sessions','groups','fact','source_provider_id,principal_id,session_id,auth_epoch,membership_epoch,provider_epoch,facts_sequence,auth_facts->''provider_config_version'',auth_facts->''groups'''),
  ('sessions','reference','reference','source_provider_id,principal_id,session_id,authentication_source,platform_authentication,credential_kind,auth_epoch,membership_epoch,absolute_expires_at,revoked_at,external_identity_id,provider_epoch,auth_facts->''provider_config_version''')
 ) AS rules(tab,kind,scope,observed)
 LOOP
  trg := 'revision_' || item.kind;
  -- Flat predicates round-trip through pg_dump/pg_restore structural attestation.
  SELECT string_agg(format('(OLD.%s IS DISTINCT FROM NEW.%s)',term,term),' OR ' ORDER BY pos),
   string_agg(DISTINCT split_part(term,'->',1) COLLATE "C",',')
  INTO pred,cols
  FROM unnest(string_to_array('tenant_id,'||item.observed,',')) WITH ORDINALITY terms(term,pos);
  -- Pure renewal preserves the validity already promised to a reference cursor.
  IF item.kind='reference' THEN
   pred := pred||' OR NEW.idle_expires_at < OLD.idle_expires_at';
   cols := cols||',idle_expires_at';
  END IF;
  EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR DELETE ON identity_authority.%I FOR EACH ROW EXECUTE FUNCTION identity_authority.advance_directory_revision(%L,%L)',trg,item.tab,item.kind,item.scope);
  EXECUTE format('CREATE TRIGGER %I AFTER UPDATE OF %s ON identity_authority.%I FOR EACH ROW WHEN (%s) EXECUTE FUNCTION identity_authority.advance_directory_revision(%L,%L)',trg||'_update',cols,item.tab,pred,item.kind,item.scope);
 END LOOP;
END $$;
CREATE INDEX directory_profile_start ON identity_authority.profile_observations(tenant_id,source,observed_at);
CREATE INDEX directory_profile_end ON identity_authority.profile_observations(tenant_id,source,expires_at);
CREATE INDEX personnel_profile_start ON identity_authority.profile_observations(tenant_id,observed_at);
CREATE INDEX personnel_profile_end ON identity_authority.profile_observations(tenant_id,expires_at);
CREATE INDEX directory_link_source ON identity_authority.external_identities(tenant_id,provider_id,principal_id);

CREATE INDEX personnel_session_idle ON identity_authority.sessions(tenant_id,idle_expires_at) WHERE revoked_at IS NULL;

-- Match serde_json/RFC 6901 array indices while preserving numeric object keys.
CREATE FUNCTION identity_authority.profile_path_scalar(document jsonb, segments text[]) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE segment text;
BEGIN
 FOREACH segment IN ARRAY segments LOOP
  CASE jsonb_typeof(document)
   WHEN 'object' THEN document := document->segment;
   WHEN 'array' THEN
    IF segment !~ '^(0|[1-9][0-9]{0,8})$' THEN RETURN NULL; END IF;
    document := document->(segment::integer);
   ELSE RETURN NULL;
  END CASE;
 END LOOP;
 RETURN document;
END $$;
REVOKE ALL ON FUNCTION identity_authority.profile_path_scalar(jsonb,text[]) FROM PUBLIC;
CREATE INDEX personnel_source_observation ON identity_authority.sessions
 (tenant_id,principal_id,source_provider_id,facts_sequence DESC,auth_epoch DESC,membership_epoch DESC,session_id)
 WHERE source_provider_id IS NOT NULL;

-- One observation family, source and bounded principal page per host transaction.
-- ref: PostgreSQL REL_17_STABLE doc/src/sgml/ref/create_function.sgml
CREATE FUNCTION identity_authority.personnel_facts(
 instance_id uuid, tenant uuid, subjects uuid[], source_key text,
 family text, field_path text[], max_age bigint
) RETURNS TABLE (
 generation bigint, sampled_at bigint, principal uuid, status text, snapshot_id uuid,
 provider_version bigint, observation_sequence bigint, source_revision bigint, collected_at_micros bigint,
 observed_at bigint, expires_at bigint, value jsonb
) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
 WITH admitted AS MATERIALIZED (
  SELECT (SELECT coalesce(sum(r.value),0)::bigint FROM identity_authority.directory_revisions r
    WHERE r.tenant_id=tenant AND r.kind IN ('rows','enabled','member','epoch','origin','profile','department','groups')) AS fact_generation, floor(extract(epoch FROM statement_timestamp()))::bigint AS now_at
  FROM identity_authority.tenants g
  WHERE g.tenant_id=tenant AND tenant::text=current_setting('rss.tenant_id',true)
    AND EXISTS (SELECT FROM identity_authority.deployment WHERE authority_id=instance_id)
    AND subjects IS NOT NULL AND cardinality(subjects)<=64
    AND NOT EXISTS (SELECT FROM unnest(subjects) s WHERE s IS NULL OR s='00000000-0000-0000-0000-000000000000')
    AND (SELECT count(DISTINCT s) FROM unnest(subjects) s)=cardinality(subjects)
    AND (source_key='local' OR source_key ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
    AND ((family IN ('groups','department_snapshot') AND source_key<>'local' AND cardinality(field_path)=0)
      OR (family='profile' AND max_age BETWEEN 1 AND 4294967295 AND cardinality(field_path) BETWEEN 1 AND 9 AND octet_length(array_to_string(field_path,''))<=1024
        AND (field_path[1]='extensions' AND cardinality(field_path)>1 OR
        field_path[1] IN ('displayName','username','email','emailVerified') AND cardinality(field_path)=1)))
 ), facts AS (
  SELECT g.*, subject.id, a.enabled AND m.active AS active,
   p.enabled AND link.linked AS linked, p.config_version, p.revocation_epoch,
   o.value AS profile, o.snapshot_id AS profile_snapshot, o.sequence AS profile_sequence, o.source_revision, o.collected_at,
   o.config_version AS profile_version, o.source_epoch, o.observed_at AS profile_time,
   LEAST(o.expires_at,o.observed_at+max_age) AS profile_end,
   s.auth_facts->family AS observation, s.facts_sequence,
   s.fact_version AS fact_version,
   s.auth_epoch=a.auth_epoch AND s.membership_epoch=m.epoch AND s.provider_epoch=p.revocation_epoch
    AND s.fact_version=p.config_version AS current_origin
  FROM admitted g LEFT JOIN LATERAL unnest(subjects) subject(id) ON true
  LEFT JOIN identity_authority.accounts a ON a.tenant_id=tenant AND a.principal_id=subject.id
  LEFT JOIN identity_authority.memberships m ON m.tenant_id=a.tenant_id AND m.principal_id=a.principal_id
  LEFT JOIN identity_authority.providers p ON p.tenant_id=tenant AND p.provider_id=nullif(source_key,'local')::uuid
  CROSS JOIN LATERAL (SELECT EXISTS (SELECT FROM identity_authority.external_identities e
    WHERE e.tenant_id=tenant AND e.principal_id=subject.id AND e.provider_id=p.provider_id) AS linked) link
  LEFT JOIN identity_authority.profile_observations o ON family='profile' AND o.tenant_id=tenant
    AND o.principal_id=subject.id AND o.source=source_key
  LEFT JOIN LATERAL (
   SELECT ses.auth_facts,ses.facts_sequence,ses.auth_epoch,ses.membership_epoch,ses.provider_epoch,
    ses.provider_config_version AS fact_version
   FROM identity_authority.sessions ses
   WHERE family<>'profile' AND ses.tenant_id=tenant AND ses.principal_id=subject.id AND ses.source_provider_id=p.provider_id
   ORDER BY ses.facts_sequence DESC,ses.auth_epoch DESC,ses.membership_epoch DESC,ses.session_id LIMIT 1
  ) s ON true
 ), selected AS (
  SELECT f.*,
   CASE WHEN family='profile' THEN profile_snapshot WHEN jsonb_typeof(observation->'snapshot_id')='string' AND pg_input_is_valid(observation->>'snapshot_id','uuid') THEN (observation->>'snapshot_id')::uuid END AS snap,
   CASE WHEN family='profile' THEN profile_time WHEN jsonb_typeof(observation->'observed_at')='number' AND pg_input_is_valid(observation->>'observed_at','bigint') THEN (observation->>'observed_at')::bigint END AS start_at,
   CASE WHEN family='profile' THEN profile_end WHEN jsonb_typeof(observation->'expires_at')='number' AND pg_input_is_valid(observation->>'expires_at','bigint') THEN (observation->>'expires_at')::bigint END AS end_at,
   CASE WHEN family='groups' THEN observation->'values'
    WHEN family='department_snapshot' THEN observation->'snapshot'
    ELSE identity_authority.profile_path_scalar(profile->field_path[1]->'value',field_path[2:]) END AS selected_value
  FROM facts f
 ), classified AS (
  SELECT s.*, CASE
   WHEN active IS NOT TRUE OR (source_key<>'local' AND linked IS NOT TRUE) THEN 'unavailable'
   WHEN family='profile' AND profile_snapshot IS NULL OR family<>'profile' AND facts_sequence IS NULL THEN 'missing'
   WHEN family='profile' AND source_key<>'local' AND (profile_version<>config_version OR source_epoch<>revocation_epoch)
     OR family<>'profile' AND current_origin IS NOT TRUE THEN 'unavailable'
   WHEN family<>'profile' AND observation->>'status'='available' AND
     (snap IS NULL OR snap='00000000-0000-0000-0000-000000000000' OR start_at IS NULL OR end_at IS NULL
      OR start_at<=0 OR end_at<=start_at OR (family='groups' AND jsonb_typeof(selected_value) IS DISTINCT FROM 'array')
      OR (family='department_snapshot' AND jsonb_typeof(selected_value) IS DISTINCT FROM 'object')) THEN 'unavailable'
   WHEN start_at>now_at THEN 'unavailable' WHEN end_at<=now_at THEN 'expired'
   WHEN family<>'profile' AND observation->>'reason'='claim_missing' THEN 'missing'
   WHEN family<>'profile' AND observation->>'status' IS DISTINCT FROM 'available' THEN 'unavailable'
   WHEN family='profile' AND profile->field_path[1]->>'status' IN ('invalid','not_configured') THEN 'unavailable'
   WHEN selected_value IS NULL OR selected_value='null'::jsonb THEN 'missing'
   WHEN family='profile' AND jsonb_typeof(selected_value) NOT IN ('string','number','boolean') THEN 'unavailable'
   ELSE 'available' END AS state
  FROM selected s
 )
 SELECT fact_generation,now_at,id,state,snap,CASE WHEN family='profile' THEN profile_version ELSE fact_version END,
  CASE WHEN family='profile' THEN profile_sequence ELSE facts_sequence END,c.source_revision,collected_at,
  start_at,end_at,CASE WHEN state='available' THEN selected_value END
 FROM classified c ORDER BY id
$$;
REVOKE ALL ON FUNCTION identity_authority.personnel_facts(uuid,uuid,uuid[],text,text,text[],bigint) FROM PUBLIC;
