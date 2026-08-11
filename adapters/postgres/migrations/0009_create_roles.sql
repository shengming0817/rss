-- 角色定义的不可变版本历史（identity RoleDefinitionLifecycle；L1 LocalTx，#1250 / #1291）。
--
-- #1291 pre-GA 窄例外：项目从未部署且不存在 `_sqlx_migrations` ledger/历史数据，直接把 fresh-install
-- schema 收敛为最终模型。`roles` 只保存稳定身份，`role_revisions` 保存 when/who/what 完整快照；不存在
-- update-in-place、兼容视图、双写或后置 backfill。

DO $owner_preflight$
DECLARE
    owner_preexisting boolean;
    owner_oid oid;
BEGIN
    owner_preexisting := EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = 'rss_role_revision_owner'
    );
    IF NOT owner_preexisting THEN
        CREATE ROLE rss_role_revision_owner NOLOGIN NOSUPERUSER NOBYPASSRLS
            NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;

    SELECT oid INTO STRICT owner_oid
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rss_role_revision_owner';

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE oid = owner_oid
          AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
               OR rolreplication OR rolinherit)
    ) THEN
        RAISE EXCEPTION 'rss_role_revision_owner has forbidden role attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members
        WHERE member = owner_oid OR roleid = owner_oid
    ) THEN
        RAISE EXCEPTION 'rss_role_revision_owner must have no role memberships';
    END IF;
    IF owner_preexisting AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_shdepend
        WHERE refclassid = 'pg_catalog.pg_authid'::regclass
          AND refobjid = owner_oid
          AND deptype IN ('a', 'o')
    ) THEN
        RAISE EXCEPTION 'pre-existing rss_role_revision_owner must own no objects or privileges';
    END IF;
END
$owner_preflight$;

CREATE TABLE roles (
    tenant_id  uuid        NOT NULL,
    id         text        NOT NULL CHECK (id <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE role_revisions (
    tenant_id       uuid        NOT NULL,
    role_id         text        NOT NULL,
    version         bigint      NOT NULL CHECK (version > 0),
    name            text        NOT NULL,
    permissions     text[]      NOT NULL DEFAULT '{}'
        CHECK (array_position(permissions, NULL) IS NULL),
    changed_by      uuid        NOT NULL,
    changed_by_kind text        NOT NULL
        CHECK (changed_by_kind IN ('user', 'device', 'admin', 'super_admin', 'service')),
    changed_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, role_id, version),
    CONSTRAINT fk_role_revisions_role
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id)
);

CREATE INDEX idx_roles_tenant ON roles (tenant_id);
CREATE INDEX idx_role_revisions_latest
    ON role_revisions (tenant_id, role_id, version DESC);

-- 唯一写漏斗：稳定 role row 的行锁串行化同一角色的 revision 分配；内容相同则不追加。
CREATE FUNCTION rss_record_role_revision(
    requested_role_id text,
    requested_name text,
    requested_permissions text[],
    requested_changed_by uuid,
    requested_changed_by_kind text
)
RETURNS TABLE(version bigint, changed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    scoped_tenant uuid;
    canonical_permissions text[];
    latest_version bigint;
    latest_name text;
    latest_permissions text[];
BEGIN
    scoped_tenant := NULLIF(current_setting('rss.tenant_id', true), '')::uuid;
    IF scoped_tenant IS NULL THEN
        RAISE EXCEPTION 'role revision requires tenant scope' USING ERRCODE = '42501';
    END IF;
    IF requested_role_id IS NULL OR requested_role_id = '' OR requested_name IS NULL
       OR requested_permissions IS NULL OR requested_changed_by IS NULL
       OR requested_changed_by_kind NOT IN ('user', 'device', 'admin', 'super_admin', 'service') THEN
        RAISE EXCEPTION 'invalid role revision input' USING ERRCODE = '22023';
    END IF;
    IF array_position(requested_permissions, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'role permissions cannot contain null' USING ERRCODE = '22023';
    END IF;

    SELECT COALESCE(array_agg(DISTINCT permission ORDER BY permission), '{}'::text[])
      INTO canonical_permissions
      FROM unnest(requested_permissions) AS permission;

    INSERT INTO public.roles (tenant_id, id)
    VALUES (scoped_tenant, requested_role_id)
    ON CONFLICT (tenant_id, id) DO NOTHING;

    PERFORM 1
      FROM public.roles
     WHERE tenant_id = scoped_tenant AND id = requested_role_id
     FOR UPDATE;

    SELECT revision.version, revision.name, revision.permissions
      INTO latest_version, latest_name, latest_permissions
      FROM public.role_revisions AS revision
     WHERE revision.tenant_id = scoped_tenant AND revision.role_id = requested_role_id
     ORDER BY revision.version DESC
     LIMIT 1;

    IF latest_version IS NOT NULL
       AND latest_name IS NOT DISTINCT FROM requested_name
       AND latest_permissions IS NOT DISTINCT FROM canonical_permissions THEN
        RETURN QUERY SELECT latest_version, false;
        RETURN;
    END IF;

    latest_version := COALESCE(latest_version, 0) + 1;
    INSERT INTO public.role_revisions (
        tenant_id, role_id, version, name, permissions, changed_by, changed_by_kind
    ) VALUES (
        scoped_tenant, requested_role_id, latest_version, requested_name,
        canonical_permissions, requested_changed_by, requested_changed_by_kind
    );
    RETURN QUERY SELECT latest_version, true;
END
$$;

ALTER FUNCTION rss_record_role_revision(text, text, text[], uuid, text)
    OWNER TO rss_role_revision_owner;
REVOKE ALL ON FUNCTION rss_record_role_revision(text, text, text[], uuid, text) FROM PUBLIC;

-- Default ACLs can name arbitrary roles. Remove every named grant before installing the exact
-- owner-only function/table capability set below. No long-lived serving role can execute role
-- definition mutation until a separately authorized product consumer owns an isolated DB lane.
DO $exact_acl$
DECLARE
    unexpected record;
BEGIN
    FOR unexpected IN
        SELECT DISTINCT grantee.rolname
        FROM pg_catalog.pg_proc AS function
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(function.proacl, pg_catalog.acldefault('f', function.proowner))
        ) AS privilege
        JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = privilege.grantee
        WHERE function.oid = 'public.rss_record_role_revision(text,text,text[],uuid,text)'::regprocedure
          AND privilege.privilege_type = 'EXECUTE'
          AND privilege.grantee <> function.proowner
    LOOP
        EXECUTE format(
            'REVOKE EXECUTE ON FUNCTION public.rss_record_role_revision(text,text,text[],uuid,text) FROM %I',
            unexpected.rolname
        );
    END LOOP;

    FOR unexpected IN
        SELECT DISTINCT relation.relname, grantee.rolname
        FROM pg_catalog.pg_class AS relation
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
        ) AS privilege
        JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = privilege.grantee
        WHERE relation.oid IN ('public.roles'::regclass, 'public.role_revisions'::regclass)
          AND privilege.grantee <> relation.relowner
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON TABLE public.%I FROM %I',
            unexpected.relname,
            unexpected.rolname
        );
    END LOOP;
END
$exact_acl$;

GRANT USAGE ON SCHEMA public TO rss_role_revision_owner;
GRANT SELECT, INSERT ON roles, role_revisions TO rss_role_revision_owner;
GRANT UPDATE ON roles TO rss_role_revision_owner; -- required only for SELECT ... FOR UPDATE row locking

REVOKE ALL ON roles, role_revisions FROM PUBLIC;
