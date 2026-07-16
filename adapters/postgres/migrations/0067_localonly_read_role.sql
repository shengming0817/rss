-- 0067_localonly_read_role.sql
--
-- Dedicated LocalOnly tenant reader. The role is intentionally independent from rss_app: explicit
-- READ ONLY transactions, this role default, exact SELECT ACL and FORCE RLS form separate barriers.
-- Password material is deployment-owned and never committed in migrations.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
DECLARE
    reader_oid oid;
    dangerous_attributes boolean;
BEGIN
    SELECT r.oid,
           r.rolsuper
               OR r.rolbypassrls
               OR r.rolcreatedb
               OR r.rolcreaterole
               OR r.rolreplication
               OR r.rolinherit
    INTO reader_oid, dangerous_attributes
    FROM pg_roles AS r
    WHERE r.rolname = 'rss_app_read';

    IF reader_oid IS NULL THEN
        CREATE ROLE rss_app_read
            LOGIN
            NOSUPERUSER
            NOBYPASSRLS
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOINHERIT;
    ELSE
        IF dangerous_attributes THEN
            RAISE EXCEPTION
                'rss_app_read has dangerous role attributes; refuse implicit normalization';
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_auth_members AS membership
            WHERE membership.roleid = reader_oid OR membership.member = reader_oid
        ) THEN
            RAISE EXCEPTION
                'rss_app_read has role membership; refuse implicit normalization';
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_shdepend AS dependency
            WHERE dependency.refclassid = 'pg_authid'::regclass
              AND dependency.refobjid = reader_oid
              AND dependency.deptype = 'o'
        ) THEN
            RAISE EXCEPTION
                'rss_app_read owns database objects; refuse implicit normalization';
        END IF;
    END IF;
END
$$;

ALTER ROLE rss_app_read
    LOGIN
    NOSUPERUSER
    NOBYPASSRLS
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOINHERIT;
ALTER ROLE rss_app_read RESET ALL;
ALTER ROLE rss_app_read SET default_transaction_read_only = 'on';
-- Pin name resolution for every reader session. The runtime catalog gate additionally rejects
-- permissive policies with non-pinned operator/function dependencies, so a policy created under a
-- hostile migrator search_path cannot retain same-text/different-semantics behavior.
ALTER ROLE rss_app_read SET search_path = pg_catalog, public;

-- A role can override its read-only default with an explicit READ WRITE transaction. PostgreSQL's
-- large-object creators/writers are pg_catalog functions with PUBLIC EXECUTE by default, so table,
-- schema, and LO ACLs do not stop a reader from minting a new persistent object. Remove the shared
-- capability, converge any direct reader grant, and restore only the existing writer lane.
REVOKE EXECUTE ON FUNCTION
    pg_catalog.lo_creat(integer),
    pg_catalog.lo_create(oid),
    pg_catalog.lo_from_bytea(oid, bytea),
    pg_catalog.lo_put(oid, bigint, bytea),
    pg_catalog.lo_truncate(integer, integer),
    pg_catalog.lo_truncate64(integer, bigint),
    pg_catalog.lo_unlink(oid),
    pg_catalog.lowrite(integer, bytea)
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION
    pg_catalog.lo_creat(integer),
    pg_catalog.lo_create(oid),
    pg_catalog.lo_from_bytea(oid, bytea),
    pg_catalog.lo_put(oid, bigint, bytea),
    pg_catalog.lo_truncate(integer, integer),
    pg_catalog.lo_truncate64(integer, bigint),
    pg_catalog.lo_unlink(oid),
    pg_catalog.lowrite(integer, bytea)
TO rss_app;

-- Server-side import also creates persistent large objects. It is not PUBLIC by default and must
-- not be restored to the writer, but a pre-existing direct/PUBLIC grant must still converge away.
REVOKE EXECUTE ON FUNCTION
    pg_catalog.lo_import(text),
    pg_catalog.lo_import(text, oid)
FROM PUBLIC, rss_app_read;

DO $$
BEGIN
    -- PostgreSQL has no per-role DENY. Remove the default PUBLIC TEMP capability, then restore it
    -- explicitly for the existing writer so this reader hardening does not change writer behavior.
    EXECUTE format(
        'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
        current_database()
    );
    EXECUTE format(
        'GRANT TEMPORARY ON DATABASE %I TO rss_app',
        current_database()
    );
    EXECUTE format(
        'REVOKE ALL PRIVILEGES ON DATABASE %I FROM rss_app_read',
        current_database()
    );
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO rss_app_read',
        current_database()
    );
END
$$;

DO $$
DECLARE
    application_schema record;
    relation_column record;
    large_object record;
    parameter_acl record;
BEGIN
    -- Converge every existing application schema instead of assuming that only `public` exists.
    -- The runtime gate repeats this check on every start, so later schema drift is fail-closed.
    FOR application_schema IN
        SELECT n.nspname AS schema_name
        FROM pg_namespace AS n
        WHERE n.nspname <> 'information_schema'
          AND n.nspname !~ '^pg_'
        ORDER BY n.nspname
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM rss_app_read',
            application_schema.schema_name
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I FROM rss_app_read',
            application_schema.schema_name
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I FROM rss_app_read',
            application_schema.schema_name
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA %I FROM rss_app_read',
            application_schema.schema_name
        );
    END LOOP;

    -- Table-level REVOKE does not clear column ACL entries. Remove every direct column grant so a
    -- pre-existing role cannot retain a hidden UPDATE/REFERENCES path.
    FOR relation_column IN
        SELECT n.nspname AS schema_name,
               c.relname AS relation_name,
               a.attname AS column_name
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        JOIN pg_attribute AS a ON a.attrelid = c.oid
        WHERE n.nspname <> 'information_schema'
          AND n.nspname !~ '^pg_'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND a.attacl IS NOT NULL
        ORDER BY c.oid, a.attnum
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM rss_app_read',
            relation_column.column_name,
            relation_column.schema_name,
            relation_column.relation_name
        );
    END LOOP;

    -- Large objects and configuration parameters have independent ACL catalogs and are not
    -- covered by schema/table/function revokes. Converge every direct reader grant explicitly.
    FOR large_object IN
        SELECT DISTINCT object.oid,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE 'rss_app_read' END AS grantee
        FROM pg_largeobject_metadata AS object
        CROSS JOIN LATERAL aclexplode(object.lomacl) AS acl
        CROSS JOIN (SELECT oid FROM pg_roles WHERE rolname = 'rss_app_read') AS reader
        WHERE acl.grantee IN (0::oid, reader.oid)
        ORDER BY object.oid, grantee
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON LARGE OBJECT %s FROM %s',
            large_object.oid,
            large_object.grantee
        );
    END LOOP;

    FOR parameter_acl IN
        SELECT DISTINCT parameter.parname,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE 'rss_app_read' END AS grantee
        FROM pg_parameter_acl AS parameter
        CROSS JOIN LATERAL aclexplode(parameter.paracl) AS acl
        CROSS JOIN (SELECT oid FROM pg_roles WHERE rolname = 'rss_app_read') AS reader
        WHERE acl.grantee IN (0::oid, reader.oid)
        ORDER BY parameter.parname, grantee
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON PARAMETER %I FROM %s',
            parameter_acl.parname,
            parameter_acl.grantee
        );
    END LOOP;
END
$$;

GRANT USAGE ON SCHEMA public TO rss_app_read;

-- 0050 expressed a deny-all tenant-index policy as a permissive `canonical AND false` predicate.
-- Rebuild it as canonical permissive tenant binding plus an explicit restrictive deny policy so
-- every permissive policy has one exact semantic shape while direct access remains impossible.
DROP POLICY saga_worker_tenant_index_no_direct_app_access ON saga_worker_tenant_index;
CREATE POLICY saga_worker_tenant_index_tenant_isolation
    ON saga_worker_tenant_index
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
CREATE POLICY saga_worker_tenant_index_no_direct_app_access
    ON saga_worker_tenant_index
    AS RESTRICTIVE
    USING (false)
    WITH CHECK (false);

DO $$
DECLARE
    relation record;
BEGIN
    FOR relation IN
        SELECT n.nspname AS schema_name, c.relname AS relation_name
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND EXISTS (
              SELECT 1
              FROM pg_attribute AS a
              WHERE a.attrelid = c.oid
                AND a.attname = 'tenant_id'
                AND NOT a.attisdropped
          )
        ORDER BY c.oid
    LOOP
        EXECUTE format(
            'GRANT SELECT ON TABLE %I.%I TO rss_app_read',
            relation.schema_name,
            relation.relation_name
        );
    END LOOP;
END
$$;
