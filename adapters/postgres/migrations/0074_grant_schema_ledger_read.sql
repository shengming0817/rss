-- Serving processes may verify the exact SQLx ledger but may never mutate it. Converge away any
-- direct grant left on a login/member role so the closed serving identities below are the only
-- non-owner ACL entries.
DO $$
DECLARE
    direct_grantee record;
BEGIN
    FOR direct_grantee IN
        SELECT DISTINCT role.rolname
        FROM pg_class AS relation
        CROSS JOIN LATERAL aclexplode(relation.relacl) AS acl
        JOIN pg_roles AS role ON role.oid = acl.grantee
        WHERE relation.oid = 'public._sqlx_migrations'::regclass
          AND acl.grantee <> relation.relowner
          AND role.rolname NOT IN ('rss_app', 'rss_app_read')
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations FROM %I',
            direct_grantee.rolname
        );
    END LOOP;
END
$$;

REVOKE ALL ON TABLE public._sqlx_migrations FROM PUBLIC, rss_app, rss_app_read;
GRANT SELECT ON TABLE public._sqlx_migrations TO rss_app, rss_app_read;
