
WITH expected_checks(definition) AS (VALUES
    ('CHECK (((failures >= 0) AND (failures <= ''4294967295''::bigint)))'),
    ('CHECK (((token IS NULL) = (lease_until IS NULL)))'),
    ('CHECK (((token IS NULL) OR (next_run IS NOT NULL)))'),
    ('CHECK ((entity ~ ''^[A-Za-z0-9_.:-]{1,128}$''::text))'),
    ('CHECK ((epoch >= 0))'),
    ('CHECK ((reconciler ~ ''^[A-Za-z0-9_.:-]{1,128}$''::text))'),
    ('CHECK ((result = ANY (ARRAY[''pending''::text, ''running''::text, ''applied''::text, ''converged''::text, ''retry''::text, ''suspended''::text])))'),
    ('CHECK ((wake_version > 0))')
)
SELECT
(SELECT array_agg(attname::text ORDER BY attnum) = ARRAY['tenant_id','reconciler','entity','wake_version','epoch','token','lease_until','next_run','failures','result']
         AND array_agg(format_type(atttypid,atttypmod) ORDER BY attnum)=ARRAY['uuid','text','text','bigint','bigint','uuid','timestamp with time zone','timestamp with time zone','bigint','text']
         AND array_agg(attnotnull ORDER BY attnum)=ARRAY[true,true,true,true,true,false,false,false,true,true]
         FROM pg_attribute WHERE attrelid='rss_reconcile.targets'::regclass AND attnum>0 AND NOT attisdropped)
    AND (SELECT count(*)=1 AND bool_and(pg_get_constraintdef(oid)='PRIMARY KEY (tenant_id, reconciler, entity)') FROM pg_constraint WHERE conrelid='rss_reconcile.targets'::regclass AND contype='p')
    AND (SELECT bool_and(convalidated) AND
         array_agg(pg_get_constraintdef(oid) ORDER BY pg_get_constraintdef(oid)) =
             (SELECT array_agg(definition ORDER BY definition) FROM expected_checks)
         FROM pg_constraint WHERE conrelid='rss_reconcile.targets'::regclass AND contype='c')
    AND NOT EXISTS (SELECT FROM pg_trigger WHERE tgrelid='rss_reconcile.targets'::regclass AND NOT tgisinternal)
    AND (SELECT obj_description(oid,'pg_namespace')='rss-reconcile-postgres:1'
         FROM pg_namespace WHERE nspname='rss_reconcile')
