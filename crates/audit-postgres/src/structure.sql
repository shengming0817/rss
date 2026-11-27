-- Shared by installation verification and runtime admission in one statement snapshot.
WITH relations AS MATERIALIZED (
 SELECT c.*, n.nspowner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_audit'
), constraints AS MATERIALIZED (
 SELECT k.*, c.relname FROM pg_catalog.pg_constraint k JOIN relations c ON c.oid=k.conrelid
), functions AS MATERIALIZED (
 SELECT p.*, n.nspowner, l.lanname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE n.nspname='rss_audit'
), structure AS (
SELECT
(SELECT count(*)=3 AND bool_and(i.indisvalid AND i.indisready AND i.indislive AND i.indexprs IS NULL)
 AND count(*) FILTER (WHERE i.indpred IS NULL)=2
 AND count(*) FILTER (WHERE i.indisunique AND i.indimmediate AND am.amname='btree'
   AND i.indnkeyatts=2 AND i.indnatts=2
   AND pg_get_indexdef(i.indexrelid,1,false)='tenant_id'
   AND pg_get_indexdef(i.indexrelid,2,false)='ledger_sequence'
   AND (SELECT array_agg(op.opcname ORDER BY k.ord)
        FROM unnest(i.indclass) WITH ORDINALITY k(oid,ord) JOIN pg_catalog.pg_opclass op ON op.oid=k.oid
        WHERE op.opcnamespace='pg_catalog'::regnamespace)=ARRAY['uuid_ops','int8_ops']::name[]
   AND pg_get_expr(i.indpred,i.indrelid)='(ledger_sequence IS NOT NULL)')=1
 FROM pg_catalog.pg_index i JOIN relations c ON c.oid=i.indrelid
 JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=idx.relam
 WHERE c.relname='records') AS indexes,
(SELECT bool_and(convalidated AND NOT condeferrable AND NOT condeferred)
 -- PostgreSQL 18 also catalogs column NOT NULL constraints; the column check covers their shape.
 AND array_agg(relname||':'||pg_get_constraintdef(oid) ORDER BY (relname||':'||pg_get_constraintdef(oid)) COLLATE "C")
   FILTER (WHERE contype<>'n')=$2::text[]
 FROM constraints) AS constraints,
(SELECT count(*)=1 AND bool_and(proname='append_batch' AND prosrc=$1
 AND prosecdef AND proowner=nspowner AND proconfig=ARRAY['search_path=pg_catalog, rss_audit']
 AND prokind='f' AND lanname='plpgsql' AND provolatile='v'
 AND pg_get_function_identity_arguments(oid)='p_tenant uuid, p_sources text[], p_events text[], p_recorded bigint[], p_canonical bytea[], p_ledger bigint[]'
 AND prorettype='record'::regtype AND proallargtypes=ARRAY['uuid'::regtype,'text[]'::regtype,'text[]'::regtype,'bigint[]'::regtype,'bytea[]'::regtype,'bigint[]'::regtype,'text'::regtype,'text'::regtype,'bigint'::regtype]::oid[]
 AND proargmodes=ARRAY['i','i','i','i','i','i','t','t','t']::"char"[]
 AND proargnames=ARRAY['p_tenant','p_sources','p_events','p_recorded','p_canonical','p_ledger','source_id','event_id','position']
 AND NOT proisstrict AND NOT proleakproof AND proparallel='u' AND proretset AND pronargdefaults=0)
 FROM functions) AS functions
)
