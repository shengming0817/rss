-- Current v3 -> v4 capacity upgrade. No generation identity is inferred or rewritten.
BEGIN;
LOCK TABLE rss_projection.sources, rss_projection.events, rss_projection.checkpoints, rss_projection.receipts IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF (SELECT obj_description('rss_projection'::regnamespace,'pg_namespace')) IS DISTINCT FROM 'rss-projection-postgres:3' THEN
        RAISE EXCEPTION 'expected projection storage revision 3';
    END IF;
END $$;
ALTER TABLE rss_projection.sources DROP CONSTRAINT sources_source_id_check,
    ADD CONSTRAINT sources_source_id_check CHECK (octet_length(source_id) BETWEEN 1 AND 255 AND (source_id COLLATE "C") !~ '[^A-Za-z0-9_.:-]');
ALTER TABLE rss_projection.checkpoints DROP CONSTRAINT checkpoints_source_id_check,
    ADD CONSTRAINT checkpoints_source_id_check CHECK (octet_length(source_id) BETWEEN 1 AND 255 AND (source_id COLLATE "C") !~ '[^A-Za-z0-9_.:-]'),
    DROP CONSTRAINT checkpoints_projection_id_check,
    ADD CONSTRAINT checkpoints_projection_id_check CHECK (octet_length(projection_id) BETWEEN 1 AND 255 AND (projection_id COLLATE "C") !~ '[^A-Za-z0-9_.:-]');
COMMENT ON SCHEMA rss_projection IS 'rss-projection-postgres:4';
COMMIT;
