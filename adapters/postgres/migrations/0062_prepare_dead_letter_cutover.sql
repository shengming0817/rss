-- 0062_prepare_dead_letter_cutover.sql
--
-- Forward-only fail-closed gate for the breaking DLX v3 cutover. A digest/count proves only which
-- rows would be destroyed; it is not a recoverable export proof. RSS therefore exposes no SQL
-- disposal function, compatibility decoder, or owner-only escape hatch. A deployment containing
-- legacy rows must stop here and use a separately reviewed offline export/restore migration that
-- proves the complete encrypted row bytes, key references, schema version, immutable object
-- version/checksum, and a successful restore drill before any source row can be removed.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    LOCK TABLE public.dead_letter IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM public.dead_letter) THEN
        RAISE EXCEPTION 'legacy dead_letter must be empty before DLX v3; automatic disposal is forbidden and a separately reviewed export/restore migration is required';
    END IF;
END
$$;
