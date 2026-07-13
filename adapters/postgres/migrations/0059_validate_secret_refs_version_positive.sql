-- 0059_validate_secret_refs_version_positive.sql
--
-- PostgreSQL validates the historical rows under a weaker lock than ADD CONSTRAINT. New writes
-- were already protected as soon as 0058 installed the NOT VALID CHECK.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE secret_refs
    VALIDATE CONSTRAINT secret_refs_version_positive;
