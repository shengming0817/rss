-- 0061_validate_same_id_delivery_constraints.sql
--
-- Validate the constraints installed NOT VALID by 0060 after the cutover rewrite has completed.
-- Keeping validation in one forward migration lets rollout watchdogs cover one explicit statement.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

ALTER TABLE outbox
    VALIDATE CONSTRAINT outbox_same_id_state_valid;
