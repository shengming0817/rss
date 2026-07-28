-- 0076_drop_credential_security_target_mappings.sql
--
-- Security audit consumes the redacted outbox fact directly. The opaque target
-- mapping has no production consumer and would otherwise grow without bound.

DROP TABLE IF EXISTS public.credential_security_target_mappings;
