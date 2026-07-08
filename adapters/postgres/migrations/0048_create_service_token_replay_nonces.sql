-- Durable service-token replay guard for one-shot operator CLIs.
--
-- The table is intentionally platform-scoped rather than tenant-owned: a service-token jti is
-- globally unique for its issuer/audience, and replay detection must not depend on tenant RLS
-- context being set before auth completes.

CREATE TABLE service_token_replay_nonces (
    nonce text PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX service_token_replay_nonces_expires_at_idx
    ON service_token_replay_nonces (expires_at);

GRANT SELECT, INSERT, DELETE ON service_token_replay_nonces TO rss_app;
REVOKE UPDATE ON service_token_replay_nonces FROM PUBLIC;
