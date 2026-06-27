CREATE TABLE distributed_cas (
    cas_key text PRIMARY KEY,
    value bytea NOT NULL,
    token bigint NOT NULL CHECK (token >= 1),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_distributed_cas_updated_at ON distributed_cas (updated_at);
