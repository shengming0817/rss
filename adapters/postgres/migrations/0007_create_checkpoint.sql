CREATE TABLE checkpoint (
    owner         text        NOT NULL,
    checkpoint_id text        NOT NULL,
    offset_lsn    bigint      NOT NULL,
    version       bigint      NOT NULL CHECK (version > 0),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, checkpoint_id)
);
