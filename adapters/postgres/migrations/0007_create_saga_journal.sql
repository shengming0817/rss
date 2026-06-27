CREATE TABLE saga_journal (
    saga_id       uuid        NOT NULL,
    seq           bigint      NOT NULL,
    step_name     text        NOT NULL,
    status        text        NOT NULL CHECK (status IN ('executing','completed','compensating','compensated','failed')),
    error_summary text,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (saga_id, seq)
);
