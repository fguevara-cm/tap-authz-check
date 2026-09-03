-- TAP AuthZ Check - evidence schema (PostgreSQL >= 13)

CREATE TABLE IF NOT EXISTS runs (
    id              BIGSERIAL PRIMARY KEY,
    finding         TEXT        NOT NULL,
    mode            TEXT        NOT NULL CHECK (mode IN ('audit', 'verify')),
    base_url        TEXT        NOT NULL,
    actor           TEXT        NOT NULL,
    tool_version    TEXT        NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    vulnerable      INTEGER     NOT NULL DEFAULT 0,
    fixed           INTEGER     NOT NULL DEFAULT 0,
    error_count     INTEGER     NOT NULL DEFAULT 0,
    skip            INTEGER     NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS case_results (
    id                BIGSERIAL PRIMARY KEY,
    run_id            BIGINT     NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    case_id           TEXT       NOT NULL,
    suite             TEXT       NOT NULL,
    category          TEXT,
    method            TEXT       NOT NULL,
    path              TEXT       NOT NULL,
    status            INTEGER,
    classification    TEXT       NOT NULL
        CHECK (classification IN ('VULNERABLE', 'FIXED', 'ERROR', 'SKIP', 'PASSIVE')),
    duration_ms       INTEGER,
    evidence          TEXT,
    response_snippet  TEXT,
    post_check_json   JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_results_run  ON case_results(run_id);
CREATE INDEX IF NOT EXISTS idx_case_results_cls  ON case_results(classification);
CREATE INDEX IF NOT EXISTS idx_case_results_case ON case_results(case_id);
