-- Run with an owner/deployment role after selecting the intended database/schema.
-- Append-only event ledger. The application role should receive INSERT and SELECT
-- only; do not grant UPDATE/DELETE to the web service identity.
CREATE TABLE IF NOT EXISTS THREATLENS_AUDIT_EVENTS (
    EVENT_ID          VARCHAR(36) NOT NULL,
    EVENT_TYPE        VARCHAR(20) NOT NULL COMMENT 'CONTRIBUTION, PEER_REVIEW, or EVALUATION',
    PROJECT_ID        VARCHAR(80) NOT NULL,
    ACTOR             VARCHAR(120) NOT NULL,
    EVENT_DATE        DATE NOT NULL,
    CONTRIBUTION_TYPE VARCHAR(60),
    POINTS            FLOAT,
    REVIEWEE          VARCHAR(120),
    REVIEW_RATING     NUMBER(1,0),
    ARTIFACT_URL      VARCHAR(500),
    METRIC_NAME       VARCHAR(80),
    METRIC_VALUE      FLOAT,
    DETAILS           VARCHAR(2000),
    CREATED_AT        TIMESTAMP_NTZ NOT NULL DEFAULT CURRENT_TIMESTAMP()
)
COMMENT = 'Append-only ThreatLens team contribution, peer review, and evaluation events';

-- Example grants (replace role/database/schema names for this account):
-- GRANT SELECT, INSERT ON TABLE <DATABASE>.<SCHEMA>.THREATLENS_AUDIT_EVENTS TO ROLE <AUDIT_WRITER_ROLE>;
-- GRANT USAGE ON DATABASE <DATABASE> TO ROLE <AUDIT_WRITER_ROLE>;
-- GRANT USAGE ON SCHEMA <DATABASE>.<SCHEMA> TO ROLE <AUDIT_WRITER_ROLE>;
