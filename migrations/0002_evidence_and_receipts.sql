-- E-06: Evidence collection and receipt production.
--
-- Adds structured evidence node storage, extends receipt projections with
-- source attribution and evidence gap tracking, and adds missing columns
-- to execution_attempts for full attempt tracking.

-- Evidence nodes table (Master Plan §10.6).
-- Each node is content-addressed by node_id_hex.
CREATE TABLE IF NOT EXISTS evidence_nodes (
    node_id_hex               TEXT PRIMARY KEY,
    registry_id               TEXT NOT NULL,
    source                    TEXT NOT NULL,
    producer_identity         TEXT NOT NULL,
    collected_at              BIGINT NOT NULL,
    asserted_event_at         BIGINT,
    content_digest            TEXT NOT NULL,
    media_type                TEXT NOT NULL,
    disclosure_classification TEXT NOT NULL,
    relationships             TEXT NOT NULL DEFAULT '[]'
);

-- Extend execution_attempts with full tracking fields.
ALTER TABLE execution_attempts
    ADD COLUMN IF NOT EXISTS intent_id_hex      TEXT,
    ADD COLUMN IF NOT EXISTS reservation_token_digest TEXT,
    ADD COLUMN IF NOT EXISTS executor_identity  TEXT,
    ADD COLUMN IF NOT EXISTS correlation_key    TEXT,
    ADD COLUMN IF NOT EXISTS github_deployment_id BIGINT;

-- Extend receipt_projections with source attribution and evidence gaps.
ALTER TABLE receipt_projections
    ADD COLUMN IF NOT EXISTS intent_id_hex      TEXT,
    ADD COLUMN IF NOT EXISTS attempt_id_hex     TEXT,
    ADD COLUMN IF NOT EXISTS dispatch_evidence_refs TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS target_evidence_refs   TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS evidence_gaps          TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS canonical_bytes        BYTEA;
