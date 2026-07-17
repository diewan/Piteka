-- Piteka first-slice schema (Master Plan §18).
--
-- Canonical Parwana bytes are immutable, id-addressed blobs. Piteka database ids
-- may reference Parwana object ids but never replace them. Multi-tenant columns,
-- cases, retention, and outbox are Stage 8 and intentionally absent here.

-- Immutable canonical protocol objects, keyed by the Parwana object id.
CREATE TABLE IF NOT EXISTS protocol_objects (
    object_id_hex TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    bytes         BYTEA NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

-- Live mandate projection. `version` drives the reservation compare-and-swap;
-- Piteka is the sole live-state authority (Master Plan §6).
CREATE TABLE IF NOT EXISTS mandate_projections (
    mandate_id_hex TEXT PRIMARY KEY,
    version        BIGINT NOT NULL,
    state          TEXT NOT NULL,
    updated_at     BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

-- Unique, idempotent webhook deliveries.
CREATE TABLE IF NOT EXISTS webhook_receipts (
    delivery_id   TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    raw_digest    TEXT NOT NULL,
    received_at   BIGINT NOT NULL
);

-- Append-only audit events, separate from editable product metadata.
CREATE TABLE IF NOT EXISTS audit_events (
    id            BIGSERIAL PRIMARY KEY,
    occurred_at   BIGINT NOT NULL,
    actor         TEXT,
    action        TEXT NOT NULL,
    decision      TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT ''
);

-- Content-addressed evidence descriptors (blobs live in EvidenceObjectStore).
CREATE TABLE IF NOT EXISTS evidence_descriptors (
    digest        TEXT PRIMARY KEY,
    media_type    TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

-- Remaining minimum tables (Master Plan §18). Columns are intentionally lean for
-- the first slice; adapters are added by the tickets that consume them.
CREATE TABLE IF NOT EXISTS integration_installations (
    installation_id TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    repository_id   BIGINT,
    environment_id  BIGINT,
    created_at      BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS credential_references (
    reference_id  TEXT PRIMARY KEY,
    purpose       TEXT NOT NULL,
    secret_ref    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_requests (
    request_id    TEXT PRIMARY KEY,
    requested_by  TEXT NOT NULL,
    intent_id_hex TEXT,
    status        TEXT NOT NULL,
    created_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS approval_decisions (
    decision_id   TEXT PRIMARY KEY,
    request_id    TEXT NOT NULL REFERENCES action_requests(request_id),
    decided_by    TEXT NOT NULL,
    decision      TEXT NOT NULL,
    decided_at    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_attempts (
    attempt_id_hex TEXT PRIMARY KEY,
    mandate_id_hex TEXT NOT NULL,
    state          TEXT NOT NULL,
    created_at     BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS receipt_projections (
    receipt_id_hex TEXT PRIMARY KEY,
    mandate_id_hex TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    created_at     BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS bundle_exports (
    bundle_id_hex TEXT PRIMARY KEY,
    created_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS verification_runs (
    run_id        TEXT PRIMARY KEY,
    bundle_id_hex TEXT,
    context_digest TEXT,
    created_at    BIGINT NOT NULL DEFAULT extract(epoch from now())::bigint
);
