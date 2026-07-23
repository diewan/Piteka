-- HARD-02..09 pilot hardening. All authority-bearing rows are tenant scoped.
-- Provider secrets and private keys are intentionally absent: only opaque
-- managed-key and credential references may be persisted.

CREATE TABLE managed_signing_keys (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('mandate', 'receipt', 'worker_capability')),
    status TEXT NOT NULL CHECK (status IN ('active', 'verify_only', 'compromised')),
    compromised_not_after BIGINT,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, key_id)
);

CREATE UNIQUE INDEX managed_signing_keys_one_active_purpose
    ON managed_signing_keys (tenant_id, purpose)
    WHERE status = 'active';

CREATE TABLE webauthn_credentials (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    credential_id BYTEA NOT NULL,
    public_key_cose BYTEA NOT NULL,
    sign_count BIGINT NOT NULL CHECK (sign_count >= 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'recovery_suspended', 'revoked')),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);

CREATE TABLE approval_challenges (
    tenant_id TEXT NOT NULL,
    challenge_digest BYTEA NOT NULL,
    user_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    intent_digest BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    PRIMARY KEY (tenant_id, challenge_digest),
    FOREIGN KEY (tenant_id, request_id) REFERENCES action_requests (tenant_id, request_id)
);

CREATE TABLE oidc_sessions (
    tenant_id TEXT NOT NULL,
    provider_session_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    PRIMARY KEY (tenant_id, provider_session_id)
);

CREATE TABLE evidence_object_versions (
    tenant_id TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    object_key TEXT NOT NULL,
    provider_version_id TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    retain_until BIGINT NOT NULL,
    deleted_at BIGINT,
    PRIMARY KEY (tenant_id, digest_hex),
    UNIQUE (tenant_id, object_key, provider_version_id)
);

CREATE TABLE evidence_legal_holds (
    tenant_id TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    hold_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason <> ''),
    placed_at BIGINT NOT NULL,
    released_at BIGINT,
    PRIMARY KEY (tenant_id, hold_id),
    FOREIGN KEY (tenant_id, digest_hex)
        REFERENCES evidence_object_versions (tenant_id, digest_hex)
);

CREATE UNIQUE INDEX evidence_one_active_hold
    ON evidence_legal_holds (tenant_id, digest_hex, hold_id)
    WHERE released_at IS NULL;

CREATE TABLE evidence_tombstones (
    tenant_id TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    deleted_at BIGINT NOT NULL,
    meaning TEXT NOT NULL CHECK (
        meaning = 'payload deleted; commitment retained; occurrence is not determined'
    ),
    PRIMARY KEY (tenant_id, digest_hex)
);

CREATE TABLE transactional_outbox (
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    payload_digest_hex TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'published', 'quarantined')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner TEXT,
    lease_expires_at BIGINT,
    created_at BIGINT NOT NULL,
    published_at BIGINT,
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX transactional_outbox_pending
    ON transactional_outbox (tenant_id, created_at)
    WHERE status IN ('pending', 'leased');

CREATE TABLE worker_capability_nonces (
    tenant_id TEXT NOT NULL,
    nonce_digest BYTEA NOT NULL,
    request_id TEXT NOT NULL,
    intent_digest_hex TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    PRIMARY KEY (tenant_id, nonce_digest),
    FOREIGN KEY (tenant_id, request_id) REFERENCES action_requests (tenant_id, request_id)
);
