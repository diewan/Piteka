-- Tenant-scoped investigator cases (CASES-01).
-- Case metadata carries only the optimistic version. Investigator-authored
-- content is immutable and append-only in investigator_case_events.
CREATE TABLE investigator_cases (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    opened_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, case_id)
);

CREATE TABLE investigator_case_events (
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE,
    actor TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence_digest_hex TEXT,
    occurred_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, case_id, sequence),
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES investigator_cases (tenant_id, case_id)
);

CREATE INDEX investigator_case_events_scope_idx
    ON investigator_case_events (tenant_id, case_id, sequence);

CREATE FUNCTION reject_investigator_case_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'investigator case events are append-only';
END;
$$;

CREATE TRIGGER investigator_case_events_no_update
BEFORE UPDATE OR DELETE ON investigator_case_events
FOR EACH ROW EXECUTE FUNCTION reject_investigator_case_event_mutation();
