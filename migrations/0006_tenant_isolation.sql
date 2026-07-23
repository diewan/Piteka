-- HARD-01: tenant scope is part of every repository key.
--
-- Existing pre-hardening rows cannot be attributed safely. They are retained
-- under a deliberately non-routable quarantine tenant rather than guessed into
-- an active organization. Product code cannot construct this value because
-- TenantScope rejects slash characters.

DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'protocol_objects', 'mandate_projections', 'webhook_receipts',
        'audit_events', 'evidence_descriptors', 'integration_installations',
        'credential_references', 'action_requests', 'approval_decisions',
        'execution_attempts', 'receipt_projections', 'bundle_exports',
        'verification_runs', 'evidence_nodes', 'seal_consumption_proofs'
    ]
    LOOP
        EXECUTE format(
            'ALTER TABLE %I ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT %L',
            table_name,
            '__legacy/unassigned__'
        );
        EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id DROP DEFAULT', table_name);
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I CHECK (tenant_id <> '''') NOT VALID',
            table_name,
            table_name || '_tenant_nonempty'
        );
    END LOOP;
END $$;

-- Replace globally unique keys with tenant-composite keys. Constraint names
-- originate in 0001-0003 and are stable because those migrations name no PKs.
ALTER TABLE approval_decisions DROP CONSTRAINT IF EXISTS approval_decisions_request_id_fkey;

ALTER TABLE protocol_objects DROP CONSTRAINT IF EXISTS protocol_objects_pkey;
ALTER TABLE protocol_objects ADD PRIMARY KEY (tenant_id, object_id_hex);
ALTER TABLE mandate_projections DROP CONSTRAINT IF EXISTS mandate_projections_pkey;
ALTER TABLE mandate_projections ADD PRIMARY KEY (tenant_id, mandate_id_hex);
ALTER TABLE webhook_receipts DROP CONSTRAINT IF EXISTS webhook_receipts_pkey;
ALTER TABLE webhook_receipts ADD PRIMARY KEY (tenant_id, delivery_id);
ALTER TABLE evidence_descriptors DROP CONSTRAINT IF EXISTS evidence_descriptors_pkey;
ALTER TABLE evidence_descriptors ADD PRIMARY KEY (tenant_id, digest);
ALTER TABLE integration_installations DROP CONSTRAINT IF EXISTS integration_installations_pkey;
ALTER TABLE integration_installations ADD PRIMARY KEY (tenant_id, installation_id);
ALTER TABLE credential_references DROP CONSTRAINT IF EXISTS credential_references_pkey;
ALTER TABLE credential_references ADD PRIMARY KEY (tenant_id, reference_id);
ALTER TABLE action_requests DROP CONSTRAINT IF EXISTS action_requests_pkey;
ALTER TABLE action_requests ADD PRIMARY KEY (tenant_id, request_id);
ALTER TABLE approval_decisions DROP CONSTRAINT IF EXISTS approval_decisions_pkey;
ALTER TABLE approval_decisions ADD PRIMARY KEY (tenant_id, decision_id);
ALTER TABLE approval_decisions ADD CONSTRAINT approval_decisions_tenant_request_fkey
    FOREIGN KEY (tenant_id, request_id) REFERENCES action_requests (tenant_id, request_id);
ALTER TABLE execution_attempts DROP CONSTRAINT IF EXISTS execution_attempts_pkey;
ALTER TABLE execution_attempts ADD PRIMARY KEY (tenant_id, attempt_id_hex);
ALTER TABLE receipt_projections DROP CONSTRAINT IF EXISTS receipt_projections_pkey;
ALTER TABLE receipt_projections ADD PRIMARY KEY (tenant_id, receipt_id_hex);
ALTER TABLE bundle_exports DROP CONSTRAINT IF EXISTS bundle_exports_pkey;
ALTER TABLE bundle_exports ADD PRIMARY KEY (tenant_id, bundle_id_hex);
ALTER TABLE verification_runs DROP CONSTRAINT IF EXISTS verification_runs_pkey;
ALTER TABLE verification_runs ADD PRIMARY KEY (tenant_id, run_id);
ALTER TABLE evidence_nodes DROP CONSTRAINT IF EXISTS evidence_nodes_pkey;
ALTER TABLE evidence_nodes ADD PRIMARY KEY (tenant_id, node_id_hex);
ALTER TABLE seal_consumption_proofs DROP CONSTRAINT IF EXISTS seal_consumption_proofs_pkey;
ALTER TABLE seal_consumption_proofs ADD PRIMARY KEY (tenant_id, mandate_id_hex);

-- 0005 made event ids globally unique even though cases were tenant scoped.
-- Keep replay protection inside a tenant without allowing one tenant to block
-- another tenant from using the same opaque event id.
ALTER TABLE investigator_case_events
    DROP CONSTRAINT IF EXISTS investigator_case_events_event_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS investigator_case_events_tenant_event_idx
    ON investigator_case_events (tenant_id, event_id);

CREATE INDEX IF NOT EXISTS audit_events_tenant_order_idx
    ON audit_events (tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS execution_attempts_tenant_mandate_idx
    ON execution_attempts (tenant_id, mandate_id_hex);
CREATE UNIQUE INDEX IF NOT EXISTS execution_attempts_tenant_deployment_idx
    ON execution_attempts (tenant_id, github_deployment_id)
    WHERE github_deployment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS receipt_projections_tenant_mandate_idx
    ON receipt_projections (tenant_id, mandate_id_hex);
CREATE INDEX IF NOT EXISTS evidence_nodes_tenant_node_idx
    ON evidence_nodes (tenant_id, node_id_hex);
