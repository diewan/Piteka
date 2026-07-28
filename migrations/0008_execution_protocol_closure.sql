-- PIT-NE-003: persist Parwana closure identity without manufacturing history.
-- Nullable columns preserve existing attempts as legacy / ungrounded.
ALTER TABLE execution_attempts
    ADD COLUMN protocol_source_state_id_hex TEXT,
    ADD COLUMN protocol_transition_id_hex TEXT,
    ADD COLUMN protocol_closure_id_hex TEXT,
    ADD COLUMN protocol_consignment_digest_hex TEXT,
    ADD COLUMN protocol_checkpoint_hex TEXT,
    ADD COLUMN protocol_closure_assurance_status TEXT;

ALTER TABLE execution_attempts
    ADD CONSTRAINT execution_attempts_protocol_closure_all_or_none CHECK (
        (protocol_source_state_id_hex IS NULL
            AND protocol_transition_id_hex IS NULL
            AND protocol_closure_id_hex IS NULL
            AND protocol_consignment_digest_hex IS NULL
            AND protocol_checkpoint_hex IS NULL
            AND protocol_closure_assurance_status IS NULL)
        OR
        (protocol_source_state_id_hex IS NOT NULL
            AND protocol_transition_id_hex IS NOT NULL
            AND protocol_closure_id_hex IS NOT NULL
            AND protocol_consignment_digest_hex IS NOT NULL
            AND protocol_checkpoint_hex IS NOT NULL
            AND protocol_closure_assurance_status IS NOT NULL)
    );
