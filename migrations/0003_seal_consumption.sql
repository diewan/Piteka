-- Phase B (§5.9): independent single-use anchor evidence.
--
-- Preserves the Single-Use Seal consumption proof for a mandate, produced off the
-- dispatch hot path by the local seal backing. It corroborates that the mandate's
-- single use was enforced independently of the private Postgres reservation; a dispute
-- bundle carries it as a SealConsumptionRecord that an offline verifier re-checks.
--
-- One row per mandate, immutable once written: the nullifier is the mandate's
-- reservation-token digest and the commitment is the authorized intent id.
CREATE TABLE IF NOT EXISTS seal_consumption_proofs (
    mandate_id_hex TEXT PRIMARY KEY,
    seal_id_hex    TEXT NOT NULL,
    nullifier_hex  TEXT NOT NULL,
    commitment_hex TEXT NOT NULL,
    anchor_backend TEXT NOT NULL
);
