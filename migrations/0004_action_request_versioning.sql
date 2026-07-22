-- Live action-request approval workflow (Master Plan §59 D-06).
--
-- The action_requests / approval_decisions tables were created lean in
-- 0001_init.sql. Backing the live approval use case with Postgres needs two
-- additions the in-memory store already tracked:
--
--   1. A `version` column on action_requests to drive the optimistic-concurrency
--      compare-and-swap on status transitions (mirrors mandate_projections.version,
--      Master Plan §6). Exactly one concurrent approver with the matching version
--      wins; the rest get a conflict.
--   2. An `intent_id_hex` column on approval_decisions so each recorded decision
--      is bound to the exact Parwana intent digest the approver reviewed, never to
--      free-form text.
ALTER TABLE action_requests ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE approval_decisions ADD COLUMN IF NOT EXISTS intent_id_hex TEXT;
