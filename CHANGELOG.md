# Piteka changelog

## Unreleased

### Added

- **ANCHOR-01 — on-chain commitment anchoring, off the dispatch hot path.**
  A new `ChainAnchorPort` (`piteka-ports`) with a `ChainAnchorRecord` DTO, a
  deterministic `LocalChainAnchor` adapter (`piteka-infra`) that anchors a
  commitment as pending and advances confirmations to reorg-safe finality on each
  read (the stand-in for a real RPC backing behind the same trait), and
  `chain_anchor_from_record` (`piteka-parwana`) mapping a port record to the
  canonical Parwana `ChainAnchor`. The mapping projects finality through
  `AnchorFinality::from_confirmations`, so finality is derived from confirmation
  depth, never asserted. A cross-boundary test proves a produced anchor
  re-verifies offline from its exact canonical bytes (pending stays pending;
  final assesses as anchored-final for the expected commitment). Contract pin
  bumped to `0.1.8`.
- **DEMO-03 — Agent overreach → fail-closed rejection (Scenario B).**
  `tests/agent_overreach_flow.rs` drives an agent with an approved single-use
  mandate attempting to exceed it (a changed commit SHA, then a different
  environment). Both attempts fail closed with `INTENT_MISMATCH` and zero
  provider dispatch; the structured rejection carries the
  `supplied_intent_id` / `computed_intent_id` dispute detail; the mandate is
  never silently consumed (the honest deployment still executes once). The
  independent Parwana verdict lives in `parwana/csv-sdk/tests/overreach_verdict.rs`;
  the config-driven scenario is `deployment/demos/agent-overreach/`. Runbook:
  `development/demo/DEMO_03_OVERREACH_DISPUTE_SCENARIO_B.md`.

- **DEMO-01 — AI-agent actor drives the MCP under a single-use mandate
  (Scenario A).** A real `AccountabilityTools` backend (`src/demo/`) wired to the
  `ActionRequestUseCase` / `DispatchUseCase`, an MCP-only `AgentActor` that drives
  propose → (human approve) → execute → receipt through `piteka_mcp::handle`, a
  live runner (`src/bin/agent_demo_flow.rs`, Postgres + GitHub App), and a
  deterministic e2e test (`tests/agent_demo_flow.rs`). The agent holds no GitHub
  credential and has no approval tool; the server recomputes the intent and
  rejects changed parameters; a second execute is rejected as
  `MANDATE.REPLAY_DETECTED` with the provider call suppressed. Runbook:
  `development/demo/DEMO_01_AGENT_ACTOR_SCENARIO_A.md`. The human path
  (`controlled_demo_flow`) remains available. The propose → approve/reject →
  revoke lifecycle is now persisted in Postgres (`PgActionRequestStore` /
  `PgApprovalDecisionStore`, migration `0004`) behind a `version` CAS, so the
  agent, the REST API, and the server-rendered work queue share one
  authoritative store; `LiveActionRequestPorts` wires it when `DATABASE_URL`
  is set. `PITEKA_WEB_BIND` makes the web listen address configurable for
  container deployments.
