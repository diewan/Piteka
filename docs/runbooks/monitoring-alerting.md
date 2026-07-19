# Runbook — monitoring and alerting

`/health` currently proves only process liveness. It must not be used as proof
that PostgreSQL, evidence storage, GitHub, webhook delivery, signing, or offline
verification is healthy. Target-environment dependency probes and alert
routing are a pilot blocker.

## Required signals

Collect request/error/latency totals by operation without tenant or evidence
content labels; reservation transitions; dispatch accepted/ambiguous/failed;
quarantine age; replay rejection; webhook signature rejection, duplicate count,
and delivery lag; evidence write/digest failure; receipt and export failure;
database pool and CAS failure; backup age; restore-drill age; and contract-pin
mismatch. Logs contain correlation IDs and stable reason codes, not secrets or
raw evidence.

## Paging policy

Page the primary support owner immediately for credential exposure, cross-tenant
access, evidence digest mismatch, unauthorized dispatch, signature failure,
contract-pin mismatch, backup failure, or any quarantine. Page for sustained
database unavailability, webhook lag beyond the signed pilot objective, or
repeated receipt/export failure. Ticket lower-rate client errors and expected
replay rejection unless they indicate abuse.

The responder acknowledges, records timestamps and correlation IDs, freezes
new dispatch when integrity or authority is uncertain, and follows the incident
runbook. No alert may automatically release quarantine or mark an action
successful.

## Release evidence

Before launch, exercise one alert from each critical signal family, prove it
reaches the named primary and backup, inspect the production log sink for
secrets and sensitive payloads, and record alert/dashboard configuration
digests. Re-run after routing or schema changes.
