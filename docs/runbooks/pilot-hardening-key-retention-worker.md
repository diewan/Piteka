# Pilot hardening operations

This runbook covers HARD-02 through HARD-09. A failure in any authority,
identity, evidence, outbox, or worker control is fail-closed; operators must
not bypass it with demo sessions, local keys, direct provider calls, or manual
database status updates.

## Managed signing keys

Production private keys exist only in the configured KMS/HSM. Piteka stores
opaque key identifiers, public keys/certificates where required for
verification, lifecycle state, and audit events.

Rotation order:

1. Provision a new managed key and distribute its public verification
   material.
2. Verify a canary signature independently.
3. atomically mark the new key `active` and the previous key `verify_only`.
4. Keep old verification material for at least the longest evidence retention
   period.

After suspected compromise, suspend signing first, record a conservative
`compromised_not_after` time, rotate, and re-verify artifacts around the
exposure window. Never delete old public verification material. Rollback may
return an uncompromised `verify_only` key to `active`; it may never reactivate
a compromised key.

## OIDC and WebAuthn

OIDC issuer, audience, tenant mappings, and group-to-role mappings are explicit
allow lists. Reject discovery/key-fetch failure, bad issuer/audience/nonce,
unmapped tenants, and empty role sets. Logout/revocation invalidates the
provider session id server-side.

Production approval additionally requires an active WebAuthn credential with
user verification. Challenges expire quickly and bind tenant, user, request,
and the exact canonical intent digest. Recovery suspends approval authority
until a security administrator re-enrolls and audits a credential; recovery
must not downgrade to SMS, email links, or knowledge factors.

## Immutable evidence and outbox

The bucket must have versioning and object lock enabled before enabling the
adapter. Writes use conditional create, retain the provider version id, and
verify bytes against the content digest on reads. Storage unavailability means
the workflow is incomplete.

Every evidence/event publication is inserted into `transactional_outbox` in
the same PostgreSQL transaction as its domain mutation. Publishers lease with
`FOR UPDATE SKIP LOCKED`, use `event_id` as the downstream idempotency key,
retry expired leases, and quarantine poison messages after the configured
limit. Alert on queue age, retry count, and quarantined count.

Rollback disables new writes but leaves object lock, versions, and pending
outbox rows intact. Do not downgrade to mutable storage or discard pending
events.

## Retention and legal hold

Deletion first checks the tenant-scoped active hold and retention deadline.
It removes database payload references and the exact object version, commits a
tombstone plus outbox event, and reports completion only after all sides
confirm. The retained tombstone says only that the payload was deleted; it
does not imply that an action did not occur.

If a partial deletion occurs, quarantine the record and retry reconciliation.
Do not manufacture a tombstone until database deletion, object deletion, and
outbox commit are all confirmed.

## Worker compromise

Workers have no KMS signing authority and no long-lived provider credential.
Immediately before dispatch, the control plane reloads the approved request
and active reservation, verifies a short-lived managed-key capability bound to
tenant, request, intent, reservation, worker identity, and a single-use nonce,
then brokers a narrowly scoped provider credential.

On suspected compromise, revoke the worker identity and capability signing
key, stop credential brokering, quarantine in-flight reservations, and inspect
capability and outbox audit events. Never release a quarantined deployment
mandate merely because the provider query returns no result.
