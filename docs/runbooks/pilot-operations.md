# Runbook — pilot operations

This runbook governs the narrow GitHub deployment pilot. It does not authorize
pilot launch; `deploy/pilot/readiness.json` is the machine-checked release gate.

## Before each deployment window

The release operator records the Piteka revision, exact Parwana contract pin,
database migration level, GitHub App installation/repository/environment,
environment-policy snapshot digest, on-call owner, and change ticket. Confirm
the health endpoint, database connectivity, evidence-object writability,
webhook authentication, backup freshness, clock synchronization, and alert
routing. Verify GitHub required reviewers, wait timers, and protection rules
remain compatible with the controlled profile. Never weaken native GitHub
controls silently.

Stop before dispatch if identity, tenant, contract pin, provider context,
backup, monitoring, or policy state is unknown or mismatched. Unknown is not a
warning state.

## During and after dispatch

Use one correlation key across request, approval, reservation, provider
deployment, webhook observations, receipt, and export. Never log credentials,
session material, reservation tokens, canonical evidence bytes, or raw webhook
payloads. Page on quarantine, repeated dispatch, signature failure, evidence
digest mismatch, database CAS errors, or a missing terminal observation.

After the window, reconcile every reservation to consumed, abandoned, or
quarantined. A quarantined GitHub deployment intent is never released for
retry. Export and independently verify the selected disclosure bundle, record
artifact digests, and retain evidence according to the signed pilot terms.

## Change and maintenance controls

Protocol changes deploy before the exactly pinned consumer. Database migrations
are forward-applied in numeric order and tested on a restored copy. Disable new
dispatch and drain workers before backup, migration, rollback, or incident
containment. Two people approve changes to credential context, retention, or
the pilot environment. See the rollback and incident runbooks for failure
paths.
